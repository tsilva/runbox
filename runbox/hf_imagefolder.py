"""Freeze and commit a reviewed ImageFolder export through a scoped gateway."""

import argparse
import base64
import hashlib
import json
import os
import re
import ssl
import stat
import sys
from pathlib import Path
from urllib.parse import urlsplit

from .config import Error, require
from .trust import regular


REVISION = re.compile(r"[a-f0-9]{40}")
DIGEST = re.compile(r"[a-f0-9]{64}")
DATASET = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}/[A-Za-z0-9][A-Za-z0-9_.-]{0,95}")
IMAGE = re.compile(r"[a-zA-Z0-9_.-]+\.(?:png|jpe?g|webp)")
MARKER = "huggingface_write_proxy_placeholder"
MAX_PLAN = 1024 * 1024


def evidence(path):
    regular(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == os.getuid()
            and not before.st_mode & 0o022,
            "Unsafe export file",
        )
        sample = stream.read(512)
        stream.seek(0)
        fingerprint = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(stream.fileno())
    require(
        (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns),
        "Export changed while hashing",
    )
    return {
        "size": after.st_size,
        "sha256": fingerprint,
        "sample": base64.b64encode(sample).decode(),
    }


def prepare(stage, parent, message):
    stage = Path(stage)
    require(
        stage.is_absolute()
        and stage == stage.resolve()
        and stage.is_dir()
        and stage.stat().st_uid == os.getuid(),
        "Expected a canonical owned export directory",
    )
    require(
        isinstance(parent, str) and REVISION.fullmatch(parent),
        "Expected a verified parent commit",
    )
    require(
        isinstance(message, str)
        and 0 < len(message) <= 256
        and all(32 <= ord(char) < 127 for char in message),
        "Invalid reviewed commit message",
    )
    folders = {entry.name for entry in stage.iterdir()} - {"README.md", "export.json"}
    require(
        len(folders) == 1 and folders <= {"images", "cropped"},
        "Expected one export image folder",
    )
    folder = stage / next(iter(folders))
    require(
        folder.is_dir() and folder == folder.resolve(),
        "Export image folder must be canonical",
    )
    images = {entry.name for entry in folder.iterdir()} - {"metadata.jsonl"}
    require(
        0 < len(images) <= 254 and all(IMAGE.fullmatch(name) for name in images),
        "Export must contain one to 254 reviewed image files",
    )
    files = [
        "README.md",
        f"{folder.name}/metadata.jsonl",
        *(f"{folder.name}/{name}" for name in sorted(images)),
    ]
    return {
        "expected_parent": parent,
        "commit_message": message,
        "files": {name: evidence(stage / name) for name in files},
    }


def checkout_item(root, relative):
    path = Path(relative)
    selected = root / path
    require(
        not path.is_absolute()
        and selected != root
        and selected == selected.resolve()
        and selected.is_relative_to(root),
        "Expected a reviewed checkout-relative input",
    )
    return selected


def read_plan(path, fingerprint):
    require(DIGEST.fullmatch(fingerprint), "Invalid reviewed plan digest")
    regular(path, private=True)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.getuid()
            and not info.st_mode & 0o077,
            "Unsafe reviewed plan file",
        )
        raw = stream.read(MAX_PLAN + 1)
    require(
        len(raw) <= MAX_PLAN and hashlib.sha256(raw).hexdigest() == fingerprint,
        "Reviewed ImageFolder plan changed",
    )

    def unique(pairs):
        value = dict(pairs)
        require(len(value) == len(pairs), "Duplicate ImageFolder plan field")
        return value

    plan = json.loads(raw, object_pairs_hook=unique)
    require(
        type(plan) is dict
        and set(plan) == {"expected_parent", "commit_message", "files"},
        "Expected one exact ImageFolder plan",
    )
    return plan


def scoped_hub(metadata):
    env = os.environ
    profile = metadata["profile"]
    repository = profile["environment"]["HF_IMAGEFOLDER_REPOSITORY"]
    endpoint = urlsplit(env["HF_ENDPOINT"])
    proxy = urlsplit(env["HTTPS_PROXY"])
    require(
        DATASET.fullmatch(repository)
        and endpoint.scheme == "http"
        and endpoint.hostname == "127.0.0.1"
        and endpoint.port
        and not (
            endpoint.username
            or endpoint.password
            or endpoint.query
            or endpoint.fragment
        )
        and endpoint.path in ("", "/")
        and env["HF_ENDPOINT"] == profile["environment"]["HF_ENDPOINT"]
        and env.get("HF_TOKEN") == MARKER
        and proxy.scheme == "http"
        and proxy.username
        and proxy.password
        and proxy.netloc.rsplit("@", 1)[-1] == profile["session"]["proxy"]
        and proxy.path in ("", "/")
        and not (proxy.query or proxy.fragment)
        and env.get("HTTP_PROXY") == env["HTTPS_PROXY"]
        and not (env.get("NO_PROXY") or env.get("no_proxy")),
        "Expected the reviewed ImageFolder proxy session",
    )
    for directory in metadata["runtime"].get("imports", []):
        sys.path.insert(0, directory)
    env.update(
        HF_HUB_DISABLE_IMPLICIT_TOKEN="1",
        HF_HUB_DISABLE_XET="1",
        HF_HUB_DISABLE_TELEMETRY="1",
        HF_HUB_DISABLE_PROGRESS_BARS="1",
        HF_HUB_DISABLE_UPDATE_CHECK="1",
    )
    import httpx2
    import huggingface_hub as hub

    context = ssl.create_default_context(cafile=metadata["runtime"]["ca-file"])
    hub.set_client_factory(
        lambda: httpx2.Client(
            proxy=env["HTTPS_PROXY"],
            verify=context,
            follow_redirects=False,
            trust_env=False,
            timeout=30,
        )
    )
    return repository, hub, hub.HfApi(endpoint=env["HF_ENDPOINT"], token=MARKER)


def commit(stage, plan, repository, api, add_file):
    result = api.create_commit(
        repo_id=repository,
        repo_type="dataset",
        revision="main",
        parent_commit=plan["expected_parent"],
        commit_message=plan["commit_message"],
        operations=[
            add_file(path_in_repo=name, path_or_fileobj=str(stage / name))
            for name in plan["files"]
        ],
    )
    require(
        isinstance(result.oid, str) and REVISION.fullmatch(result.oid),
        "Hub commit ID could not be verified",
    )
    return {"commit": result.oid}


def main(arguments):
    parser = argparse.ArgumentParser(prog="runbox --imagefolder", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    local = commands.add_parser("prepare")
    for option in ("stage", "parent", "message"):
        local.add_argument("--" + option, required=True)
    publishing = commands.add_parser("publish")
    for argument in ("stage", "plan", "plan_sha256"):
        publishing.add_argument(argument)
    commands.add_parser("check")
    args = parser.parse_args(arguments)
    if args.command == "prepare":
        print(
            json.dumps(prepare(args.stage, args.parent, args.message), sort_keys=True)
        )
        return 0
    require(
        "RUNBOX_POLICY" in os.environ,
        "A reviewed Runbox profile is required for Hub access",
    )
    metadata = json.loads(base64.urlsafe_b64decode(os.environ["RUNBOX_POLICY"]))
    mode = "probe" if args.command == "check" else "run"
    require(
        metadata["mode"] == mode,
        "ImageFolder command differs from the reviewed execution mode",
    )
    if args.command == "publish":
        root = Path(metadata["root"])
        stage = checkout_item(root, args.stage)
        plan = read_plan(checkout_item(root, args.plan), args.plan_sha256)
        require(
            prepare(stage, plan["expected_parent"], plan["commit_message"]) == plan,
            "Staged export differs from the reviewed plan",
        )
    repository, hub, api = scoped_hub(metadata)
    try:
        if args.command == "check":
            identity = api.whoami()
            require(
                identity.get("name") == repository.split("/", 1)[0]
                and identity.get("type") == "user",
                "Hugging Face account differs from the reviewed publisher",
            )
            result = {
                "ok": True,
                "read_only": True,
                "credential_mode": "public-placeholder",
                "item_count": 1,
            }
        else:
            result = commit(stage, plan, repository, api, hub.CommitOperationAdd)
    except hub.errors.HfHubHTTPError as error:
        status = getattr(error.response, "status_code", None)
        message = "ImageFolder operation failed"
        if type(status) is int and 400 <= status <= 599:
            message += f" (HTTP {status})"
        raise Error(message) from None
    print(json.dumps(result))
    return 0
