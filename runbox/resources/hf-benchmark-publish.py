"""Freeze, publish and verify a staged TurboBench bundle."""

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from urllib.parse import urlsplit


HUB = "https://huggingface.co"
MARKER = "huggingface_write_proxy_placeholder"
COMMIT = re.compile(r"[a-f0-9]{40}")
SHA256 = re.compile(r"[a-f0-9]{64}")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:\.post[0-9]+)?")
REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}/[A-Za-z0-9][A-Za-z0-9_.-]{0,95}")
BASELINE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}")
TOP_FILES = {"README.md", "benchmark-index.json"}
MAX_JSON = 1024 * 1024


class PublicationError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise PublicationError(message)


def canonical_root(root):
    root = Path(root)
    require(
        root.is_absolute()
        and root == root.resolve()
        and root.is_dir()
        and root.stat().st_uid == os.getuid(),
        "Expected one owned, canonical benchmark directory",
    )
    return root


def read_json(path, expected_sha256=None):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Duplicate benchmark metadata field")
            result[key] = value
        return result

    with regular_file(path) as stream:
        data = stream.read(MAX_JSON + 1)
    require(len(data) <= MAX_JSON, "Benchmark metadata exceeds the size limit")
    if expected_sha256 is not None:
        require(
            hashlib.sha256(data).hexdigest() == expected_sha256,
            "Benchmark publication plan digest differs",
        )
    value = json.loads(data, object_pairs_hook=unique)
    require(type(value) is dict, "Expected benchmark metadata object")
    return value


def regular_file(path):
    require(
        path.is_absolute() and path.resolve() == path,
        "Benchmark files must be canonical",
    )
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    stream = os.fdopen(fd, "rb")
    try:
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.getuid()
            and not info.st_mode & 0o022,
            "Benchmark file ownership or permissions differ",
        )
        return stream
    except BaseException:
        stream.close()
        raise


def file_evidence(path):
    with regular_file(path) as stream:
        before = os.fstat(stream.fileno())
        sample = stream.read(512)
        stream.seek(0)
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(stream.fileno())
    require(
        (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns),
        "Benchmark file changed while hashing",
    )
    return {
        "size": after.st_size,
        "sha256": digest,
        "sample": base64.b64encode(sample).decode(),
    }


def stage_plan(directory, repository, project, version, expected_parent):
    root = canonical_root(directory)
    require(
        REPO.fullmatch(repository)
        and BASELINE.fullmatch(project)
        and VERSION.fullmatch(version)
        and (expected_parent is None or COMMIT.fullmatch(expected_parent)),
        "Invalid benchmark publication binding",
    )
    index = read_json(root / "benchmark-index.json")
    require(
        index.get("schema") == project + ".benchmark-index/v1"
        and index.get("repo_id") == repository
        and index.get("latest_version") == version
        and isinstance(index.get("entries"), list),
        "Benchmark index differs from the requested publication",
    )
    matching = [
        entry for entry in index["entries"] if entry.get("package_version") == version
    ]
    require(len(matching) == 1, "Expected one staged version in the benchmark index")
    entry = matching[0]
    bundle_id = entry.get("bundle_id")
    parts = entry["path"].split("/")
    require(
        type(bundle_id) is str
        and SHA256.fullmatch(bundle_id)
        and index.get("latest_bundle_id") == bundle_id
        and len(parts) == 4
        and parts[:2] == ["bundles", "v" + version]
        and parts[2].startswith("vs-")
        and BASELINE.fullmatch(parts[2][3:])
        and parts[3] == bundle_id,
        "Benchmark bundle path differs from the staged index",
    )
    bundle = root / entry["path"]
    require(
        bundle.is_dir() and bundle.resolve() == bundle,
        "Staged benchmark bundle is unavailable",
    )
    files = {}
    for path in root.rglob("*"):
        require(not path.is_symlink(), "Benchmark input contains a symlink")
        if path.is_dir():
            require(
                path.is_relative_to(bundle) or bundle.is_relative_to(path),
                "Unreviewed benchmark directory",
            )
            continue
        name = path.relative_to(root).as_posix()
        require(
            name in TOP_FILES or path.is_relative_to(bundle),
            "Unreviewed file in benchmark staging",
        )
        require(
            len(files) < 256
            and all(not part.startswith(".") for part in path.relative_to(root).parts),
            "Benchmark file inventory exceeds the reviewed scope",
        )
        files[name] = file_evidence(path)
    require(
        TOP_FILES <= files.keys() and len(files) > len(TOP_FILES),
        "Incomplete staged benchmark bundle",
    )
    return {
        "version": version,
        "bundle_id": bundle_id,
        "baseline": parts[2][3:],
        "expected_parent": expected_parent,
        "commit_message": f"Add TurboBench evidence for v{version}",
        "tag_message": f"Official TurboBench evidence for {project} {version}",
        "files": files,
    }


def publish(
    stage,
    plan,
    repository,
    project,
    client,
    operation_add,
    missing_repo,
    missing_revision,
):
    staging = canonical_root(stage)
    require(
        stage_plan(
            staging, repository, project, plan["version"], plan["expected_parent"]
        )
        == plan,
        "Staged benchmark bytes differ from the reviewed plan",
    )
    tag = "v" + plan["version"]
    try:
        dataset = client.dataset_info(repository)
    except missing_repo as error:
        require(
            plan["expected_parent"] is None
            and error.response.status_code == 404
            and error.response.headers.get("x-error-code") == "RepoNotFound",
            "Repository absence was not verified",
        )
        client.create_repo(repository, repo_type="dataset", visibility="public")
        dataset = client.dataset_info(repository)
    else:
        require(
            plan["expected_parent"] is not None
            and dataset.sha == plan["expected_parent"],
            "Existing dataset parent differs from the reviewed plan",
        )
    require(
        dataset.id == repository
        and dataset.private is False
        and COMMIT.fullmatch(dataset.sha),
        "Dataset metadata differs from the reviewed scope",
    )
    try:
        client.dataset_info(repository, revision=tag)
    except missing_revision as error:
        require(
            error.response.status_code == 404
            and error.response.headers.get("x-error-code") == "RevisionNotFound",
            "Version tag absence was not verified",
        )
    else:
        raise PublicationError(
            "Version tag already exists; verify it before making changes"
        )
    result = client.create_commit(
        repository,
        repo_type="dataset",
        revision="main",
        parent_commit=dataset.sha,
        commit_message=plan["commit_message"],
        operations=[
            operation_add(name, staging / name) for name in sorted(plan["files"])
        ],
    )
    require(COMMIT.fullmatch(result.oid), "Missing acknowledged benchmark commit")
    client.create_tag(
        repository,
        repo_type="dataset",
        tag=tag,
        revision=result.oid,
        tag_message=plan["tag_message"],
        exist_ok=True,
    )
    require(
        client.dataset_info(repository, revision=tag).sha == result.oid,
        "Version tag differs from the acknowledged benchmark commit",
    )
    return {
        "repo_id": repository,
        "version": plan["version"],
        "bundle_id": plan["bundle_id"],
        "tag": tag,
        "commit": result.oid,
    }


def download_back(plan, receipt, repository, destination, client, download):
    destination = canonical_root(destination)
    require(
        set(receipt) == {"repo_id", "version", "bundle_id", "tag", "commit"}
        and REPO.fullmatch(repository)
        and receipt.get("repo_id") == repository
        and receipt.get("version") == plan["version"]
        and receipt.get("bundle_id") == plan["bundle_id"]
        and receipt.get("tag") == "v" + plan["version"]
        and COMMIT.fullmatch(receipt.get("commit", ""))
        and not any(destination.iterdir()),
        "Expected an empty directory and the acknowledged benchmark receipt",
    )

    def verify_tag():
        return (
            client.dataset_info(repository, revision=receipt["tag"], token=False).sha
            == receipt["commit"]
        )

    require(verify_tag(), "Public benchmark tag differs from the acknowledged commit")
    files = sorted(plan["files"])
    prefix = f"bundles/v{plan['version']}/vs-{plan['baseline']}/{plan['bundle_id']}/"
    require(
        all(
            re.fullmatch(r"[A-Za-z0-9_. /-]+", name)
            and not name.startswith("/")
            and (name in TOP_FILES or name.startswith(prefix))
            and all(part and not part.startswith(".") for part in name.split("/"))
            for name in files
        )
        and TOP_FILES <= set(files)
        and len(files) > len(TOP_FILES),
        "Unexpected public download path",
    )
    for name in files:
        download(
            repository,
            filename=name,
            repo_type="dataset",
            revision=receipt["commit"],
            token=False,
            endpoint=HUB,
            local_dir=destination,
        )
        require(
            file_evidence(destination / name) == plan["files"][name],
            "Public benchmark artifact bytes differ",
        )
    require(verify_tag(), "Public benchmark tag changed during verification")
    return {**receipt, "downloaded_file_count": len(files), "transport_verified": True}


def sdk():
    os.environ.update(
        HF_HUB_DISABLE_IMPLICIT_TOKEN="1",
        HF_HUB_DISABLE_XET="1",
        HF_HUB_DISABLE_TELEMETRY="1",
        HF_HUB_DISABLE_PROGRESS_BARS="1",
        HF_HUB_DISABLE_UPDATE_CHECK="1",
    )
    import huggingface_hub
    from huggingface_hub import errors

    return huggingface_hub, errors


def scoped_client():
    metadata = json.loads(base64.urlsafe_b64decode(os.environ["RUNBOX_POLICY"]))
    for directory in metadata["runtime"].get("imports", []):
        sys.path.insert(0, directory)
    import httpx2

    env = os.environ
    profile = metadata["profile"]
    endpoint = urlsplit(env["HF_ENDPOINT"])
    proxy = urlsplit(env["HTTPS_PROXY"])
    require(
        endpoint.scheme == "http"
        and endpoint.hostname == "127.0.0.1"
        and endpoint.port
        and not endpoint.username
        and not endpoint.password
        and endpoint.path in ("", "/")
        and not endpoint.query
        and not endpoint.fragment
        and profile["environment"]["HF_ENDPOINT"] == env["HF_ENDPOINT"]
        and env.get("HF_TOKEN") == MARKER
        and proxy.scheme == "http"
        and proxy.username
        and proxy.password
        and proxy.netloc.rsplit("@", 1)[-1] == profile["session"]["proxy"]
        and not proxy.query
        and not proxy.fragment
        and proxy.path in ("", "/")
        and env.get("HTTP_PROXY") == env["HTTPS_PROXY"]
        and not env.get("NO_PROXY")
        and not env.get("no_proxy"),
        "Expected the reviewed Hugging Face proxy session",
    )
    hub, errors = sdk()
    import ssl

    context = ssl.create_default_context(cafile=metadata["runtime"]["ca-file"])
    hub.set_client_factory(
        lambda: httpx2.Client(
            proxy=env["HTTPS_PROXY"],
            verify=context,
            trust_env=False,
            follow_redirects=False,
            timeout=30,
        )
    )
    return hub, errors, hub.HfApi(endpoint=env["HF_ENDPOINT"], token=MARKER)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    for field in ("stage", "repository", "project", "version", "parent"):
        prepare.add_argument("--" + field, required=True)
    commands.add_parser("publish")
    commands.add_parser("check")
    verify = commands.add_parser("download-back")
    for field in ("plan", "receipt", "repository", "destination"):
        verify.add_argument("--" + field, required=True)
    args = parser.parse_args()
    if args.command == "prepare":
        print(
            json.dumps(
                stage_plan(
                    args.stage,
                    args.repository,
                    args.project,
                    args.version,
                    None if args.parent == "absent" else args.parent,
                ),
                sort_keys=True,
            )
        )
        return
    if args.command == "download-back":
        hub, _ = sdk()
        print(
            json.dumps(
                download_back(
                    read_json(Path(args.plan)),
                    read_json(Path(args.receipt)),
                    args.repository,
                    args.destination,
                    hub.HfApi(endpoint=HUB, token=False),
                    hub.hf_hub_download,
                )
            )
        )
        return
    hub, errors, client = scoped_client()
    if args.command == "check":
        identity = client.whoami()
        require(
            identity.get("name") == os.environ["HF_BENCHMARK_OWNER"]
            and identity.get("type") == "user",
            "Hugging Face account identity differs from the approved publisher",
        )
        print(
            json.dumps(
                {
                    "ok": True,
                    "read_only": True,
                    "credential_mode": "public-placeholder",
                    "item_count": 1,
                }
            )
        )
        return
    env = os.environ
    plan = read_json(Path(env["HF_BENCHMARK_PLAN"]), env["HF_BENCHMARK_PLAN_SHA256"])
    print(
        json.dumps(
            publish(
                env["HF_BENCHMARK_STAGE"],
                plan,
                env["HF_BENCHMARK_REPOSITORY"],
                env["HF_BENCHMARK_PROJECT"],
                client,
                hub.CommitOperationAdd,
                errors.RepositoryNotFoundError,
                errors.RevisionNotFoundError,
            )
        )
    )


if __name__ == "__main__":
    try:
        main()
    except PublicationError as error:
        raise SystemExit(str(error)) from None
    except Exception:
        raise SystemExit(
            "Benchmark publication check failed; private details withheld"
        ) from None
