"""Owner-only approval snapshots; ordinary execution never updates trust."""

import hashlib
import json
import os
import ssl
import stat
from pathlib import Path

from .config import Error, fields, require, retired_configs


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def regular(path, private=False, symlink=False, system=False):
    require(path.is_absolute(), "Expected an absolute file path")
    target = path.resolve() if symlink else path
    require(target.resolve() == target, "Symlinked file requires review")
    info = target.lstat()
    require(
        stat.S_ISREG(info.st_mode)
        and info.st_uid in ((0, os.getuid()) if system else (os.getuid(),))
        and not info.st_mode & (0o077 if private else 0o022),
        "Unsafe file ownership or permissions",
    )
    return target


def directory(path, create=False):
    if create:
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = path.lstat()
    require(
        path.resolve() == path
        and stat.S_ISDIR(info.st_mode)
        and info.st_uid == os.getuid()
        and not info.st_mode & 0o077,
        "Approval directory must be canonical and owner-only",
    )


def state():
    return Path.home() / ".config/runbox"


def record_path(root, name):
    key = hashlib.sha256((str(root) + "\0" + name).encode()).hexdigest()
    return state() / "approvals" / (key + ".json")


def source_pins(root, profile):
    execution = profile["execution"]
    if execution["sandbox"] == "none" and "command" not in execution:
        return {}
    if (
        execution["sandbox"] == "macos-command"
        or execution["sandbox"] == "none"
        and "command" in execution
    ):
        integrity = execution["integrity"]
        files = {root / name for name in integrity["files"]}
        for name in integrity.get("directories", []):
            folder = root / name
            require(
                folder.is_dir() and folder.resolve() == folder,
                "Reviewed source directory is unavailable",
            )
            paths = list(folder.rglob("*"))
            require(
                not any(p.is_symlink() for p in paths),
                "Symlinked source content requires review",
            )
            files.update(
                p for p in paths if p.is_file() and "__pycache__" not in p.parts
            )
        return {
            str(path.relative_to(root)): digest(regular(path)) for path in sorted(files)
        }
    python = execution["python"]
    source = root / python["source"]
    package = source / python["package"]
    require(
        source.resolve() == source
        and package.resolve() == package
        and package.is_dir(),
        "Reviewed Python package is unavailable",
    )
    paths = list(package.rglob("*"))
    require(
        not any(p.is_symlink() for p in paths),
        "Symlinked package content requires review",
    )
    files = [p for p in paths if p.is_file() and "__pycache__" not in p.parts]
    files += [root / "pyproject.toml", root / "uv.lock"]
    return {str(p.relative_to(root)): digest(regular(p)) for p in sorted(files)}


def runtime_pins(runtime, sandbox):
    fields(
        runtime,
        ("infisical", "ca-file", "ca-fingerprint"),
        (
            "python",
            "python-root",
            "venv",
            "node",
            "binaries",
            "files",
            "directories",
            "imports",
            "integrity-files",
            "path",
        ),
    )
    if sandbox == "macos-staging":
        require(
            set(("python", "python-root", "venv")) <= set(runtime),
            "Python runtime is required",
        )
    paths = ["infisical", "ca-file"]
    if "python" in runtime:
        python = Path(runtime["python"])
        root = Path(runtime["python-root"])
        venv = Path(runtime["venv"]) if "venv" in runtime else None
        require(
            root.is_absolute()
            and root.resolve() == root
            and (
                venv is None
                or (venv.resolve() == venv and python == venv / "bin/python")
            )
            and python.resolve().is_relative_to(root),
            "Python runtime identity changed",
        )
        paths.append("python")
    if "node" in runtime:
        paths.append("node")
    pins = {
        key: digest(regular(Path(runtime[key]), symlink=(key == "python"), system=True))
        for key in paths
    }
    names = set()
    for inventory in ("binaries", "files", "directories"):
        entries = runtime.get(inventory, {})
        require(
            type(entries) is dict and len(entries) <= 128,
            "Invalid reviewed runtime inventory",
        )
        for name, entry in entries.items():
            from .config import word

            word(name)
            import re

            require(
                not re.fullmatch(r"argument-[0-9]+", name),
                "Reserved service argument substitution",
            )
            require(name not in names, "Duplicate runtime substitution")
            names.add(name)
            require(
                name
                not in {
                    "repo",
                    "release",
                    "home",
                    "workspace",
                    "pid",
                    "python-host",
                    "python",
                    "python-root",
                    "python-real",
                    "node",
                    "node-root",
                    "node-real",
                    "venv",
                    "ca-file",
                    "ca-fingerprint",
                    "ca-base64",
                    "infisical",
                },
                "Reserved runtime substitution",
            )
            if inventory == "binaries":
                path, private = entry, False
            else:
                fields(entry, ("path",), ("private",))
                path, private = entry["path"], entry.get("private", False)
                require(type(private) is bool, "Invalid runtime privacy requirement")
            require(isinstance(path, str), "Invalid runtime path")
            if inventory == "directories":
                pins["directory:" + name] = runtime_directory(Path(path), private)
            else:
                pins[inventory + ":" + name] = digest(
                    regular(Path(path), private=private, system=not private)
                )
    imports = runtime.get("imports", [])
    require(
        type(imports) is list and len(imports) <= 32, "Invalid Python import inventory"
    )
    pins["imports"] = [runtime_directory(Path(path)) for path in imports]
    paths = runtime.get("path", [])
    require(
        type(paths) is list and len(paths) <= 16, "Invalid executable search inventory"
    )
    pins["path"] = [runtime_directory(Path(path)) for path in paths]
    files = runtime.get("integrity-files", [])
    require(
        type(files) is list and len(files) <= 256,
        "Invalid external integrity inventory",
    )
    pins["integrity-files"] = {
        path: digest(regular(Path(path), system=True)) for path in files
    }
    try:
        der = ssl.PEM_cert_to_DER_cert(Path(runtime["ca-file"]).read_text())
        fingerprint = "SHA256:" + ":".join(
            f"{b:02X}" for b in hashlib.sha256(der).digest()
        )
        require(
            runtime["ca-fingerprint"] == fingerprint,
            "Public CA fingerprint does not match",
        )
    except Error:
        raise
    except Exception:
        raise Error("Invalid public proxy CA") from None
    return pins


def runtime_directory(path, private=False):
    require(
        path.is_absolute() and path.resolve() == path,
        "Runtime directory must be canonical",
    )
    info = path.lstat()
    require(
        stat.S_ISDIR(info.st_mode)
        and info.st_uid in ((os.getuid(),) if private else (0, os.getuid()))
        and not info.st_mode & (0o077 if private else 0o022),
        "Unsafe runtime directory",
    )
    return {"path": str(path), "owner": info.st_uid, "mode": stat.S_IMODE(info.st_mode)}


def snapshot(root, name, profile, runtime, archive):
    require(
        not retired_configs(root),
        "Conflicting legacy/native configuration; finish explicit migration first",
    )
    regular(root / ".runbox.yaml")
    result = {
        "version": 1,
        "root": str(root),
        "profile": name,
        "config-sha256": digest(root / ".runbox.yaml"),
        "source-sha256": source_pins(root, profile),
        "runtime": runtime,
        "runtime-sha256": runtime_pins(runtime, profile["execution"]["sandbox"]),
        "runbox-sha256": digest(regular(archive)),
        "sandbox-sha256": digest(regular(archive.with_name("staging.sb"))),
    }
    if (
        profile["execution"]["sandbox"] == "macos-command"
        or "command" in profile["execution"]
    ):
        import zipfile

        resources = {}
        with zipfile.ZipFile(archive) as bundle:
            for entry in bundle.namelist():
                if entry.startswith("runbox/resources/") and not entry.endswith("/"):
                    relative_name = entry.removeprefix("runbox/")
                    path = archive.parent / relative_name
                    actual = digest(regular(path))
                    require(
                        actual == hashlib.sha256(bundle.read(entry)).hexdigest(),
                        "Installed shared resource differs from the reviewed archive",
                    )
                    resources[relative_name] = actual
        result["resource-sha256"] = resources
    return result


def approve(root, name, profile, runtime, archive):
    value = snapshot(root, name, profile, runtime, archive)
    directory(state(), create=True)
    target = record_path(root, name)
    directory(target.parent, create=True)
    # Exclusive temporary creation plus atomic replace preserves the previous approval on failure.
    import tempfile

    fd, temporary = tempfile.mkstemp(prefix=".approval-", dir=target.parent)
    try:
        with os.fdopen(fd, "w") as output:
            json.dump(value, output, sort_keys=True)
            output.write("\n")
        os.replace(temporary, target)
    finally:
        Path(temporary).unlink(missing_ok=True)


def verified(root, name, profile, archive):
    directory(state())
    path = record_path(root, name)
    directory(path.parent)
    regular(path, private=True)
    try:
        record = json.loads(path.read_text())
        require(
            record == snapshot(root, name, profile, record["runtime"], archive),
            "Approved files or scope changed; trusted review is required",
        )
        return record["runtime"]
    except Error:
        raise
    except Exception:
        raise Error(
            "Missing or invalid approval; explicit trusted review is required"
        ) from None
