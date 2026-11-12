"""Owner-only approval snapshots; ordinary execution never updates trust."""

import hashlib
import json
import os
import ssl
import stat
from pathlib import Path

from .config import Error, fields, require


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def regular(path, private=False, symlink=False):
    require(path.is_absolute(), "Expected an absolute file path")
    target = path.resolve() if symlink else path
    require(target.resolve() == target, "Symlinked file requires review")
    info = target.lstat()
    require(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == os.getuid()
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
    if execution["sandbox"] == "none":
        return {}
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
        ("python", "python-root", "venv"),
    )
    if sandbox != "none":
        require(
            set(("python", "python-root", "venv")) <= set(runtime),
            "Python runtime is required",
        )
    paths = ["infisical", "ca-file"]
    if "python" in runtime:
        python = Path(runtime["python"])
        root, venv = Path(runtime["python-root"]), Path(runtime["venv"])
        require(
            root.is_absolute()
            and root.resolve() == root
            and venv.resolve() == venv
            and python == venv / "bin/python"
            and python.resolve().is_relative_to(root),
            "Python runtime identity changed",
        )
        paths.append("python")
    pins = {
        key: digest(regular(Path(runtime[key]), symlink=(key == "python")))
        for key in paths
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


def snapshot(root, name, profile, runtime, archive):
    require(
        not any(
            (root / p).exists() or (root / p).is_symlink()
            for p in (
                ".infisical.yaml",
                ".infisical.json",
                ".access.toml",
                ".access.local.toml",
            )
        ),
        "Conflicting legacy/native configuration; finish explicit migration first",
    )
    regular(root / ".runbox.yaml")
    return {
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
