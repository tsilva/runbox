#!/usr/bin/env python3
"""Install a reviewed local build alongside existing tools; never overwrite another command."""

import argparse
import hashlib
import json
import os
import shlex
import shutil
import stat
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def private(path):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if (
        path.resolve() != path
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise SystemExit(
            "Install directory must be canonical, owner-only and owned by this user"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--build", type=Path, default=Path(__file__).resolve().parents[1] / "dist"
    )
    parser.add_argument(
        "--python",
        type=Path,
        required=True,
        help="Reviewed, persistent Python 3.11+ executable",
    )
    opts = parser.parse_args()
    source, python = opts.build.resolve(), opts.python.resolve()
    if not python.is_file() or not os.access(python, os.X_OK):
        raise SystemExit("Reviewed Python is unavailable")
    manifest = json.loads((source / "checksums.json").read_text())
    valid_names = {"runbox.pyz", "staging.sb"} <= set(manifest) and all(
        name in ("runbox.pyz", "staging.sb")
        or (
            name.startswith("resources/")
            and not Path(name).is_absolute()
            and all(p not in ("", ".", "..") for p in name.split("/"))
        )
        for name in manifest
    )
    if not valid_names or any(digest(source / n) != h for n, h in manifest.items()):
        raise SystemExit("Build checksum mismatch")
    prefix = Path.home() / ".config/runbox"
    private(prefix)
    releases = prefix / "releases"
    private(releases)
    release = (
        releases
        / hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
    )
    private(release)
    for name in manifest:
        destination = release / name
        parent = release
        for part in Path(name).parts[:-1]:
            parent = parent / part
            private(parent)
        if destination.exists() and digest(destination) != manifest[name]:
            raise SystemExit("Existing release content differs")
        if not destination.exists():
            shutil.copyfile(source / name, destination)
            destination.chmod(0o600)
    binary = Path.home() / ".local/bin/runbox"
    binary.parent.mkdir(parents=True, exist_ok=True)
    if binary.exists() or binary.is_symlink():
        if not binary.is_symlink() or not binary.resolve().is_relative_to(releases):
            raise SystemExit("Refusing to replace an unrelated runbox command")
    archive = release / "runbox.pyz"
    code = (
        "import hashlib,runpy,sys; from pathlib import Path; "
        f"p=Path({str(archive)!r}); "
        f"assert hashlib.sha256(p.read_bytes()).hexdigest()=={manifest['runbox.pyz']!r},'Runbox checksum mismatch'; "
        f"assert hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()=={digest(python)!r},'Python checksum mismatch'; "
        "sys.argv=[str(p),*sys.argv[1:]]; sys.path.insert(0,str(p)); runpy.run_path(str(p),run_name='__main__')"
    )
    launcher = release / "runbox"
    launcher.write_text(
        "#!/bin/sh\nexec "
        + shlex.quote(str(python))
        + " -I -S -c "
        + shlex.quote(code)
        + ' --invocation "$0" "$@"\n'
    )
    launcher.chmod(0o700)
    temporary = binary.with_name(".runbox-install-" + str(os.getpid()))
    try:
        temporary.symlink_to(launcher)
        os.replace(temporary, binary)
    finally:
        temporary.unlink(missing_ok=True)
    print("Installed runbox alongside existing launchers. Approvals remain explicit.")


if __name__ == "__main__":
    main()
