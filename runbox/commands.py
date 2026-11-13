"""Owner-reviewed command links share one runner and contain no wrapper code."""

import json
import os
import tempfile
import fcntl
from pathlib import Path

from .config import fields, require, word
from .trust import digest, directory, regular, state


def registry(selected=None):
    folder = state()
    directory(folder, create=True)
    path = folder / "commands.json"
    value = (
        json.loads(regular(path, private=True).read_text())
        if path.exists()
        else {"version": 1, "commands": {}}
    )
    fields(value, ("version", "commands"))
    require(
        type(value["version"]) is int
        and value["version"] == 1
        and type(value["commands"]) is dict,
        "Invalid command-link registry",
    )
    for name, entry in value["commands"].items():
        if selected is not None and name != selected:
            continue
        require(
            isinstance(name, str) and Path(name).is_absolute(),
            "Invalid command-link path",
        )
        fields(
            entry,
            ("root", "profile", "command", "launcher-sha256"),
            ("rewrite-first", "strip-prefix", "stdin-dispatch"),
        )
        word(entry["profile"])
        if "stdin-dispatch" in entry:
            from .stdin_dispatch import validate

            validate(entry["stdin-dispatch"])
        require(
            isinstance(entry["root"], str)
            and Path(entry["root"]).is_absolute()
            and type(entry["command"]) is list
            and entry["command"]
            and all(
                isinstance(s, str) and "\0" not in s and "\n" not in s
                for s in entry["command"]
            ),
            "Invalid command-link target",
        )
        if "rewrite-first" in entry:
            require(
                type(entry["rewrite-first"]) is list
                and len(entry["rewrite-first"]) == 2
                and all(
                    isinstance(s, str) and s.startswith("--")
                    for s in entry["rewrite-first"]
                ),
                "Invalid command-link argument translation",
            )
        if "strip-prefix" in entry:
            require(
                type(entry["strip-prefix"]) is list
                and entry["strip-prefix"]
                and all(
                    isinstance(s, str) and "\0" not in s and "\n" not in s
                    for s in entry["strip-prefix"]
                ),
                "Invalid command-link compatibility prefix",
            )
    return path, value


def resolve(invocation, arguments, payload=None):
    path = Path(invocation).absolute()
    if path.name == "runbox":
        return arguments
    _, value = registry(str(path))
    require(str(path) in value["commands"], "Unregistered Runbox command link")
    require(
        path.parent.resolve() == path.parent
        and not path.is_symlink()
        and digest(regular(path, private=True))
        == value["commands"][str(path)]["launcher-sha256"],
        "Command link has changed; review its registration",
    )
    entry = value["commands"][str(path)]
    profile = entry["profile"]
    if "stdin-dispatch" in entry:
        from .stdin_dispatch import selected

        require(not arguments, "This command link accepts JSON on stdin only")
        if selected(entry["stdin-dispatch"], payload):
            profile = entry["stdin-dispatch"]["profile"]
    supplied = list(arguments)
    if "strip-prefix" in entry:
        prefix = entry["strip-prefix"]
        require(
            supplied[: len(prefix)] == prefix, "Unexpected legacy command entrypoint"
        )
        supplied = supplied[len(prefix) :]
    if "rewrite-first" in entry:
        before, after = entry["rewrite-first"]
        require(
            supplied[:1] == [before],
            "Use the registered command's reviewed argument form",
        )
        supplied[0] = after
    return [
        "--repo",
        entry["root"],
        "--profile",
        profile,
        "run",
        "--",
        *entry["command"],
        *supplied,
    ]


def dispatch(invocation, arguments):
    path = Path(invocation).absolute()
    if path.name == "runbox":
        return None
    _, value = registry(str(path))
    rule = value["commands"].get(str(path), {}).get("stdin-dispatch")
    if rule is None:
        return None
    from .stdin_dispatch import execute, selected
    import sys

    require(not arguments, "This command link accepts JSON on stdin only")
    payload = sys.stdin.buffer.read(rule["max-bytes"] + 1)
    arguments = resolve(invocation, arguments, payload)
    return execute(arguments, payload, rule, selected(rule, payload))


def link(
    path, root, profile, command, rewrite=None, strip_prefix=None, stdin_dispatch=None
):
    directory(state(), create=True)
    lock = state() / "commands.lock"
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a+") as stream:
        regular(lock, private=True)
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        return _link(
            path, root, profile, command, rewrite, strip_prefix, stdin_dispatch
        )


def _link(
    path, root, profile, command, rewrite=None, strip_prefix=None, stdin_dispatch=None
):
    if stdin_dispatch is not None:
        from .stdin_dispatch import validate

        validate(stdin_dispatch)
        require(
            rewrite is None and strip_prefix is None,
            "JSON dispatch cannot translate argv",
        )
    require(
        type(command) is list
        and command
        and all(
            isinstance(s, str) and "\0" not in s and "\n" not in s for s in command
        ),
        "Invalid fixed command prefix",
    )
    require(
        rewrite is None
        or type(rewrite) is list
        and len(rewrite) == 2
        and all(isinstance(s, str) and s.startswith("--") for s in rewrite),
        "Invalid command-link argument translation",
    )
    require(
        strip_prefix is None
        or type(strip_prefix) is list
        and strip_prefix
        and all(
            isinstance(s, str) and "\0" not in s and "\n" not in s for s in strip_prefix
        ),
        "Invalid command-link compatibility prefix",
    )
    path = Path(path).absolute()
    require(
        path.name != "runbox"
        and path.parent.resolve() == path.parent
        and path.parent.is_dir()
        and path.parent.stat().st_uid == os.getuid(),
        "Select an existing owned directory for the command link",
    )
    target = Path.home() / ".local/bin/runbox"
    require(target.is_file(), "Install the shared Runbox command first")
    registry_path, value = registry()
    if path.exists() or path.is_symlink():
        previous = value["commands"].get(str(path))
        require(
            previous
            and not path.is_symlink()
            and digest(regular(path, private=True)) == previous["launcher-sha256"],
            "An unrelated command already exists; no overwrite performed",
        )
    launcher = regular(target.resolve(), private=True)
    entry = {
        "root": str(root),
        "profile": profile,
        "command": command,
        "launcher-sha256": digest(launcher),
    }
    if rewrite:
        entry["rewrite-first"] = rewrite
    if strip_prefix:
        entry["strip-prefix"] = strip_prefix
    if stdin_dispatch is not None:
        entry["stdin-dispatch"] = stdin_dispatch
    value["commands"][str(path)] = entry
    fd, temporary = tempfile.mkstemp(dir=registry_path.parent, prefix=".commands-")
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write("\n")
        os.replace(temporary, registry_path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    # A hard link preserves argv[0] even when callers canonicalize executable
    # paths. It is the identical shared launcher inode, with no per-command code.
    temporary_link = path.with_name(".runbox-link-" + str(os.getpid()))
    try:
        os.link(launcher, temporary_link)
        os.replace(temporary_link, path)
    finally:
        temporary_link.unlink(missing_ok=True)
