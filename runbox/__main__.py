"""Runbox command line. Approval is explicit administration, never a run fallback."""

import argparse
import base64
import json
import subprocess
import sys
from pathlib import Path

import yaml

from . import __version__
from .config import Error, load, require
from .providers import PROVIDERS
from .runner import command, execute
from .trust import approve, regular, verified


def repository(selected):
    path = Path(selected).absolute()
    require(
        path.resolve() == path and path.is_dir(),
        "Expected a canonical working directory",
    )
    result = subprocess.run(
        ["/usr/bin/git", "-C", str(path), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
    )
    root = Path(result.stdout.strip()) if result.returncode == 0 else path
    require(root.resolve() == root, "Repository root must be canonical")
    regular(root / ".runbox.yaml")
    return root


def main(arguments=None):
    args = list(sys.argv[1:] if arguments is None else arguments)
    if args[:1] == ["--child"]:
        from .child import main as child

        return child(json.loads(base64.urlsafe_b64decode(args[1])), args[2:])
    parser = argparse.ArgumentParser(
        description="Run a command with reviewed access and execution settings."
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument(
        "--repo",
        default=str(Path.cwd()),
        help="Checkout or subdirectory (default: current directory)",
    )
    parser.add_argument("--profile", help="Named profile (default: config default)")
    sub = parser.add_subparsers(dest="action", required=True)
    run = sub.add_parser(
        "run", help="Start a bounded native session and execute a command"
    )
    run.add_argument(
        "--workspace", help="Existing or new directory within approved staging"
    )
    run.add_argument("command", nargs=argparse.REMAINDER)
    check = sub.add_parser(
        "check", help="Verify approvals without network; optionally probe the service"
    )
    check.add_argument(
        "--online", action="store_true", help="Make the reviewed read-only catalog GET"
    )
    check.add_argument("--workspace")
    approval = sub.add_parser(
        "approve",
        help="Record an explicitly reviewed scope, runtime and source snapshot",
    )
    approval.add_argument(
        "--runtime",
        required=True,
        type=Path,
        help="Owner-only reviewed machine runtime JSON",
    )
    sub.add_parser(
        "native-config",
        help="Print derived, metadata-only native configuration; never fetch secrets",
    )
    opts = parser.parse_args(args)
    root = repository(opts.repo)
    config = load(root / ".runbox.yaml")
    name = opts.profile or config["default"]
    require(name in config["profiles"], "Selected profile is missing")
    profile = config["profiles"][name]
    archive = Path(sys.argv[0]).absolute()
    require(
        archive.suffix == ".pyz" and archive.is_file(),
        "Build and install Runbox before using trusted commands",
    )
    if opts.action == "approve":
        regular(opts.runtime.absolute(), private=True)
        runtime = json.loads(opts.runtime.read_text())
        approve(root, name, profile, runtime, archive)
        print("Approved reviewed configuration, source, runtime and Runbox release.")
        return 0
    runtime = verified(root, name, profile, archive)
    if opts.action == "native-config":
        print(
            yaml.safe_dump(
                PROVIDERS[profile["provider"]["type"]].native_config(profile),
                sort_keys=False,
            ),
            end="",
        )
        return 0
    if opts.action == "check" and not opts.online:
        print(
            json.dumps(
                {
                    "ok": True,
                    "approved": True,
                    "provider": profile["provider"]["type"],
                    "sandbox": profile["execution"]["sandbox"],
                    "network_used": False,
                }
            )
        )
        return 0
    rest = opts.command if opts.action == "run" else []
    if rest[:1] == ["--"]:
        rest = rest[1:]
    require(opts.action != "run" or rest, "Specify a command after --")
    argv, cwd = command(
        root,
        profile,
        runtime,
        archive,
        "probe" if opts.action == "check" else "run",
        rest,
        opts.workspace,
    )
    return execute(argv, cwd, probe=opts.action == "check")


def entry():
    try:
        return main()
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(
            "runbox: "
            + (
                str(exc)
                if isinstance(exc, Error)
                else "Operation failed; private diagnostics withheld"
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(entry())
