"""Runbox command line. Approval is explicit administration, never a run fallback."""

import argparse
import base64
import json
import os
import subprocess
import sys
from pathlib import Path

import yaml

from . import __version__
from .config import Error, arguments_match, load, require, retired_configs
from .providers import PROVIDERS
from .runner import command, execute
from .trust import approve, directory, digest, record_path, regular, state, verified


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


def select_profile(config, explicit, action, arguments=()):
    if explicit or action != "run":
        return explicit or config.get("default")
    supplied = list(arguments)
    if supplied[:1] == ["--"]:
        supplied = supplied[1:]
    if not supplied:
        return config.get("default")
    matches = []
    for name, profile in config.get("profiles", {}).items():
        execution = profile["execution"]
        command = execution.get("python", execution).get("command")
        allowed = execution.get("python", execution).get("arguments")
        if command == supplied[0] and arguments_match(allowed, supplied[1:]):
            matches.append(name)
    require(
        len(matches) <= 1,
        "Multiple approved command profiles match; select --profile explicitly",
    )
    return matches[0] if matches else config.get("default")


def main(arguments=None):
    args = list(sys.argv[1:] if arguments is None else arguments)
    if args[:1] == ["--invocation"]:
        from .commands import dispatch, resolve

        require(len(args) >= 2, "Missing command invocation")
        result = dispatch(args[1], args[2:])
        if result is not None:
            return result
        args = resolve(args[1], args[2:])
    if args[:1] == ["--child"]:
        from .child import main as child

        return child(json.loads(base64.urlsafe_b64decode(args[1])), args[2:])
    if args[:1] == ["--command-child"]:
        from .python_client import main as python_client

        return python_client(args[1:])
    if args[:1] == ["--handoff"]:
        from .handoff import main as handoff

        return handoff(args[1:])
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
    sub.add_parser(
        "bindings",
        help="Print metadata-only source inventories as JSON; never access credentials",
    )
    linked = sub.add_parser(
        "link", help="Create a reviewed command link to the shared runner"
    )
    linked.add_argument("path", type=Path)
    linked.add_argument(
        "--rewrite-first",
        type=json.loads,
        help="JSON pair of the old and new first argument",
    )
    linked.add_argument(
        "--strip-prefix",
        type=json.loads,
        help="Exact JSON argument prefix accepted from an existing caller",
    )
    linked.add_argument(
        "--stdin-dispatch",
        type=json.loads,
        help="Reviewed bounded JSON selector and response policy",
    )
    linked.add_argument("--command", nargs=argparse.REMAINDER, required=True)
    opts = parser.parse_args(args)
    root = repository(opts.repo)
    config = load(root / ".runbox.yaml")
    if opts.action == "bindings":
        require(
            not retired_configs(root),
            "Conflicting retired access configuration",
        )
        print(json.dumps(config.get("bindings", {}), sort_keys=True))
        return 0
    name = select_profile(
        config, opts.profile, opts.action, getattr(opts, "command", ())
    )
    require(
        name in config.get("profiles", {}),
        "Selected command profile is missing; metadata alone cannot run a command",
    )
    profile = config["profiles"][name]
    if opts.action == "link":
        from .commands import link
        from .stdin_dispatch import validate as validate_dispatch

        require(opts.command, "Specify the fixed command prefix")
        # The ordinary check selects and verifies the already approved release.
        # Linking cannot approve configuration or promote a new release.
        targets = {name}
        if opts.stdin_dispatch is not None:
            validate_dispatch(opts.stdin_dispatch)
            targets.add(opts.stdin_dispatch["profile"])
        for target in targets:
            require(
                target in config.get("profiles", {}),
                "Missing command-link target profile",
            )
            checked = subprocess.run(
                [
                    str(Path.home() / ".local/bin/runbox"),
                    "--repo",
                    str(root),
                    "--profile",
                    target,
                    "check",
                ],
                capture_output=True,
            )
            require(
                checked.returncode == 0,
                "The command-link target must pass its existing approval check",
            )
        link(
            opts.path,
            root,
            name,
            opts.command,
            opts.rewrite_first,
            opts.strip_prefix,
            opts.stdin_dispatch,
        )
        print("Linked the command to the reviewed shared Runbox profile.")
        return 0
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
    # Deterministic version selection precedes validation: installing another
    # release never silently activates it for an already approved consumer.
    approved = record_path(root, name)
    if approved.exists():
        directory(state())
        directory(approved.parent)
        regular(approved, private=True)
        record = json.loads(approved.read_text())
        expected = record.get("runbox-sha256")
        if expected != digest(archive):
            releases = state() / "releases"
            directory(releases)
            matches = []
            for release in releases.iterdir():
                directory(release)
                candidate = release / "runbox.pyz"
                if candidate.is_file() and digest(regular(candidate)) == expected:
                    policy = regular(release / "staging.sb")
                    if digest(policy) == record.get("sandbox-sha256"):
                        matches.append(candidate)
            require(
                len(matches) == 1,
                "Approved Runbox release is missing or ambiguous; trusted review is required",
            )
            os.execv(
                sys.executable,
                [
                    sys.executable,
                    "-I",
                    "-S",
                    str(matches[0]),
                    *([] if opts.profile else ["--profile", name]),
                    *args,
                ],
            )
    runtime = verified(root, name, profile, archive)
    from .readiness import ready

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
                    "ready": profile.get("ready", True)
                    and ready(root, profile, runtime, archive),
                }
            )
        )
        return 0
    rest = opts.command if opts.action == "run" else []
    if rest[:1] == ["--"]:
        rest = rest[1:]
    require(opts.action != "run" or rest, "Specify a command after --")
    if opts.action == "run":
        require(
            ready(root, profile, runtime, archive),
            "Administrative readiness is pending; verify the same approved route before running",
        )
    if opts.action == "run" and "handoff" in profile["execution"]:
        from .handoff import preflight

        preflight(profile)
    argv, cwd = command(
        root,
        profile,
        runtime,
        archive,
        "probe" if opts.action == "check" else "run",
        rest,
        opts.workspace,
    )
    from .services import Session
    from .sessions import prepare

    workspace = cwd if "workspace" in profile["execution"] else None
    with Session(root, profile, runtime, archive, workspace, rest) as services:
        with prepare(profile, runtime, rest) as auxiliary:
            return execute(
                argv,
                cwd,
                probe=opts.action == "check",
                health=services.healthy if profile.get("services") else None,
                extra_environment=auxiliary.environment,
                redactions=auxiliary.redactions,
                before_start=auxiliary.mark_started,
                sanitize=bool(
                    profile.get("services")
                    or profile["session"].get("worker")
                    or profile["execution"].get("sanitize-output")
                ),
                stderr_policy=profile["execution"].get("stderr", "inherit"),
            )


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
