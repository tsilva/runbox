"""Explicitly public browser configuration, separate from credential proxying.

Only reviewed names are read. Values exist in memory and the selected child's
environment; they never enter argv, configuration, approval records or logs.
This is an opt-in provider, never a fallback from Agent Vault.
"""

import json
import os
import re
import selectors
import signal
import subprocess
import time
from pathlib import Path

from .config import (
    Error,
    argument_policy,
    arguments_match,
    fields,
    infisical,
    require,
)
from .sessions import duration


def validate(value):
    fields(value, ("provider", "session", "environment", "execution"), ("ready",))
    require(type(value.get("ready", True)) is bool, "Invalid readiness flag")
    provider = fields(
        value["provider"],
        ("type", "instance", "source", "classification", "variables"),
        ("login-profile",),
    )
    require(
        provider["type"] == "infisical-public-config",
        "Expected the explicit public configuration provider",
    )
    require(
        provider["classification"] == "browser-public",
        "Public configuration must be explicitly classified browser-public",
    )
    fields(provider["source"], ("project-id", "environment", "secret-path"))
    # Reuse the native instance, login and source validation; this is not an
    # Agent Vault project/bundle mapping and creates no proxy session.
    infisical(
        {
            "type": "infisical",
            "instance": provider["instance"],
            "source": provider["source"],
            "project-id": provider["source"].get("project-id"),
            "access-bundle": "metadata-only",
            **(
                {"login-profile": provider["login-profile"]}
                if "login-profile" in provider
                else {}
            ),
        }
    )
    variables = provider["variables"]
    require(
        type(variables) is dict and 0 < len(variables) <= 16,
        "Public configuration requires a bounded named variable inventory",
    )
    for name, rule in variables.items():
        require(
            isinstance(name, str)
            and re.fullmatch(
                r"(?:VITE_|NEXT_PUBLIC_|PUBLIC_)[A-Z][A-Z0-9_]{0,95}", name
            ),
            "Only explicitly browser-public variable names are supported",
        )
        fields(rule, ("pattern",))
        argument_policy([[rule]])
    session = fields(value["session"], ("ttl",))
    duration(session["ttl"])
    require(
        value["environment"] == {},
        "Public configuration does not accept additional environment values",
    )
    execution = fields(
        value["execution"],
        ("sandbox", "command", "argv", "arguments", "integrity"),
    )
    require(
        execution["sandbox"] == "none",
        "Public configuration currently requires an explicit fixed unsandboxed command",
    )
    from .sandbox import validate as validate_execution

    validate_execution(execution)
    require(
        type(execution["arguments"]) is list
        and execution["arguments"]
        and all(
            all(isinstance(arg, str) for arg in row) for row in execution["arguments"]
        ),
        "Public configuration commands require exact argument allowlists",
    )
    require(
        execution["integrity"]["files"] or execution["integrity"].get("directories"),
        "Public configuration commands require source integrity pins",
    )
    require(
        re.fullmatch(r"\{[a-z][a-z0-9-]*\}", execution["argv"][0]) is not None,
        "Public configuration must execute a pinned runtime binary",
    )
    return value


def _native_value(root, provider, runtime, name, *, deadline=None):
    source = provider["source"]
    argv = [
        runtime["infisical"],
        *(
            ["--profile=" + provider["login-profile"]]
            if "login-profile" in provider
            else []
        ),
        "secrets",
        "get",
        name,
        "--plain",
        "--domain=" + provider["instance"],
        "--projectId=" + source["project-id"],
        "--env=" + source["environment"],
        "--path=" + source["secret-path"],
        "--expand=false",
        "--include-imports=false",
        "--recursive=false",
        "--secret-overriding=false",
        "--silent",
        "--telemetry=false",
    ]
    environment = {"HOME": str(Path.home()), "PATH": "/usr/bin:/bin"}
    # Native HTTPS keeps normal certificate verification. The additional public
    # source trust bundle must itself be included in the runtime approval.
    ca = runtime.get("files", {}).get("source-ca")
    require(
        ca and ca.get("private", False) is False,
        "Public configuration requires a pinned public source CA bundle",
    )
    environment.update(SSL_CERT_FILE=ca["path"], SSL_CERT_DIR="/var/empty")
    process = subprocess.Popen(
        argv,
        cwd=root,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    selector = selectors.DefaultSelector()
    output = bytearray()
    deadline = (
        min(time.monotonic() + 30, deadline)
        if deadline is not None
        else time.monotonic() + 30
    )
    try:
        selector.register(process.stdout, selectors.EVENT_READ)
        while selector.get_map():
            require(
                time.monotonic() < deadline,
                "Public configuration read timed out; private details withheld",
            )
            for key, _ in selector.select(0.1):
                block = os.read(key.fileobj.fileno(), 4096)
                if not block:
                    selector.unregister(key.fileobj)
                else:
                    output.extend(block)
                    require(
                        len(output) <= 4096,
                        "Public configuration exceeds its read bound; details withheld",
                    )
        process.wait(timeout=max(0.01, deadline - time.monotonic()))
        require(
            process.returncode == 0,
            "Public configuration access failed; renew Infisical login or review the source; private details withheld",
        )
        try:
            result = output.decode("utf-8").removesuffix("\n").removesuffix("\r")
        except UnicodeError:
            raise Error(
                "Invalid public configuration encoding; details withheld"
            ) from None
        require(
            0 < len(result) <= 512 and not any(ord(c) < 32 for c in result),
            "Invalid public configuration value; details withheld",
        )
        return result
    except (OSError, subprocess.TimeoutExpired):
        raise Error(
            "Public configuration read failed; private details withheld"
        ) from None
    finally:
        selector.close()
        output.clear()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        process.stdout.close()


def run(root, name, profile, runtime, archive, arguments, *, probe=False):
    """Validate authority before any source reads, then probe or launch once."""
    validate(profile)
    execution = profile["execution"]
    require(
        probe or profile.get("ready", True),
        "Public configuration route remains disabled pending review",
    )
    require(
        probe
        or arguments
        and arguments[0] == execution["command"]
        and arguments_match(execution["arguments"], arguments[1:]),
        "Command is outside the reviewed public configuration allowlist",
    )
    from .sandbox import expand, substitutions
    from .trust import verified

    # Resolve only public paths before fetching values. The executable must be
    # one of the approved runtime binaries, never an arbitrary substituted file.
    values = substitutions(root, runtime, archive)
    variable = execution["argv"][0][1:-1]
    require(
        variable in {"node", "python", "infisical"} | set(runtime.get("binaries", {})),
        "Public configuration executable is not a pinned runtime binary",
    )
    argv = [expand(arg, values) for arg in execution["argv"]] + arguments[1:]
    public = {}
    try:
        read_deadline = time.monotonic() + 60
        for key, rule in profile["provider"]["variables"].items():
            verified(root, name, profile, archive)
            require(
                time.monotonic() < read_deadline,
                "Public configuration read reached its total time bound",
            )
            setting = _native_value(
                root, profile["provider"], runtime, key, deadline=read_deadline
            )
            require(
                re.fullmatch(rule["pattern"], setting) is not None,
                "Public configuration failed its reviewed format check; details withheld",
            )
            public[key] = setting
        verified(root, name, profile, archive)
        if probe:
            print(
                json.dumps(
                    {
                        "ok": True,
                        "read_only": True,
                        "credential_mode": "browser-public-configuration",
                        "item_count": len(public),
                    }
                )
            )
            return 0
        from .runner import execute

        elapsed_deadline = time.monotonic() + duration(profile["session"]["ttl"])
        wall_deadline = time.time() + duration(profile["session"]["ttl"])

        def lifetime():
            require(
                time.monotonic() < elapsed_deadline and time.time() < wall_deadline,
                "Public configuration command reached its approved lifetime",
            )

        environment = {
            "PATH": ":".join(
                [
                    *([str(Path(runtime["node"]).parent)] if "node" in runtime else []),
                    *runtime.get("path", []),
                    "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
                ]
            ),
            **public,
        }
        return execute(
            argv,
            root,
            health=lifetime,
            extra_environment=environment,
            redactions=tuple(public.values()),
            sanitize=True,
            before_start=lambda: verified(root, name, profile, archive),
        )
    finally:
        public.clear()
