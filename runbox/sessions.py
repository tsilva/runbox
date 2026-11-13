"""Reviewed auxiliary tunnels and bounded delegated session lifecycles.

Session capabilities travel only in inherited environments. This module never
retrieves source keys and never revokes a delegated capability after child start
was attempted: lost acknowledgements must not terminate an admitted workload.
"""

import ipaddress
import json
import os
import re
import socket
import subprocess
from contextlib import contextmanager
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit
from uuid import UUID

from .config import fields, require, word


def duration(value):
    require(
        isinstance(value, str) and re.fullmatch(r"[1-9][0-9]*[mh]", value),
        "Invalid delegated session duration",
    )
    seconds = int(value[:-1]) * (60 if value[-1] == "m" else 3600)
    require(60 <= seconds <= 8 * 3600, "Delegated session duration exceeds its bound")
    return seconds


def expiry(value, maximum):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        require(
            parsed.tzinfo is not None
            and 0
            < (parsed - datetime.now(timezone.utc)).total_seconds()
            <= maximum + 60,
            "Invalid delegated session expiry",
        )
    except (AttributeError, ValueError, TypeError):
        raise ValueError("Invalid delegated session expiry") from None


def address(value, *, loopback=False):
    require(
        isinstance(value, str) and value.count(":") == 1,
        "Invalid reviewed tunnel endpoint",
    )
    host, port = value.split(":")
    try:
        parsed = ipaddress.ip_address(host)
        valid = (
            parsed.version == 4
            and not parsed.is_unspecified
            and not parsed.is_multicast
        )
        valid = valid and (parsed.is_loopback if loopback else parsed.is_private)
    except ValueError:
        valid = False
    require(
        valid and port.isdecimal() and 1024 <= int(port) <= 65535,
        "Expected an explicit private tunnel endpoint",
    )


def variable(value):
    require(
        isinstance(value, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{1,95}", value),
        "Invalid delegated session variable",
    )
    require(
        not value.startswith(
            ("HTTP", "HTTPS", "ALL_PROXY", "NO_PROXY", "LD_", "DYLD_", "PYTHON")
        )
        and value not in ("PATH", "HOME", "RUNBOX_POLICY"),
        "Reserved delegated session variable",
    )


def validate(session):
    if "tunnel" in session:
        tunnel = fields(session["tunnel"], ("host", "local", "remote"))
        require(
            isinstance(tunnel["host"], str)
            and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}", tunnel["host"]),
            "Expected a configured managed SSH alias",
        )
        address(tunnel["local"], loopback=True)
        address(tunnel["remote"])
        require(
            tunnel["local"] == session["proxy"],
            "Tunnel must serve the reviewed proxy endpoint",
        )
    if "worker" in session:
        worker = fields(
            session["worker"],
            (
                "access-bundle",
                "ttl",
                "proxy",
                "when",
                "capability-variable",
                "context-variable",
                "secret-prefix",
            ),
        )
        word(worker["access-bundle"])
        duration(worker["ttl"])
        address(worker["proxy"])
        variable(worker["capability-variable"])
        variable(worker["context-variable"])
        require(
            worker["capability-variable"] != worker["context-variable"],
            "Session variables must differ",
        )
        variable(worker["secret-prefix"])
        require(
            type(worker["when"]) is list and 1 <= len(worker["when"]) <= 16,
            "Expected explicit delegated-session command prefixes",
        )
        for prefix in worker["when"]:
            require(
                type(prefix) is list
                and 1 <= len(prefix) <= 8
                and all(
                    isinstance(s, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,96}", s)
                    for s in prefix
                ),
                "Invalid delegated-session command prefix",
            )


def safe_output(line):
    """Never print session-bearing URLs or bearer capability tokens."""
    value = re.sub(r"https?://[^\s/]+@", "http://<vault-session>@", line)
    return re.sub(r"agv_[A-Za-z0-9_.%+-]+", "<vault-session>", value)


def _native(profile, runtime, arguments):
    provider = profile["provider"]
    require(
        provider["type"] == "infisical", "Provider does not support delegated sessions"
    )
    argv = [
        runtime["infisical"],
        *(
            ["--profile=" + provider["login-profile"]]
            if "login-profile" in provider
            else []
        ),
        "agent-vault",
        "sessions",
        *arguments,
        "--domain=" + provider["instance"],
        "--silent",
        "--telemetry=false",
    ]
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=65,
            env={"HOME": os.path.expanduser("~"), "PATH": "/usr/bin:/bin"},
            cwd="/",
        )
        require(
            result.returncode == 0,
            "Delegated session operation failed; private diagnostics withheld",
        )
        return result.stdout
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError(
            "Delegated session operation unavailable; private diagnostics withheld"
        ) from None


class Prepared:
    def __init__(self, profile, runtime, arguments):
        self.profile, self.runtime, self.arguments = profile, runtime, list(arguments)
        self.environment = {}
        self.started = False
        self.worker_id = None
        self.forward = None

    def mark_started(self):
        # Called immediately before Popen, including an attempt that loses its acknowledgement.
        self.started = True

    @property
    def redactions(self):
        worker = self.profile["session"].get("worker")
        if worker and self.environment:
            return (self.environment[worker["capability-variable"]],)
        return ()

    def _ssh(self, arguments):
        binary = self.runtime.get("binaries", {}).get("ssh")
        require(binary, "The managed tunnel requires a pinned SSH executable")
        result = subprocess.run(
            [binary, *arguments],
            capture_output=True,
            timeout=20,
            env={"HOME": os.path.expanduser("~"), "PATH": "/usr/bin:/bin"},
        )
        require(
            result.returncode == 0,
            "Managed SSH forwarding unavailable; use its normal recovery policy",
        )

    def open(self):
        session = self.profile["session"]
        validate(session)
        if "tunnel" in session:
            tunnel = session["tunnel"]
            host, port = tunnel["local"].split(":")
            try:
                with socket.create_connection((host, int(port)), timeout=1):
                    pass
            except OSError:
                self._ssh(["-O", "check", tunnel["host"]])
                specification = tunnel["local"] + ":" + tunnel["remote"]
                self._ssh(["-O", "forward", "-L", specification, tunnel["host"]])
                self.forward = specification
        worker = session.get("worker")
        if worker and any(
            self.arguments[: len(prefix)] == prefix for prefix in worker["when"]
        ):
            text = _native(
                self.profile,
                self.runtime,
                [
                    "create",
                    "--project-id=" + self.profile["provider"]["project-id"],
                    "--access-bundle=" + worker["access-bundle"],
                    "--ttl=" + worker["ttl"],
                    "-o",
                    "json",
                ],
            )
            try:
                value = json.loads(text)
                identifier = value["id"]
                require(
                    str(UUID(identifier)) == identifier,
                    "Invalid delegated session identity",
                )
                # Retain the ID as soon as validated so later response errors trigger cleanup.
                self.worker_id = identifier
                token = value["token"]
                require(
                    isinstance(token, str)
                    and re.fullmatch(r"agv_[A-Za-z0-9_.-]+", token),
                    "Unexpected delegated session capability",
                )
                expiry(value["expiresAt"], duration(worker["ttl"]))
                capability = (
                    "http://x-agent-vault:"
                    + quote(token, safe="")
                    + "@"
                    + worker["proxy"]
                )
                context = {
                    "session_id": identifier,
                    "expires_at": value["expiresAt"],
                    "proxy_address": worker["proxy"],
                    "secret_ref": worker["secret-prefix"]
                    + identifier.replace("-", "").upper(),
                }
                self.environment = {
                    worker["capability-variable"]: capability,
                    worker["context-variable"]: json.dumps(context),
                }
            except (KeyError, TypeError, json.JSONDecodeError):
                raise ValueError(
                    "Invalid delegated session response; private diagnostics withheld"
                ) from None
        return self

    def close(self):
        failure = None
        if self.worker_id and not self.started:
            try:
                _native(self.profile, self.runtime, ["revoke", self.worker_id])
            except Exception:
                failure = (
                    "Delegated session cleanup failed; finite expiry still applies"
                )
        if self.forward:
            try:
                self._ssh(
                    [
                        "-O",
                        "cancel",
                        "-L",
                        self.forward,
                        self.profile["session"]["tunnel"]["host"],
                    ]
                )
            except Exception:
                failure = (
                    "Owned managed tunnel cleanup failed; check the managed connection"
                )
        if failure:
            raise ValueError(failure)


@contextmanager
def prepare(profile, runtime, arguments):
    prepared = Prepared(profile, runtime, arguments)
    try:
        yield prepared.open()
    finally:
        prepared.close()


def dynamic_environment(profile):
    """Revalidate only approved ephemeral fields before a child clears its environment."""
    worker = profile["session"].get("worker")
    if not worker:
        return {}
    capability = os.environ.get(worker["capability-variable"])
    context_text = os.environ.get(worker["context-variable"])
    require(
        bool(capability) == bool(context_text), "Incomplete delegated session context"
    )
    if not capability:
        return {}
    try:
        parsed = urlsplit(capability)
        host, port = worker["proxy"].split(":")
        context = json.loads(context_text)
        identifier = context["session_id"]
        require(
            str(UUID(identifier)) == identifier, "Invalid delegated session context"
        )
        require(
            parsed.scheme == "http"
            and parsed.hostname == host
            and parsed.port == int(port)
            and parsed.username == "x-agent-vault"
            and re.fullmatch(r"agv_[A-Za-z0-9_.-]+", parsed.password or "")
            and not parsed.path
            and not parsed.query
            and not parsed.fragment,
            "Unreviewed delegated session capability",
        )
        require(
            set(context) == {"session_id", "expires_at", "proxy_address", "secret_ref"}
            and context["proxy_address"] == worker["proxy"]
            and context["secret_ref"]
            == worker["secret-prefix"] + identifier.replace("-", "").upper()
            and isinstance(context["expires_at"], str)
            and len(context["expires_at"]) <= 64,
            "Unreviewed delegated session context",
        )
        expiry(context["expires_at"], duration(worker["ttl"]))
    except (KeyError, TypeError, ValueError):
        # This fixed error also covers malformed proxy ports and JSON; no reflected input.
        raise ValueError(
            "Invalid delegated session environment; private diagnostics withheld"
        ) from None
    return {
        worker["capability-variable"]: capability,
        worker["context-variable"]: context_text,
    }
