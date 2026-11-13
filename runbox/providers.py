"""Built-in adapters. A provider change cannot replace the execution policy."""

import json
import re
import sys
from urllib.parse import quote
from uuid import UUID

from .config import require


class Infisical:
    @staticmethod
    def native_config(profile):
        provider = profile["provider"]
        value = {"version": 1, "general": {"domain": provider["instance"]}}
        if "source" in provider:
            value["secrets-management"] = provider["source"]
        return value

    @staticmethod
    def command(profile, runtime, child, *, existing_session=False):
        provider, session = profile["provider"], profile["session"]
        return [
            runtime["infisical"],
            *(
                ["--profile=" + provider["login-profile"]]
                if "login-profile" in provider
                else []
            ),
            "agent-vault",
            "run",
            "--domain=" + provider["instance"],
            *(
                []
                if existing_session
                else [
                    "--project-id=" + provider["project-id"],
                    "--access-bundle=" + provider["access-bundle"],
                    "--ttl=" + session["ttl"],
                ]
            ),
            "--proxy=" + session["proxy"],
            "--ca-fingerprint=" + runtime["ca-fingerprint"],
            "--no-ca-trust",
            "--silent",
            "--telemetry=false",
            "--no-skills",
            *(["--no-mcp-servers"] if provider.get("no-mcp-servers") else []),
            "--",
            *child,
        ]

    @staticmethod
    def create_lease(profile, runtime):
        from .sessions import _native, duration, expiry

        identifier = None
        try:
            value = json.loads(
                _native(
                    profile,
                    runtime,
                    [
                        "create",
                        "--project-id=" + profile["provider"]["project-id"],
                        "--access-bundle=" + profile["provider"]["access-bundle"],
                        "--ttl=" + profile["session"]["ttl"],
                        "-o",
                        "json",
                    ],
                )
            )
            candidate = value["id"]
            require(str(UUID(candidate)) == candidate, "Invalid owned session identity")
            identifier = candidate
            require(
                isinstance(value["token"], str)
                and re.fullmatch(r"agv_[A-Za-z0-9_.-]+", value["token"]),
                "Invalid owned session capability",
            )
            expiry(value["expiresAt"], duration(profile["session"]["ttl"]))
            return {key: value[key] for key in ("id", "token", "expiresAt")}
        except BaseException:
            if identifier:
                try:
                    Infisical.revoke_lease(profile, runtime, identifier)
                except Exception:
                    print(
                        "Session cleanup could not be verified; finite expiry still applies",
                        file=sys.stderr,
                    )
            raise ValueError(
                "Owned session creation failed; private diagnostics withheld"
            ) from None

    @staticmethod
    def proxy_url(profile, lease):
        return (
            "http://x-agent-vault:"
            + quote(lease["token"], safe="")
            + "@"
            + profile["session"]["proxy"]
        )

    @staticmethod
    def session_environment(lease):
        return {"INFISICAL_AGENT_VAULT_SESSION_TOKEN": lease["token"]}

    @staticmethod
    def revoke_lease(profile, runtime, identifier):
        from .sessions import _native

        require(str(UUID(identifier)) == identifier, "Invalid owned session identity")
        _native(profile, runtime, ["revoke", identifier])


PROVIDERS = {"infisical": Infisical}
