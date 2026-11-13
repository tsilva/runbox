"""Provider-local transport handoff without global proxy or CA inheritance."""

import base64
import json
import os
import re
import socket
from pathlib import Path

from .child import environment
from .config import fields, require


def validate(value):
    fields(value, ("proxy-variable", "ca-variable", "require-stopped"))
    for key, suffix in (("proxy-variable", "_PROXY_URL"), ("ca-variable", "_CA_FILE")):
        require(
            isinstance(value[key], str)
            and re.fullmatch(r"[A-Z][A-Z0-9_]*", value[key])
            and value[key].endswith(suffix)
            and not value[key].startswith(("INFISICAL", "RUNBOX")),
            "Expected a provider-local transport variable",
        )
    require(
        type(value["require-stopped"]) is list and len(value["require-stopped"]) <= 16,
        "Invalid stopped-service inventory",
    )
    for endpoint in value["require-stopped"]:
        require(
            isinstance(endpoint, str)
            and re.fullmatch(r"127[.]0[.]0[.]1:[0-9]{1,5}", endpoint)
            and 1024 <= int(endpoint.rsplit(":", 1)[1]) <= 65535,
            "Expected an explicit loopback service",
        )


def preflight(profile):
    value = profile["execution"].get("handoff")
    if not value:
        return
    validate(value)
    for endpoint in value["require-stopped"]:
        host, port = endpoint.rsplit(":", 1)
        with socket.socket() as connection:
            connection.settimeout(1)
            require(
                connection.connect_ex((host, int(port))) != 0,
                "An existing service is running; stop or restart needs separate authorization",
            )


def provider_environment(profile, runtime, native):
    value = profile["execution"]["handoff"]
    return {
        "HOME": str(Path.home()),
        "PATH": "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        **profile["environment"],
        value["proxy-variable"]: native["HTTPS_PROXY"],
        value["ca-variable"]: runtime["ca-file"],
    }


def main(arguments):
    payload = json.loads(base64.urlsafe_b64decode(os.environ["RUNBOX_POLICY"]))
    profile, runtime = payload["profile"], payload["runtime"]
    require(
        payload["mode"] == "run" and arguments,
        "Provider handoff requires the reviewed application",
    )
    environment(profile, runtime, payload["home"])
    preflight(profile)
    selected = provider_environment(profile, runtime, os.environ)
    os.execvpe(arguments[0], arguments, selected)
