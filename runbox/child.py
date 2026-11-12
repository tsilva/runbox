"""Trusted child bootstrap. Repository imports occur only after guard installation."""

import importlib
import json
import os
import sys
import urllib.parse
import urllib.request
from pathlib import Path

from .config import require
from .guard import Guard


def environment(profile, runtime, home):
    proxy = os.environ.get("HTTP_PROXY", "")
    parsed = urllib.parse.urlsplit(proxy)
    expected = urllib.parse.urlsplit("http://" + profile["session"]["proxy"])
    require(
        parsed.scheme == "http"
        and parsed.hostname == expected.hostname
        and parsed.port == expected.port
        and parsed.username
        and parsed.password
        and not parsed.path
        and not parsed.query
        and not parsed.fragment,
        "Expected scoped native proxy is missing",
    )
    for key in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "http_proxy",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ):
        require(
            key not in os.environ or os.environ[key] == proxy,
            "Conflicting native proxy rejected",
        )
    require(
        not os.environ.get("NO_PROXY") and not os.environ.get("no_proxy"),
        "Proxy bypass rejected",
    )
    result = {
        "HOME": home,
        "PATH": "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        **profile["environment"],
        "HTTP_PROXY": proxy,
        "HTTPS_PROXY": proxy,
        "http_proxy": proxy,
        "https_proxy": proxy,
        "NO_PROXY": "",
        "no_proxy": "",
        "SSL_CERT_FILE": runtime["ca-file"],
        "REQUESTS_CA_BUNDLE": runtime["ca-file"],
        "CURL_CA_BUNDLE": runtime["ca-file"],
        "PYTHONDONTWRITEBYTECODE": "1",
        "HF_HUB_DISABLE_IMPLICIT_TOKEN": "1",
    }
    for key, value in profile["environment"].items():
        require(
            os.environ.get(key) == value,
            "Expected public environment or placeholder is missing",
        )
    os.environ.clear()
    os.environ.update(result)


def main(payload, arguments):
    profile, runtime = payload["profile"], payload["runtime"]
    environment(profile, runtime, payload["home"])
    if profile["execution"]["sandbox"] == "none":
        require(
            payload["mode"] == "run" and arguments,
            "Online probe requires a Python HTTP profile",
        )
        os.execvpe(arguments[0], arguments, os.environ)
    policy = profile["http"]
    Guard(policy).install()
    if payload["mode"] == "probe":
        base = urllib.parse.urlsplit(policy["base-url"])
        request = urllib.request.Request(
            urllib.parse.urlunsplit(
                (base.scheme, base.netloc, policy["probe"], "", "")
            ),
            headers={"Authorization": "Bearer " + policy["placeholder"]},
        )
        with urllib.request.urlopen(request, timeout=25) as response:
            body = json.loads(response.read(4 * 1024 * 1024))
        rows = body.get("data")
        require(isinstance(rows, list), "Invalid model catalog")
        print(
            json.dumps(
                {
                    "ok": True,
                    "read_only": True,
                    "credential_mode": "public-placeholder",
                    "model_count": len(rows),
                }
            )
        )
        return 0
    python = profile["execution"]["python"]
    require(
        arguments and arguments[0] == python["command"],
        "Only the reviewed Python command is allowed",
    )
    # -B prevents writes, not reads. Never load unpinned repository bytecode.
    sys.pycache_prefix = "/dev/null"
    sys.path.insert(0, str(Path(payload["root"]) / python["source"]))
    module, function = python["entrypoint"].split(":")
    sys.argv = arguments
    return getattr(importlib.import_module(module), function)()
