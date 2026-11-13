"""Shared Python entrypoint and bounded read-only HTTP verification."""

import base64
import json
import importlib
import os
import runpy
import sys
import urllib.parse
import urllib.request
from pathlib import Path

from .child import environment
from .config import require
from .guard import Guard


def lookup(body, path):
    for name in path:
        require(type(body) is dict and name in body, "Invalid verification response")
        body = body[name]
    return body


def response_result(body, policy):
    for check in policy["checks"]:
        actual = lookup(body, check["path"])
        require(
            type(actual) is type(check["equals"]) and actual == check["equals"],
            "Read-only response did not match the reviewed identity or status",
        )
    result = {"ok": True, "read_only": True, "credential_mode": "public-placeholder"}
    if "count" in policy:
        rows = lookup(body, policy["count"])
        require(type(rows) is list, "Invalid verification collection")
        result["item_count"] = len(rows)
    return result


def main(arguments):
    payload = json.loads(base64.urlsafe_b64decode(os.environ["RUNBOX_POLICY"]))
    profile, runtime = payload["profile"], payload["runtime"]
    client = profile["execution"]["client"]
    require(client["type"] == "python", "Expected the reviewed Python client")
    environment(profile, runtime, payload["home"])
    sys.pycache_prefix = "/dev/null"
    # External dependency roots are separately approved, with selected SDK
    # integrity files included in the runtime snapshot.
    sys.path[:0] = runtime.get("imports", [])
    if "http" in profile:
        Guard(profile["http"]).install()
    result = {"ok": True, "read_only": True, "credential_mode": "public-placeholder"}
    identity = "probe" in client and (
        payload["mode"] == "probe" or not {"script", "entrypoint"} & set(client)
    )
    if identity:
        http = profile["http"]
        base = urllib.parse.urlsplit(http["base-url"])
        target = urllib.parse.urlunsplit(
            (base.scheme, base.netloc, http["probe"], "", "")
        )
        request = urllib.request.Request(
            target, headers={"Authorization": "Bearer " + http["placeholder"]}
        )
        with urllib.request.urlopen(request, timeout=25) as response:
            if client["probe"].get("format") == "status":
                require(
                    200 <= response.status < 300, "Read-only status verification failed"
                )
            else:
                raw = response.read(4 * 1024 * 1024 + 1)
                require(
                    len(raw) <= 4 * 1024 * 1024,
                    "Verification response exceeds size limit",
                )
                result = response_result(json.loads(raw), client["probe"])
        for path in http.get("additional-probes", []):
            target = urllib.parse.urlunsplit((base.scheme, base.netloc, path, "", ""))
            with urllib.request.urlopen(
                urllib.request.Request(
                    target, headers={"Authorization": "Bearer " + http["placeholder"]}
                ),
                timeout=25,
            ):
                pass
    else:
        require(
            "script" in client or "entrypoint" in client,
            "No runnable Python entrypoint is configured",
        )
        if payload["mode"] == "probe":
            require(
                "probe-arguments" in client, "No read-only verification is configured"
            )
            supplied = client["probe-arguments"]
        else:
            if "script" in client:
                require(
                    arguments[:1] == [client["script"]], "Unexpected Python entrypoint"
                )
                supplied = arguments[1:]
            else:
                supplied = arguments
        if "script" in client:
            script = Path(payload["root"]) / client["script"]
            sys.path.insert(0, str(script.parent))
            sys.argv = [str(script), *supplied]
        else:
            sys.argv = [profile["execution"]["command"], *supplied]
        try:
            if "script" in client:
                runpy.run_path(str(script), run_name="__main__")
            else:
                module, function = client["entrypoint"].split(":")
                code = getattr(importlib.import_module(module), function)()
                require(
                    code in (None, 0),
                    "Reviewed Python command failed; private diagnostics withheld",
                )
        except SystemExit as exc:
            require(
                exc.code in (None, 0),
                "Reviewed Python command failed; private diagnostics withheld",
            )
    if payload["mode"] == "probe" or identity:
        print(json.dumps(result))
    return 0
