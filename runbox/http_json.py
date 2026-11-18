"""One guarded JSON HTTP request over a neutral, bounded stdin/stdout protocol."""

import copy
import importlib
import json
import sys
import urllib.request

from .config import require
from .guard import Guard

MAX_INPUT = 4 * 1024 * 1024
MAX_RESPONSE = 16 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise ValueError("HTTP executor redirect rejected")


def mapping(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, "Duplicate HTTP request field")
        result[name] = value
    return result


def invalid_constant(_value):
    raise ValueError("Non-finite JSON value")


def request_data(raw, policy, context=None):
    require(
        type(raw) is bytes and 0 < len(raw) <= MAX_INPUT, "Invalid HTTP payload size"
    )
    payload = json.loads(
        raw, object_pairs_hook=mapping, parse_constant=invalid_constant
    )
    require(
        type(payload) is dict
        and {"method", "url"} <= payload.keys()
        and payload.keys() <= {"method", "url", "body", "context"},
        "Invalid HTTP request fields",
    )
    require(
        type(payload.get("context", {})) is dict
        and json.dumps(payload.get("context", {}), sort_keys=True)
        == json.dumps(context or {}, sort_keys=True),
        "HTTP executor binding context differs from policy",
    )
    method, target = payload["method"], payload["url"]
    require(
        method in ("GET", "POST") and isinstance(target, str) and len(target) <= 8192,
        "Invalid HTTP request",
    )
    body = payload.get("body")
    require(method != "GET" or body is None, "GET requests cannot contain a body")
    require(body is None or type(body) in (dict, list), "Expected a JSON request body")
    headers = {
        "Authorization": "Bearer " + policy["placeholder"],
        "Accept-Encoding": "identity",
        "Content-Type": "application/json",
    }
    # Keep validation mandatory even when called outside the standard bootstrap.
    target = Guard(policy).validate(method, target, headers)
    return payload, method, target, body, headers


def request_group(raw, policy, context=None):
    """Validate every route before any member of a small ordered batch runs."""
    require(
        type(raw) is bytes and 0 < len(raw) <= MAX_INPUT, "Invalid HTTP payload size"
    )
    payload = json.loads(
        raw, object_pairs_hook=mapping, parse_constant=invalid_constant
    )
    if type(payload) is not dict or "requests" not in payload:
        request_data(raw, policy, context)
        return payload, [raw]
    require(set(payload) <= {"requests", "context"}, "Invalid HTTP batch fields")
    require(
        type(payload["requests"]) is list and 1 <= len(payload["requests"]) <= 3,
        "Invalid HTTP batch size",
    )
    members = []
    for item in payload["requests"]:
        require(
            type(item) is dict and "context" not in item, "Invalid HTTP batch member"
        )
        require(item.get("method") == "POST", "HTTP batches contain writes only")
        member = json.dumps(
            {**item, "context": payload.get("context", {})}, allow_nan=False
        ).encode()
        request_data(member, policy, context)
        members.append(member)
    return payload, members


def execute(raw, policy, open_request=None, context=None):
    _payload, method, target, body, headers = request_data(raw, policy, context)
    request = urllib.request.Request(
        target,
        method=method,
        headers=headers,
        data=None if body is None else json.dumps(body, allow_nan=False).encode(),
    )
    transport = open_request or urllib.request.build_opener(NoRedirect()).open
    with transport(request, timeout=30) as response:
        require(200 <= response.status < 300, "Upstream HTTP request rejected")
        raw_response = response.read(MAX_RESPONSE + 1)
        require(len(raw_response) <= MAX_RESPONSE, "HTTP response exceeds size limit")
        result = (
            json.loads(
                raw_response, object_pairs_hook=mapping, parse_constant=invalid_constant
            )
            if raw_response
            else {}
        )
        require(type(result) in (dict, list), "Expected a JSON response")
        return {"status": response.status, "body": result}


def validate_request(raw, profile, context, validator=None, open_request=None):
    payload, _ = request_group(raw, profile["http"], context)
    selected = profile["execution"]["client"].get("validator")
    require(
        "requests" not in payload or selected, "HTTP batches require a pinned validator"
    )
    if selected:
        if validator is None:
            module, function = selected.split(":")
            validator = getattr(importlib.import_module(module), function)
        reads = 0

        def read(url):
            nonlocal reads
            reads += 1
            require(reads <= 4, "HTTP request validation exceeded its read limit")
            request = {"method": "GET", "url": url, "context": context}
            return execute(
                json.dumps(request).encode(), profile["http"], open_request, context
            )["body"]

        require(
            validator(
                copy.deepcopy(payload), read, copy.deepcopy(profile["environment"])
            )
            is None,
            "HTTP request validator returned an unsupported result",
        )


def main(profile, arguments):
    try:
        require(not arguments, "This HTTP executor accepts JSON on stdin only")
        context = json.loads(
            profile.get("environment", {}).get("HTTP_EXECUTOR_CONTEXT", "{}"),
            object_pairs_hook=mapping,
            parse_constant=invalid_constant,
        )
        require(
            type(context) is dict
            and len(context) <= 16
            and all(
                type(k) is str
                and len(k) <= 64
                and type(v) in (str, int, bool)
                and len(str(v)) <= 256
                for k, v in context.items()
            ),
            "Invalid HTTP executor context",
        )
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        validate_request(raw, profile, context)
        payload, members = request_group(raw, profile["http"], context)
        if "requests" in payload:
            result = {
                "status": 200,
                "body": {
                    "responses": [
                        execute(member, profile["http"], context=context)
                        for member in members
                    ]
                },
            }
        else:
            result = execute(raw, profile["http"], context=context)
        encoded = json.dumps(result, allow_nan=False)
        require(
            len(encoded.encode()) <= MAX_RESPONSE,
            "Encoded HTTP response exceeds size limit",
        )
    except Exception:
        # Provider bodies, submitted values, URLs and credentials are never diagnostics.
        result = {
            "status": 502,
            "body": {"error": "External HTTP request failed; details withheld."},
        }
        encoded = json.dumps(result)
    print(encoded)
    return 0
