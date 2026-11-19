"""Fixed, read-only identity and scope probes for reviewed service routes."""

import base64
import contextlib
import io
import json
import os
import re
import ssl
import sys
import tempfile
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
    proxy_bypass,
)
from unittest.mock import patch

from .config import Error, require


def _session(variable, marker):
    require(
        os.environ.get(variable) == marker, "Expected the reviewed public placeholder"
    )
    return _native_session()


def _native_session():
    require(
        os.environ.get("INFISICAL_AGENT_VAULT_URL") == "https://app.infisical.com",
        "Expected the reviewed native session",
    )
    proxy = os.environ.get("HTTPS_PROXY", "")
    parsed = urlsplit(proxy)
    require(
        parsed.scheme == "http"
        and parsed.hostname == "127.0.0.1"
        and parsed.port is not None
        and parsed.username
        and parsed.password
        and parsed.path in ("", "/")
        and not parsed.query
        and not parsed.fragment
        and os.environ.get("HTTP_PROXY") == proxy,
        "Expected the reviewed native proxy",
    )
    ca = os.environ.get("SSL_CERT_FILE", "")
    require(Path(ca).is_file(), "Expected the reviewed public CA")
    return proxy, ca


class _NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def agent_vault_http_scope():
    """Verify one exact HTTP grant using Agent Vault's own session catalog."""
    arguments = sys.argv[1:]
    require(
        5 <= len(arguments) <= 20,
        "Specify the reviewed bundle, host, method, path prefix and injected headers",
    )
    bundle, host, method, prefix, *headers = arguments
    expected_headers = sorted(header.lower() for header in headers)
    require(
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", bundle)
        and re.fullmatch(r"[a-z0-9]+(?:[.-][a-z0-9]+)+", host)
        and len(host) <= 253
        and method in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}
        and re.fullmatch(r"/[A-Za-z0-9._~/-]{0,255}", prefix)
        and all(re.fullmatch(r"[a-z0-9-]{1,64}", header) for header in expected_headers)
        and len(set(expected_headers)) == len(expected_headers),
        "Invalid reviewed HTTP scope",
    )
    proxy, ca = _native_session()
    require(
        not proxy_bypass("app.infisical.com"), "The native proxy must cover its catalog"
    )
    try:
        client = build_opener(
            ProxyHandler({"https": proxy}),
            HTTPSHandler(context=ssl.create_default_context(cafile=ca)),
            _NoRedirects(),
        )
        request = Request(
            "https://app.infisical.com/api/v1/agent-vault/session/services",
            headers={"Accept": "application/json"},
        )
        limit = 128 * 1024
        with client.open(request, timeout=8) as response:
            require(response.status == 200, "Agent Vault catalog unavailable")
            raw = response.read(limit + 1)
        require(len(raw) <= limit, "Agent Vault catalog exceeds its size limit")
        inventory = json.loads(raw)
        services = inventory["services"]
        require(
            inventory["session"]["accessBundle"] == bundle
            and bool(inventory["agentVault"]["proxy"])
            and type(services) is list
            and len(services) == 1,
            "Agent Vault session scope differs from review",
        )
        service = services[0]
        custom_headers = service["customHeaders"]
        credential = service["credential"]
        require(
            type(custom_headers) is list and type(credential["addedByProxy"]) is bool,
            "Invalid Agent Vault credential metadata",
        )
        injected_headers = list(custom_headers)
        if credential["addedByProxy"]:
            injected_headers.append(credential["header"])
        require(
            service["type"] == "http"
            and service["hosts"] == [host]
            and service["status"] == "ready"
            and service["allowedMethods"] == [method]
            and service["allowedPathPrefixes"] == [prefix]
            and all(type(header) is str for header in injected_headers)
            and sorted(header.lower() for header in injected_headers)
            == expected_headers,
            "Agent Vault HTTP grant differs from review",
        )
    except (OSError, ValueError, TypeError, KeyError):
        raise Error(
            "Agent Vault HTTP scope verification failed; details withheld"
        ) from None


@contextlib.contextmanager
def _isolated():
    # Explicit SDK credentials are public markers. No SDK may read a personal
    # login cache, .netrc, settings file, or write persistent verification data.
    with tempfile.TemporaryDirectory(prefix="runbox-service-probe-") as directory:
        values = {
            "HOME": directory,
            "XDG_CONFIG_HOME": directory + "/config",
            "XDG_CACHE_HOME": directory + "/cache",
            "HF_HOME": directory + "/hf",
            "HF_HUB_CACHE": directory + "/hub",
            "HF_HUB_DISABLE_IMPLICIT_TOKEN": "1",
            "HF_HUB_DISABLE_TELEMETRY": "1",
            "HF_HUB_DISABLE_PROGRESS_BARS": "1",
            "NETRC": "/dev/null",
            "WANDB_DIR": directory,
            "WANDB_CACHE_DIR": directory + "/wandb-cache",
            "WANDB_CONFIG_DIR": directory + "/wandb-config",
            "WANDB_DATA_DIR": directory + "/wandb-data",
            "WANDB_ERROR_REPORTING": "false",
            "WANDB_SILENT": "true",
            "DO_NOT_TRACK": "1",
        }
        with (
            patch.dict(os.environ, values),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            yield


def _huggingface(mode):
    arguments = sys.argv[1:]
    require(
        len(arguments) == 4
        and arguments[0] == "--account"
        and arguments[2] == "--token-name"
        and all(
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value)
            for value in arguments[1::2]
        ),
        "Specify the reviewed public account and token name",
    )
    account, token_name = arguments[1], arguments[3]
    marker = "huggingface_" + mode + "_proxy_placeholder"
    proxy, ca = _session("HF_TOKEN", marker)
    permissions = {"repo.content.read"}
    if mode == "write":
        permissions |= {"repo.access.read", "repo.contribute.write", "repo.write"}
    try:
        with _isolated():
            import httpx2
            import huggingface_hub
            from huggingface_hub import HfApi, set_client_factory
            from huggingface_hub.utils._http import close_session

            require(
                huggingface_hub.__version__ == "2.4.0",
                "Review the pinned Hugging Face SDK",
            )
            calls = []

            def admit(request):
                require(
                    not calls
                    and request.method == "GET"
                    and str(request.url) == "https://huggingface.co/api/whoami-v2"
                    and request.headers.get("authorization") == "Bearer " + marker,
                    "Identity probe request is outside its reviewed route",
                )
                calls.append(True)

            set_client_factory(
                lambda: httpx2.Client(
                    proxy=proxy,
                    verify=ssl.create_default_context(cafile=ca),
                    trust_env=False,
                    follow_redirects=False,
                    timeout=20,
                    event_hooks={"request": [admit]},
                )
            )
            try:
                identity = HfApi(
                    endpoint="https://huggingface.co", token=marker
                ).whoami(cache=False)
                token = identity["auth"]["accessToken"]
                fine = token["fineGrained"]
                scoped = fine["scoped"]
                require(
                    identity.get("name") == account
                    and token.get("displayName") == token_name
                    and token.get("role") == "fineGrained"
                    and fine.get("global", []) == []
                    and fine.get("canReadGatedRepos", False) is False
                    and len(scoped) == 1
                    and scoped[0]["entity"].get("type") == "user"
                    and scoped[0]["entity"].get("name") == account
                    and set(scoped[0]["permissions"]) == permissions
                    and len(calls) == 1,
                    "Hugging Face identity or permission verification failed",
                )
            finally:
                close_session()
    except Exception:
        raise Error(
            "Hugging Face read-only SDK verification failed; details withheld"
        ) from None


def huggingface_read():
    _huggingface("read")


def huggingface_write():
    _huggingface("write")


def wandb():
    marker = "wandb_proxy_placeholder"
    proxy, ca = _session("WANDB_API_KEY", marker)
    try:
        with _isolated():
            import requests
            import wandb as sdk
            from wandb.sdk.internal.internal_api import Api

            require(sdk.__version__ == "0.22.3", "Review the pinned W&B SDK")
            calls = []
            original = requests.sessions.Session.send

            def send(session, request, **kwargs):
                require(
                    not calls
                    and request.method == "POST"
                    and request.url == "https://api.wandb.ai/graphql"
                    and request.headers.get("Authorization")
                    == "Basic " + base64.b64encode(("api:" + marker).encode()).decode(),
                    "Viewer probe request is outside its reviewed route",
                )
                body = json.loads(request.body)
                query = " ".join(body["query"].split())
                require(
                    query
                    == "query Viewer { viewer { id entity username flags teams { edges { node { name } } } } }",
                    "Only the fixed viewer query is allowed",
                )
                calls.append(True)
                kwargs.update(
                    allow_redirects=False,
                    timeout=25,
                    verify=ca,
                    proxies={"http": proxy, "https": proxy},
                )
                response = original(session, request, **kwargs)
                require(response.status_code == 200, "Viewer identity was rejected")
                return response

            with patch.object(requests.sessions.Session, "send", send):
                api = Api(
                    default_settings={"base_url": "https://api.wandb.ai"},
                    load_settings=False,
                    retry_timedelta=timedelta(0),
                    api_key=marker,
                )
                viewer = api.viewer()
                require(
                    type(viewer) is dict and bool(viewer.get("id")) and len(calls) == 1,
                    "Viewer identity verification failed",
                )
    except Exception:
        raise Error("W&B read-only SDK verification failed; details withheld") from None
