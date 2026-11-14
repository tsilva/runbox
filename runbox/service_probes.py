"""Fixed, read-only SDK identity probes for reviewed personal service routes."""

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
from unittest.mock import patch

from .config import Error, require


def _session(variable, marker):
    require(
        os.environ.get(variable) == marker, "Expected the reviewed public placeholder"
    )
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
