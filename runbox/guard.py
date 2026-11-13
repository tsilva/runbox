"""Shared Python HTTP guard; native proxy and OS sandbox enforce transport access."""

import os
import re
import urllib.parse
import urllib.request

from .config import Error


class PolicyError(Error):
    pass


class Guard:
    def __init__(self, policy):
        self.policy = policy
        self.failed = False

    def validate(self, method, url, headers):
        if self.failed:
            raise PolicyError("Session stopped after a request failure")
        parsed = urllib.parse.urlsplit(str(url))
        base = urllib.parse.urlsplit(self.policy["base-url"])
        if (
            (parsed.scheme, parsed.netloc) != (base.scheme, base.netloc)
            or parsed.fragment
            or "%" in parsed.path
            or "\\" in parsed.path
            or any(part in (".", "..") for part in parsed.path.split("/"))
        ):
            raise PolicyError("Unreviewed destination rejected")
        routes = [
            r
            for r in self.policy["routes"]
            if r["method"] == method.upper()
            and re.fullmatch(
                re.escape(r["path"]).replace(r"\{segment\}", r"[A-Za-z0-9_.-]+"),
                parsed.path,
            )
            and parsed.query in r.get("queries", [""])
        ]
        if not routes:
            raise PolicyError("Unreviewed method or route rejected")
        normalized = {str(k).lower(): str(v) for k, v in headers.items()}
        if normalized.get("authorization") != "Bearer " + self.policy["placeholder"]:
            raise PolicyError("Expected public placeholder is missing")
        if any(k in normalized for k in ("api-key", "x-api-key", "cookie")):
            raise PolicyError("Additional authentication rejected")
        forward = routes[0].get("forward-host")
        return urllib.parse.urlunsplit(
            (parsed.scheme, forward or parsed.netloc, parsed.path, parsed.query, "")
        )

    def install(self):
        if (
            os.environ.get(self.policy["credential-variable"])
            != self.policy["placeholder"]
        ):
            raise PolicyError("Expected public placeholder is missing")
        guard = self
        original = urllib.request.OpenerDirector.open

        def guarded_open(opener, fullurl, data=None, timeout=60):
            req = (
                fullurl
                if isinstance(fullurl, urllib.request.Request)
                else urllib.request.Request(fullurl, data=data)
            )
            parsed = urllib.parse.urlsplit(req.full_url)
            base = urllib.parse.urlsplit(guard.policy["base-url"])
            alias = {"method": req.get_method(), "path": parsed.path}
            if (
                (parsed.scheme, parsed.netloc) == (base.scheme, base.netloc)
                and not parsed.query
                and not parsed.fragment
                and alias in guard.policy.get("probe-aliases", [])
            ):
                headers = dict(req.header_items())
                auth = {k.lower(): v for k, v in headers.items()}.get("authorization")
                if auth not in (None, "Bearer " + guard.policy["placeholder"]):
                    raise PolicyError("Unexpected readiness credential rejected")
                headers["Authorization"] = "Bearer " + guard.policy["placeholder"]
                req = urllib.request.Request(
                    urllib.parse.urlunsplit(
                        (base.scheme, base.netloc, guard.policy["probe"], "", "")
                    ),
                    headers=headers,
                )
            target = guard.validate(
                req.get_method(), req.full_url, dict(req.header_items())
            )
            if target != req.full_url:
                req = urllib.request.Request(
                    target,
                    data=req.data,
                    headers=dict(req.header_items()),
                    method=req.get_method(),
                )
            try:
                result = original(opener, req, data, timeout)
                if not 200 <= result.status < 300:
                    result.close()
                    raise PolicyError()
                return result
            except Exception as exc:
                guard.failed = True
                code = getattr(exc, "code", None)
                status = (
                    " (HTTP " + str(code) + ")"
                    if type(code) is int and 400 <= code <= 599
                    else ""
                )
                raise PolicyError(
                    "Service request failed" + status + "; details withheld"
                ) from None

        def no_redirect(*_args, **_kwargs):
            guard.failed = True
            raise PolicyError("Redirect rejected")

        urllib.request.OpenerDirector.open = guarded_open
        urllib.request.HTTPRedirectHandler.redirect_request = no_redirect
        try:
            import requests
        except ImportError:
            pass
        else:
            requests_send = requests.Session.send

            def guarded_requests_send(session, request, **kwargs):
                target = guard.validate(request.method, request.url, request.headers)
                if target != request.url:
                    request.headers["Host"] = urllib.parse.urlsplit(target).netloc
                    request.url = target
                kwargs["allow_redirects"] = False
                try:
                    response = requests_send(session, request, **kwargs)
                    if not 200 <= response.status_code < 300:
                        response.close()
                        raise PolicyError()
                    return response
                except Exception:
                    guard.failed = True
                    raise PolicyError(
                        "Service request failed; details withheld"
                    ) from None

            requests.Session.send = guarded_requests_send
        try:
            import httpx
        except ImportError:
            httpx = None
        if httpx:
            send, async_send = httpx.Client.send, httpx.AsyncClient.send

            def guarded_send(client, request, **kwargs):
                target = guard.validate(request.method, request.url, request.headers)
                if target != str(request.url):
                    request.headers["Host"] = httpx.URL(target).netloc.decode()
                request.url = httpx.URL(target)
                kwargs["follow_redirects"] = False
                try:
                    response = send(client, request, **kwargs)
                    if not 200 <= response.status_code < 300:
                        response.close()
                        raise PolicyError()
                    return response
                except Exception:
                    guard.failed = True
                    raise PolicyError(
                        "Service request failed; details withheld"
                    ) from None

            async def guarded_async_send(client, request, **kwargs):
                target = guard.validate(request.method, request.url, request.headers)
                if target != str(request.url):
                    request.headers["Host"] = httpx.URL(target).netloc.decode()
                request.url = httpx.URL(target)
                kwargs["follow_redirects"] = False
                try:
                    response = await async_send(client, request, **kwargs)
                    if not 200 <= response.status_code < 300:
                        await response.aclose()
                        raise PolicyError()
                    return response
                except Exception:
                    guard.failed = True
                    raise PolicyError(
                        "Service request failed; details withheld"
                    ) from None

            httpx.Client.send, httpx.AsyncClient.send = guarded_send, guarded_async_send
        try:
            import openai
        except ImportError:
            pass
        else:
            for cls in (openai.OpenAI, openai.AsyncOpenAI):
                constructor = cls.__init__

                def init(client, *args, _constructor=constructor, **kwargs):
                    kwargs["max_retries"] = 0
                    _constructor(client, *args, **kwargs)

                cls.__init__ = init
        try:
            import dotenv
        except ImportError:
            pass
        else:
            dotenv.load_dotenv = lambda *_args, **_kwargs: False
