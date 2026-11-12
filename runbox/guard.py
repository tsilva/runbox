"""Shared Python HTTP guard; native proxy and OS sandbox enforce transport access."""

import os
import urllib.parse
import urllib.request


class PolicyError(RuntimeError):
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
            or parsed.query
            or parsed.fragment
            or "%" in parsed.path
            or "\\" in parsed.path
        ):
            raise PolicyError("Unreviewed destination rejected")
        if {"method": method.upper(), "path": parsed.path} not in self.policy["routes"]:
            raise PolicyError("Unreviewed method or route rejected")
        normalized = {str(k).lower(): str(v) for k, v in headers.items()}
        if normalized.get("authorization") != "Bearer " + self.policy["placeholder"]:
            raise PolicyError("Expected public placeholder is missing")
        if any(k in normalized for k in ("api-key", "x-api-key", "cookie")):
            raise PolicyError("Additional authentication rejected")

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
            guard.validate(req.get_method(), req.full_url, dict(req.header_items()))
            try:
                result = original(opener, req, data, timeout)
                if not 200 <= result.status < 300:
                    result.close()
                    raise PolicyError()
                return result
            except Exception:
                guard.failed = True
                raise PolicyError("Service request failed; details withheld") from None

        def no_redirect(*_args, **_kwargs):
            guard.failed = True
            raise PolicyError("Redirect rejected")

        urllib.request.OpenerDirector.open = guarded_open
        urllib.request.HTTPRedirectHandler.redirect_request = no_redirect
        try:
            import httpx
        except ImportError:
            httpx = None
        if httpx:
            send, async_send = httpx.Client.send, httpx.AsyncClient.send

            def guarded_send(client, request, **kwargs):
                guard.validate(request.method, request.url, request.headers)
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
                guard.validate(request.method, request.url, request.headers)
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
