"""Secret-free stdio adapter for the reviewed Waxon remote MCP service."""

import asyncio
import base64
from contextlib import asynccontextmanager
import json
import logging
import os
from pathlib import Path
import ssl
import sys
from urllib.parse import urlsplit

# Isolated Python skips site startup hooks; only the protected reviewed SDK is loaded.
POLICY = json.loads(base64.urlsafe_b64decode(os.environ["RUNBOX_POLICY"]))
for directory in POLICY["runtime"].get("imports", []):
    sys.path.insert(0, directory)
import httpx  # noqa: E402 -- approved SDK paths precede imports under isolated -S
from mcp import ClientSession, types  # noqa: E402
from mcp.client.streamable_http import streamablehttp_client  # noqa: E402
from mcp.server import Server  # noqa: E402
from mcp.server.stdio import stdio_server  # noqa: E402

ALLOWED = frozenset({"search_questions", "check_questions", "add_questions"})
MARKER = "waxon_mcp_public_placeholder"
ENDPOINT = POLICY["profile"]["environment"]["MCP_ENDPOINT"]
logging.disable(logging.CRITICAL)


def settings():
    endpoint = urlsplit(ENDPOINT)
    if (
        os.environ.get("MCP_ENDPOINT") != ENDPOINT
        or endpoint.scheme != "https"
        or not endpoint.hostname
        or endpoint.port not in (None, 443)
        or endpoint.username
        or endpoint.password
        or endpoint.query
        or endpoint.fragment
        or not endpoint.path.startswith("/")
        or "%" in endpoint.path
        or any(part in (".", "..") for part in endpoint.path.split("/"))
    ):
        raise ValueError("Expected the approved HTTPS MCP endpoint.")
    expected_proxy = urlsplit("http://" + POLICY["profile"]["session"]["proxy"])
    if os.environ.get("WAXON_MCP_TOKEN") != MARKER:
        raise ValueError("Expected the public Waxon MCP placeholder.")
    forbidden = (
        "OPENROUTER_API_KEY",
        "AGENTBRIDGE_API_KEY",
        "DATABASE_URL",
        "DATABASE_URL_UNPOOLED",
        "CLERK_SECRET_KEY",
        "NEON_REALTIME_SECRET",
        "INFISICAL_TOKEN",
        "INFISICAL_CLIENT_SECRET",
        "BWS_ACCESS_TOKEN",
    )
    if any(os.environ.get(name) for name in forbidden):
        raise ValueError("Unexpected inherited service credentials.")
    if os.environ.get("NO_PROXY") or os.environ.get("no_proxy"):
        raise ValueError("Proxy bypasses are not allowed.")
    proxy = os.environ.get("HTTPS_PROXY", "")
    parsed = urlsplit(proxy)
    if (
        parsed.scheme != "http"
        or parsed.hostname != expected_proxy.hostname
        or parsed.port != expected_proxy.port
        or not parsed.username
        or not parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise ValueError("Expected the reviewed proxy session.")
    if os.environ.get("HTTP_PROXY") != proxy:
        raise ValueError("Conflicting proxy sessions.")
    ca = Path(os.environ["WAXON_MCP_CA"])
    expected = Path(POLICY["runtime"]["ca-file"])
    if ca != expected or not ca.is_file():
        raise ValueError("Expected the reviewed public CA.")
    return proxy, ca


@asynccontextmanager
async def remote(endpoint=ENDPOINT, *, proxy=None, ca=None):
    if proxy is None:
        proxy, ca = settings()
    context = ssl.create_default_context(cafile=str(ca))

    def factory(headers=None, timeout=None, auth=None):
        return httpx.AsyncClient(
            headers=headers,
            timeout=timeout or 30,
            auth=auth,
            verify=context,
            proxy=proxy,
            trust_env=False,
            follow_redirects=False,
        )

    async with streamablehttp_client(
        endpoint,
        headers={"Authorization": "Bearer " + MARKER},
        timeout=20,
        httpx_client_factory=factory,
    ) as (read, write, _get_session_id):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


async def checked_tools(session):
    response = await session.list_tools()
    tools = [tool for tool in response.tools if tool.name in ALLOWED]
    if {tool.name for tool in tools} != ALLOWED or len(tools) != len(ALLOWED):
        raise ValueError("The required Waxon tool set is unavailable.")
    return tools


async def serve(session):
    tools = await checked_tools(session)
    server = Server("waxon-vault")

    @server.list_tools()
    async def list_tools():
        return tools

    @server.call_tool()
    async def call_tool(name, arguments):
        if name not in ALLOWED:
            return types.CallToolResult(
                isError=True,
                content=[
                    types.TextContent(
                        type="text", text="Tool is outside the reviewed Waxon profile."
                    )
                ],
            )
        try:
            result = await session.call_tool(name, arguments)
            if result.isError:
                raise ValueError("Upstream MCP error")
            return result
        except Exception:
            return types.CallToolResult(
                isError=True,
                content=[
                    types.TextContent(
                        type="text",
                        text="Waxon request failed; provider details withheld. Verify the result before retrying with the same idempotency key.",
                    )
                ],
            )

    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


async def main(mode):
    settings()
    async with remote() as session:
        tools = await checked_tools(session)
        if mode == "check":
            print(
                json.dumps(
                    {
                        "ok": True,
                        "read_only": True,
                        "credential_mode": "public-placeholder",
                        "item_count": len(tools),
                    }
                )
            )
        else:
            await serve(session)


if __name__ == "__main__":
    try:
        if sys.argv[1:] not in (["check"], ["serve"]):
            raise ValueError("Use check or serve.")
        asyncio.run(main(sys.argv[1]))
    except Exception:
        if sys.argv[1:] == ["check"]:
            print(
                json.dumps(
                    {
                        "ok": False,
                        "reason": "Waxon MCP authentication or discovery failed; provider details withheld.",
                    }
                )
            )
        else:
            print(
                "Waxon MCP startup failed; verify the reviewed profile and Infisical login.",
                file=sys.stderr,
            )
        sys.exit(1)
