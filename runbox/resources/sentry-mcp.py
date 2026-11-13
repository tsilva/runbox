"""Bounded, secret-free MCP transport. Credentials are attached by Agent Vault."""

import base64
import http.client
import json
import os
from pathlib import Path
import ssl
import sys
from urllib.parse import unquote, urlsplit

MARKER = "sentry_mcp_public_placeholder"
ALLOWED = frozenset(
    {
        "whoami",
        "find_organizations",
        "find_projects",
        "find_releases",
        "get_release_details",
        "get_issue_details",
        "get_event_stacktrace",
        "get_issue_breadcrumbs",
        "get_issue_tag_values",
        "get_trace_details",
        "update_issue",
        "search_errors",
        "search_traces",
        "search_issues",
        "search_issue_events",
        "find_dropped_events",
        "get_sentry_mcp_info",
    }
)
MAX_BYTES = 8 * 1024 * 1024
STATUS_FIELDS = {
    "organizationSlug",
    "regionUrl",
    "issueId",
    "issueUrl",
    "status",
    "ignoreMode",
    "ignoreDurationMinutes",
    "ignoreCount",
    "ignoreWindowMinutes",
    "ignoreUserCount",
    "ignoreUserWindowMinutes",
    "inRelease",
    "inCommit",
    "inCommitRepository",
}


def settings():
    policy = json.loads(base64.urlsafe_b64decode(os.environ["RUNBOX_POLICY"]))
    endpoint = urlsplit(os.environ.get("MCP_ENDPOINT", ""))
    if (
        endpoint.scheme != "https"
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
        raise ValueError("Expected the approved HTTPS MCP endpoint")
    if os.environ.get("MCP_ENDPOINT") != policy["profile"]["environment"].get(
        "MCP_ENDPOINT"
    ):
        raise ValueError("MCP endpoint differs from the reviewed profile")
    expected_proxy = urlsplit("http://" + policy["profile"]["session"]["proxy"])
    if os.environ.get("SENTRY_MCP_AUTH") != MARKER:
        raise ValueError("Expected the reviewed public placeholder")
    if os.environ.get("NO_PROXY") or os.environ.get("no_proxy"):
        raise ValueError("Proxy bypasses are not permitted")
    raw = os.environ.get("HTTPS_PROXY", "")
    proxy = urlsplit(raw)
    if (
        proxy.scheme != "http"
        or proxy.hostname != expected_proxy.hostname
        or proxy.port != expected_proxy.port
        or not proxy.password
        or os.environ.get("HTTP_PROXY") != raw
    ):
        raise ValueError("Expected the reviewed scoped proxy")
    ca = Path(os.environ.get("SENTRY_MCP_CA", ""))
    if ca != Path(policy["runtime"]["ca-file"]):
        raise ValueError("Unexpected CA binding")
    return proxy, ca, endpoint


def validate_tool(name, arguments):
    if name not in ALLOWED or not isinstance(arguments, dict):
        raise ValueError("Tool is outside the reviewed profile")
    if arguments.get("regionUrl") not in {
        None,
        "https://de.sentry.io",
        "https://us.sentry.io",
    }:
        raise ValueError("Region is outside the reviewed Sentry instance")
    if arguments.get("issueUrl"):
        issue_url = urlsplit(arguments["issueUrl"])
        if (
            issue_url.scheme != "https"
            or issue_url.username
            or issue_url.password
            or not issue_url.hostname
            or not (
                issue_url.hostname == "sentry.io"
                or issue_url.hostname.endswith(".sentry.io")
            )
        ):
            raise ValueError("Issue URL is outside the reviewed Sentry instance")
    if name == "update_issue":
        if set(arguments) - STATUS_FIELDS or arguments.get("status") not in {
            "resolved",
            "unresolved",
            "ignored",
        }:
            raise ValueError("Only explicit issue-status transitions are permitted")
        if arguments["status"] == "ignored" and arguments.get("ignoreMode") not in {
            "untilEscalating",
            "forDuration",
            "untilOccurrenceCount",
            "untilUserCount",
        }:
            raise ValueError(
                "Archives require an explicit recurrence or time condition"
            )


class Remote:
    def __init__(self):
        self.proxy, ca, self.endpoint = settings()
        self.tls = ssl.create_default_context(cafile=str(ca))
        self.session = None
        self.protocol = "2025-06-18"
        self.decisions = set()

    def request(self, message):
        method = message.get("method")
        if method not in {
            "initialize",
            "ping",
            "notifications/initialized",
            "notifications/cancelled",
            "tools/list",
            "tools/call",
        }:
            raise ValueError("MCP method is outside the reviewed profile")
        if method == "tools/call":
            params = message.get("params", {})
            validate_tool(params.get("name"), params.get("arguments", {}))
        connection = http.client.HTTPSConnection(
            self.proxy.hostname, self.proxy.port, context=self.tls, timeout=25
        )
        credential = (
            unquote(self.proxy.username or "") + ":" + unquote(self.proxy.password)
        )
        connection.set_tunnel(
            self.endpoint.hostname,
            443,
            headers={
                "Proxy-Authorization": "Basic "
                + base64.b64encode(credential.encode()).decode(),
            },
        )
        headers = {
            "Authorization": "Bearer " + MARKER,
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": self.protocol,
        }
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        try:
            connection.request("POST", self.endpoint.path, json.dumps(message), headers)
            response = connection.getresponse()
            decision = response.getheader("X-Agent-Vault-Decision")
            if decision:
                self.decisions.add(decision)
            if response.status not in {200, 202, 204}:
                raise ValueError("MCP request rejected: HTTP " + str(response.status))
            self.session = response.getheader("Mcp-Session-Id") or self.session
            if "id" not in message or response.status in {202, 204}:
                return None
            if "text/event-stream" in response.getheader("Content-Type", ""):
                parts, size = [], 0
                while True:
                    line = response.readline(MAX_BYTES + 1)
                    size += len(line)
                    if size > MAX_BYTES:
                        raise ValueError("MCP response exceeded its bound")
                    if not line:
                        raise ValueError("MCP stream ended before a response")
                    if line.startswith(b"data:"):
                        parts.append(line[5:].strip())
                    if line.strip() == b"" and parts:
                        result = json.loads(b"\n".join(parts))
                        parts = []
                        if result.get("id") == message["id"]:
                            break
            else:
                body = response.read(MAX_BYTES + 1)
                if len(body) > MAX_BYTES:
                    raise ValueError("MCP response exceeded its bound")
                result = json.loads(body)
            if result.get("id") != message["id"]:
                raise ValueError("Unexpected MCP response identity")
            if method == "initialize":
                self.protocol = result.get("result", {}).get(
                    "protocolVersion", self.protocol
                )
            if method == "tools/list" and "result" in result:
                result["result"]["tools"] = [
                    t
                    for t in result["result"].get("tools", [])
                    if t.get("name") in ALLOWED
                ]
                for tool in result["result"]["tools"]:
                    if tool["name"] == "update_issue":
                        props = tool["inputSchema"]["properties"]
                        tool["inputSchema"]["properties"] = {
                            k: v for k, v in props.items() if k in STATUS_FIELDS
                        }
                        tool["inputSchema"]["properties"]["status"]["enum"] = [
                            "resolved",
                            "unresolved",
                            "ignored",
                        ]
                        tool["inputSchema"]["properties"]["ignoreMode"]["enum"] = [
                            "untilEscalating",
                            "forDuration",
                            "untilOccurrenceCount",
                            "untilUserCount",
                        ]
            return result
        finally:
            connection.close()


def initialize(remote):
    response = remote.request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "sentry-vault", "version": "1.0"},
            },
        }
    )
    if "error" in response:
        raise ValueError("MCP initialization failed")
    remote.request({"jsonrpc": "2.0", "method": "notifications/initialized"})


def main(mode):
    remote = Remote()
    if mode == "serve":
        for line in sys.stdin:
            message = None
            try:
                if len(line) > MAX_BYTES:
                    raise ValueError("Request exceeded its bound")
                message = json.loads(line)
                result = remote.request(message)
                if result is not None:
                    print(json.dumps(result), flush=True)
            except Exception:
                if isinstance(message, dict) and "id" in message:
                    print(
                        json.dumps(
                            {
                                "jsonrpc": "2.0",
                                "id": message["id"],
                                "error": {
                                    "code": -32603,
                                    "message": "Sentry Vault request failed; details withheld",
                                },
                            }
                        ),
                        flush=True,
                    )
        return
    initialize(remote)
    if mode == "check":
        result = remote.request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = {t["name"] for t in result.get("result", {}).get("tools", [])}
        if names != ALLOWED:
            raise ValueError("The reviewed tool set is unavailable")
        print(
            json.dumps(
                {
                    "ok": True,
                    "read_only": True,
                    "credential_mode": "public-placeholder",
                    "item_count": len(names),
                }
            )
        )
    elif mode == "list":
        print(
            json.dumps(
                remote.request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            )
        )
    elif mode == "call":
        request = json.loads(sys.stdin.read(MAX_BYTES))
        validate_tool(request["name"], request.get("arguments", {}))
        print(
            json.dumps(
                remote.request(
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": request,
                    }
                )
            )
        )
    else:
        raise ValueError("Use check, list, call or serve")


if __name__ == "__main__":
    try:
        main(sys.argv[1])
    except Exception:
        print(
            json.dumps(
                {
                    "ok": False,
                    "reason": "Sentry Vault request failed; provider details withheld",
                }
            )
        )
        sys.exit(1)
