import base64
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from threading import Thread
import unittest

from runbox.config import Error
from runbox.python_client import response_result
from runbox.runner import probe_failure
from tests.support import PROFILE


class ResponseTests(unittest.TestCase):
    def test_only_verified_identity_and_count_are_emitted(self):
        result = response_result(
            {"name": "expected", "private": "never emitted", "data": [1, 2]},
            {"checks": [{"path": ["name"], "equals": "expected"}], "count": ["data"]},
        )
        self.assertEqual(
            result,
            {
                "ok": True,
                "read_only": True,
                "credential_mode": "public-placeholder",
                "item_count": 2,
            },
        )

    def test_identity_shape_and_type_must_match(self):
        for body in ({}, {"name": "wrong"}, {"name": True}):
            with self.assertRaises(Error):
                response_result(
                    body, {"checks": [{"path": ["name"], "equals": "expected"}]}
                )

    def test_boolean_is_not_an_integer_status(self):
        with self.assertRaises(Error):
            response_result(
                {"code": True}, {"checks": [{"path": ["code"], "equals": 1}]}
            )

    def test_urllib_probe_preserves_only_a_single_recognized_vault_decision(self):
        class Proxy(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                self.server.requests.append(self.path)
                if len(self.server.requests) < self.server.failure_step:
                    self.send_response(204)
                    self.end_headers()
                    return
                body = b"synthetic-private-provider-body"
                self.send_response(502)
                for value in self.server.decisions:
                    self.send_header("X-Agent-Vault-Decision", value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        with (
            tempfile.TemporaryDirectory() as home,
            HTTPServer(("127.0.0.1", 0), Proxy) as server,
        ):
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                profile = deepcopy(PROFILE)
                profile["session"]["proxy"] = f"127.0.0.1:{server.server_port}"
                profile["execution"]["client"] = {
                    "type": "python",
                    "probe": {"checks": [], "format": "status"},
                }
                for entry, decisions, decision, mode, count, failure_step in (
                    ("--command-child", ["brokered"], "brokered", "probe", 1, 1),
                    ("--command-child", ["synthetic-private-header"], None, "probe", 1, 1),
                    ("--command-child", ["blocked", "brokered"], None, "probe", 1, 1),
                    ("--command-child", ["brokered"], None, "run", 1, 1),
                    ("--child", ["blocked"], "blocked", "probe", 1, 1),
                    ("--command-child", [], None, "probe", 3, 1),
                    ("--command-child", [], None, "probe", 3, 2),
                    ("--command-child", ["brokered"], "brokered", "probe", 3, 3),
                    ("--command-child", ["brokered"], None, "run", 3, 3),
                ):
                    with self.subTest(entry=entry, decisions=decisions, mode=mode, step=failure_step):
                        server.decisions, server.requests = decisions, []
                        server.failure_step = failure_step
                        paths = ["/api/v1/models", "/api/v1/private-path", "/api/v1/provider"][:count]
                        profile["http"]["additional-probes"] = paths[1:]
                        profile["http"]["routes"] = [{"method": "GET", "path": path} for path in paths]
                        payload = {
                            "profile": profile,
                            "runtime": {"ca-file": "/dev/null"},
                            "home": home,
                            "mode": mode,
                        }
                        session = (
                            f"http://fixture:capability@{profile['session']['proxy']}"
                        )
                        encoded = base64.urlsafe_b64encode(
                            json.dumps(payload).encode()
                        ).decode()
                        argv = [sys.executable, "-B", "-m", "runbox", entry]
                        if entry == "--child":
                            argv.append(encoded)
                        result = subprocess.run(
                            argv,
                            cwd=Path(__file__).resolve().parents[1],
                            timeout=10,
                            capture_output=True,
                            env={
                                "HTTP_PROXY": session,
                                "HTTPS_PROXY": session,
                                "RUNBOX_POLICY": encoded,
                                **profile["environment"],
                            },
                        )
                        self.assertEqual(result.returncode, 1)
                        self.assertEqual(result.stdout, b"")
                        self.assertNotIn(b"synthetic-private", result.stderr)
                        self.assertNotIn(b"private-path", result.stderr)
                        stage = (
                            f" at Python read-only request {failure_step}"
                            if count > 1 and mode == "probe"
                            else ""
                        )
                        label = f"; Agent Vault decision {decision}" if decision else ""
                        self.assertEqual(
                            probe_failure(result.stdout, result.stderr),
                            f"Online check failed{stage} (HTTP 502){label}; provider diagnostics withheld",
                        )
                        origin = profile["http"]["base-url"].removesuffix("/api/v1")
                        self.assertEqual(
                            server.requests, [origin + path for path in paths[:failure_step]]
                        )
            finally:
                server.shutdown()
                thread.join(5)
