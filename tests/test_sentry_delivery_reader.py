import hashlib
import json
import shutil
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which("node")
DSN = "https://synthetic@example.invalid/1"
EVENT = "1" * 32
RELEASE = "2" * 40
SITE = "https://site.example.invalid"
PREFIX = "/api/0/projects/example/selected"
MARKER = "sentry_read_public_placeholder"


def headers(connection):
    with connection.makefile("rb") as stream:
        first = stream.readline(8192).decode().strip()
        result = {}
        for _ in range(32):
            line = stream.readline(8192)
            if line == b"\r\n":
                return first, result
            name, _, value = line.decode().partition(":")
            result[name.lower()] = value.strip()
    raise ValueError("Invalid synthetic request")


@unittest.skipUnless(
    sys.platform == "darwin" and NODE, "Requires macOS sandbox and Node"
)
class SentryDeliveryReaderTests(unittest.TestCase):
    def test_actual_reader_in_runbox_sandbox_uses_only_the_reviewed_receipt(self):
        node = str(Path(NODE).resolve())
        options = subprocess.check_output([node, "--help"], text=True, timeout=5)
        if "--use-env-proxy" not in options:
            self.skipTest("Node must implement --use-env-proxy")
        base = Path(
            self.enterContext(
                tempfile.TemporaryDirectory(prefix="runbox-sentry-delivery-")
            )
        ).resolve()
        home = base / "home"
        repo = home / "receipt"
        repo.mkdir(parents=True)
        release = base / "release"
        subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts/build.py"), str(release)],
            check=True,
            capture_output=True,
            timeout=10,
        )
        ca, key, openssl_config = base / "ca.pem", base / "ca.key", base / "req.cnf"
        openssl_config.write_text(
            "[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ext\n"
            "[dn]\nCN=sentry.io\n[ext]\nsubjectAltName=DNS:sentry.io\n"
        )
        subprocess.run(
            [
                "/usr/bin/openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-config",
                str(openssl_config),
                "-out",
                str(ca),
                "-keyout",
                str(key),
            ],
            check=True,
            capture_output=True,
            timeout=10,
        )
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(ca, key)
        certificate = hashlib.sha256(ssl.PEM_cert_to_DER_cert(ca.read_text())).digest()
        fingerprint = "SHA256:" + ":".join(f"{byte:02X}" for byte in certificate)
        cases = {
            "active": True,
            "brokered": True,
            "event_status": 200,
            "oversized": False,
            "site": SITE,
        }
        requests = []

        class Proxy(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(3)
                connect, connect_headers = headers(self.request)
                self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                with tls.wrap_socket(self.request, server_side=True) as connection:
                    line, request = headers(connection)
                    target = line.split()[1]
                    requests.append((connect, connect_headers, line, request))
                    status = 200
                    if target == f"{PREFIX}/keys/":
                        data = [
                            {
                                "isActive": cases["active"],
                                "dsn": {"public": DSN, "secret": "fixture-private-DSN"},
                            }
                        ]
                    else:
                        status = cases["event_status"]
                        data = {
                            "eventID": EVENT,
                            "tags": [{"key": "environment", "value": "production"}],
                            "release": {"version": RELEASE},
                            "dateCreated": "2026-11-20T08:30:00Z",
                            "entries": [
                                {
                                    "type": "request",
                                    "data": {
                                        "url": cases["site"]
                                        + "/fixture-private-path?fixture-private-query=1",
                                        "cookies": "fixture-private-cookie",
                                    },
                                }
                            ],
                        }
                    payload = json.dumps(data).encode()
                    if cases["oversized"]:
                        payload += b" " * (2 * 1024 * 1024)
                    decision = (
                        b"X-Agent-Vault-Decision: brokered\r\n"
                        if cases["brokered"]
                        else b""
                    )
                    response = (
                        f"HTTP/1.1 {status} Fixture\r\nContent-Length: {len(payload)}\r\n"
                        "Content-Type: application/json\r\nConnection: close\r\n"
                    ).encode()
                    try:
                        connection.sendall(response + decision + b"\r\n" + payload)
                    except (BrokenPipeError, ssl.SSLError):
                        if not cases["oversized"]:
                            raise

        server = self.enterContext(socketserver.TCPServer(("127.0.0.1", 0), Proxy))
        worker = threading.Thread(
            target=server.serve_forever, args=(0.01,), daemon=True
        )
        worker.start()
        self.addCleanup(worker.join, 3)
        self.addCleanup(server.shutdown)
        proxy = f"127.0.0.1:{server.server_address[1]}"
        fake = base / "infisical"
        fake.write_text(
            "#!"
            + sys.executable
            + " -I\n"
            + """
import os, subprocess, sys
args = sys.argv[1:]
assert args[:2] == ['agent-vault', 'run']
assert '--access-bundle=example-sentry-read' in args
port = next(arg.split('=', 1)[1] for arg in args if arg.startswith('--proxy='))
endpoint = 'http://fixture:session@' + port
env = dict(os.environ, HTTP_PROXY=endpoint, HTTPS_PROXY=endpoint)
raise SystemExit(subprocess.run(args[args.index('--')+1:], env=env).returncode)
"""
        )
        fake.chmod(0o700)
        runtime = base / "runtime.json"
        runtime.write_text(
            json.dumps(
                {
                    "infisical": str(fake),
                    "ca-file": str(ca),
                    "ca-fingerprint": fingerprint,
                    "node": node,
                }
            )
        )
        runtime.chmod(0o600)
        argv = [
            "{node}",
            "--use-env-proxy",
            "{release}/resources/sentry-delivery-reader.mjs",
        ]
        profile = {
            "provider": {
                "type": "infisical",
                "instance": "https://app.infisical.com",
                "project-id": "11111111-1111-4111-8111-111111111111",
                "access-bundle": "example-sentry-read",
            },
            "session": {"ttl": "10m", "proxy": proxy},
            "environment": {
                "SENTRY_VAULT_TRANSPORT": "agent-vault",
                "SENTRY_AUTH_TOKEN": MARKER,
                "SENTRY_ORG": "example",
                "SENTRY_PROJECT": "selected",
                "SENTRY_DELIVERY_SITE": SITE,
                "SENTRY_DELIVERY_EVENT_ID": EVENT,
                "SENTRY_DELIVERY_RELEASE": RELEASE,
                "SENTRY_DELIVERY_DSN_SHA256": hashlib.sha256(DSN.encode()).hexdigest(),
            },
            "execution": {
                "sandbox": "macos-command",
                "command": "sentry-delivery",
                "argv": argv + ["read"],
                "probe-argv": argv + ["check"],
                "arguments": [[]],
                "integrity": {"files": []},
                "permissions": {
                    "read": [
                        {"directory": "{node-root}"},
                        {"file": "{ca-file}"},
                        {"file": "{release}/resources/sentry-delivery-reader.mjs"},
                    ],
                    "write": [],
                    "execute": ["{node}"],
                    "deny-all-writes": True,
                },
            },
        }
        (repo / ".runbox.yaml").write_text(
            json.dumps(
                {"version": 1, "default": "delivery", "profiles": {"delivery": profile}}
            )
        )
        env = {"HOME": str(home), "PATH": "/usr/bin:/bin"}
        command = [
            sys.executable,
            "-I",
            "-B",
            str(release / "runbox.pyz"),
            "--repo",
            str(repo),
        ]

        def run(*arguments, success=True):
            result = subprocess.run(
                command + list(arguments),
                cwd=repo,
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(
                result.returncode == 0, success, result.stdout + result.stderr
            )
            self.assertNotIn("fixture-private", result.stdout + result.stderr)
            return result.stdout

        run("approve", "--runtime", str(runtime))
        run("check")
        self.assertEqual(requests, [])
        self.assertTrue(json.loads(run("check", "--online"))["read_only"])
        receipt = json.loads(run("run", "--", "sentry-delivery"))
        self.assertEqual(
            (receipt["eventId"], receipt["release"], receipt["site"]),
            (EVENT, RELEASE, SITE),
        )
        self.assertEqual(
            [line.split()[1] for _, _, line, _ in requests],
            [f"{PREFIX}/keys/", f"{PREFIX}/events/{EVENT}/"] * 2,
        )
        for connect, proxy_headers, line, request in requests:
            self.assertTrue(connect.startswith("CONNECT sentry.io:443"))
            self.assertIn("proxy-authorization", proxy_headers)
            self.assertTrue(line.startswith("GET "))
            self.assertEqual(request["authorization"], "Bearer " + MARKER)
            self.assertNotIn("proxy-authorization", request)
        count = len(requests)
        run("run", "--", "sentry-delivery", "--event-id", "anything", success=False)
        self.assertEqual(len(requests), count)
        for scenario, value, expected_calls in (
            ("active", False, 1),
            ("brokered", False, 1),
            ("oversized", True, 1),
            ("event_status", 404, 2),
            ("site", "https://foreign.example.invalid", 2),
        ):
            with self.subTest(scenario=scenario):
                old = cases[scenario]
                cases[scenario] = value
                count = len(requests)
                self.assertEqual(run("run", "--", "sentry-delivery", success=False), "")
                self.assertEqual(len(requests) - count, expected_calls)
                cases[scenario] = old
