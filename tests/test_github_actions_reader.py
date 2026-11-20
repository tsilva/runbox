import base64
import hashlib
import importlib.util
import json
import shutil
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch


SOURCE = (
    Path(__file__).resolve().parents[1] / "runbox/resources/github-actions-reader.py"
)
SPEC = importlib.util.spec_from_file_location("github_actions_reader", SOURCE)
reader_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reader_module)

STORAGE_HOST = "archives.example.test"
REPOSITORY = "example/project"
PREFIX = f"/repos/{REPOSITORY}/actions"
FIXTURE_ARCHIVE = b"synthetic artifact response"
FIXTURE_RUN = {
    "id": 11,
    "repository": {"id": 22},
    "head_repository": {"id": 22},
    "workflow_id": 33,
    "head_sha": "a" * 40,
    "event": "push",
}
FIXTURE_ARTIFACT = {
    "id": 44,
    "name": "runtime-receipt",
    "size_in_bytes": len(FIXTURE_ARCHIVE),
    "digest": "sha256:" + hashlib.sha256(FIXTURE_ARCHIVE).hexdigest(),
    "expired": False,
    "workflow_run": {
        "id": 11,
        "repository_id": 22,
        "head_repository_id": 22,
        "head_sha": "a" * 40,
    },
}


def request_headers(connection):
    with connection.makefile("rb") as reader:
        first_line = reader.readline(8192).decode().strip()
        headers = {}
        for _ in range(30):
            line = reader.readline(8192)
            if line == b"\r\n":
                return first_line, headers
            name, _, value = line.decode().partition(":")
            headers[name.lower()] = value.strip()
    raise ValueError("Invalid fixture HTTP request")


def respond(connection, status, body=b"", location=None):
    headers = f"HTTP/1.1 {status} Fixture\r\nContent-Length: {len(body)}\r\nConnection: close\r\n"
    if location is not None:
        headers += f"Location: {location}\r\n"
    connection.sendall((headers + "\r\n").encode() + body)


@unittest.skipUnless(shutil.which("openssl"), "Requires a test certificate")
class GitHubActionsReaderTests(unittest.TestCase):
    def setUp(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        ca, key, config = root / "ca.pem", root / "key.pem", root / "openssl.cnf"
        config.write_text(
            "[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ext\n"
            "[dn]\nCN=api.github.com\n[ext]\n"
            f"subjectAltName=DNS:api.github.com,DNS:{STORAGE_HOST}\n"
        )
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-config",
                str(config),
                "-out",
                str(ca),
                "-keyout",
                str(key),
            ],
            check=True,
            capture_output=True,
            timeout=10,
        )
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(ca, key)
        self.requests = []
        self.location = f"https://{STORAGE_HOST}/receipt.zip?signature=fixture"
        self.storage_status = 200
        self.artifact = dict(FIXTURE_ARTIFACT)
        self.run = dict(FIXTURE_RUN)
        self.api_status = 200
        self.archive = FIXTURE_ARCHIVE
        case = self

        class Proxy(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(3)
                case.requests.append(("proxy", *request_headers(self.request)))
                self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                with case.context.wrap_socket(
                    self.request, server_side=True
                ) as connection:
                    line, headers = request_headers(connection)
                    case.requests.append(("api", line, headers))
                    path = line.split()[1].removeprefix(PREFIX)
                    if path == "/artifacts/44/zip":
                        respond(connection, 302, location=case.location)
                        return
                    data = {
                        "/artifacts/44": case.artifact,
                        "/runs/11": case.run,
                        "/runs/11/artifacts?per_page=100": {
                            "artifacts": [case.artifact]
                        },
                        "/workflows/33/runs?per_page=50&branch=feature%2Fexample": {
                            "workflow_runs": [case.run],
                        },
                    }[path]
                    respond(connection, case.api_status, json.dumps(data).encode())

        class Storage(socketserver.BaseRequestHandler):
            def handle(self):
                with case.context.wrap_socket(
                    self.request, server_side=True
                ) as connection:
                    case.requests.append(("storage", *request_headers(connection)))
                    respond(
                        connection, case.storage_status, case.archive, case.location
                    )

        proxy = self.server(Proxy)
        storage = self.server(Storage)
        original_connect = socket.create_connection

        def connect(address, *args, **kwargs):
            if address == (STORAGE_HOST, 443):
                address = storage.server_address
            if address not in (proxy.server_address, storage.server_address):
                self.fail(f"Unexpected network destination {address}")
            return original_connect(address, *args, **kwargs)

        self.enterContext(patch("socket.create_connection", side_effect=connect))
        self.reader = reader_module.Reader(
            {
                "HTTPS_PROXY": f"http://fixture:session@127.0.0.1:{proxy.server_address[1]}",
                "GH_TOKEN": reader_module.PLACEHOLDER,
                "SSL_CERT_FILE": str(ca),
                "GITHUB_ACTIONS_ARCHIVE_CA": str(ca),
                "GITHUB_ACTIONS_READER_POLICY": json.dumps(
                    {
                        "repository": REPOSITORY,
                        "repository_id": 22,
                        "workflows": {
                            "training image": {
                                "id": 33,
                                "artifacts": ["runtime-receipt"],
                            }
                        },
                        "storage_hosts": [STORAGE_HOST],
                    }
                ),
            }
        )

    def server(self, handler):
        server = self.enterContext(socketserver.TCPServer(("127.0.0.1", 0), handler))
        worker = threading.Thread(
            target=server.serve_forever, args=(0.01,), daemon=True
        )
        worker.start()
        self.addCleanup(worker.join, 3)
        self.addCleanup(server.shutdown)
        return server

    def test_verified_archive_sends_authorization_only_to_api_and_proxy(self):
        command = ["api", PREFIX.lstrip("/") + "/artifacts/44/zip"]
        result = reader_module.read_command(self.reader, command)
        self.assertEqual(result, FIXTURE_ARCHIVE)
        self.assertEqual(
            [line[0] for line in self.requests], ["proxy", "api"] * 3 + ["storage"]
        )
        for target, line, headers in self.requests:
            if target == "proxy":
                self.assertTrue(line.startswith("CONNECT api.github.com:443"))
                self.assertEqual(
                    headers["proxy-authorization"],
                    "Basic " + base64.b64encode(b"fixture:session").decode(),
                )
                self.assertNotIn("authorization", headers)
            elif target == "api":
                self.assertEqual(
                    headers["authorization"], "Bearer " + reader_module.PLACEHOLDER
                )
                self.assertNotIn("proxy-authorization", headers)
            else:
                self.assertEqual(line, "GET /receipt.zip?signature=fixture HTTP/1.1")
                self.assertFalse(
                    {"authorization", "proxy-authorization", "cookie"} & headers.keys()
                )

    def test_cli_listings_match_gradlab_request_shape(self):
        rows = reader_module.read_command(
            self.reader,
            [
                "run",
                "list",
                "--workflow",
                "training image",
                "--branch",
                "feature/example",
                "--limit",
                "50",
                "--json",
                reader_module.RUN_FIELDS,
            ],
        )
        self.assertEqual(rows[0]["databaseId"], 11)
        self.assertEqual(rows[0]["headSha"], "a" * 40)
        listing = reader_module.read_command(
            self.reader, ["api", PREFIX[1:] + "/runs/11/artifacts?per_page=100"]
        )
        self.assertEqual(
            listing,
            {"artifacts": [{"id": 44, "name": "runtime-receipt", "expired": False}]},
        )

    def test_wrong_destinations_and_dispatch_issue_no_requests(self):
        for command in (
            ["workflow", "run", "training image"],
            ["api", "repos/example/other/actions/artifacts/44/zip"],
            ["api", PREFIX[1:] + "/artifacts/44/zip?unexpected=1"],
            [
                "run",
                "list",
                "--workflow",
                "other",
                "--limit",
                "50",
                "--json",
                reader_module.RUN_FIELDS,
            ],
        ):
            with (
                self.subTest(command=command),
                self.assertRaises(reader_module.ReaderError),
            ):
                reader_module.read_command(self.reader, command)
        self.assertEqual(self.requests, [])

    def test_rejects_unreviewed_redirects_before_storage(self):
        for location in (
            f"http://{STORAGE_HOST}/receipt.zip?signature=fixture",
            f"https://{STORAGE_HOST}.unreviewed.test/receipt.zip?signature=fixture",
            f"https://{STORAGE_HOST}@unreviewed.test/receipt.zip?signature=fixture",
            f"https://{STORAGE_HOST}/receipt.zip",
        ):
            self.location = location
            with (
                self.subTest(location=location),
                self.assertRaisesRegex(reader_module.ReaderError, "redirect"),
            ):
                self.reader.read_archive(44)
        self.assertNotIn("storage", [request[0] for request in self.requests])

    def test_api_refusal_does_not_use_storage(self):
        self.api_status = 401
        with self.assertRaisesRegex(
            reader_module.ReaderError, "metadata request failed"
        ):
            self.reader.read_archive(44)
        self.assertEqual([line[0] for line in self.requests], ["proxy", "api"])

    def test_storage_redirect_is_not_followed_and_digest_is_verified(self):
        self.storage_status = 302
        with self.assertRaisesRegex(
            reader_module.ReaderError, "storage request failed"
        ):
            self.reader.read_archive(44)
        self.assertEqual([line[0] for line in self.requests].count("storage"), 1)
        self.storage_status = 200
        self.archive = b"x" * len(FIXTURE_ARCHIVE)
        with self.assertRaisesRegex(reader_module.ReaderError, "digest mismatch"):
            self.reader.read_archive(44)

    def test_unreviewed_artifact_is_rejected_before_archive_request(self):
        self.artifact["name"] = "unrelated-artifact"
        with self.assertRaisesRegex(reader_module.ReaderError, "receipt scope"):
            self.reader.read_archive(44)
        self.assertFalse(any("/zip" in line for _, line, _ in self.requests))

    def test_cli_errors_are_sanitized(self):
        outcome = subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(SOURCE), "repo", "view"],
            env={"GITHUB_ACTIONS_READER_POLICY": "{synthetic-secret"},
            capture_output=True,
            check=False,
            timeout=3,
        )
        self.assertEqual(outcome.returncode, 1)
        self.assertEqual(outcome.stdout, b"")
        self.assertEqual(
            outcome.stderr, b"Actions reader failed; upstream details withheld\n"
        )
