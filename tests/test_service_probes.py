import copy
import json
import os
import shutil
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from runbox.config import Error
from runbox.service_probes import (
    _isolated,
    _session,
    agent_vault_http_scope,
    huggingface_read,
    wandb,
)


class ServiceProbeTests(unittest.TestCase):
    def test_unreviewed_marker_fails_before_sdk_import_or_network(self):
        for probe, variable in (
            (huggingface_read, "HF_TOKEN"),
            (wandb, "WANDB_API_KEY"),
        ):
            with (
                self.subTest(variable=variable),
                patch.dict(os.environ, {variable: "ordinary-secret"}, clear=True),
            ):
                with (
                    patch.object(
                        sys,
                        "argv",
                        [
                            "probe",
                            "--account",
                            "synthetic-user",
                            "--token-name",
                            "synthetic-token",
                        ],
                    ),
                    self.assertRaises(Error),
                ):
                    probe()

    def test_expected_identity_must_be_explicit_public_identifiers(self):
        for arguments in (
            [],
            ["--account", "user", "--token-name", "bad\nname"],
            ["--account", "../user", "--token-name", "token"],
        ):
            with (
                patch.object(sys, "argv", ["probe", *arguments]),
                self.assertRaises(Error),
            ):
                huggingface_read()

    def test_proxy_requires_loopback_capability_and_exact_native_instance(self):
        with tempfile.TemporaryDirectory() as directory:
            ca = Path(directory) / "ca.pem"
            ca.write_text("synthetic public CA")
            base = {
                "HF_TOKEN": "huggingface_read_proxy_placeholder",
                "INFISICAL_AGENT_VAULT_URL": "https://app.infisical.com",
                "SSL_CERT_FILE": str(ca),
            }
            for proxy in (
                "http://remote.invalid:8283",
                "http://127.0.0.1:8283",
                "https://u:p@127.0.0.1:8283",
                "http://u:p@127.0.0.1:8283/extra",
            ):
                with (
                    self.subTest(proxy=proxy),
                    patch.dict(
                        os.environ,
                        {**base, "HTTP_PROXY": proxy, "HTTPS_PROXY": proxy},
                        clear=True,
                    ),
                ):
                    with self.assertRaises(Error):
                        _session("HF_TOKEN", "huggingface_read_proxy_placeholder")
            proxy = "http://u:p@127.0.0.1:8283"
            with patch.dict(
                os.environ,
                {**base, "HTTP_PROXY": proxy, "HTTPS_PROXY": proxy},
                clear=True,
            ):
                self.assertEqual(
                    _session("HF_TOKEN", "huggingface_read_proxy_placeholder"),
                    (proxy, str(ca)),
                )
            with patch.dict(
                os.environ,
                {
                    **base,
                    "HTTP_PROXY": proxy,
                    "HTTPS_PROXY": proxy,
                    "INFISICAL_AGENT_VAULT_URL": "https://alternate.invalid",
                },
                clear=True,
            ):
                with self.assertRaises(Error):
                    _session("HF_TOKEN", "huggingface_read_proxy_placeholder")

    def test_isolation_uses_disposable_cache_and_restores_parent_environment(self):
        original = dict(os.environ)
        with _isolated():
            home = Path(os.environ["HOME"])
            self.assertTrue(home.is_dir())
            self.assertEqual(os.environ["NETRC"], "/dev/null")
            self.assertEqual(os.environ["HF_HUB_DISABLE_IMPLICIT_TOKEN"], "1")
            (home / "synthetic-cache").write_text("no credentials")
        self.assertFalse(home.exists())
        self.assertEqual(dict(os.environ), original)


class AgentVaultCatalogProbeTests(unittest.TestCase):
    arguments = [
        "probe",
        "trace-bundle",
        "trace.example.com",
        "POST",
        "/otel/v1/traces",
        "x-api-key",
        "trace-tenant",
    ]

    def test_catalog_bypass_stops_before_opening_a_connection(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(sys, "argv", self.arguments),
        ):
            cert = Path(directory) / "ca.pem"
            cert.touch()
            proxy = "http://fixture:session@127.0.0.1:1234"
            with (
                patch.dict(
                    os.environ,
                    {
                        "INFISICAL_AGENT_VAULT_URL": "https://app.infisical.com",
                        "HTTP_PROXY": proxy,
                        "HTTPS_PROXY": proxy,
                        "SSL_CERT_FILE": str(cert),
                        "NO_PROXY": "app.infisical.com",
                    },
                    clear=True,
                ),
                patch("runbox.service_probes.build_opener") as opener,
            ):
                with self.assertRaisesRegex(Error, "native proxy must cover"):
                    agent_vault_http_scope()
                opener.assert_not_called()

    @unittest.skipUnless(
        shutil.which("openssl"), "Requires an OpenSSL fixture certificate"
    )
    def test_actual_tls_catalog_checks_exact_permissions_without_contacting_the_service(
        self,
    ):
        catalog = {
            "agentVault": {"proxy": "synthetic-proxy"},
            "session": {"accessBundle": "trace-bundle"},
            "services": [
                {
                    "type": "http",
                    "hosts": ["trace.example.com"],
                    "status": "ready",
                    "allowedMethods": ["POST"],
                    "allowedPathPrefixes": ["/otel/v1/traces"],
                    "credential": {"addedByProxy": False},
                    "customHeaders": ["Trace-Tenant", "X-Api-Key"],
                }
            ],
        }
        response = {}
        requests = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert, key = root / "ca.pem", root / "fixture-key.pem"
            config = root / "req.cnf"
            config.write_text(
                "[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=extension\n"
                "[dn]\nCN=app.infisical.com\n[extension]\nsubjectAltName=DNS:app.infisical.com\n"
            )
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    str(key),
                    "-out",
                    str(cert),
                    "-days",
                    "1",
                    "-config",
                    str(config),
                ],
                capture_output=True,
                check=True,
                timeout=10,
            )
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(cert, key)

            class Proxy(socketserver.BaseRequestHandler):
                def handle(self):
                    self.request.settimeout(3)
                    connect = self.headers(self.request)
                    self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    with tls.wrap_socket(self.request, server_side=True) as connection:
                        request = self.headers(connection)
                        requests.append((connect.lower(), request.lower()))
                        body = response["body"]
                        location = (
                            b"Location: https://trace.example.com/otel/v1/traces\r\n"
                            if response["status"] == 302
                            else b""
                        )
                        connection.sendall(
                            f"HTTP/1.1 {response['status']} Fixture\r\n"
                            f"Content-Length: {len(body)}\r\n".encode()
                            + location
                            + b"Connection: close\r\n\r\n"
                            + body,
                        )

                @staticmethod
                def headers(stream):
                    with stream.makefile("rb") as reader:
                        lines = []
                        for _ in range(30):
                            line = reader.readline(4096)
                            if line == b"\r\n":
                                return b"".join(lines)
                            if not line:
                                break
                            lines.append(line)
                    raise ValueError("Invalid test request headers")

            registered_header = copy.deepcopy(catalog)
            registered_header["services"][0].update(
                credential={"addedByProxy": True, "header": "X-Api-Key"},
                customHeaders=["Trace-Tenant"],
            )
            variants = [(200, catalog, True), (200, registered_header, True)]
            for field, value in (
                ("hosts", ["*.example.com"]),
                ("status", "needs-personal-values"),
                ("allowedMethods", ["GET", "POST"]),
                ("allowedPathPrefixes", ["/otel"]),
                ("customHeaders", ["Authorization"]),
                ("customHeaders", ["Trace-Tenant", "X-Api-Key", "Authorization"]),
                ("customHeaders", []),
            ):
                wrong = copy.deepcopy(catalog)
                wrong["services"][0][field] = value
                variants.append((200, wrong, False))
            variants.extend(
                [
                    (200, {**catalog, "session": {"accessBundle": "other"}}, False),
                    (200, {**catalog, "services": catalog["services"] * 2}, False),
                    (302, {}, False),
                    (200, b"x" * (128 * 1024 + 1), False),
                ]
            )
            with socketserver.TCPServer(("127.0.0.1", 0), Proxy) as server:
                thread = threading.Thread(
                    target=server.serve_forever, kwargs={"poll_interval": 0.01}
                )
                thread.start()
                proxy = f"http://fixture:session@127.0.0.1:{server.server_address[1]}"
                try:
                    with (
                        patch.dict(
                            os.environ,
                            {
                                "INFISICAL_AGENT_VAULT_URL": "https://app.infisical.com",
                                "HTTP_PROXY": proxy,
                                "HTTPS_PROXY": proxy,
                                "SSL_CERT_FILE": str(cert),
                            },
                            clear=True,
                        ),
                        patch.object(sys, "argv", self.arguments),
                    ):
                        for status, body, allowed in variants:
                            response.update(
                                status=status,
                                body=body
                                if isinstance(body, bytes)
                                else json.dumps(body).encode(),
                            )
                            if allowed:
                                agent_vault_http_scope()
                            else:
                                with self.assertRaises(Error):
                                    agent_vault_http_scope()
                finally:
                    server.shutdown()
                    thread.join(3)
                self.assertFalse(thread.is_alive())
        self.assertEqual(len(requests), len(variants))
        for connect, request in requests:
            self.assertTrue(connect.startswith(b"connect app.infisical.com:443 "))
            self.assertIn(b"\r\nproxy-authorization: basic ", connect)
            self.assertTrue(
                request.startswith(b"get /api/v1/agent-vault/session/services ")
            )
            self.assertNotIn(b"authorization:", request)
