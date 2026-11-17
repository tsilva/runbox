"""Exercise the real Google SDK over authenticated CONNECT and verified TLS."""

import importlib.util
import gzip
import json
import os
from pathlib import Path
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
import zlib

from runbox.guard import decoded_response, PolicyError


class CompressedResponseTests(unittest.TestCase):
    def test_compressed_bytes_and_headers(self):
        body = b'{"emailAddress":"reader@example.test"}'
        for encoding, wire in (("gzip", gzip.compress(body)),
                               ("deflate", zlib.compress(body))):
            with self.subTest(encoding=encoding):
                result, headers = decoded_response(
                    wire, {"Content-Encoding": encoding, "Content-Length": str(len(wire))}
                )
                self.assertEqual(result, body)
                self.assertNotIn("content-encoding", headers)
                self.assertEqual(headers["content-length"], str(len(body)))

    def test_wire_and_decoded_limits(self):
        with self.assertRaises(PolicyError):
            decoded_response(b"x" * 33, {}, limit=32)
        with self.assertRaises(PolicyError):
            decoded_response(gzip.compress(b"x" * 1000), {"Content-Encoding": "gzip"}, limit=32)
        body = b"x" * 40
        self.assertEqual(decoded_response(gzip.compress(body), {"Content-Encoding": "gzip"}, limit=40)[0], body)

    def test_invalid_truncated_trailing_and_unsupported_data(self):
        wire = gzip.compress(b"synthetic-private-response")
        for encoding, data in (("gzip", b"invalid"), ("gzip", wire[:-1]),
                               ("gzip", wire + b"trailing"), ("gzip", wire + wire),
                               ("br", b"anything"), ("deflate", b"invalid")):
            with self.subTest(encoding=encoding, size=len(data)), self.assertRaises(PolicyError) as caught:
                decoded_response(data, {"Content-Encoding": encoding})
            self.assertNotIn("synthetic-private", str(caught.exception))


@unittest.skipUnless(importlib.util.find_spec("googleapiclient"), "Requires Google API SDK")
class GoogleTransportTests(unittest.TestCase):
    def test_actual_sdk_proxy_ca_redirect_failure_and_no_refresh(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert, key = root / "ca.pem", root / "fixture-key.pem"
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                 "-keyout", str(key), "-out", str(cert), "-days", "1",
                 "-subj", "/CN=gmail.googleapis.com", "-addext",
                 "subjectAltName=DNS:gmail.googleapis.com"],
                capture_output=True, check=True,
            )
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            cases = [(s, p, "identity") for s in (200, 401, 302) for p in (False, True)]
            cases += [(200, True, encoding) for encoding in ("gzip", "deflate", "invalid-gzip")]
            for status, parameters, encoding in cases:
                with self.subTest(status=status, parameters=parameters, encoding=encoding):
                    observed = []

                    class Proxy(socketserver.BaseRequestHandler):
                        def handle(self):
                            self.request.settimeout(10)
                            def headers(stream):
                                data = b""
                                while not data.endswith(b"\r\n\r\n"):
                                    chunk = stream.recv(1)
                                    if not chunk:
                                        raise EOFError
                                    data += chunk
                                return data.decode("ascii")
                            connect = headers(self.request)
                            self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                            with context.wrap_socket(self.request, server_side=True) as tls:
                                request = headers(tls)
                                observed.append((connect, request))
                                payload = json.dumps({"emailAddress": "reader@example.test"}).encode()
                                extra = b"Location: https://unreviewed.invalid/secret\r\n" if status == 302 else b""
                                if encoding != "identity":
                                    payload = (gzip.compress(payload) if encoding == "gzip" else
                                               zlib.compress(payload) if encoding == "deflate" else b"invalid")
                                    extra += ("Content-Encoding: " + ("gzip" if encoding == "invalid-gzip" else encoding) + "\r\n").encode()
                                tls.sendall(
                                    f"HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {len(payload)}\r\n".encode()
                                    + extra + b"Connection: close\r\n\r\n" + payload
                                )

                    with socketserver.TCPServer(("127.0.0.1", 0), Proxy) as server:
                        thread = threading.Thread(target=server.serve_forever, daemon=True)
                        thread.start()
                        try:
                            code = r'''
import os
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from runbox.guard import Guard, PolicyError
guard = Guard({"base-url": "https://gmail.googleapis.com/gmail/v1",
 "credential-variable": "GMAIL_ACCESS_TOKEN", "placeholder": "gmail_test_placeholder",
 "routes": [{"method": "GET", "path": "/gmail/v1/users/me/profile",
             "queries": ["fields=emailAddress&alt=json"]}]})
if os.environ['FIXTURE_PARAMETERS'] == '1':
    route = guard.policy['routes'][0]
    del route['queries']
    route['query-parameters'] = {
        'fields': {'pattern': 'emailAddress', 'required': True},
        'alt': {'pattern': 'json', 'required': True},
    }
guard.install()
creds = Credentials(token=os.environ['GMAIL_ACCESS_TOKEN'])
def forbidden(*a, **k): raise AssertionError('refresh attempted')
creds.refresh = forbidden
service = build('gmail', 'v1', credentials=creds, cache_discovery=False)
try:
    result = service.users().getProfile(userId='me', fields='emailAddress').execute()
    assert result == {'emailAddress': 'reader@example.test'}
    assert os.environ['FIXTURE_SUCCESS'] == '1'
except PolicyError as error:
    assert os.environ['FIXTURE_SUCCESS'] == '0'
    assert 'reader@example' not in str(error)
    assert guard.failed
    try: service.users().getProfile(userId='me', fields='emailAddress').execute()
    except PolicyError: pass
    else: raise AssertionError('failure latch bypassed')
print('verified')
'''
                            env = {k: v for k, v in os.environ.items()
                                   if k.lower() not in ("https_proxy", "http_proxy", "all_proxy", "no_proxy")}
                            env.update({
                                "HTTPS_PROXY": f"http://fixture:capability@127.0.0.1:{server.server_address[1]}",
                                "NO_PROXY": "", "SSL_CERT_FILE": str(cert),
                                "GMAIL_ACCESS_TOKEN": "gmail_test_placeholder",
                                "FIXTURE_STATUS": str(status),
                                "FIXTURE_SUCCESS": "1" if status == 200 and encoding != "invalid-gzip" else "0",
                                "FIXTURE_PARAMETERS": "1" if parameters else "0",
                            })
                            result = subprocess.run(
                                [sys.executable, "-c", code], env=env,
                                cwd=Path(__file__).resolve().parents[1],
                                capture_output=True, text=True, timeout=20,
                            )
                            self.assertEqual(result.returncode, 0, result.stderr)
                            self.assertEqual(result.stdout.strip(), "verified")
                            self.assertEqual(len(observed), 1)
                            connect, request = observed[0]
                            self.assertIn("CONNECT gmail.googleapis.com:443 ", connect)
                            self.assertIn("proxy-authorization: basic ", connect.lower())
                            self.assertIn("authorization: bearer gmail_test_placeholder", request.lower())
                            self.assertNotIn("proxy-authorization", request.lower())
                        finally:
                            server.shutdown()
                            thread.join(timeout=5)
