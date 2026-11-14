import base64
import copy
import io
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from runbox.config import Error
from runbox.renewal import (
    ConnectRelay,
    Lease,
    Supervisor,
    _lease_deadline,
    execute_renewing,
    validate,
)

try:
    import httpx
except ImportError:
    httpx = None


def profile():
    return {
        "provider": {"type": "infisical"},
        "session": {
            "ttl": "8h",
            "proxy": "127.0.0.1:8283",
            "renewal": {"renew-before": "15m", "max-connections": 64},
        },
        "environment": {"EXAMPLE_API_KEY": "public_placeholder"},
        "http": {"base-url": "https://example.test/api"},
        "execution": {
            "sandbox": "none",
            "command": "example-daemon",
            "argv": ["/usr/bin/true"],
            "probe-argv": ["/usr/bin/true"],
            "arguments": [[]],
            "handoff": {
                "proxy-variable": "EXAMPLE_PROXY_URL",
                "ca-variable": "EXAMPLE_CA_FILE",
                "require-stopped": [],
            },
        },
    }


def wait_for(predicate):
    deadline = time.monotonic() + 3
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("Synthetic lifecycle did not complete")
        time.sleep(0.01)


class Clock:
    def __init__(self):
        self.now = 0

    def __call__(self):
        return self.now


class NativeProxy:
    """Synthetic native proxy: records session selection and serves no real data."""

    def __init__(self, context=None):
        self.context = context
        self.closed = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.listener.settimeout(0.1)
        self.port = self.listener.getsockname()[1]
        self.requests, self.connections, self.threads = [], set(), []
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        while not self.closed.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self.lock:
                self.connections.add(connection)
            thread = threading.Thread(
                target=self.handle, args=(connection,), daemon=True
            )
            self.threads.append(thread)
            thread.start()

    @staticmethod
    def read_header(connection):
        data = b""
        while not data.endswith(b"\r\n\r\n"):
            block = connection.recv(1)
            if not block:
                return None
            data += block
            if len(data) > 8192:
                raise ValueError
        return data

    def handle(self, connection):
        original = connection
        try:
            connection.settimeout(3)
            head = self.read_header(connection)
            if head is None:
                return
            lines = head.decode().split("\r\n")
            auth = next(
                line.split(": ", 1)[1]
                for line in lines
                if line.startswith("Proxy-Authorization:")
            )
            identity = base64.b64decode(auth.split(" ", 1)[1]).decode().split(":", 1)[1]
            self.requests.append((identity, lines[0], head))
            connection.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            if self.context:
                connection = self.context.wrap_socket(connection, server_side=True)
                with self.lock:
                    self.connections.discard(original)
                    self.connections.add(connection)
                while not self.closed.is_set():
                    request = self.read_header(connection)
                    if request is None:
                        break
                    body = identity.encode()
                    connection.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Length: "
                        + str(len(body)).encode()
                        + b"\r\n\r\n"
                        + body
                    )
            else:
                while not self.closed.is_set():
                    block = connection.recv(8192)
                    if not block:
                        break
                    connection.sendall(block)
        except (OSError, ValueError, ssl.SSLError, StopIteration):
            pass
        finally:
            connection.close()
            with self.lock:
                self.connections.discard(connection)
                self.connections.discard(original)

    def close(self):
        self.closed.set()
        self.listener.close()
        with self.lock:
            connections = list(self.connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        self.thread.join(1)
        for thread in self.threads:
            thread.join(1)


class RenewalTests(unittest.TestCase):
    def test_system_sleep_triggers_renewal_without_monotonic_progress(self):
        monotonic, wall, issued, revoked = Clock(), Clock(), [], []
        wall.now = 1000

        def factory():
            identifier = str(uuid4())
            issued.append(identifier)
            return Lease(
                identifier,
                "http://x:agv_synthetic@127.0.0.1:8283",
                monotonic() + 10,
                wall_deadline=wall() + 10,
            )

        supervisor = Supervisor(
            factory, revoked.append, 3, clock=monotonic, wall_clock=wall
        ).start()
        self.addCleanup(supervisor.close)
        old = supervisor.acquire()
        wall.now += 8
        wait_for(lambda: len(issued) == 2)
        self.assertEqual(monotonic(), 0)
        self.assertEqual(supervisor.remaining(old), 2)
        self.assertIsNot(supervisor.current, old)
        wall.now += 3
        wait_for(lambda: old.identifier in revoked)
        self.assertLess(supervisor.remaining(old), 0)
        supervisor.release(old)

    def test_wall_clock_rollback_cannot_extend_original_monotonic_bound(self):
        monotonic, wall = Clock(), Clock()
        wall.now = 1000
        supervisor = Supervisor(None, None, 3, clock=monotonic, wall_clock=wall)
        lease = Lease("synthetic", "unused", 10, wall_deadline=1010)
        supervisor.current = lease
        supervisor.leases = [lease]
        wall.now = 900
        monotonic.now = 11
        self.assertEqual(supervisor.remaining(lease), -1)
        self.assertIsNone(supervisor.acquire())

    def test_expired_wall_clock_blocks_admission_before_rotation_thread_runs(self):
        monotonic, wall = Clock(), Clock()
        wall.now = 1011
        supervisor = Supervisor(None, None, 3, clock=monotonic, wall_clock=wall)
        supervisor.current = Lease("synthetic", "unused", 10, wall_deadline=1010)
        self.assertEqual(monotonic(), 0)
        self.assertIsNone(supervisor.acquire())

    def test_slow_issuance_keeps_conservative_original_ttl_bound(self):
        for delay in (20, 65):
            expires = datetime.fromtimestamp(
                1000 + delay + 600, timezone.utc
            ).isoformat()
            deadline = _lease_deadline(expires, 600, 100, 1000, 1000 + delay)
            self.assertEqual(deadline, 700)
        expires = datetime.fromtimestamp(1000 + 600, timezone.utc).isoformat()
        self.assertEqual(_lease_deadline(expires, 600, 100, 1000, 1000), 695)
        with self.assertRaises(Error):
            _lease_deadline(expires, 100, 100, 1000, 1000)

    def setup_relay(self, *, context=None, maximum=8, fail_after=None, wall_clock=None):
        proxy = NativeProxy(context)
        self.addCleanup(proxy.close)
        clock, revoked, issued = Clock(), [], []

        def factory():
            if fail_after is not None and len(issued) >= fail_after:
                raise RuntimeError("agv_synthetic-private-error")
            identifier = str(uuid4())
            issued.append(identifier)
            return Lease(
                identifier,
                "http://x-agent-vault:agv_synthetic"
                + str(len(issued))
                + "@127.0.0.1:"
                + str(proxy.port),
                clock() + 10,
                wall_deadline=wall_clock() + 10 if wall_clock else None,
            )

        supervisor = Supervisor(
            factory,
            revoked.append,
            3,
            clock=clock,
            wall_clock=wall_clock or time.time,
        ).start()
        self.addCleanup(supervisor.close)
        relay = ConnectRelay(
            supervisor, "127.0.0.1:" + str(proxy.port), "example.test:443", maximum
        ).start()
        self.addCleanup(relay.close)
        return proxy, clock, supervisor, relay, issued, revoked

    def connect(self, relay, *, headers=None, target="example.test:443"):
        port = int(relay.url.rsplit(":", 1)[1])
        client = socket.create_connection(("127.0.0.1", port), timeout=2)
        self.addCleanup(client.close)
        if headers is None:
            headers = [
                "Host: example.test:443",
                "Proxy-Authorization: Basic " + relay.authorization.decode(),
            ]
        client.sendall(
            (
                "CONNECT "
                + target
                + " HTTP/1.1\r\n"
                + "\r\n".join(headers)
                + "\r\n\r\n"
            ).encode()
        )
        return client, NativeProxy.read_header(client)

    def test_schema_rejects_unreviewed_expansion(self):
        validate(profile())
        for mutate in (
            lambda p: p["session"]["renewal"].update({"renew-before": "2m"}),
            lambda p: p["session"]["renewal"].update({"renew-before": "5h"}),
            lambda p: p["session"]["renewal"].update({"max-connections": True}),
            lambda p: p["session"]["renewal"].update({"retry": True}),
            lambda p: p["session"].update({"ttl": "5m"}),
            lambda p: p["session"].update({"worker": {}}),
            lambda p: p["session"].update({"tunnel": {}}),
            lambda p: p.update({"services": {}}),
            lambda p: p["http"].update({"base-url": "http://example.test"}),
            lambda p: p["execution"].update({"arguments": "any"}),
            lambda p: p["execution"].update({"sandbox": "macos-command"}),
            lambda p: p["execution"].update({"cwd": "workspace"}),
            lambda p: p["execution"].update({"preloads": []}),
            lambda p: p["execution"].update({"inputs": {}}),
            lambda p: p["execution"].pop("probe-argv"),
        ):
            candidate = copy.deepcopy(profile())
            mutate(candidate)
            with self.assertRaises(Error):
                validate(candidate)

    def test_rotation_does_not_interrupt_or_replay_existing_tunnels(self):
        proxy, clock, supervisor, relay, issued, revoked = self.setup_relay()
        old, status = self.connect(relay)
        self.assertIn(b" 200 ", status)
        old.sendall(b"synthetic-before")
        self.assertEqual(old.recv(32), b"synthetic-before")
        clock.now = 8
        wait_for(lambda: len(issued) == 2)
        new, status = self.connect(relay)
        self.assertIn(b" 200 ", status)
        old.sendall(b"synthetic-after")
        self.assertEqual(old.recv(32), b"synthetic-after")
        new.sendall(b"synthetic-new")
        self.assertEqual(new.recv(32), b"synthetic-new")
        self.assertEqual(
            [row[0] for row in proxy.requests], ["agv_synthetic1", "agv_synthetic2"]
        )
        self.assertNotIn(issued[0], revoked)
        old.shutdown(socket.SHUT_RDWR)
        old.close()
        wait_for(lambda: issued[0] in revoked)
        self.assertEqual(revoked.count(issued[0]), 1)
        relay.close()
        supervisor.close()
        self.assertEqual(set(issued), set(revoked))
        self.assertFalse(relay.thread.is_alive())
        self.assertFalse(supervisor.thread.is_alive())

    def test_failure_gates_new_work_without_interrupting_old_or_retrying(self):
        _, clock, supervisor, relay, issued, revoked = self.setup_relay(fail_after=1)
        old, _ = self.connect(relay)
        clock.now = 8
        wait_for(lambda: supervisor.failed)
        _, status = self.connect(relay)
        self.assertIn(b" 503 ", status)
        old.sendall(b"drain")
        self.assertEqual(old.recv(8), b"drain")
        time.sleep(0.1)
        self.assertEqual(len(issued), 1)
        self.assertEqual(revoked, [])
        clock.now = 11
        wait_for(lambda: issued[0] in revoked)
        self.assertEqual(old.recv(8), b"")

    def test_admission_rechecks_drift_without_interrupting_existing_tunnel(self):
        proxy, _, supervisor, relay, issued, _ = self.setup_relay()
        old, _ = self.connect(relay)
        events = []
        supervisor.on_failure = lambda: events.append("safe failure notice")

        def changed():
            raise Error("Synthetic approval changed")

        supervisor.check = changed
        _, status = self.connect(relay)
        self.assertIn(b" 503 ", status)
        self.assertTrue(supervisor.failed)
        self.connect(relay)
        self.assertEqual(events, ["safe failure notice"])
        old.sendall(b"existing-request")
        self.assertEqual(old.recv(32), b"existing-request")
        self.assertEqual(len(issued), 1)
        self.assertEqual(len(proxy.requests), 1)

    def test_shutdown_owns_and_revokes_a_lease_returning_during_cancellation(self):
        clock, issued, revoked = Clock(), [], []
        pending, finish = threading.Event(), threading.Event()

        def factory():
            identifier = str(uuid4())
            issued.append(identifier)
            if len(issued) == 2:
                pending.set()
                finish.wait(2)
            return Lease(
                identifier, "http://x:agv_synthetic@127.0.0.1:8283", clock() + 10
            )

        supervisor = Supervisor(factory, revoked.append, 3, clock=clock).start()
        self.addCleanup(supervisor.close)
        clock.now = 8
        self.assertTrue(pending.wait(1))
        closing = threading.Thread(target=supervisor.close)
        closing.start()
        finish.set()
        closing.join(2)
        self.assertFalse(closing.is_alive())
        self.assertIsNone(supervisor.acquire())
        self.assertEqual(set(issued), set(revoked))

    def test_auth_target_framing_and_header_bounds_fail_before_native_contact(self):
        proxy, _, _, relay, _, _ = self.setup_relay()
        auth = "Proxy-Authorization: Basic " + relay.authorization.decode()
        for headers, target in (
            (
                ["Host: example.test:443", "Proxy-Authorization: Basic wrong"],
                "example.test:443",
            ),
            (["Host: example.test:443", auth, auth], "example.test:443"),
            (["Host: example.test:443", auth, "Content-Length: 1"], "example.test:443"),
            (
                ["Host: example.test:443", auth, "Transfer-Encoding: chunked"],
                "example.test:443",
            ),
            (
                ["Host: example.test:443", auth, "Authorization: private"],
                "example.test:443",
            ),
            (["Host: other.test:443", auth], "other.test:443"),
            (["Host: example.test:443", auth, " Folded: bad"], "example.test:443"),
            (
                ["Host: example.test:443", auth, "X-Large: " + "x" * 8192],
                "example.test:443",
            ),
        ):
            _, status = self.connect(relay, headers=headers, target=target)
            self.assertIn(b" 502 ", status)
            self.assertNotIn(relay.capability.encode(), status)
        self.assertEqual(proxy.requests, [])

    def test_connection_bound_and_unsupported_upstream_fail_closed(self):
        proxy, _, supervisor, relay, _, _ = self.setup_relay(maximum=1)
        first, _ = self.connect(relay)
        port = int(relay.url.rsplit(":", 1)[1])
        extra = socket.create_connection(("127.0.0.1", port), timeout=2)
        self.addCleanup(extra.close)
        self.assertEqual(extra.recv(1), b"")
        first.shutdown(socket.SHUT_RDWR)
        first.close()
        wait_for(lambda: not relay.handlers)
        supervisor.current.proxy_url = "socks5://x:agv_synthetic@127.0.0.1:" + str(
            proxy.port
        )
        _, status = self.connect(relay)
        self.assertIn(b" 502 ", status)
        self.assertEqual(len(proxy.requests), 1)

    @unittest.skipIf(
        httpx is None, "HTTPX optional actual-client verification unavailable"
    )
    def test_actual_https_httpx_reuses_old_tunnel_and_selects_new_lease_on_new_client(
        self,
    ):
        with tempfile.TemporaryDirectory(prefix="runbox-renewal-tls-") as temporary:
            directory = Path(temporary)
            key, cert = directory / "synthetic.key", directory / "synthetic.pem"
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
                    "-subj",
                    "/CN=example.test",
                    "-addext",
                    "subjectAltName=DNS:example.test",
                    "-keyout",
                    str(key),
                    "-out",
                    str(cert),
                ],
                check=True,
                capture_output=True,
            )
            server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server.load_cert_chain(cert, key)
            trusted = ssl.create_default_context(cafile=str(cert))
            wall = Clock()
            wall.now = 1000
            proxy, clock, _, relay, issued, revoked = self.setup_relay(
                context=server, wall_clock=wall
            )
            with httpx.Client(
                proxy=relay.url, verify=trusted, trust_env=False, timeout=2
            ) as old:
                self.assertEqual(
                    old.get("https://example.test/old").text, "agv_synthetic1"
                )
                wall.now += 8
                wait_for(lambda: len(issued) == 2)
                self.assertEqual(clock(), 0)
                with httpx.Client(
                    proxy=relay.url, verify=trusted, trust_env=False, timeout=2
                ) as new:
                    self.assertEqual(
                        new.get("https://example.test/new").text, "agv_synthetic2"
                    )
                self.assertEqual(
                    old.get("https://example.test/same-tunnel").text, "agv_synthetic1"
                )
                self.assertNotIn(issued[0], revoked)
                wall.now += 3
                wait_for(lambda: issued[0] in revoked)
                with self.assertRaises(httpx.HTTPError):
                    old.get("https://example.test/expired-tunnel")
            wait_for(lambda: issued[0] in revoked)
            self.assertEqual(len(proxy.requests), 2)
            self.assertTrue(
                all(b"runbox:" not in request[2] for request in proxy.requests)
            )

    def test_factory_checks_both_sides_of_probe_and_runs_standalone_env(self):
        candidate = profile()
        runtime = {"ca-file": "/synthetic/ca.pem"}
        session = {
            "id": str(uuid4()),
            "token": "agv_synthetic-secret",
            "expiresAt": (datetime.now(timezone.utc) + timedelta(hours=8)).isoformat(),
        }
        observations, revocations = [], []

        class Provider:
            @staticmethod
            def create_lease(*_):
                observations.append("mint")
                return session

            @staticmethod
            def proxy_url(*_):
                return "http://x-agent-vault:agv_synthetic-secret@127.0.0.1:8283"

            @staticmethod
            def session_environment(_):
                return {"INFISICAL_AGENT_VAULT_SESSION_TOKEN": session["token"]}

            @staticmethod
            def revoke_lease(_profile, _runtime, identifier):
                revocations.append(identifier)

        def verify(*_):
            observations.append("verify")
            return runtime

        def probe(*_args, **kwargs):
            observations.append("probe")
            self.assertFalse(kwargs["report_probe"])
            self.assertEqual(
                kwargs["extra_environment"]["INFISICAL_AGENT_VAULT_SESSION_TOKEN"],
                session["token"],
            )
            return 0

        def substitutions(*_):
            return {}

        with (
            tempfile.TemporaryDirectory(prefix="runbox-renewal-app-") as temporary,
            patch(
                "runbox.renewal.load", return_value={"profiles": {"daemon": candidate}}
            ),
            patch("runbox.trust.verified", side_effect=verify),
            patch("runbox.providers.PROVIDERS", {"infisical": Provider}),
            patch(
                "runbox.runner.command",
                return_value=(["synthetic-probe"], Path(temporary)),
            ) as command,
            patch("runbox.runner.execute", side_effect=probe),
            patch("runbox.sandbox.substitutions", side_effect=substitutions),
            patch.dict(
                "os.environ",
                {
                    "HTTPS_PROXY": "http://ambient:never-copy@localhost:1",
                    "RUNBOX_PRIVATE": "never-copy",
                },
            ),
            redirect_stdout(io.StringIO()) as output,
        ):
            candidate["execution"]["argv"] = ["/usr/bin/env"]
            status = execute_renewing(
                Path(temporary),
                "daemon",
                candidate,
                runtime,
                Path(temporary) / "release.pyz",
                ["example-daemon"],
            )
        self.assertEqual(status, 0)
        self.assertLess(observations.index("verify"), observations.index("mint"))
        self.assertIn("verify", observations[observations.index("probe") + 1 :])
        self.assertTrue(command.call_args.kwargs["existing_session"])
        self.assertEqual(revocations, [session["id"]])
        self.assertIn("EXAMPLE_API_KEY=public_placeholder", output.getvalue())
        self.assertNotIn("HTTPS_PROXY=", output.getvalue())
        self.assertNotIn("RUNBOX_", output.getvalue())
        self.assertNotIn("agv_synthetic-secret", output.getvalue())
        self.assertIn("[redacted]", output.getvalue())

    def test_drift_after_mint_revokes_without_starting_app(self):
        candidate = profile()
        runtime = {"ca-file": "/synthetic/ca.pem"}
        session = {
            "id": str(uuid4()),
            "token": "agv_synthetic-secret",
            "expiresAt": (datetime.now(timezone.utc) + timedelta(hours=8)).isoformat(),
        }
        provider = unittest.mock.Mock()
        provider.create_lease.return_value = session
        provider.proxy_url.return_value = (
            "http://x-agent-vault:agv_synthetic-secret@127.0.0.1:8283"
        )
        provider.session_environment.return_value = {
            "INFISICAL_AGENT_VAULT_SESSION_TOKEN": session["token"]
        }
        changes = [
            {"profiles": {"daemon": candidate}},
            {"profiles": {"daemon": candidate}},
            {"profiles": {"daemon": {}}},
        ]
        with (
            patch("runbox.renewal.load", side_effect=changes),
            patch("runbox.trust.verified", return_value=runtime),
            patch("runbox.providers.PROVIDERS", {"infisical": provider}),
            patch("runbox.runner.command", return_value=([], Path("/"))),
            patch("runbox.runner.execute", return_value=0),
            patch("runbox.renewal.subprocess.Popen") as popen,
            self.assertRaises(Error) as caught,
        ):
            execute_renewing(
                Path("/synthetic"),
                "daemon",
                candidate,
                runtime,
                Path("/synthetic/release.pyz"),
                ["example-daemon"],
            )
        self.assertNotIn(session["token"], str(caught.exception))
        provider.revoke_lease.assert_called_once_with(candidate, runtime, session["id"])
        popen.assert_not_called()

    def test_failed_probe_and_revocation_report_only_fixed_cleanup_warning(self):
        candidate = profile()
        runtime = {"ca-file": "/synthetic/ca.pem"}
        session = {
            "id": str(uuid4()),
            "token": "agv_synthetic-private",
            "expiresAt": (datetime.now(timezone.utc) + timedelta(hours=8)).isoformat(),
        }
        provider = unittest.mock.Mock()
        provider.create_lease.return_value = session
        provider.proxy_url.return_value = (
            "http://x-agent-vault:agv_synthetic-private@127.0.0.1:8283"
        )
        provider.session_environment.return_value = {
            "INFISICAL_AGENT_VAULT_SESSION_TOKEN": session["token"]
        }
        provider.revoke_lease.side_effect = RuntimeError("agv_synthetic-revoke-private")
        with (
            patch(
                "runbox.renewal.load", return_value={"profiles": {"daemon": candidate}}
            ),
            patch("runbox.trust.verified", return_value=runtime),
            patch("runbox.providers.PROVIDERS", {"infisical": provider}),
            patch("runbox.runner.command", return_value=([], Path("/"))),
            patch(
                "runbox.runner.execute",
                side_effect=Error("agv_synthetic-probe-private"),
            ),
            patch("runbox.renewal.subprocess.Popen") as popen,
            redirect_stderr(io.StringIO()) as errors,
            self.assertRaises(Error) as caught,
        ):
            execute_renewing(
                Path("/synthetic"),
                "daemon",
                candidate,
                runtime,
                Path("/synthetic/release.pyz"),
                ["example-daemon"],
            )
        self.assertEqual(
            errors.getvalue(),
            "Session cleanup could not be verified; finite expiry still applies\n",
        )
        self.assertNotIn("agv_", str(caught.exception))
        provider.revoke_lease.assert_called_once_with(candidate, runtime, session["id"])
        popen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
