"""Opt-in finite lease rotation behind an authenticated, opaque CONNECT relay."""

import base64
import copy
import hmac
import os
import re
import secrets
import select
import selectors
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import unquote, urlsplit
from uuid import UUID

from .config import Error, fields, load, online_profile, require
from .output import safe_output

HEADER_LIMIT = 8192
BUFFER_LIMIT = 65536


def _seconds(value):
    require(
        isinstance(value, str) and re.fullmatch(r"[1-9][0-9]{0,3}[mh]", value),
        "Invalid renewal duration",
    )
    return int(value[:-1]) * (60 if value[-1] == "m" else 3600)


def _lease_deadline(expires_at, ttl, beginning, wall, issued_wall):
    try:
        expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        require(expiry.tzinfo is not None, "Invalid renewed expiry")
        epoch = expiry.astimezone(timezone.utc).timestamp()
        require(5 < epoch - issued_wall <= ttl + 60, "Invalid renewed lifetime")
        # Slow issuance never extends the locally owned maximum lifetime.
        return min(beginning + ttl, beginning + epoch - wall - 5)
    except (TypeError, ValueError, AttributeError, OverflowError):
        raise Error("Invalid renewed lifetime") from None


def validate(profile):
    """Renew only a reviewed fixed daemon with a provider-local HTTPS handoff."""
    session, execution = profile["session"], profile["execution"]
    policy = fields(session["renewal"], ("renew-before", "max-connections"))
    ttl, before = _seconds(session["ttl"]), _seconds(policy["renew-before"])
    require(600 <= ttl <= 28800 and 180 <= before <= ttl / 2, "Invalid renewal window")
    require(
        type(policy["max-connections"]) is int
        and 1 <= policy["max-connections"] <= 256,
        "Invalid renewal connection bound",
    )
    require(
        execution.get("sandbox") == "none"
        and "command" in execution
        and execution.get("arguments") == [[]]
        and execution.get("cwd", "repo") == "repo"
        and "handoff" in execution
        and "probe-argv" in execution
        and not set(execution) & {"workspace", "preloads", "inputs", "outputs"}
        and not set(session) & {"worker", "tunnel"}
        and "services" not in profile,
        "Renewal requires a fixed provider-local daemon without auxiliary sessions",
    )
    try:
        target = urlsplit(profile["http"]["base-url"])
        require(
            target.scheme == "https"
            and target.hostname
            and not target.username
            and not target.password
            and not target.query
            and not target.fragment
            and re.fullmatch(r"[A-Za-z0-9.-]+", target.hostname)
            and 1 <= (target.port or 443) <= 65535,
            "Renewal requires a fixed HTTPS origin",
        )
    except (KeyError, TypeError, ValueError):
        raise Error("Renewal requires a fixed HTTPS origin") from None


@dataclass(eq=False, repr=False)
class Lease:
    identifier: str
    proxy_url: str = field(repr=False)
    deadline: float
    wall_deadline: float | None = None
    references: int = 0
    revoking: bool = False


class Supervisor:
    """Own leases independently of the application's lifetime and worker grants."""

    def __init__(
        self,
        factory,
        revoke,
        renew_before,
        *,
        clock=time.monotonic,
        wall_clock=time.time,
        check=None,
        on_failure=None,
    ):
        self.factory, self.revoke, self.renew_before = factory, revoke, renew_before
        self.clock = clock
        self.wall_clock = wall_clock
        self.check = check
        self.on_failure = on_failure
        self.lock = threading.RLock()
        self.closed = threading.Event()
        self.failed = False
        self.cleanup_failed = False
        self.current = None
        self.leases = []
        self.revokers = []
        self.thread = None

    def remaining(self, lease):
        # On macOS the monotonic clock can pause during system sleep. Server
        # expiry does not pause. Either clock may shorten access; neither may
        # extend it when the other clock reaches its original bound.
        remaining = lease.deadline - self.clock()
        if lease.wall_deadline is not None:
            remaining = min(remaining, lease.wall_deadline - self.wall_clock())
        return remaining

    def _fail(self):
        with self.lock:
            first = not self.failed
            self.failed = True
        if first and self.on_failure and not self.closed.is_set():
            try:
                self.on_failure()
            except Exception:
                pass

    def start(self):
        lease = self.factory()
        with self.lock:
            self.leases.append(lease)
            require(self.remaining(lease) > 0, "Renewed session is already expired")
            self.current = lease
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        return self

    def _revoke(self, lease):
        try:
            self.revoke(lease.identifier)
        except Exception:
            self.cleanup_failed = True
        finally:
            with self.lock:
                # IDs suffice for cleanup; do not retain retired capabilities forever.
                lease.proxy_url = ""
                if lease in self.leases:
                    self.leases.remove(lease)

    def _retire(self, *, all_owned=False):
        with self.lock:
            self.revokers = [thread for thread in self.revokers if thread.is_alive()]
            for lease in self.leases:
                if not lease.revoking and (
                    all_owned
                    or self.remaining(lease) <= 0
                    or lease is not self.current
                    and not lease.references
                ):
                    lease.revoking = True
                    thread = threading.Thread(
                        target=self._revoke, args=(lease,), daemon=True
                    )
                    self.revokers.append(thread)
                    thread.start()

    def _run(self):
        while not self.closed.wait(0.05):
            self._retire()
            with self.lock:
                due = (
                    not self.failed
                    and self.remaining(self.current) <= self.renew_before
                )
            if not due:
                continue
            try:
                candidate = self.factory()
                with self.lock:
                    self.leases.append(candidate)
                    invalid = self.failed or self.remaining(candidate) <= 0
                    if not self.closed.is_set() and not invalid:
                        self.current = candidate
                if invalid:
                    self._fail()
                self._retire(all_owned=self.closed.is_set())
            except Exception:
                # No automatic auth retries and no reuse of the previous lease for new work.
                self._fail()

    def acquire(self):
        if self.check:
            try:
                self.check()
            except Exception:
                self._fail()
                return None
        with self.lock:
            lease = self.current
            if (
                self.closed.is_set()
                or self.failed
                or not lease
                or lease.revoking
                or self.remaining(lease) <= 0
            ):
                return None
            lease.references += 1
            return lease

    def release(self, lease):
        with self.lock:
            lease.references -= 1
        self._retire()

    def close(self):
        self.closed.set()
        # Native issuance is bounded (65s); a cancelled probe is interrupted by its health check.
        if self.thread:
            self.thread.join(210)
        self._retire(all_owned=True)
        deadline = time.monotonic() + 70
        for thread in self.revokers:
            thread.join(max(0, deadline - time.monotonic()))


def _header(connection, deadline, clock=time.monotonic):
    data = bytearray()
    while b"\r\n\r\n" not in data:
        remaining = deadline - clock()
        if remaining <= 0:
            raise ValueError
        connection.settimeout(min(remaining, 1))
        try:
            block = connection.recv(min(4096, HEADER_LIMIT + 1 - len(data)))
        except socket.timeout:
            continue
        if not block:
            raise ValueError
        data.extend(block)
        if len(data) > HEADER_LIMIT:
            raise ValueError
    head, tail = bytes(data).split(b"\r\n\r\n", 1)
    if tail:
        # CONNECT clients must wait for 200 before sending the TLS handshake.
        raise ValueError
    return head.decode("ascii").split("\r\n")


def _proxy_authorization(value, address):
    parsed = urlsplit(value)
    require(
        parsed.scheme == "http"
        and parsed.hostname == address[0]
        and parsed.port == address[1]
        and parsed.username
        and parsed.password
        and not parsed.path
        and not parsed.query
        and not parsed.fragment,
        "Unreviewed renewal proxy",
    )
    return base64.b64encode(
        (unquote(parsed.username) + ":" + unquote(parsed.password)).encode()
    ).decode()


class ConnectRelay:
    """Only CONNECT to one HTTPS authority, through one pinned native proxy."""

    def __init__(self, supervisor, proxy, target, max_connections=64):
        self.supervisor, self.proxy, self.target = supervisor, proxy, target.lower()
        host, port = proxy.rsplit(":", 1)
        require(
            host == "127.0.0.1" and 1 <= int(port) <= 65535, "Invalid renewal proxy"
        )
        self.address = (host, int(port))
        self.capability = secrets.token_urlsafe(32)
        self.authorization = base64.b64encode(("runbox:" + self.capability).encode())
        self.slots = threading.BoundedSemaphore(max_connections)
        self.closed = threading.Event()
        self.lock = threading.Lock()
        self.connections, self.handlers = set(), set()
        self.listener = None
        self.thread = None

    def start(self):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(64)
        self.listener.settimeout(0.1)
        self.url = (
            "http://runbox:"
            + self.capability
            + "@127.0.0.1:"
            + str(self.listener.getsockname()[1])
        )
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.thread.start()
        return self

    def _accept(self):
        while not self.closed.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self.slots.acquire(blocking=False):
                connection.close()
                continue
            thread = threading.Thread(
                target=self._handle, args=(connection,), daemon=True
            )
            with self.lock:
                if self.closed.is_set():
                    connection.close()
                    self.slots.release()
                    return
                self.connections.add(connection)
                self.handlers.add(thread)
            thread.start()

    def _authorize(self, lines):
        require(lines and len(lines) <= 33, "Invalid CONNECT request")
        require(
            lines[0] == "CONNECT " + self.target + " HTTP/1.1", "Invalid CONNECT target"
        )
        headers = {}
        for line in lines[1:]:
            key, separator, value = line.partition(":")
            key = key.lower()
            require(
                separator
                and re.fullmatch(r"[a-z0-9-]+", key)
                and key not in headers
                and all(32 <= ord(c) <= 126 for c in value),
                "Invalid CONNECT headers",
            )
            headers[key] = value.strip()
        require(
            headers.get("host") == self.target
            and not set(headers)
            & {"content-length", "transfer-encoding", "authorization"},
            "Invalid CONNECT framing",
        )
        auth = headers.get("proxy-authorization", "")
        require(auth.startswith("Basic "), "Missing CONNECT capability")
        require(
            hmac.compare_digest(auth[6:].encode(), self.authorization),
            "Invalid CONNECT capability",
        )

    def _upstream_auth(self, lease):
        return _proxy_authorization(lease.proxy_url, self.address)

    def _handle(self, client):
        upstream, lease, established = None, None, False
        try:
            self._authorize(_header(client, time.monotonic() + 5))
            lease = self.supervisor.acquire()
            if lease is None:
                client.sendall(
                    b"HTTP/1.1 503 Session unavailable\r\nConnection: close\r\n\r\n"
                )
                return
            auth = self._upstream_auth(lease)
            upstream = socket.create_connection(self.address, timeout=5)
            with self.lock:
                require(not self.closed.is_set(), "Renewal relay stopped")
                self.connections.add(upstream)
            upstream.sendall(
                (
                    "CONNECT "
                    + self.target
                    + " HTTP/1.1\r\nHost: "
                    + self.target
                    + "\r\nProxy-Authorization: Basic "
                    + auth
                    + "\r\n\r\n"
                ).encode()
            )
            response = _header(upstream, time.monotonic() + 5)
            require(
                response
                and re.fullmatch(r"HTTP/1[.][01] 200(?: [\x20-\x7e]*)?", response[0]),
                "Native CONNECT unavailable",
            )
            require(self.supervisor.remaining(lease) > 0, "Session expired")
            client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            established = True
            self._pump(client, upstream, lease)
        except Exception:
            if not established:
                try:
                    client.sendall(
                        b"HTTP/1.1 502 Proxy unavailable\r\nConnection: close\r\n\r\n"
                    )
                except OSError:
                    pass
        finally:
            for connection in (client, upstream):
                if connection:
                    connection.close()
                    with self.lock:
                        self.connections.discard(connection)
            if lease:
                self.supervisor.release(lease)
            with self.lock:
                self.handlers.discard(threading.current_thread())
            self.slots.release()

    def _pump(self, client, upstream, lease):
        peers = {client: upstream, upstream: client}
        pending = {client: bytearray(), upstream: bytearray()}
        reading, shut = set(peers), set()
        for connection in peers:
            connection.setblocking(False)
        while (reading or any(pending.values())) and not self.closed.is_set():
            if self.supervisor.remaining(lease) <= 0:
                return
            readers = [s for s in reading if len(pending[peers[s]]) < BUFFER_LIMIT]
            writers = [s for s in peers if pending[s]]
            ready, writable, _ = select.select(readers, writers, [], 0.1)
            for connection in ready:
                try:
                    block = connection.recv(
                        min(16384, BUFFER_LIMIT - len(pending[peers[connection]]))
                    )
                except BlockingIOError:
                    continue
                if block:
                    pending[peers[connection]].extend(block)
                else:
                    reading.discard(connection)
            for connection in writable:
                try:
                    count = connection.send(pending[connection])
                except BlockingIOError:
                    continue
                if not count:
                    return
                del pending[connection][:count]
            for source, destination in peers.items():
                if (
                    source not in reading
                    and not pending[destination]
                    and destination not in shut
                ):
                    destination.shutdown(socket.SHUT_WR)
                    shut.add(destination)

    def close(self):
        self.closed.set()
        if self.listener:
            self.listener.close()
        with self.lock:
            connections, handlers = list(self.connections), list(self.handlers)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        for thread in [self.thread, *handlers]:
            if thread:
                thread.join(6)


def execute_renewing(root, name, profile, runtime, archive, arguments):
    """Run the ordinary app once; rotate only externally owned proxy leases."""
    from .handoff import preflight, provider_environment
    from .providers import PROVIDERS
    from .runner import command, execute
    from .sandbox import expand, substitutions
    from .trust import verified

    validate(profile)
    require(
        arguments == [profile["execution"]["command"]],
        "Renewal accepts only the fixed daemon",
    )
    captured = copy.deepcopy(profile)
    cancelled = threading.Event()
    provider = PROVIDERS[profile["provider"]["type"]]

    def guard():
        require(not cancelled.is_set(), "Renewal cancelled")
        config = load(root / ".runbox.yaml")
        require(
            config.get("profiles", {}).get(name) == captured,
            "Approved renewal profile changed",
        )
        require(
            verified(root, name, captured, archive) == runtime,
            "Approved renewal runtime changed",
        )

    def mint():
        guard()
        beginning, wall = time.monotonic(), time.time()
        lease = provider.create_lease(captured, runtime)
        identifier = None
        try:
            candidate_id = lease["id"]
            require(
                str(UUID(candidate_id)) == candidate_id,
                "Invalid renewed session identity",
            )
            identifier = candidate_id
            deadline = _lease_deadline(
                lease["expiresAt"],
                _seconds(captured["session"]["ttl"]),
                beginning,
                wall,
                time.time(),
            )
            wall_deadline = wall + deadline - beginning
            proxy = provider.proxy_url(captured, lease)
            host, port = captured["session"]["proxy"].rsplit(":", 1)
            _proxy_authorization(proxy, (host, int(port)))
            probe, cwd = command(
                root,
                online_profile(captured),
                runtime,
                archive,
                "probe",
                [],
                existing_session=True,
            )
            require(
                execute(
                    probe,
                    cwd,
                    probe=True,
                    report_probe=False,
                    extra_environment=provider.session_environment(lease),
                    health=guard,
                )
                == 0,
                "Renewed session probe failed",
            )
            guard()
            require(
                deadline > time.monotonic() and wall_deadline > time.time(),
                "Renewed session expired during verification",
            )
            return Lease(identifier, proxy, deadline, wall_deadline=wall_deadline)
        except BaseException:
            if identifier:
                try:
                    provider.revoke_lease(captured, runtime, identifier)
                except Exception:
                    print(
                        "Session cleanup could not be verified; finite expiry still applies",
                        file=sys.stderr,
                        flush=True,
                    )
            raise Error("Session renewal failed; new access is disabled") from None

    supervisor = Supervisor(
        mint,
        lambda identifier: provider.revoke_lease(captured, runtime, identifier),
        _seconds(profile["session"]["renewal"]["renew-before"]),
        check=guard,
        on_failure=lambda: print(
            "Proxy renewal or approval verification failed; new connections are disabled",
            file=sys.stderr,
            flush=True,
        ),
    )
    relay, process, previous = None, None, {}

    def forward(number, _frame):
        cancelled.set()
        supervisor.closed.set()
        if process and process.poll() is None:
            try:
                os.killpg(process.pid, number)
            except ProcessLookupError:
                pass

    try:
        for number in (signal.SIGINT, signal.SIGTERM):
            previous[number] = signal.signal(number, forward)
        guard()
        preflight(profile)
        supervisor.start()
        parsed = urlsplit(profile["http"]["base-url"])
        relay = ConnectRelay(
            supervisor,
            profile["session"]["proxy"],
            parsed.hostname.lower() + ":" + str(parsed.port or 443),
            profile["session"]["renewal"]["max-connections"],
        ).start()
        values = substitutions(root, runtime, archive)
        selected = {
            **profile,
            "environment": {
                key: expand(value, values)
                for key, value in profile["environment"].items()
            },
        }
        environment = provider_environment(
            selected, runtime, {"HTTPS_PROXY": relay.url}
        )
        argv = [expand(value, values) for value in profile["execution"]["argv"]]
        guard()
        preflight(profile)
        process = subprocess.Popen(
            argv,
            cwd=root,
            env=environment,
            start_new_session=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL
            if profile["execution"].get("stderr") == "discard"
            else subprocess.STDOUT,
        )

        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        pending, oversized, stopped = b"", False, None
        redactions = (relay.url, relay.capability, relay.authorization.decode())
        try:
            while selector.get_map() or process.poll() is None:
                if cancelled.is_set():
                    stopped = stopped or time.monotonic()
                    if process.poll() is None and time.monotonic() - stopped >= 15:
                        os.killpg(process.pid, signal.SIGKILL)
                for key, _ in selector.select(0.1):
                    block = os.read(key.fileobj.fileno(), 8192)
                    if not block:
                        selector.unregister(key.fileobj)
                        if pending and not oversized:
                            print(
                                safe_output(
                                    pending.decode(errors="replace"), redactions
                                ),
                                end="",
                                flush=True,
                            )
                        continue
                    pending += block
                    while b"\n" in pending:
                        line, _, pending = pending.partition(b"\n")
                        if not oversized and len(line) <= BUFFER_LIMIT:
                            print(
                                safe_output(line.decode(errors="replace"), redactions),
                                flush=True,
                            )
                        else:
                            print("[oversized command output withheld]", flush=True)
                        oversized = False
                    if len(pending) > BUFFER_LIMIT:
                        pending, oversized = b"", True
            status = process.wait()
            return status if status >= 0 else 128 - status
        finally:
            selector.close()
    except BaseException:
        if process and process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        raise
    finally:
        cancelled.set()
        supervisor.closed.set()
        if relay:
            relay.close()
        supervisor.close()
        if supervisor.cleanup_failed:
            print(
                "Session cleanup could not be verified; finite expiry still applies",
                file=sys.stderr,
            )
        if process and process.stdout:
            process.stdout.close()
        for number, handler in previous.items():
            signal.signal(number, handler)
