"""Share only forwarding opened by Runbox on an explicitly reserved endpoint."""

import fcntl
import hashlib
import json
import os
import re
import socket
import stat
import time
from contextlib import contextmanager

from .config import Error, require
from .trust import directory, state


def private_file(path):
    fd = os.open(
        path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600
    )
    try:
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.getuid()
            and not info.st_mode & 0o077,
            "Shared tunnel state must be owner-only",
        )
        return os.fdopen(fd, "r+b")
    except BaseException:
        os.close(fd)
        raise


def exclusive(stream):
    try:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except BlockingIOError:
        return False


@contextmanager
def gate(path):
    with private_file(path) as stream:
        deadline = time.monotonic() + 45
        while not exclusive(stream):
            require(time.monotonic() < deadline, "Shared tunnel state is busy")
            time.sleep(0.05)
        yield stream


def read_binding(stream):
    data = stream.read(4097)
    try:
        require(len(data) <= 4096, "Invalid shared tunnel state")
        return json.loads(data)
    except (ValueError, UnicodeError):
        raise Error("Invalid shared tunnel state") from None


def write_binding(stream, binding):
    stream.seek(0)
    stream.truncate()
    if binding is not None:
        stream.write(json.dumps(binding, sort_keys=True).encode())
    stream.flush()


class SharedForward:
    def __init__(self, tunnel, binary, ssh):
        host, port = tunnel["local"].split(":")
        self.endpoint = (host, int(port))
        self.host = tunnel["host"]
        self.specification = tunnel["local"] + ":" + tunnel["remote"]
        self.binding = {"host": self.host, "specification": self.specification, "ssh": binary}
        self.ssh = ssh
        self.lease = None
        self.owner = None

        root = state()
        directory(root, create=True)
        records = root / "shared-tunnels"
        directory(records, create=True)
        key = hashlib.sha256(f"{host}:{int(port)}".encode()).hexdigest()
        self.gate_path = records / (key + ".gate")
        self.lease_path = records / (key + ".leases")

    def master(self):
        check = self.ssh(["-O", "check", self.host])
        match = re.search(rb"(?m)^Master running \(pid=([1-9][0-9]*)\)\r?$", check.stderr)
        require(match is not None, "Unable to identify the existing managed SSH master")
        return int(match[1])

    def listening(self):
        try:
            with socket.create_connection(self.endpoint, timeout=1):
                return True
        except OSError:
            return False

    def control(self, operation):
        self.ssh(["-O", operation, "-L", self.specification, self.host])

    def open(self):
        lease = private_file(self.lease_path)
        try:
            with gate(self.gate_path) as record:
                if exclusive(lease):
                    require(
                        not self.listening(),
                        "Shared tunnel endpoint already has an unowned listener",
                    )
                    owner = {**self.binding, "master": self.master()}
                    write_binding(record, owner)
                    self.control("forward")
                else:
                    owner = {**self.binding, "master": self.master()}
                    require(
                        read_binding(record) == owner and self.listening(),
                        "Shared tunnel no longer matches its reviewed managed forward",
                    )
                fcntl.flock(lease, fcntl.LOCK_SH)
        except BaseException:
            lease.close()
            raise
        self.owner, self.lease = owner, lease
        return self

    def close(self):
        lease, self.lease = self.lease, None
        if lease is None:
            return
        try:
            with gate(self.gate_path) as record:
                fcntl.flock(lease, fcntl.LOCK_UN)
                if not exclusive(lease):
                    return
                require(read_binding(record) == self.owner, "Shared tunnel ownership changed")
                if self.listening():
                    require(
                        self.master() == self.owner["master"],
                        "Shared tunnel SSH master changed before cleanup",
                    )
                    self.control("cancel")
                write_binding(record, None)
        finally:
            lease.close()
