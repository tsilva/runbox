"""Bounded, memory-only JSON dispatch for reviewed command compatibility links."""

import json
import os
import selectors
import signal
import subprocess
import threading
import time
from pathlib import Path

from .config import Error, fields, require, word
from .trust import regular


def validate(value):
    fields(
        value,
        (
            "max-bytes",
            "path",
            "equals",
            "profile",
            "timeout",
            "otherwise-timeout",
            "output-field",
            "max-output-bytes",
        ),
    )
    for name in ("max-bytes", "max-output-bytes"):
        require(
            type(value[name]) is int and 1 <= value[name] <= 64 * 1024 * 1024,
            "Invalid command-link payload limit",
        )
    for name in ("timeout", "otherwise-timeout"):
        require(
            type(value[name]) is int and 1 <= value[name] <= 3600,
            "Invalid command-link timeout",
        )
    require(
        type(value["path"]) is list and 1 <= len(value["path"]) <= 8,
        "Invalid JSON selector path",
    )
    for name in [*value["path"], value["output-field"]]:
        require(
            isinstance(name, str)
            and 1 <= len(name) <= 64
            and not any(c in name for c in "\0\n"),
            "Invalid JSON selector field",
        )
    require(
        type(value["equals"]) in (str, int, bool) and len(str(value["equals"])) <= 256,
        "Invalid JSON selector value",
    )
    word(value["profile"])
    return value


def mapping(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate command-link JSON field")
        result[key] = value
    return result


def selected(rule, payload):
    validate(rule)
    require(
        type(payload) is bytes and 0 < len(payload) <= rule["max-bytes"],
        "Command-link payload is empty or exceeds its limit",
    )
    try:
        value = json.loads(payload, object_pairs_hook=mapping)
    except (ValueError, UnicodeError, RecursionError):
        raise Error("Invalid command-link JSON payload") from None
    require(type(value) is dict, "Expected a command-link JSON object")
    for key in rule["path"]:
        value = value.get(key) if type(value) is dict else None
    return type(value) is type(rule["equals"]) and value == rule["equals"]


def execute(arguments, payload, rule, matches):
    target = regular((Path.home() / ".local/bin/runbox").resolve(), private=True)
    require(target.name == "runbox", "Invalid shared command dispatcher")
    timeout = rule["timeout"] if matches else rule["otherwise-timeout"]
    process = subprocess.Popen(
        [str(target), *arguments],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        env={"HOME": str(Path.home()), "PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )

    def write():
        try:
            process.stdin.write(payload)
            process.stdin.flush()
        except (OSError, ValueError):
            pass
        finally:
            try:
                process.stdin.close()
            except OSError:
                pass

    writer = threading.Thread(target=write, daemon=True)
    writer.start()
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    output = bytearray()
    previous = {}

    def stop(*_args):
        raise KeyboardInterrupt()

    try:
        if threading.current_thread() is threading.main_thread():
            for number in (signal.SIGINT, signal.SIGTERM):
                previous[number] = signal.signal(number, stop)
        deadline = time.monotonic() + timeout
        while selector.get_map():
            require(time.monotonic() < deadline, "Command-link request timed out")
            for key, _ in selector.select(
                min(0.25, max(0, deadline - time.monotonic()))
            ):
                chunk = os.read(key.fileobj.fileno(), 8192)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                require(
                    len(output) + len(chunk) <= rule["max-output-bytes"],
                    "Command-link response exceeds its limit",
                )
                output.extend(chunk)
        process.wait(timeout=max(0.01, deadline - time.monotonic()))
        require(
            process.returncode == 0,
            "Command-link request failed; private diagnostics withheld",
        )
        records = []
        for line in output.splitlines():
            try:
                record = json.loads(line, object_pairs_hook=mapping)
            except (ValueError, UnicodeError, RecursionError):
                continue
            if type(record) is dict and type(record.get(rule["output-field"])) is int:
                records.append(record)
        require(len(records) == 1, "Expected one command-link response record")
        print(json.dumps(records[0]))
        return 0
    except subprocess.TimeoutExpired:
        raise Error("Command-link request timed out") from None
    finally:
        selector.close()
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
        writer.join(timeout=1)
        process.stdout.close()
        for number, handler in previous.items():
            signal.signal(number, handler)
