"""Reviewed host-side service lifecycles; ordinary commands never receive their state."""

import fcntl
import json
import os
import re
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import threading

from .config import Error, fields, require
from .sandbox import expand, substitutions


def validate(value):
    fields(value, ("lock", "processes"), ("postgres", "transient-files"))
    require(isinstance(value["lock"], str), "Invalid service lock")
    require(
        type(value["processes"]) is list
        and len(value["processes"]) <= 16
        and (value["processes"] or "postgres" in value),
        "Expected a bounded local service inventory",
    )
    for process in value["processes"]:
        fields(process, ("argv", "cwd", "ready", "timeout"), ("environment",))
        require(
            type(process["argv"]) is list
            and 1 <= len(process["argv"]) <= 64
            and all(
                isinstance(arg, str) and "\0" not in arg and "\n" not in arg
                for arg in process["argv"]
            ),
            "Invalid local service command",
        )
        require(isinstance(process["cwd"], str), "Invalid local service directory")
        require(
            "{argument-"
            not in json.dumps(
                {key: item for key, item in process.items() if key != "argv"}
            ),
            "Public service arguments may appear only in argv",
        )
        for arg in process["argv"]:
            for index in re.findall(r"\{argument-([0-9]+)\}", arg):
                require(
                    0 <= int(index) <= 63, "Invalid forwarded service argument index"
                )
        require(
            type(process["ready"]) is dict
            and len(process["ready"]) <= 16
            and all(
                isinstance(key, str) and type(item) in (str, int, bool)
                for key, item in process["ready"].items()
            ),
            "Invalid local service readiness record",
        )
        require(
            type(process["timeout"]) is int and 1 <= process["timeout"] <= 30,
            "Invalid local service startup timeout",
        )
        environment = process.get("environment", {})
        require(
            type(environment) is dict and len(environment) <= 32,
            "Invalid local service environment",
        )
        for key, item in environment.items():
            require(
                re.fullmatch(r"[A-Z][A-Z0-9_]*", key)
                and key
                not in {
                    "HOME",
                    "PATH",
                    "HTTP_PROXY",
                    "HTTPS_PROXY",
                    "ALL_PROXY",
                    "NO_PROXY",
                }
                and not key.startswith(("DYLD_", "LD_", "PYTHON", "INFISICAL"))
                and isinstance(item, str)
                and len(item) <= 1024
                and "\0" not in item
                and "\n" not in item,
                "Unsupported local service environment",
            )
            if re.search(r"KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL", key):
                require(
                    item.endswith("_placeholder"),
                    "Local services accept public placeholders only",
                )
    if "postgres" in value:
        postgres = fields(
            value["postgres"],
            ("binary", "data", "log", "timeout"),
            ("start-if-stopped",),
        )
        require(
            all(isinstance(postgres[key], str) for key in ("binary", "data", "log"))
            and type(postgres["timeout"]) is int
            and 1 <= postgres["timeout"] <= 30,
            "Invalid reviewed PostgreSQL lifecycle",
        )
        require(
            type(postgres.get("start-if-stopped", True)) is bool,
            "Invalid local PostgreSQL startup policy",
        )
    transient = value.get("transient-files", [])
    require(
        type(transient) is list
        and len(transient) <= 16
        and all(isinstance(path, str) and "{pid}" in path for path in transient),
        "Transient paths require the owned process identifier",
    )


def canonical(path):
    path = Path(path)
    require(
        path.is_absolute() and path.resolve() == path,
        "Local service path must be canonical",
    )
    return path


def private(path, directory=False):
    path = canonical(path)
    info = path.lstat()
    require(
        (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
        and info.st_uid == os.getuid()
        and not info.st_mode & 0o077,
        "Local service state must be owner-only",
    )
    return path


class Session:
    def __init__(self, root, profile, runtime, archive, workspace=None, arguments=()):
        self.root = Path(root)
        self.config = profile.get("services")
        self.values = substitutions(root, runtime, archive, workspace)
        if self.config:
            from .inputs import select

            selected = select(root, profile.get("execution", {}), arguments)
            require(
                not set(selected) & set(self.values),
                "Service input and runtime paths conflict",
            )
            self.values.update(selected)
            for process in self.config["processes"]:
                for arg in process["argv"]:
                    for index in re.findall(r"\{argument-([0-9]+)\}", arg):
                        value = (
                            arguments[int(index)]
                            if len(arguments) > int(index)
                            else "/dev/null"
                        )
                        require(
                            isinstance(value, str)
                            and len(value) <= 4096
                            and "\0" not in value
                            and "\n" not in value,
                            "Invalid forwarded public service argument",
                        )
                        name = "argument-" + index
                        require(
                            name not in self.values or self.values[name] == value,
                            "Service argument substitutions conflict",
                        )
                        self.values[name] = value
        self.runtime = runtime
        self.processes = []
        self.lock = None
        self.database_started = False
        self.transient = []
        self.handlers = {}
        self.environment = {
            "HOME": str(Path.home()),
            "PATH": "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
            "LC_ALL": "C",
        }

    def path(self, value):
        return canonical(expand(value, self.values))

    def executable(self, value):
        path = self.path(value)
        allowed = [
            self.runtime[key]
            for key in ("python", "node", "infisical")
            if key in self.runtime
        ]
        allowed += list(self.runtime.get("binaries", {}).values())
        require(
            str(path) in allowed and path.is_file(),
            "Local service executable is not runtime-pinned",
        )
        return str(path)

    def postgres(self, action):
        postgres = self.config["postgres"]
        executable = self.executable(postgres["binary"])
        data = private(self.path(postgres["data"]), directory=True)
        log = self.path(postgres["log"])
        private(log.parent, directory=True)
        require(not log.is_symlink(), "Unsafe local database log")
        if log.exists():
            info = log.lstat()
            require(
                stat.S_ISREG(info.st_mode)
                and info.st_uid == os.getuid()
                and not info.st_mode & 0o022,
                "Unsafe local database log",
            )
        args = [executable, "-D", str(data)]
        if action == "start":
            args += ["-l", str(log), "-w", "start"]
        elif action == "stop":
            args += ["-m", "fast", "-w", "stop"]
        else:
            args += ["status"]
        result = subprocess.run(
            args,
            env=self.environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            timeout=postgres["timeout"],
            umask=0o077,
        )
        return result.returncode

    def __enter__(self):
        if not self.config:
            return self
        validate(self.config)
        try:
            if threading.current_thread() is threading.main_thread():

                def interrupted(*_args):
                    raise KeyboardInterrupt()

                for number in (signal.SIGINT, signal.SIGTERM):
                    self.handlers[number] = signal.signal(number, interrupted)
            path = self.path(self.config["lock"])
            private(path.parent, directory=True)
            fd = os.open(
                path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600
            )
            self.lock = os.fdopen(fd, "a+")
            private(path)
            try:
                fcntl.flock(self.lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Error(
                    "An approved local service session is already active"
                ) from None
            for value in self.config.get("transient-files", []):
                path = self.path(value)
                require(
                    path.is_relative_to(self.root)
                    and path.name.startswith(".")
                    and str(os.getpid()) in path.name,
                    "Invalid session-owned transient path",
                )
                if not path.exists() and not path.is_symlink():
                    self.transient.append(path)
            if "postgres" in self.config:
                status = self.postgres("status")
                require(status in (0, 3), "Local PostgreSQL status is unavailable")
                if status == 3:
                    require(
                        self.config["postgres"].get("start-if-stopped", True),
                        "The required existing local PostgreSQL server is stopped",
                    )
                    self.database_started = True
                    require(
                        self.postgres("start") == 0,
                        "Owned local PostgreSQL startup failed",
                    )
            for spec in self.config["processes"]:
                argv = [expand(arg, self.values) for arg in spec["argv"]]
                argv[0] = self.executable(spec["argv"][0])
                directory = self.path(spec["cwd"])
                require(directory.is_dir(), "Local service directory is unavailable")
                environment = {
                    **self.environment,
                    **{
                        key: expand(item, self.values)
                        for key, item in spec.get("environment", {}).items()
                    },
                }
                process = subprocess.Popen(
                    argv,
                    cwd=directory,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                    umask=0o077,
                )
                self.processes.append(process)
                selector = selectors.DefaultSelector()
                try:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    require(
                        selector.select(spec["timeout"]),
                        "Local service startup timed out",
                    )
                    # Buffering/readline could block forever after a partial line.
                    raw = os.read(process.stdout.fileno(), 8193)
                    require(
                        len(raw) <= 8192 and b"\n" in raw,
                        "Invalid local service readiness record",
                    )
                    first, _, _rest = raw.partition(b"\n")
                    try:
                        ready = json.loads(first)
                    except (ValueError, UnicodeError):
                        raise Error("Invalid local service readiness record") from None
                    require(
                        type(ready) is dict
                        and ready == spec["ready"]
                        and all(
                            type(ready[key]) is type(value)
                            for key, value in spec["ready"].items()
                        ),
                        "Local service readiness did not match its approved binding",
                    )
                finally:
                    selector.close()
                # Discard ordinary relay output without ever storing provider diagnostics.
                threading.Thread(
                    target=self.drain, args=(process.stdout,), daemon=True
                ).start()
                self.healthy()
            return self
        except BaseException:
            self.close()
            raise

    @staticmethod
    def drain(stream):
        try:
            while stream.read(8192):
                pass
        except (OSError, ValueError):
            pass

    def healthy(self):
        require(
            all(process.poll() is None for process in self.processes),
            "A required local service stopped; the command must stop",
        )

    def close(self):
        failed = False
        for process in reversed(self.processes):
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=10)
                except ProcessLookupError:
                    pass
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                except OSError:
                    failed = True
            if process.stdout:
                process.stdout.close()
        self.processes.clear()
        if self.database_started:
            try:
                status = self.postgres("status")
                failed = (
                    self.postgres("stop") != 0 if status == 0 else status != 3
                ) or failed
            except (OSError, subprocess.SubprocessError, Error):
                failed = True
            self.database_started = False
        for path in self.transient:
            if path.exists() and not path.is_symlink():
                try:
                    private(path).unlink()
                except (OSError, Error):
                    failed = True
        self.transient.clear()
        if self.lock:
            self.lock.close()
            self.lock = None
        for number, handler in self.handlers.items():
            signal.signal(number, handler)
        self.handlers.clear()
        require(
            not failed, "Local service cleanup is incomplete; inspect the owned session"
        )

    def __exit__(self, *_args):
        self.close()
        return False
