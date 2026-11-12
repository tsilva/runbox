"""Compose a clean native session and optional built-in sandbox."""

import base64
import json
import os
import signal
import subprocess
import sys
from pathlib import Path

from .config import Error, require
from .providers import PROVIDERS


def workspace(root, execution, override=None):
    allowed = root / execution["workspace"]
    path = Path(override).absolute() if override else allowed
    require(
        (path == allowed or path.is_relative_to(allowed)) and path.resolve() == path,
        "Use only the approved canonical staging workspace",
    )
    require(
        path != root and path.is_relative_to(root / ".internal"),
        "Invalid staging workspace",
    )
    # Create only the declared staging directory; do not follow an existing symlink.
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    require(path.resolve() == path and path.is_dir(), "Invalid staging workspace")
    home = path / "home"
    require(not home.is_symlink(), "Staging home cannot be a symlink")
    home.mkdir(mode=0o700, exist_ok=True)
    return path


def command(root, profile, runtime, archive, mode, arguments, staging=None):
    execution = profile["execution"]
    sandbox = []
    if execution["sandbox"] == "macos-staging":
        require(
            sys.platform == "darwin" and Path("/usr/bin/sandbox-exec").is_file(),
            "Required macOS staging sandbox is unavailable",
        )
        require(
            mode == "probe"
            or (arguments and arguments[0] == execution["python"]["command"]),
            "Only the reviewed Python command is allowed",
        )
        cwd = workspace(root, execution, staging)
        home = str(cwd / "home")
        sandbox = ["/usr/bin/sandbox-exec"]
        values = {
            "USER_HOME": str(Path.home()),
            "REPO_ROOT": str(root),
            "WORKSPACE": str(cwd),
            "PYTHON_ROOT": runtime["python-root"],
            "VENV_ROOT": runtime["venv"],
            "PYTHON_BIN": runtime["python"],
            "PYTHON_REAL": str(Path(runtime["python"]).resolve()),
            "CA_FILE": runtime["ca-file"],
            "RUNBOX_ARCHIVE": str(archive),
            "PROXY": "localhost:" + profile["session"]["proxy"].rsplit(":", 1)[1],
        }
        for key, value in values.items():
            sandbox += ["-D", key + "=" + value]
        sandbox += ["-f", str(archive.with_name("staging.sb"))]
        python = runtime["python"]
    else:
        require(not staging, "Workspace override requires a staging profile")
        require(
            mode == "run" and arguments, "Online probe requires a Python HTTP profile"
        )
        cwd, home, python = root, str(Path.home()), sys.executable
    payload = {
        "root": str(root),
        "profile": profile,
        "runtime": runtime,
        "home": home,
        "mode": mode,
    }
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    child = [
        "/usr/bin/env",
        "HOME=" + home,
        "NO_PROXY=",
        "no_proxy=",
        "SSL_CERT_FILE=" + runtime["ca-file"],
        "REQUESTS_CA_BUNDLE=" + runtime["ca-file"],
        "PYTHONDONTWRITEBYTECODE=1",
        "HF_HUB_DISABLE_IMPLICIT_TOKEN=1",
        *(key + "=" + value for key, value in profile["environment"].items()),
        *sandbox,
        python,
        "-I",
        "-B",
        str(archive),
        "--child",
        encoded,
        *arguments,
    ]
    return PROVIDERS[profile["provider"]["type"]].command(profile, runtime, child), cwd


def execute(argv, cwd, probe=False):
    env = {
        "HOME": str(Path.home()),
        "PATH": "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
    }
    # Native CLI owns session revocation; forward cancellation and allow its cleanup to finish.
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        start_new_session=True,
        stdout=subprocess.PIPE if probe else None,
        stderr=subprocess.PIPE if probe else None,
    )
    previous = {}

    def forward(number, _frame):
        if process.poll() is None:
            try:
                os.killpg(process.pid, number)
            except ProcessLookupError:
                pass

    try:
        for number in (signal.SIGINT, signal.SIGTERM):
            previous[number] = signal.signal(number, forward)
        if probe:
            try:
                stdout, _ = process.communicate(timeout=65)
            except subprocess.TimeoutExpired:
                forward(signal.SIGTERM, None)
                try:
                    process.communicate(timeout=15)
                except subprocess.TimeoutExpired:
                    forward(signal.SIGKILL, None)
                    process.communicate()
                    raise Error(
                        "Unresponsive session stopped; immediate revocation unverified; TTL still applies"
                    ) from None
                raise Error(
                    "Online check timed out; provider diagnostics withheld"
                ) from None
            records = []
            for line in stdout.splitlines():
                try:
                    item = json.loads(line)
                except (ValueError, UnicodeError):
                    continue
                if (
                    type(item) is dict
                    and set(item)
                    == {"ok", "read_only", "credential_mode", "model_count"}
                    and item["ok"] is True
                    and item["read_only"] is True
                    and item["credential_mode"] == "public-placeholder"
                    and type(item["model_count"]) is int
                ):
                    records.append(item)
            require(
                process.returncode == 0 and len(records) == 1,
                "Online check failed; renew login or review the route; provider diagnostics withheld",
            )
            print(json.dumps(records[0]))
        else:
            process.wait()
        return (
            process.returncode if process.returncode >= 0 else 128 - process.returncode
        )
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
