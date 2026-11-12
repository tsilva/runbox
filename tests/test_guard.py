import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from runbox.guard import Guard, PolicyError
from tests.support import PROFILE


class GuardTests(unittest.TestCase):
    def test_exact_routes_placeholders_extra_auth_and_failure_latch(self):
        policy = PROFILE["http"]
        headers = {"Authorization": "Bearer " + policy["placeholder"]}
        guard = Guard(policy)
        guard.validate("GET", policy["base-url"] + "/models", headers)
        guard.validate("POST", policy["base-url"] + "/chat/completions", headers)
        for method, url, auth in [
            ("GET", "https://example.com/api/v1/models", headers),
            ("POST", policy["base-url"] + "/keys", headers),
            ("DELETE", policy["base-url"] + "/models", headers),
            ("GET", policy["base-url"] + "/models?token=synthetic", headers),
            ("GET", policy["base-url"] + "/models%2f..%2fkeys", headers),
            ("GET", policy["base-url"] + "/models", {}),
            (
                "GET",
                policy["base-url"] + "/models",
                {"Authorization": "Bearer synthetic-other-key"},
            ),
            ("GET", policy["base-url"] + "/models", {**headers, "Cookie": "synthetic"}),
            (
                "GET",
                policy["base-url"] + "/models",
                {**headers, "X-API-Key": "synthetic"},
            ),
        ]:
            with self.subTest(method=method, url=url), self.assertRaises(PolicyError):
                guard.validate(method, url, auth)
        guard.failed = True
        with self.assertRaises(PolicyError):
            guard.validate("GET", policy["base-url"] + "/models", headers)
        with self.assertRaises(PolicyError):
            Guard(policy).install()

    def test_actual_httpx_transport_hides_error_and_blocks_retry(self):
        try:
            import httpx
        except ImportError:
            self.skipTest("Run transport tests with the reviewed HTTPX runtime")
        self.assertTrue(callable(httpx.Client))
        # Separate process avoids permanently replacing the test runner's HTTP library methods.
        code = """
import os, json, httpx
from runbox.guard import Guard, PolicyError
from tests.support import PROFILE
os.environ.update(PROFILE['environment'])
def response(self, request, **kwargs):
    return httpx.Response(401, text='synthetic-private-provider-key', request=request)
httpx.Client.send = response
guard = Guard(PROFILE['http'])
guard.install()
for attempt in range(2):
    try:
        with httpx.Client(trust_env=False) as client:
            client.get(PROFILE['http']['base-url']+'/models', headers={'Authorization':'Bearer '+PROFILE['http']['placeholder']})
    except PolicyError as error:
        assert 'synthetic-private' not in str(error)
    else:
        raise AssertionError('request allowed')
assert guard.failed
print('sanitized and latched')
"""
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "sanitized and latched")


@unittest.skipUnless(sys.platform == "darwin", "Requires macOS sandbox-exec")
class SandboxTests(unittest.TestCase):
    def test_protected_file_reads_writes_and_process_execution(self):
        policy = Path(__file__).resolve().parents[1] / "runbox/staging.sb"
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            repo = home / "repo"
            staging = repo / ".internal/work"
            staging.mkdir(parents=True)
            values = {
                "USER_HOME": str(home),
                "REPO_ROOT": str(repo),
                "WORKSPACE": str(staging),
                "PYTHON_ROOT": str(Path(sys.executable).resolve().parent.parent),
                "VENV_ROOT": str(Path(sys.prefix)),
                "PYTHON_BIN": sys.executable,
                "PYTHON_REAL": str(Path(sys.executable).resolve()),
                "CA_FILE": str(home / "ca.pem"),
                "RUNBOX_ARCHIVE": str(home / "runbox.pyz"),
                "PROXY": "localhost:8283",
            }
            command = ["/usr/bin/sandbox-exec"]
            for key, value in values.items():
                command += ["-D", key + "=" + value]
            command += ["-f", str(policy), sys.executable, "-I", "-B", "-c"]
            public = repo / "source.txt"
            public.write_text("synthetic public fixture")

            def run(code):
                return subprocess.run(
                    command + [code], capture_output=True, text=True, timeout=10
                )

            result = run(f"print(open({str(public)!r}).read())")
            self.assertEqual(result.returncode, 0, result.stderr)
            for path in [
                repo / p
                for p in (
                    ".env",
                    ".env.local",
                    ".env.production.local",
                    ".netrc",
                    ".access.local.toml",
                    ".git/config",
                )
            ] + [staging / ".env", home / "private-credential"]:
                path.parent.mkdir(exist_ok=True)
                path.write_text("synthetic private fixture")
                with self.subTest(path=path.name):
                    self.assertNotEqual(
                        run(f"print(open({str(path)!r}).read())").returncode, 0
                    )
            self.assertNotEqual(
                run(f"open({str(public)!r}, 'w').write('changed')").returncode, 0
            )
            self.assertEqual(
                run(
                    f"open({str(staging / 'output')!r}, 'w').write('allowed')"
                ).returncode,
                0,
            )
            self.assertNotEqual(
                run(
                    "import subprocess; subprocess.run(['/bin/echo','forbidden'],check=True)"
                ).returncode,
                0,
            )
            self.assertNotEqual(
                run(
                    "import socket; socket.create_connection(('127.0.0.1',8082),timeout=1)"
                ).returncode,
                0,
            )
