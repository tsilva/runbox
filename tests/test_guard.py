import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from runbox.guard import Guard, PolicyError
from tests.support import PROFILE


class GuardTests(unittest.TestCase):
    def test_installed_httpx_variants_keep_sync_and_async_restrictions(self):
        import importlib.util

        libraries = [name for name in ("httpx", "httpx2")
                     if importlib.util.find_spec(name) is not None]
        if not libraries:
            self.skipTest("Requires a reviewed HTTPX runtime")
        code = """
import asyncio, importlib, os, sys
from runbox.guard import Guard, PolicyError
from tests.support import PROFILE
httpx = importlib.import_module(sys.argv[1])
os.environ.update(PROFILE['environment'])
calls = []
def send(client, request, **kwargs):
    calls.append(str(request.url))
    assert kwargs['follow_redirects'] is False
    return httpx.Response(200, json={'ok': True}, request=request)
async def async_send(client, request, **kwargs):
    assert kwargs['follow_redirects'] is False
    return httpx.Response(401, text='synthetic-private-provider-key', request=request)
httpx.Client.send, httpx.AsyncClient.send = send, async_send
guard = Guard(PROFILE['http'])
guard.install()
target = PROFILE['http']['base-url'] + '/models'
headers = {'Authorization': 'Bearer ' + PROFILE['http']['placeholder']}
with httpx.Client(trust_env=False) as client:
    assert client.get(target, headers=headers).json() == {'ok': True}
    try:
        client.get(target, headers={})
    except PolicyError:
        pass
    else:
        raise AssertionError('Missing placeholder accepted')
assert len(calls) == 1
async def check():
    async with httpx.AsyncClient(trust_env=False) as client:
        for _ in range(2):
            try:
                await client.get(target, headers=headers)
            except PolicyError as error:
                assert 'synthetic-private' not in str(error)
            else:
                raise AssertionError('Provider rejection accepted')
asyncio.run(check())
assert guard.failed
print('sync and async guarded')
"""
        for library in libraries:
            with self.subTest(library=library):
                result = subprocess.run(
                    [sys.executable, "-B", "-c", code, library],
                    cwd=Path(__file__).resolve().parents[1],
                    capture_output=True, text=True, timeout=20, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "sync and async guarded")

    def test_exact_queries_are_preserved_and_unreviewed_queries_rejected(self):
        from copy import deepcopy

        policy = deepcopy(PROFILE["http"])
        policy["routes"].append(
            {
                "method": "GET",
                "path": "/api/v1/openrouter/models",
                "queries": [
                    "",
                    "output_modalities=image",
                    "output_modalities=embeddings",
                ],
                "forward-host": "localhost:8082",
            }
        )
        guard = Guard(policy)
        headers = {"Authorization": "Bearer " + policy["placeholder"]}
        url = policy["base-url"] + "/openrouter/models?output_modalities=image"
        self.assertEqual(
            guard.validate("GET", url, headers), url.replace("127.0.0.1", "localhost")
        )
        with self.assertRaises(PolicyError):
            guard.validate("GET", url + "&token=synthetic", headers)

    def test_metadata_route_template_and_loopback_alias_are_get_only(self):
        from copy import deepcopy

        policy = deepcopy(PROFILE["http"])
        policy["routes"].append(
            {
                "method": "GET",
                "path": "/api/v1/openrouter/models/{segment}/{segment}/endpoints",
                "forward-host": "localhost:8082",
            }
        )
        guard = Guard(policy)
        headers = {"Authorization": "Bearer " + policy["placeholder"]}
        url = policy["base-url"] + "/openrouter/models/example/model-v1/endpoints"
        self.assertEqual(
            guard.validate("GET", url, headers), url.replace("127.0.0.1", "localhost")
        )
        for method, target in (
            ("POST", url),
            ("GET", url + "/extra"),
            ("GET", url.replace("model-v1", "..")),
        ):
            with self.assertRaises(PolicyError):
                guard.validate(method, target, headers)

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
            ("GET", policy["base-url"] + "/models", {**headers, "Proxy-Authorization": "synthetic"}),
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
