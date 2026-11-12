#!/usr/bin/env python3
"""Exercise the packaged runner and real Repologogen client using only synthetic local traffic."""

import argparse
import hashlib
import http.server
import json
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo",
        required=True,
        type=Path,
        help="Local Repologogen checkout, copied read-only",
    )
    parser.add_argument(
        "--python",
        required=True,
        type=Path,
        help="Its reviewed persistent Python environment",
    )
    parser.add_argument(
        "--build", type=Path, default=Path(__file__).resolve().parents[1] / "dist"
    )
    opts = parser.parse_args()
    if sys.platform != "darwin":
        raise SystemExit("This pilot requires macOS sandbox-exec")
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from tests.support import config

    requests = []
    state = {"error": False}

    class Proxy(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def answer(self):
            requests.append(
                (self.command, self.path, self.headers.get("Authorization"))
            )
            if self.command == "POST":
                body = json.loads(
                    self.rfile.read(int(self.headers.get("Content-Length", "0")))
                )
                assert "synthetic" in json.dumps(body).lower()
            body = (
                {"error": "synthetic-private-provider-key"}
                if state["error"]
                else {
                    "data": [{"id": "synthetic-model"}],
                    "choices": [{"message": {"content": "Synthetic client response"}}],
                }
            )
            data = json.dumps(body).encode()
            self.send_response(401 if state["error"] else 200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        do_GET = answer
        do_POST = answer

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="runbox-fake-pilot-") as temporary:
            base = Path(temporary).resolve()
            home = base / "home"
            home.mkdir()
            (home / "synthetic-credential").write_text("synthetic protected fixture")
            root = home / "repo"
            (root / "src").mkdir(parents=True)
            shutil.copytree(
                opts.repo.resolve() / "src/repologogen",
                root / "src/repologogen",
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
            for name in ("pyproject.toml", "uv.lock"):
                shutil.copyfile(opts.repo / name, root / name)
            (root / "src/repologogen/fakecheck.py").write_text("""
import os, sys, socket, subprocess
import httpx
from pathlib import Path
from repologogen.generator import digest_readme
from runbox.guard import PolicyError

def main():
    mode = sys.argv[1]
    if mode == 'actual':
        assert digest_readme('# Synthetic project', api_key=os.environ['EXAMPLE_API_KEY']) == 'Synthetic client response'
    elif mode == 'return-seven':
        return 7
    elif mode == 'error':
        assert digest_readme('# Synthetic project', api_key=os.environ['EXAMPLE_API_KEY']) == ''
        try:
            httpx.get(os.environ['EXAMPLE_BASE_URL']+'/models',headers={'Authorization':'Bearer '+os.environ['EXAMPLE_API_KEY']})
        except PolicyError as error:
            assert 'synthetic-private' not in str(error)
        else:
            raise AssertionError('failure latch bypassed')
    elif mode in ('bad-route', 'bad-credential'):
        path = '/keys' if mode == 'bad-route' else '/models'
        marker = 'synthetic-unreviewed-key' if mode == 'bad-credential' else os.environ['EXAMPLE_API_KEY']
        try:
            httpx.get(os.environ['EXAMPLE_BASE_URL']+path,headers={'Authorization':'Bearer '+marker})
        except PolicyError:
            pass
        else:
            raise AssertionError('guard bypassed')
    elif mode == 'direct':
        try:
            socket.create_connection(('127.0.0.1',8082),timeout=1)
        except PermissionError:
            pass
        else:
            raise AssertionError('direct egress allowed')
    elif mode == 'read-secret':
        path = Path(__file__).parents[3]/'synthetic-credential'
        try:
            path.read_text()
        except PermissionError:
            pass
        else:
            raise AssertionError('credential read allowed')
    elif mode == 'spawn':
        try:
            subprocess.run(['/bin/echo','forbidden'],check=True)
        except PermissionError:
            pass
        else:
            raise AssertionError('helper execution allowed')
    print('synthetic check passed')
""")
            value = config()
            profile = value["profiles"]["dev"]
            profile["session"]["proxy"] = f"127.0.0.1:{server.server_port}"
            profile["environment"]["AGENTBRIDGE_BASE_URL"] = profile["http"]["base-url"]
            profile["execution"]["python"] = {
                "source": "src",
                "package": "repologogen",
                "command": "repologogen",
                "entrypoint": "repologogen.fakecheck:main",
            }
            (root / ".runbox.yaml").write_text(json.dumps(value))
            # A repository writer must not bypass source approval using a matching .pyc.
            import importlib._bootstrap_external
            import importlib.util

            source = root / "src/repologogen/fakecheck.py"
            cache = Path(importlib.util.cache_from_source(str(source)))
            cache.parent.mkdir(exist_ok=True)
            cache.write_bytes(
                importlib._bootstrap_external._code_to_timestamp_pyc(
                    compile(
                        "raise RuntimeError('unreviewed bytecode loaded')",
                        str(source),
                        "exec",
                    ),
                    int(source.stat().st_mtime),
                    source.stat().st_size,
                )
            )
            release = base / "release"
            release.mkdir()
            for name in ("runbox.pyz", "staging.sb"):
                shutil.copyfile(opts.build / name, release / name)
            ca = base / "ca.pem"
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
                    "/CN=Runbox synthetic pilot",
                    "-keyout",
                    str(base / "test.key"),
                    "-out",
                    str(ca),
                ],
                check=True,
                capture_output=True,
            )
            fingerprint = "SHA256:" + ":".join(
                f"{b:02X}"
                for b in hashlib.sha256(
                    ssl.PEM_cert_to_DER_cert(ca.read_text())
                ).digest()
            )
            fake = base / "infisical"
            fake.write_text(
                "#!"
                + str(opts.python)
                + "\n"
                + """
import os, subprocess, sys
from pathlib import Path
args = sys.argv[1:]
assert args[:2] == ['agent-vault','run']
assert '--no-ca-trust' in args and '--no-skills' in args and '--ttl=30m' in args
assert '--domain=https://app.infisical.com' in args
assert '--project-id=11111111-1111-4111-8111-111111111111' in args
assert '--access-bundle=example-read' in args
proxy = next(a.split('=',1)[1] for a in args if a.startswith('--proxy='))
env = dict(os.environ, HTTP_PROXY='http://synthetic:session@'+proxy, HTTPS_PROXY='http://synthetic:session@'+proxy)
try:
    result = subprocess.run(args[args.index('--')+1:],env=env)
finally:
    (Path(__file__).parent/'fake-session-closed').write_text('closed')
raise SystemExit(result.returncode)
"""
            )
            fake.chmod(0o700)
            runtime = {
                "infisical": str(fake),
                "ca-file": str(ca),
                "ca-fingerprint": fingerprint,
                "python": str(opts.python),
                "venv": str(opts.python.parent.parent),
                "python-root": str(opts.python.resolve().parent.parent),
            }
            runtime_file = base / "runtime.json"
            runtime_file.write_text(json.dumps(runtime))
            runtime_file.chmod(0o600)
            prefix = [
                str(opts.python),
                "-I",
                "-B",
                str(release / "runbox.pyz"),
                "--repo",
                str(root),
            ]
            env = {"HOME": str(home), "PATH": "/usr/bin:/bin"}

            def run(args, status=0):
                result = subprocess.run(
                    prefix + args, env=env, capture_output=True, text=True, timeout=30
                )
                if result.returncode != status:
                    raise AssertionError(
                        f"Synthetic pilot failed: {args[0]} (exit {result.returncode})\n{result.stdout}\n{result.stderr}"
                    )
                assert "synthetic-private" not in result.stdout + result.stderr
                return result

            run(["approve", "--runtime", str(runtime_file)])
            run(["check"])
            run(["check", "--online"])
            assert requests[-1][:2] == ("GET", profile["http"]["base-url"] + "/models")
            run(["run", "--", "repologogen", "actual"])
            assert requests[-1][:2] == (
                "POST",
                profile["http"]["base-url"] + "/chat/completions",
            )
            assert all(r[2] == "Bearer example_public_placeholder" for r in requests)
            count = len(requests)
            for mode in (
                "bad-route",
                "bad-credential",
                "direct",
                "read-secret",
                "spawn",
            ):
                run(["run", "--", "repologogen", mode])
            assert len(requests) == count
            run(["run", "--", "repologogen", "return-seven"], status=7)
            state["error"] = True
            run(["run", "--", "repologogen", "error"])
            assert len(requests) == count + 1
            assert (base / "fake-session-closed").read_text() == "closed"
            # Exercise a generic command under an explicitly unsandboxed profile too.
            profile["execution"] = {"sandbox": "none"}
            profile.pop("http")
            (root / ".runbox.yaml").write_text(json.dumps(value))
            run(["approve", "--runtime", str(runtime_file)])
            result = run(["run", "--", "/bin/echo", "argument with spaces"])
            assert result.stdout.strip() == "argument with spaces"
            print(
                "Packaged fake pilot passed: actual HTTPX client, catalog GET, placeholders, denied routes/credentials,"
            )
            print(
                "sandbox file/network/helper denials, sanitized failure latch, exit status and generic command argv."
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    main()
