#!/usr/bin/env python3
"""Verify packaged Node access against synthetic local traffic and actual app adapters."""

import argparse
import hashlib
import http.client
import http.server
import json
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

import yaml


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument(
        "--build", type=Path, default=Path(__file__).resolve().parents[1] / "dist"
    )
    opts = parser.parse_args()
    document = yaml.safe_load(opts.config.read_text())
    machine = json.loads(opts.runtime.read_text())
    calls = []
    model_ids = {
        p["execution"]
        .get("client", {})
        .get("expected-model", "openrouter/deepseek/deepseek-v4.1-flash-1017")
        for p in document["profiles"].values()
    }

    class Proxy(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def do_GET(self):
            calls.append((self.command, self.path, self.headers.get("Authorization")))
            data = json.dumps(
                {"data": [{"id": name} for name in sorted(model_ids)]}
            ).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(data)

        def do_CONNECT(self):
            authority = self.path
            assert authority in ("127.0.0.1:8082", "localhost:8082")
            self.send_response(200)
            self.end_headers()
            self.wfile.flush()
            method, path, _protocol = (
                self.rfile.readline().decode().strip().split(" ", 2)
            )
            headers = http.client.parse_headers(self.rfile)
            assert method == "GET"
            calls.append(
                (method, "http://" + authority + path, headers.get("Authorization"))
            )
            data = json.dumps(
                {"data": [{"id": name} for name in sorted(model_ids)]}
            ).encode()
            self.wfile.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                + str(len(data)).encode()
                + b"\r\nConnection: close\r\n\r\n"
                + data
            )
            self.wfile.flush()
            self.close_connection = True

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="runbox-node-pilot-") as temporary:
            base = Path(temporary).resolve()
            home = base / "home"
            home.mkdir()
            root = home / "repo"
            root.mkdir()
            release = base / "release"
            shutil.copytree(opts.build, release)
            files = set()
            for profile in document["profiles"].values():
                files.update(profile["execution"]["integrity"]["files"])
            for name in files:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(opts.repo / name, target)
            for profile in document["profiles"].values():
                script = profile["execution"].get("client", {}).get("script")
                if script:
                    (root / script).write_text(
                        "import assert from 'node:assert/strict';\nassert.deepEqual(process.argv.slice(2),['--port','auto']);\nconsole.log('synthetic script entrypoint passed');\n"
                    )
            ca = base / "public-ca.pem"
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
                    "/CN=Runbox synthetic Node pilot",
                    "-keyout",
                    str(base / "synthetic.key"),
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
                + sys.executable
                + " -I\n"
                + """import os,subprocess,sys
args=sys.argv[1:]
assert args[:2]==['agent-vault','run']
assert '--no-ca-trust' in args and '--no-skills' in args
assert '--domain=https://app.infisical.com' in args
assert '--project-id=5078c850-3f93-46d8-8afe-82107df8b931' in args
proxy=next(arg.split('=',1)[1] for arg in args if arg.startswith('--proxy='))
env=dict(os.environ,HTTP_PROXY='http://synthetic:session@'+proxy,HTTPS_PROXY='http://synthetic:session@'+proxy)
result=subprocess.run(args[args.index('--')+1:],env=env)
print('session revoked')
raise SystemExit(result.returncode)
"""
            )
            fake.chmod(0o700)
            machine.update(
                {
                    "infisical": str(fake),
                    "ca-file": str(ca),
                    "ca-fingerprint": fingerprint,
                }
            )
            runtime = base / "runtime.json"
            runtime.write_text(json.dumps(machine))
            runtime.chmod(0o600)
            for profile in document["profiles"].values():
                profile["session"]["proxy"] = "127.0.0.1:" + str(server.server_port)
            (root / ".runbox.yaml").write_text(
                yaml.safe_dump(json.loads(json.dumps(document)), sort_keys=False)
            )
            prefix = [
                sys.executable,
                "-I",
                "-B",
                str(release / "runbox.pyz"),
                "--repo",
                str(root),
            ]
            env = {"HOME": str(home), "PATH": "/usr/bin:/bin"}
            for name, profile in document["profiles"].items():
                selected = prefix + ["--profile", name]
                for command in (
                    ["approve", "--runtime", str(runtime)],
                    ["check"],
                    ["check", "--online"],
                ):
                    result = subprocess.run(
                        selected + command,
                        env=env,
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                    if result.returncode:
                        raise AssertionError(
                            f"Synthetic Node profile failed: {name} {command[0]}\n{result.stdout}\n{result.stderr}"
                        )
                marker = profile["http"]["placeholder"]
                assert calls[-1][2] == "Bearer " + marker
                assert calls[-1][1] == profile["http"]["base-url"] + "/models"
                # Exercise real source/runtime drift rejection before authentication.
                before = len(calls)
                adapter = root / profile["execution"]["client"]["adapter"]
                content = adapter.read_bytes()
                adapter.write_bytes(content + b"\n// synthetic unreviewed change\n")
                result = subprocess.run(
                    selected + ["check", "--online"],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                assert result.returncode != 0 and len(calls) == before
                adapter.write_bytes(content)
                if profile["execution"].get("client", {}).get("script"):
                    supplied = profile["execution"]["arguments"][0]
                    result = subprocess.run(
                        prefix
                        + ["run", "--", profile["execution"]["command"], *supplied],
                        env=env,
                        capture_output=True,
                        text=True,
                        timeout=20,
                    )
                    if (
                        result.returncode
                        or "synthetic script entrypoint passed" not in result.stdout
                    ):
                        raise AssertionError(
                            "Synthetic script entrypoint/automatic profile selection failed: "
                            + result.stderr
                        )
            print(
                f"Packaged Node fake pilot passed for {opts.repo.name}: {len(document['profiles'])} profiles, actual app adapters, scoped proxy/placeholder requests and pre-authentication source-drift denial."
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    main()
