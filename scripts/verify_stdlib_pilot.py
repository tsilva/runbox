#!/usr/bin/env python3
"""Exercise shared Python checks and actual domain code with a synthetic TLS proxy."""

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
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", type=Path, required=True)
    p.add_argument("--config", type=Path, required=True)
    p.add_argument("--runtime", type=Path, required=True)
    p.add_argument(
        "--build", type=Path, default=Path(__file__).resolve().parents[1] / "dist"
    )
    o = p.parse_args()
    document = yaml.safe_load(o.config.read_text())
    runtime = json.loads(o.runtime.read_text())
    state = {"bad": False, "calls": 0}
    with tempfile.TemporaryDirectory(prefix="runbox-stdlib-") as temporary:
        base = Path(temporary).resolve()
        home = base / "home"
        home.mkdir()
        root = home / "repo"
        root.mkdir()
        release = base / "release"
        shutil.copytree(o.build, release)
        ca = base / "ca.pem"
        key = base / "synthetic.key"
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
                "/CN=Runbox synthetic TLS",
                "-addext",
                "subjectAltName=DNS:huggingface.co,DNS:api.cloudflare.com",
                "-keyout",
                str(key),
                "-out",
                str(ca),
            ],
            check=True,
            capture_output=True,
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(ca, key)

        class Proxy(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_CONNECT(self):
                assert self.path in ("huggingface.co:443", "api.cloudflare.com:443")
                assert self.headers.get("Proxy-Authorization")
                self.send_response(200)
                self.end_headers()
                self.wfile.flush()
                connection = context.wrap_socket(self.connection, server_side=True)
                with connection.makefile("rb") as stream:
                    method, path, _ = stream.readline().decode().split()
                    headers = http.client.parse_headers(stream)
                assert method == "GET"
                assert headers.get("Authorization", "").endswith("_placeholder")
                state["calls"] += 1
                if self.path == "huggingface.co:443":
                    assert path == "/api/whoami-v2"
                    body = {
                        "name": "wrong" if state["bad"] else "tsilva",
                        "private": "synthetic-private-never-output",
                    }
                elif path.endswith("/user/tokens/verify"):
                    body = {"success": True, "result": {"status": "active"}}
                elif path.endswith("/subscriptions"):
                    body = {
                        "success": True,
                        "result": [
                            {"state": "Active", "price": 0, "rate_plan": {"id": "free"}}
                        ],
                    }
                elif path.endswith("/secrets"):
                    body = {
                        "success": True,
                        "result": [
                            {"name": n, "type": "secret_text"}
                            for n in (
                                "GITHUB_APP_ID",
                                "GITHUB_INSTALLATION_ID",
                                "GITHUB_APP_PRIVATE_KEY",
                                "INFISICAL_WEBHOOK_SIGNING_KEYS",
                            )
                        ],
                    }
                else:
                    raise AssertionError("unexpected route")
                data = json.dumps(body).encode()
                connection.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "
                    + str(len(data)).encode()
                    + b"\r\n\r\n"
                    + data
                )
                connection.close()
                self.close_connection = True

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            selected = document["profiles"]["read"]
            selected["session"]["proxy"] = "127.0.0.1:" + str(server.server_port)
            document["profiles"] = {"read": selected}
            document["default"] = "read"
            for file in selected["execution"]["integrity"]["files"]:
                target = root / file
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(o.repo / file, target)
                if file == "scripts/deploy.py":
                    target.write_text(
                        target.read_text().replace(
                            "url.port == 8283", "url.port == " + str(server.server_port)
                        )
                    )
            config = root / ".runbox.yaml"
            config.write_text(yaml.safe_dump(document, sort_keys=False))
            fake = base / "infisical"
            fake.write_text(
                "#!"
                + sys.executable
                + "\n"
                + """import os,subprocess,sys
args=sys.argv[1:]
assert args[:2]==['agent-vault','run']
assert '--no-skills' in args and '--no-ca-trust' in args
proxy=next(a.split('=',1)[1] for a in args if a.startswith('--proxy='))
env=dict(os.environ,HTTP_PROXY='http://synthetic:agv_fake@'+proxy,HTTPS_PROXY='http://synthetic:agv_fake@'+proxy)
raise SystemExit(subprocess.call(args[args.index('--')+1:],env=env))
"""
            )
            fake.chmod(0o700)
            runtime.update(
                infisical=str(fake),
                **{
                    "ca-file": str(ca),
                    "ca-fingerprint": "SHA256:"
                    + ":".join(
                        f"{b:02X}"
                        for b in hashlib.sha256(
                            ssl.PEM_cert_to_DER_cert(ca.read_text())
                        ).digest()
                    ),
                },
            )
            runtimefile = base / "runtime.json"
            runtimefile.write_text(json.dumps(runtime))
            runtimefile.chmod(0o600)
            prefix = [
                sys.executable,
                "-I",
                "-S",
                "-B",
                str(release / "runbox.pyz"),
                "--repo",
                str(root),
            ]

            def run(args, status=0):
                result = subprocess.run(
                    prefix + args,
                    env={"HOME": str(home), "PATH": "/usr/bin:/bin"},
                    capture_output=True,
                    text=True,
                    timeout=35,
                )
                if result.returncode != status and args == ["check", "--online"]:
                    command = selected["execution"]
                    diagnostic = subprocess.run(
                        prefix
                        + ["run", "--", command["command"], *command["arguments"][0]],
                        env={"HOME": str(home), "PATH": "/usr/bin:/bin"},
                        capture_output=True,
                        text=True,
                        timeout=35,
                    )
                    raise AssertionError(
                        (
                            args,
                            result.stdout,
                            result.stderr,
                            diagnostic.stdout,
                            diagnostic.stderr,
                        )
                    )
                if result.returncode != status:
                    diagnostic = subprocess.run(
                        [
                            sys.executable,
                            "-I",
                            "-S",
                            "-c",
                            "import sys;sys.path.insert(0,sys.argv[1]);sys.argv=sys.argv[1:];from runbox.__main__ import main;main()",
                            str(release / "runbox.pyz"),
                            "--repo",
                            str(root),
                            *args,
                        ],
                        env={"HOME": str(home), "PATH": "/usr/bin:/bin"},
                        capture_output=True,
                        text=True,
                        timeout=35,
                    )
                    raise AssertionError(
                        (args, result.stdout, result.stderr, diagnostic.stderr)
                    )
                assert "synthetic-private" not in result.stdout + result.stderr
                return result

            run(["approve", "--runtime", str(runtimefile)])
            run(["check"])
            result = run(["check", "--online"])
            assert "public-placeholder" in result.stdout
            assert state["calls"] == (1 if o.repo.name == "scummhd" else 3)
            before = state["calls"]
            run(["run", "--", selected["execution"]["command"], "unreviewed"], 1)
            assert state["calls"] == before
            if o.repo.name == "scummhd":
                state["bad"] = True
                run(["check", "--online"], 1)
            else:
                (root / "scripts/deploy.py").write_text('raise RuntimeError("drift")')
                run(["check", "--online"], 1)
                assert state["calls"] == before
            print(
                "Packaged shared Python pilot passed for "
                + o.repo.name
                + ": TLS proxy, placeholder, actual read-only checks, rejection and output sanitation."
            )
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
