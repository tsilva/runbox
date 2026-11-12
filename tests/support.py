import copy
import json
import subprocess


PROFILE = {
    "provider": {
        "type": "infisical",
        "instance": "https://app.infisical.com",
        "project-id": "11111111-1111-4111-8111-111111111111",
        "access-bundle": "example-read",
        "source": {
            "project-id": "22222222-2222-4222-8222-222222222222",
            "environment": "dev",
            "secret-path": "/agents/example",
        },
    },
    "session": {"ttl": "30m", "proxy": "127.0.0.1:8283"},
    "environment": {
        "EXAMPLE_API_KEY": "example_public_placeholder",
        "EXAMPLE_BASE_URL": "http://127.0.0.1:8082/api/v1",
    },
    "execution": {
        "sandbox": "macos-staging",
        "workspace": ".internal/agent-vault/work",
        "python": {
            "source": "src",
            "package": "example",
            "command": "example",
            "entrypoint": "example.cli:main",
        },
    },
    "http": {
        "base-url": "http://127.0.0.1:8082/api/v1",
        "credential-variable": "EXAMPLE_API_KEY",
        "placeholder": "example_public_placeholder",
        "routes": [
            {"method": "GET", "path": "/api/v1/models"},
            {"method": "POST", "path": "/api/v1/chat/completions"},
        ],
        "probe": "/api/v1/models",
    },
}


def config():
    return {"version": 1, "default": "dev", "profiles": {"dev": copy.deepcopy(PROFILE)}}


def fixture(directory):
    root = directory / "repo"
    package = root / "src/example"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (package / "cli.py").write_text("def main():\n    return 7\n")
    (root / "pyproject.toml").write_text("[project]\nname='example'\n")
    (root / "uv.lock").write_text("version=1\n")
    (root / ".runbox.yaml").write_text(json.dumps(config()))
    runtime = directory / "runtime"
    runtime.mkdir()
    cli = runtime / "infisical"
    cli.write_text("synthetic CLI\n")
    python_root = runtime / "python"
    (python_root / "bin").mkdir(parents=True)
    real = python_root / "bin/python3"
    real.write_text("synthetic Python\n")
    venv = runtime / "venv"
    (venv / "bin").mkdir(parents=True)
    (venv / "bin/python").symlink_to(real)
    ca = runtime / "ca.pem"
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
            "/CN=Runbox synthetic test",
            "-keyout",
            str(runtime / "test.key"),
            "-out",
            str(ca),
        ],
        check=True,
        capture_output=True,
    )
    import ssl
    import hashlib

    fingerprint = "SHA256:" + ":".join(
        f"{b:02X}"
        for b in hashlib.sha256(ssl.PEM_cert_to_DER_cert(ca.read_text())).digest()
    )
    values = {
        "python": str(venv / "bin/python"),
        "python-root": str(python_root),
        "venv": str(venv),
        "infisical": str(cli),
        "ca-file": str(ca),
        "ca-fingerprint": fingerprint,
    }
    archive = directory / "release/runbox.pyz"
    archive.parent.mkdir()
    archive.write_text("synthetic reviewed archive")
    archive.with_name("staging.sb").write_text("synthetic sandbox")
    return root, values, archive
