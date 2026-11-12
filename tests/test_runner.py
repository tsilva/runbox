import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from runbox.child import environment, main
from runbox.config import Error
from runbox.providers import Infisical
from runbox.runner import command, execute, workspace
from tests.support import PROFILE, fixture


class RunnerTests(unittest.TestCase):
    def test_termination_waits_for_native_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            native = directory / "fake-native.py"
            ready, closed = directory / "ready", directory / "closed"
            native.write_text(
                "import signal,time\nfrom pathlib import Path\n"
                f"closed=Path({str(closed)!r})\n"
                "def stop(number, frame):\n"
                "    closed.write_text('cleanup complete')\n"
                "    raise SystemExit(128+number)\n"
                "signal.signal(signal.SIGTERM,stop)\n"
                f"Path({str(ready)!r}).write_text('ready')\n"
                "while True: time.sleep(1)\n"
            )
            code = (
                "from runbox.runner import execute\n"
                f"raise SystemExit(execute({[sys.executable, str(native)]!r}, {str(directory)!r}))\n"
            )
            process = subprocess.Popen(
                [sys.executable, "-c", code],
                cwd=Path(__file__).resolve().parents[1],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                deadline = time.monotonic() + 5
                while (
                    not ready.exists()
                    and time.monotonic() < deadline
                    and process.poll() is None
                ):
                    time.sleep(0.01)
                self.assertTrue(
                    ready.exists(), "Synthetic native session did not become ready"
                )
                process.send_signal(signal.SIGTERM)
                process.communicate(timeout=5)
                self.assertEqual(process.returncode, 143)
                self.assertEqual(closed.read_text(), "cleanup complete")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()

    def test_native_translation_distinguishes_source_from_vault(self):
        argv = Infisical.command(
            PROFILE,
            {"infisical": "/trusted/infisical", "ca-fingerprint": "SHA256:fixture"},
            ["client", "arg with spaces"],
        )
        self.assertIn("--project-id=" + PROFILE["provider"]["project-id"], argv)
        self.assertNotIn(
            "--project-id=" + PROFILE["provider"]["source"]["project-id"], argv
        )
        self.assertIn("--domain=https://app.infisical.com", argv)
        for flag in ("--no-skills", "--no-ca-trust", "--ttl=30m"):
            self.assertIn(flag, argv)
        self.assertEqual(argv[-2:], ["client", "arg with spaces"])
        native = Infisical.native_config(PROFILE)
        self.assertEqual(native["secrets-management"], PROFILE["provider"]["source"])

    def test_workspace_and_command_cannot_broaden_sandbox(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, runtime, archive = fixture(Path(temporary).resolve())
            selected = workspace(root, PROFILE["execution"])
            with self.assertRaises(Error):
                workspace(root, PROFILE["execution"], str(root))
            link = selected / "escape"
            link.symlink_to(root)
            with self.assertRaises(Error):
                workspace(root, PROFILE["execution"], str(link))
            with (
                patch("sys.platform", "darwin"),
                patch("pathlib.Path.is_file", return_value=True),
            ):
                with self.assertRaises(Error):
                    command(
                        root,
                        PROFILE,
                        runtime,
                        archive,
                        "run",
                        ["sh", "-c", "echo unreviewed"],
                    )
                argv, cwd = command(
                    root, PROFILE, runtime, archive, "run", ["example", "--help"]
                )
            self.assertIn("/usr/bin/sandbox-exec", argv)
            self.assertEqual(cwd, selected)

    def test_clean_child_environment_rejects_missing_placeholder_and_proxy(self):
        runtime = {"ca-file": "/public/ca.pem"}
        good = {
            **PROFILE["environment"],
            "HTTP_PROXY": "http://synthetic:session@127.0.0.1:8283",
            "NO_PROXY": "",
            "no_proxy": "",
            "LEAKED_API_KEY": "synthetic-private-fixture",
        }
        with patch.dict(os.environ, good, clear=True):
            environment(PROFILE, runtime, "/staging/home")
            self.assertNotIn("LEAKED_API_KEY", os.environ)
        for key, replacement in (
            ("HTTP_PROXY", "http://other:session@127.0.0.1:9999"),
            ("EXAMPLE_API_KEY", "wrong"),
            ("NO_PROXY", "*"),
        ):
            with (
                patch.dict(os.environ, {**good, key: replacement}, clear=True),
                self.assertRaises(Error),
            ):
                environment(PROFILE, runtime, "/staging/home")

    def test_entrypoint_preserves_return_value_and_system_exit(self):
        from types import SimpleNamespace

        payload = {
            "profile": PROFILE,
            "runtime": {},
            "home": "/staging/home",
            "root": "/repo",
            "mode": "run",
        }
        for code in (None, 0, 1, 7):
            with (
                patch("sys.path", list(__import__("sys").path)),
                patch("sys.argv", []),
                patch("sys.pycache_prefix", None),
                patch("runbox.child.environment"),
                patch("runbox.child.Guard.install"),
                patch(
                    "runbox.child.importlib.import_module",
                    return_value=SimpleNamespace(main=lambda: code),
                ),
            ):
                self.assertEqual(main(payload, ["example", "--help"]), code)

        def exit_app():
            raise SystemExit(9)

        with (
            patch("sys.path", list(__import__("sys").path)),
            patch("sys.argv", []),
            patch("sys.pycache_prefix", None),
            patch("runbox.child.environment"),
            patch("runbox.child.Guard.install"),
            patch(
                "runbox.child.importlib.import_module",
                return_value=SimpleNamespace(main=exit_app),
            ),
            self.assertRaises(SystemExit) as result,
        ):
            main(payload, ["example"])
        self.assertEqual(result.exception.code, 9)

    def test_provider_error_and_probe_output_are_not_reflected(self):
        import io
        import sys
        from contextlib import redirect_stdout

        with (
            tempfile.TemporaryDirectory() as temporary,
            redirect_stdout(io.StringIO()) as output,
        ):
            with self.assertRaises(Error) as error:
                execute(
                    [
                        sys.executable,
                        "-c",
                        "import sys; print('synthetic-private-provider-body'); sys.exit(1)",
                    ],
                    temporary,
                    probe=True,
                )
            self.assertNotIn("synthetic-private", str(error.exception))
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(
                execute([sys.executable, "-c", "raise SystemExit(7)"], temporary), 7
            )
