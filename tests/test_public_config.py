import contextlib
import copy
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.request import urlopen

from runbox.config import Error, profile
from runbox.public_config import run
from runbox.trust import approve, verified
from scripts.build import build
from tests.support import fixture


PUBLIC = {
    "provider": {
        "type": "infisical-public-config",
        "instance": "https://app.infisical.com",
        "classification": "browser-public",
        "source": {
            "project-id": "22222222-2222-4222-8222-222222222222",
            "environment": "dev",
            "secret-path": "/maps",
        },
        "variables": {
            "VITE_GOOGLE_MAPS_API_KEY": {"pattern": "AIza[A-Za-z0-9_-]{35}"},
            "VITE_GOOGLE_MAPS_MAP_ID": {"pattern": "[a-f0-9]{16,32}"},
        },
    },
    "session": {"ttl": "1m"},
    "environment": {},
    "execution": {
        "sandbox": "none",
        "command": "preview",
        "argv": ["{node}", "server.mjs"],
        "arguments": [[]],
        "integrity": {"files": ["server.mjs"]},
    },
}
KEY = "AIza" + "S" * 35
MAP = "a" * 16


class PublicConfigurationTests(unittest.TestCase):
    def test_closed_public_schema_rejects_secret_names_and_broad_execution(self):
        profile(copy.deepcopy(PUBLIC))
        mutations = [
            lambda p: p["provider"].update(classification="secret"),
            lambda p: p["provider"]["variables"].update(API_KEY={"pattern": "[a-z]+"}),
            lambda p: p["provider"]["variables"].update(PATH={"pattern": "[a-z]+"}),
            lambda p: p["provider"]["variables"].update(VITE_BAD={"pattern": "(a+)+"}),
            lambda p: p["provider"].update(token="secret"),
            lambda p: p["session"].update(proxy="127.0.0.1:8283"),
            lambda p: p["session"].update(ttl="9h"),
            lambda p: p["environment"].update(NODE_OPTIONS="--import=bad"),
            lambda p: p["execution"].update(arguments="any"),
            lambda p: p["execution"].update(arguments=[[{"pattern": "[a-z]+"}]]),
            lambda p: p["execution"].update(argv=["/bin/sh"]),
            lambda p: p["execution"].update(sandbox="macos-command"),
            lambda p: p["execution"].update(integrity={"files": []}),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                candidate = copy.deepcopy(PUBLIC)
                mutate(candidate)
                with self.assertRaises(Error):
                    profile(candidate)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        directory = Path(self.temporary.name).resolve()
        self.root, self.runtime, _ = fixture(directory)
        self.archive = directory / "built/runbox.pyz"
        with contextlib.redirect_stdout(io.StringIO()):
            build(self.archive.parent)
        self.state = directory / "state"
        self.state.mkdir(mode=0o700)
        self.addCleanup(patch.stopall)
        patch("runbox.trust.state", return_value=self.state).start()
        self.runtime["node"] = str(Path(shutil.which("node")).resolve())
        self.runtime["files"] = {"source-ca": {"path": self.runtime["ca-file"]}}
        self.selected = copy.deepcopy(PUBLIC)
        self.server = self.root / "server.mjs"
        self.server.write_text("console.log(process.env.VITE_GOOGLE_MAPS_API_KEY);\n")
        self._native("success")
        self._approve()

    def _native(self, behavior):
        self.runtime_cli = Path(self.runtime["infisical"])
        self.runtime_cli.write_text(
            "#!" + sys.executable + "\nimport sys\n"
            "assert '--expand=false' in sys.argv\n"
            "assert '--include-imports=false' in sys.argv\n"
            "assert '--recursive=false' in sys.argv\n"
            "assert '--secret-overriding=false' in sys.argv\n"
            "assert '--projectId=22222222-2222-4222-8222-222222222222' in sys.argv\n"
            "assert '--env=dev' in sys.argv and '--path=/maps' in sys.argv\n"
            + (
                f"print({KEY!r},file=sys.stderr); sys.exit(1)\n"
                if behavior == "fail"
                else "print('x' * 8192)\n"
                if behavior == "large"
                else "print('invalid public format')\n"
                if behavior == "invalid"
                else f"print({KEY!r} if sys.argv[3] == 'VITE_GOOGLE_MAPS_API_KEY' else {MAP!r})\n"
            )
        )
        self.runtime_cli.chmod(0o700)

    def _approve(self):
        (self.root / ".runbox.yaml").write_text(
            json.dumps(
                {
                    "version": 1,
                    "default": "public",
                    "profiles": {"public": self.selected},
                }
            )
        )
        approve(self.root, "public", self.selected, self.runtime, self.archive)

    def _run(self, arguments=("preview",), *, probe=False):
        return run(
            self.root,
            "public",
            self.selected,
            self.runtime,
            self.archive,
            list(arguments),
            probe=probe,
        )

    def test_native_output_and_key_are_never_command_arguments_or_logs(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(self._run(), 0)
        self.assertNotIn(KEY, output.getvalue())
        self.assertIn("[redacted]", output.getvalue())

    def test_probe_reads_only_selected_settings_and_reports_safe_counts(self):
        self.selected["ready"] = False
        self._approve()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(self._run(probe=True), 0)
        self.assertEqual(
            json.loads(output.getvalue()),
            {
                "ok": True,
                "read_only": True,
                "item_count": 2,
                "credential_mode": "browser-public-configuration",
            },
        )
        with self.assertRaises(Error):
            self._run()

    def test_wrong_command_and_changed_source_are_rejected_before_reading(self):
        with patch("runbox.public_config._native_value") as read:
            with self.assertRaises(Error):
                self._run(("preview", "--unapproved"))
            read.assert_not_called()
            self.server.write_text("// changed since approval\n")
            with self.assertRaises(Error):
                self._run()
            read.assert_not_called()

    def test_native_failure_oversize_and_invalid_format_never_launch(self):
        for behavior in ("fail", "large", "invalid"):
            self._native(behavior)
            self._approve()
            with patch("runbox.runner.execute") as launch:
                with self.assertRaises(Error) as result:
                    self._run()
                self.assertNotIn(KEY, str(result.exception))
                launch.assert_not_called()

    def test_parent_environment_and_other_settings_are_not_inherited(self):
        self.server.write_text(
            "if (process.env.UNRELATED_SECRET || process.env.HTTPS_PROXY) process.exit(9);\n"
            "if (!process.env.VITE_GOOGLE_MAPS_MAP_ID) process.exit(8);\n"
        )
        self._approve()
        with patch.dict(
            "os.environ", {"UNRELATED_SECRET": "private", "HTTPS_PROXY": "private"}
        ):
            self.assertEqual(self._run(), 0)

    def test_bounded_lifetime_stops_owned_process(self):
        self.server.write_text("setInterval(() => {}, 1000);\n")
        self._approve()
        with patch("runbox.public_config.duration", return_value=0.1):
            with self.assertRaisesRegex(Error, "approved lifetime"):
                self._run()

    def test_actual_vite_receives_settings_and_terminates_without_saving_them(self):
        # Use an existing reviewed Vite installation; no downloads or installs.
        selected = os.environ.get("RUNBOX_TEST_VITE_ENTRY")
        if not selected:
            self.skipTest("Set RUNBOX_TEST_VITE_ENTRY to exercise the actual Vite client")
        vite = Path(selected).resolve()
        if not vite.is_file():
            self.skipTest("Actual Vite installation not available")
        ready = self.root / "ready.json"
        self.server.write_text(
            f"import {{ createServer }} from {json.dumps(vite.as_uri())};\n"
            "import { writeFileSync } from 'node:fs';\n"
            "const server = await createServer({ configFile:false, logLevel:'silent',"
            " server:{host:'127.0.0.1',port:0},"
            " plugins:[{name:'synthetic-stop', configureServer(s){s.middlewares.use((req,res,next)=>{"
            "if(req.url!='/__stop') return next();res.end('stopping');"
            "setTimeout(async()=>{await server.close();process.exit(0)},20);})}}] });\n"
            "await server.listen();\n"
            "writeFileSync('ready.json',JSON.stringify({port:server.httpServer.address().port}));\n"
            "console.log(process.env.VITE_GOOGLE_MAPS_API_KEY);\n"
        )
        (self.root / "client.js").write_text(
            "export const key = import.meta.env.VITE_GOOGLE_MAPS_API_KEY;\n"
            "export const map = import.meta.env.VITE_GOOGLE_MAPS_MAP_ID;\n"
        )
        self._approve()
        results, errors = [], []

        def start():
            try:
                results.append(self._run())
            except BaseException as exc:
                errors.append(exc)

        output = io.StringIO()
        thread = threading.Thread(target=start)
        with contextlib.redirect_stdout(output):
            thread.start()
            try:
                deadline = time.monotonic() + 10
                while (
                    not ready.exists()
                    and thread.is_alive()
                    and time.monotonic() < deadline
                ):
                    time.sleep(0.05)
                self.assertTrue(ready.exists(), errors)
                port = json.loads(ready.read_text())["port"]
                with urlopen(
                    f"http://127.0.0.1:{port}/client.js", timeout=5
                ) as response:
                    body = response.read().decode()
                self.assertIn(KEY, body)
                self.assertIn(MAP, body)
            finally:
                if ready.exists() and thread.is_alive():
                    port = json.loads(ready.read_text())["port"]
                    with urlopen(
                        f"http://127.0.0.1:{port}/__stop", timeout=5
                    ) as response:
                        response.read()
                thread.join(timeout=10)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(results, [0])
        self.assertNotIn(KEY, output.getvalue())
        for path in self.root.rglob("*"):
            if path.is_file() and path != Path(self.runtime["infisical"]):
                self.assertNotIn(KEY.encode(), path.read_bytes(), str(path))
        verified(self.root, "public", self.selected, self.archive)
