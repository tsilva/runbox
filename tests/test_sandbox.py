import copy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from runbox.config import Error, profile
from runbox.sandbox import compile_policy, expand
from tests.support import PROFILE


def command_profile():
    value = copy.deepcopy(PROFILE)
    value["execution"] = {
        "sandbox": "macos-command",
        "command": "node-probe",
        "argv": [
            "{node}",
            "--use-env-proxy",
            "{release}/resources/node-client.mjs",
            "probe",
        ],
        "probe-argv": [
            "{node}",
            "--use-env-proxy",
            "{release}/resources/node-client.mjs",
            "probe",
        ],
        "arguments": [[]],
        "integrity": {"files": ["package.json", "src/adapter.ts"]},
        "permissions": {
            "read": [{"file": "{repo}/source.txt"}, {"directory": "{node-root}"}],
            "write": [{"directory": "{repo}/output"}],
            "execute": ["{node}"],
        },
        "client": {"type": "node-http", "adapter": "src/adapter.ts"},
    }
    return value


class CommandPolicyTests(unittest.TestCase):
    def test_next_http_guard_covers_probe_and_run_but_not_non_http_next(self):
        from runbox.sandbox import command
        from tests.support import fixture

        with tempfile.TemporaryDirectory() as temporary:
            root, runtime, archive = fixture(Path(temporary).resolve())
            runtime["node"] = runtime["python"]
            value = command_profile()
            value["execution"]["client"] = {"type": "node-next"}
            value["execution"]["sandbox"] = "none"
            for mode, args in [("probe", []), ("run", ["node-probe"])]:
                vector, _ = command(root, value, runtime, archive, mode, args)
                options = next(arg for arg in vector if arg.startswith("NODE_OPTIONS="))
                self.assertIn("/resources/node-preload.mjs", options)
            del value["http"]
            vector, _ = command(root, value, runtime, archive, "probe", [])
            self.assertFalse(any(arg.startswith("NODE_OPTIONS=") for arg in vector))

    def test_closed_schema_and_immutable_source_adapter(self):
        value = command_profile()
        profile(value)
        value["execution"]["client"]["adapter"] = "src/unpinned.ts"
        with self.assertRaises(Error):
            profile(value)
        value = command_profile()
        value["execution"]["permissions"]["network"] = ["example.com:443"]
        with self.assertRaises(Error):
            profile(value)
        with self.assertRaises(Error):
            expand("{unreviewed}/program", {})

    @unittest.skipUnless(sys.platform == "darwin", "Requires macOS sandbox-exec")
    def test_compiled_policy_retains_read_write_and_helper_denials(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            root = home / "repo"
            root.mkdir()
            output = root / "output"
            output.mkdir()
            public = root / "source.txt"
            public.write_text("synthetic public fixture")
            private = home / "private-credential"
            private.write_text("synthetic private fixture")
            (root / ".env").write_text("synthetic private fixture")
            execution = command_profile()["execution"]
            execution["permissions"]["read"] = [
                {"directory": "{repo}"},
                {"directory": "{python-root}"},
            ]
            execution["permissions"]["execute"] = ["{python}", "{python-real}"]
            values = {
                "home": str(home),
                "repo": str(root),
                "python": sys.executable,
                "python-real": str(Path(sys.executable).resolve()),
                "python-root": str(Path(sys.executable).resolve().parent.parent),
            }
            policy = compile_policy(execution, values, "127.0.0.1:8283")

            def run(code):
                return subprocess.run(
                    [
                        "/usr/bin/sandbox-exec",
                        "-p",
                        policy,
                        sys.executable,
                        "-I",
                        "-B",
                        "-c",
                        code,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

            self.assertEqual(
                run(
                    f'assert open({str(public)!r}).read()=="synthetic public fixture"'
                ).returncode,
                0,
            )
            for path in (private, root / ".env"):
                self.assertNotEqual(run(f"open({str(path)!r}).read()").returncode, 0)
            self.assertNotEqual(
                run(f'open({str(public)!r},"w").write("changed")').returncode, 0
            )
            self.assertEqual(
                run(
                    f'open({str(output / "result")!r},"w").write("allowed")'
                ).returncode,
                0,
            )
            self.assertNotEqual(
                run(
                    'import subprocess;subprocess.run(["/bin/echo","forbidden"],check=True)'
                ).returncode,
                0,
            )

    def test_regex_root_is_escaped_and_cannot_reference_unreviewed_roots(self):
        execution = command_profile()["execution"]
        execution["permissions"]["write"] = [
            {"pattern": "{repo}/\\.next-dev-[0-9]+(/|$)"}
        ]
        policy = compile_policy(
            execution,
            {
                "home": "/synthetic/home",
                "repo": "/synthetic/repo.with-dots",
                "node": "/trusted/node",
                "node-root": "/trusted",
            },
            "127.0.0.1:8283",
        )
        self.assertIn("repo\\\\.with", policy)
        execution["permissions"]["write"] = [{"pattern": ".*"}]
        with self.assertRaises(Error):
            compile_policy(
                execution, {"home": "/h", "repo": "/r", "node": "/n"}, "127.0.0.1:8283"
            )
