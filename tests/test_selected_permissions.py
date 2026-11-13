from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from runbox.sandbox import compile_policy


@unittest.skipUnless(sys.platform == "darwin", "Requires macOS sandbox-exec")
class SelectedPermissionTests(unittest.TestCase):
    def test_selected_output_overrides_private_parent_but_not_credential_denials(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            selected = root / ".internal/comparisons/selected"
            selected.mkdir(parents=True)
            (selected / "public.txt").write_text("synthetic")
            (selected / ".env").write_text("synthetic private")
            sibling = selected.parent / "other"
            sibling.mkdir()
            (sibling / "private.txt").write_text("synthetic sibling")
            policy = compile_policy(
                {
                    "inputs": {"payload": {}},
                    "outputs": {"chosen": {}},
                    "permissions": {
                        "read": [
                            {"directory": "{repo}"},
                            {"directory": "{python-root}"},
                            {"directory": "{chosen}"},
                            {"directory": "{chosen-parent}"},
                            {"file": "{payload}"},
                        ],
                        "deny-read": [{"directory": "{repo}/.internal"}],
                        "write": [],
                        "execute": ["{python}", "{python-real}"],
                    },
                },
                {
                    "repo": str(root),
                    "home": str(root),
                    "python": sys.executable,
                    "python-real": str(Path(sys.executable).resolve()),
                    "python-root": str(Path(sys.executable).resolve().parent.parent),
                    "chosen": str(selected),
                    "chosen-parent": str(selected.parent),
                    "payload": str(sibling / "private.txt"),
                },
                "127.0.0.1:8283",
            )

            def run(code):
                return subprocess.run(
                    [
                        "/usr/bin/sandbox-exec",
                        "-p",
                        policy,
                        sys.executable,
                        "-I",
                        "-S",
                        "-B",
                        "-c",
                        code,
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                ).returncode

            self.assertEqual(
                run(
                    f'import os;assert "public.txt" in os.listdir({str(selected)!r});assert open({str(selected / "public.txt")!r}).read()=="synthetic"'
                ),
                0,
            )
            for target in (selected / ".env", sibling / "private.txt"):
                self.assertNotEqual(run(f"open({str(target)!r}).read()"), 0)
            self.assertNotEqual(run(f"import os;os.listdir({str(sibling)!r})"), 0)
