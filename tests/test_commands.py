import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from runbox.commands import link, resolve
from runbox.config import Error


class CommandLinkTests(unittest.TestCase):
    def test_shared_link_preserves_profile_and_fixed_arguments(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            binary = home / ".local/bin/runbox"
            binary.parent.mkdir(parents=True)
            binary.write_text("# synthetic shared command")
            binary.chmod(0o700)
            alias = home / "report"
            with patch("pathlib.Path.home", return_value=home):
                link(alias, home, "historical", ["python", "report.py"])
                self.assertEqual(alias.stat().st_ino, binary.stat().st_ino)
                self.assertEqual(
                    resolve(str(alias), ["--request-json", "123456789"]),
                    [
                        "--repo",
                        str(home),
                        "--profile",
                        "historical",
                        "run",
                        "--",
                        "python",
                        "report.py",
                        "--request-json",
                        "123456789",
                    ],
                )
                alias.unlink()
                alias.write_text("unrelated user command")
                with self.assertRaises(Error):
                    link(alias, home, "historical", ["python", "report.py"])
                with self.assertRaises(Error):
                    resolve(str(alias), [])

    def test_realtime_translation_accepts_only_the_registered_flag(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            binary = home / ".local/bin/runbox"
            binary.parent.mkdir(parents=True)
            binary.write_text("# synthetic shared command")
            binary.chmod(0o700)
            with patch("pathlib.Path.home", return_value=home):
                alias = home / "realtime-report"
                link(
                    alias,
                    home,
                    "realtime",
                    ["python", "report.py"],
                    ["--request-json", "--request-realtime-json"],
                )
                self.assertEqual(
                    resolve(str(alias), ["--request-json", "123456789"])[-2:],
                    ["--request-realtime-json", "123456789"],
                )
                with self.assertRaises(Error):
                    resolve(str(alias), ["--request-realtime-json", "123456789"])

    def test_legacy_prefix_cannot_select_a_different_program(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            binary = home / ".local/bin/runbox"
            binary.parent.mkdir(parents=True)
            binary.write_text("# synthetic shared command")
            binary.chmod(0o700)
            with patch("pathlib.Path.home", return_value=home):
                alias = home / "existing-worker"
                link(
                    alias,
                    home,
                    "worker",
                    ["approved-worker"],
                    strip_prefix=["/node", "/repo/worker.mjs"],
                )
                self.assertEqual(
                    resolve(
                        str(alias),
                        ["/node", "/repo/worker.mjs", "--run-id", "synthetic"],
                    )[-3:],
                    ["approved-worker", "--run-id", "synthetic"],
                )
                with self.assertRaises(Error):
                    resolve(
                        str(alias),
                        ["/node", "/repo/other.mjs", "--run-id", "synthetic"],
                    )
