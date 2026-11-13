import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from runbox.commands import link, resolve
from runbox.config import Error
from runbox.stdin_dispatch import execute

RULE = {
    "max-bytes": 256,
    "path": ["operation"],
    "equals": "chat",
    "profile": "chat",
    "timeout": 2,
    "otherwise-timeout": 1,
    "output-field": "status",
    "max-output-bytes": 512,
}


class StdinDispatchTests(unittest.TestCase):
    def test_profile_selection_and_strict_payload_preflight(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            binary = home / ".local/bin/runbox"
            binary.parent.mkdir(parents=True)
            binary.write_text("# synthetic launcher")
            binary.chmod(0o700)
            with patch("pathlib.Path.home", return_value=home):
                alias = home / "worker"
                link(alias, home, "speech", ["request"], stdin_dispatch=RULE)
                self.assertEqual(
                    resolve(str(alias), [], b'{"operation":"chat"}')[3], "chat"
                )
                self.assertEqual(
                    resolve(str(alias), [], b'{"operation":"speech"}')[3], "speech"
                )
                for payload in [
                    b"",
                    b"x" * 257,
                    b'{"operation":"chat","operation":"speech"}',
                    b"[]",
                    b"{",
                ]:
                    with self.assertRaises(Error):
                        resolve(str(alias), [], payload)
                with self.assertRaises(Error):
                    resolve(str(alias), ["--unreviewed"], b"{}")

    def test_exact_bytes_forwarded_one_json_record_and_bounded_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            binary = home / ".local/bin/runbox"
            binary.parent.mkdir(parents=True)
            binary.write_text(
                "#!"
                + sys.executable
                + '\nimport sys,json,hashlib\np=sys.stdin.buffer.read()\nprint("lifecycle")\nprint(json.dumps({"status":200,"sha":hashlib.sha256(p).hexdigest(),"args":sys.argv[1:]}))\n'
            )
            binary.chmod(0o700)
            payload = b'{"operation": "chat", "text": "synthetic"}\n'
            output = io.StringIO()
            with (
                patch("pathlib.Path.home", return_value=home),
                contextlib.redirect_stdout(output),
            ):
                self.assertEqual(execute(["--profile", "chat"], payload, RULE, True), 0)
            import hashlib

            record = json.loads(output.getvalue())
            self.assertEqual(record["sha"], hashlib.sha256(payload).hexdigest())
            self.assertEqual(record["args"], ["--profile", "chat"])
            binary.write_text("#!" + sys.executable + '\nprint("x"*1024)\n')
            with (
                patch("pathlib.Path.home", return_value=home),
                self.assertRaises(Error),
            ):
                execute([], b"{}", RULE, False)
            binary.write_text("#!" + sys.executable + "\nimport time\ntime.sleep(5)\n")
            with (
                patch("pathlib.Path.home", return_value=home),
                self.assertRaises(Error),
            ):
                execute([], b"{}", RULE, False)
