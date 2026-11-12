import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from runbox.config import Error
from runbox.trust import approve, verified
from tests.support import PROFILE, fixture


class TrustTests(unittest.TestCase):
    def test_pins_and_approval_permissions(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            root, runtime, archive = fixture(home)
            with patch("pathlib.Path.home", return_value=home):
                with self.assertRaises((Error, OSError)):
                    verified(root, "dev", PROFILE, archive)
                approve(root, "dev", PROFILE, runtime, archive)
                self.assertEqual(verified(root, "dev", PROFILE, archive), runtime)
                mutations = [
                    root / ".runbox.yaml",
                    root / "src/example/cli.py",
                    root / "uv.lock",
                    archive,
                    archive.with_name("staging.sb"),
                    Path(runtime["infisical"]),
                    Path(runtime["python"]).resolve(),
                    Path(runtime["ca-file"]),
                ]
                for path in mutations:
                    old = path.read_bytes()
                    try:
                        path.write_bytes(old + b"\nchanged")
                        with (
                            self.subTest(path=path.name),
                            self.assertRaises((Error, OSError)),
                        ):
                            verified(root, "dev", PROFILE, archive)
                    finally:
                        path.write_bytes(old)
                extra = root / "src/example/new.py"
                extra.write_text("unreviewed")
                with self.assertRaises(Error):
                    verified(root, "dev", PROFILE, archive)
                extra.unlink()
                extra.symlink_to(root / "src/example/cli.py")
                with self.assertRaises(Error):
                    verified(root, "dev", PROFILE, archive)
                extra.unlink()
                for name in (
                    ".infisical.yaml",
                    ".infisical.json",
                    ".access.toml",
                    ".access.local.toml",
                ):
                    path = root / name
                    path.write_text("{}")
                    with self.assertRaises(Error):
                        verified(root, "dev", PROFILE, archive)
                    path.unlink()
                approval = next((home / ".config/runbox/approvals").glob("*.json"))
                approval.chmod(0o644)
                with self.assertRaises(Error):
                    verified(root, "dev", PROFILE, archive)

    def test_repository_identity_and_runtime_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            root, runtime, archive = fixture(home)
            with patch("pathlib.Path.home", return_value=home):
                bad = {**runtime, "ca-fingerprint": "SHA256:00"}
                with self.assertRaises(Error):
                    approve(root, "dev", PROFILE, bad, archive)
                approve(root, "dev", PROFILE, runtime, archive)
                with self.assertRaises((Error, OSError)):
                    verified(root, "different", PROFILE, archive)
