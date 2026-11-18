import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from runbox.config import Error
from runbox.trust import approve, verified
from tests.support import PROFILE, fixture


class TrustTests(unittest.TestCase):
    def test_private_directory_integrity_pins_complete_sdk(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            root, runtime, archive = fixture(home)
            deps = home / "deps"
            deps.mkdir(mode=0o700)
            pkg = deps / "package"
            pkg.mkdir(mode=0o700)
            module = pkg / "sdk.py"
            module.write_text("from platform import system\n")
            module.chmod(0o600)
            runtime["directories"] = {
                "sdk": {"path": str(deps), "private": True, "integrity": True}
            }
            runtime["imports"] = [str(deps)]
            with patch("pathlib.Path.home", return_value=home):
                approve(root, "dev", PROFILE, runtime, archive)
                self.assertEqual(verified(root, "dev", PROFILE, archive), runtime)
                original = module.read_bytes()
                module.write_bytes(b"new bytes")
                with self.assertRaises(Error):
                    verified(root, "dev", PROFILE, archive)
                module.write_bytes(original)
                extra = pkg / "extra.py"
                extra.touch(mode=0o600)
                with self.assertRaises(Error):
                    verified(root, "dev", PROFILE, archive)
                extra.unlink()
                extra.symlink_to(module)
                with self.assertRaises(Error):
                    verified(root, "dev", PROFILE, archive)
                extra.unlink()
                module.chmod(0o644)
                with self.assertRaises(Error):
                    verified(root, "dev", PROFILE, archive)
                module.chmod(0o600)
                pkg.chmod(0o755)
                with self.assertRaises(Error):
                    verified(root, "dev", PROFILE, archive)
                pkg.chmod(0o700)
                self.assertEqual(verified(root, "dev", PROFILE, archive), runtime)

    def test_runtime_directory_integrity_requires_explicit_privacy(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            root, runtime, archive = fixture(home)
            runtime["directories"] = {"sdk": {"path": str(home), "integrity": True}}
            with patch("pathlib.Path.home", return_value=home):
                with self.assertRaisesRegex(Error, "private directories"):
                    approve(root, "dev", PROFILE, runtime, archive)

    def test_private_runtime_files_and_sdk_integrity_are_pinned(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            root, runtime, archive = fixture(home)
            settings = home / "settings.json"
            settings.write_text('{"metadata":"synthetic"}')
            settings.chmod(0o600)
            dependencies = home / "deps"
            dependencies.mkdir(mode=0o700)
            sdk = dependencies / "sdk.py"
            sdk.write_text("# synthetic SDK")
            runtime.update(
                {
                    "files": {"settings": {"path": str(settings), "private": True}},
                    "directories": {
                        "receipts": {"path": str(dependencies), "private": True}
                    },
                    "imports": [str(dependencies)],
                    "integrity-files": [str(sdk)],
                }
            )
            with patch("pathlib.Path.home", return_value=home):
                approve(root, "dev", PROFILE, runtime, archive)
                verified(root, "dev", PROFILE, archive)
                sdk.write_text("# changed SDK")
                with self.assertRaises(Error):
                    verified(root, "dev", PROFILE, archive)
                sdk.write_text("# synthetic SDK")
                dependencies.chmod(0o755)
                with self.assertRaises(Error):
                    verified(root, "dev", PROFILE, archive)

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
