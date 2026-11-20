import base64
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from runbox import hf_imagefolder as imagefolder
from runbox.config import Error


PARENT = "a" * 40
COMMIT = "b" * 40
MESSAGE = "Publish reviewed images"


class ImageFolderTests(unittest.TestCase):
    def setUp(self):
        self.checkout = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.stage = self.checkout / "stage"
        self.stage.mkdir()
        (self.stage / "images").mkdir()
        (self.stage / "README.md").write_text("# Verified frames\n")
        (self.stage / "images/metadata.jsonl").write_text('{"file_name":"frame.png"}\n')
        (self.stage / "images/frame.png").write_bytes(b"synthetic pixels")
        (self.stage / "export.json").write_text('{"local":true}')
        self.plan_file = self.checkout / "plan.json"

    def freeze(self):
        plan = imagefolder.prepare(self.stage, PARENT, MESSAGE)
        raw = json.dumps(plan).encode()
        self.plan_file.write_bytes(raw)
        self.plan_file.chmod(0o600)
        return plan, hashlib.sha256(raw).hexdigest()

    def test_prepare_excludes_local_export_receipt_and_supports_cropped_files(self):
        plan, _ = self.freeze()
        self.assertEqual(
            set(plan["files"]),
            {"README.md", "images/metadata.jsonl", "images/frame.png"},
        )
        (self.stage / "images").rename(self.stage / "cropped")
        plan, _ = self.freeze()
        self.assertIn("cropped/frame.png", plan["files"])
        self.assertNotIn("export.json", plan["files"])

    def test_prepare_rejects_surprise_file_and_symlink(self):
        extra = self.stage / "unreviewed.txt"
        extra.write_text("synthetic")
        with self.assertRaisesRegex(Error, "one export image folder"):
            self.freeze()
        extra.unlink()
        (self.stage / "images/another.png").symlink_to(self.stage / "images/frame.png")
        with self.assertRaisesRegex(Error, "Symlinked file"):
            self.freeze()

    def test_invalid_hash_or_changed_file_stops_before_sdk_initialization(self):
        _, digest = self.freeze()
        policy = base64.urlsafe_b64encode(
            json.dumps({"root": str(self.checkout), "mode": "run"}).encode()
        ).decode()
        with (
            patch.dict(os.environ, {"RUNBOX_POLICY": policy}),
            patch.object(imagefolder, "scoped_hub") as connect,
        ):
            with self.assertRaisesRegex(Error, "plan changed"):
                imagefolder.main(["publish", "stage", "plan.json", "0" * 64])
            (self.stage / "images/frame.png").write_bytes(b"edited synthetic pixels")
            with self.assertRaisesRegex(Error, "Staged export differs"):
                imagefolder.main(["publish", "stage", "plan.json", digest])
            connect.assert_not_called()

    def test_commit_pins_parent_and_never_creates_a_dataset(self):
        plan, _ = self.freeze()
        api = Mock()
        api.create_commit.return_value = SimpleNamespace(oid=COMMIT)
        result = imagefolder.commit(
            self.stage, plan, "owner/captures", api, lambda **data: data
        )
        self.assertEqual(result, {"commit": COMMIT})
        api.create_repo.assert_not_called()
        call = api.create_commit.call_args.kwargs
        self.assertEqual(call["parent_commit"], PARENT)
        self.assertEqual(call["repo_id"], "owner/captures")
        self.assertEqual(
            {entry["path_in_repo"] for entry in call["operations"]}, set(plan["files"])
        )
