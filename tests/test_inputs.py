import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import os

from runbox.config import Error
from runbox.inputs import select, validate


def execution():
    return {
        "inputs": {
            "payload": {
                "argument": 3,
                "when-prefix": ["hf", "upload"],
                "root": "repo",
                "exclude": [".git", ".local", ".venv", ".internal"],
                "allow": [".internal/huggingface-vault/payloads"],
            }
        }
    }


class InputTests(unittest.TestCase):
    def test_external_selection_requires_owned_regular_files(self):
        target = self.root / "synthetic.bin"
        target.write_bytes(b"synthetic")
        policy = execution()
        policy["inputs"]["payload"].update(root="any-file", allow=[])
        arguments = ["hf", "upload", "owner/repo", str(target)]
        self.assertEqual(select(self.root, policy, arguments)["payload"], str(target))
        different = os.getuid() + 1
        with (
            patch("runbox.inputs.os.getuid", return_value=different),
            self.assertRaises(Error),
        ):
            select(self.root, policy, arguments)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def test_only_selected_explicit_payload_is_exposed(self):
        payload = self.root / "payload.bin"
        payload.write_bytes(b"synthetic")
        self.assertEqual(
            select(
                self.root, execution(), ["hf", "upload", "owner/repo", str(payload)]
            ),
            {"payload": str(payload)},
        )
        self.assertEqual(
            select(self.root, execution(), ["hf", "auth", "whoami"]),
            {"payload": "/dev/null"},
        )

    def test_private_roots_and_checkout_root_rejected(self):
        for name in (".git/config", ".local/secret", ".internal/notes.md"):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("synthetic")
            with self.assertRaises(Error):
                select(
                    self.root, execution(), ["hf", "upload", "owner/repo", str(target)]
                )
        with self.assertRaises(Error):
            select(
                self.root, execution(), ["hf", "upload", "owner/repo", str(self.root)]
            )

    def test_narrow_prepared_private_payload_remains_usable(self):
        target = self.root / ".internal/huggingface-vault/payloads/model.bin"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"fake")
        self.assertEqual(
            select(self.root, execution(), ["hf", "upload", "owner/repo", str(target)])[
                "payload"
            ],
            str(target),
        )

    def test_symlink_payload_and_descendant_rejected(self):
        target = self.root / "data"
        target.mkdir()
        outside = self.root.parent / "outside-not-created"
        (target / "linked").symlink_to(outside)
        for selected in (target, target / "linked"):
            with self.assertRaises(Error):
                select(
                    self.root,
                    execution(),
                    ["hf", "upload", "owner/repo", str(selected)],
                )

    def test_missing_and_parent_traversal_rejected(self):
        for args in (
            ["hf", "upload", "owner/repo"],
            ["hf", "upload", "owner/repo", "../outside"],
            ["hf", "upload", "owner/repo", "missing"],
        ):
            with self.assertRaises(Error):
                select(self.root, execution(), args)

    def test_payload_exception_cannot_broaden_root(self):
        value = execution()["inputs"]
        value["payload"]["allow"] = [".internal"]
        with self.assertRaises(Error):
            validate(value)
