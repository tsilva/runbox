import tempfile
import unittest
from pathlib import Path

from runbox.config import Error
from runbox.outputs import select, validate


def execution(excluded=()):
    return {
        "outputs": {
            "result": {
                "argument": 2,
                "when-prefix": ["tool", "--output"],
                "kind": "new-file",
                "separate-from": ["payload"],
                "exclude": list(excluded),
            }
        }
    }


class OutputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.output = self.root / "output"
        self.output.mkdir(mode=0o700)
        self.payload = self.root / "input.bin"
        self.payload.write_bytes(b"synthetic payload")
        self.inputs = {"payload": str(self.payload)}

    def selected(self, path=None, rule=None):
        return select(
            self.root,
            rule or execution(),
            ["tool", "--output", str(path or self.output / "result.json")],
            self.inputs,
        )

    def test_only_exact_new_file_and_private_parent_are_returned(self):
        result = self.selected()
        self.assertEqual(
            result,
            {
                "result": str(self.output / "result.json"),
                "result-parent": str(self.output),
            },
        )
        self.assertFalse((self.output / "result.json").exists())
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertEqual(self.payload.read_bytes(), b"synthetic payload")

    def test_nonmatching_command_gets_only_denied_sentinels(self):
        self.assertEqual(
            select(self.root, execution(), ["tool", "check"]),
            {"result": "/dev/null", "result-parent": "/dev/null"},
        )

    def test_existing_output_and_nonempty_parent_are_rejected(self):
        target = self.output / "result.json"
        target.write_text("preserved")
        for path in (target, self.output / "other.json"):
            with self.assertRaises(Error):
                self.selected(path)
        self.assertEqual(target.read_text(), "preserved")

    def test_relative_traversal_and_symlink_targets_are_rejected(self):
        linked = self.root / "linked"
        linked.symlink_to(self.output, target_is_directory=True)
        dangling = self.output / "dangling.json"
        dangling.symlink_to(self.root / "missing")
        for target in (
            Path("relative.json"),
            self.output / ".." / "result.json",
            linked / "result.json",
            dangling,
        ):
            with self.assertRaises(Error):
                self.selected(target)

    def test_missing_or_shared_directory_is_not_created_or_repaired(self):
        with self.assertRaises(Error):
            self.selected(self.root / "missing" / "result.json")
        self.output.chmod(0o755)
        with self.assertRaises(Error):
            self.selected()
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o755)

    def test_protected_state_and_input_directory_cannot_be_outputs(self):
        with self.assertRaises(Error):
            self.selected(rule=execution([str(self.root)]))
        with self.assertRaises(Error):
            select(
                self.root,
                execution(),
                ["tool", "--output", str(self.output / "result.json")],
                {"payload": str(self.output / "not-created")},
            )
        with self.assertRaises(Error):
            select(
                self.root,
                execution(),
                ["tool", "--output", str(self.output / "result.json")],
                {},
            )

    def test_empty_directory_selection_preserves_user_directory(self):
        rule = execution()
        rule["outputs"]["result"]["kind"] = "empty-directory"
        result = self.selected(self.output, rule)
        self.assertEqual(result["result"], str(self.output))
        self.assertEqual(result["result-parent"], str(self.output))
        self.assertTrue(self.output.is_dir())

    def test_schema_rejects_boolean_indices_unknown_fields_and_variable_collisions(
        self,
    ):
        for mutate in (
            lambda v: v["result"].update(argument=True),
            lambda v: v["result"].update(create=True),
            lambda v: v.update(home=v.pop("result")),
            lambda v: v.update({"result-parent": v["result"]}),
        ):
            value = execution()["outputs"]
            mutate(value)
            with self.assertRaises(Error):
                validate(value)
