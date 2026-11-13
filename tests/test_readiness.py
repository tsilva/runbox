import json
import tempfile
import unittest
from pathlib import Path

from runbox.config import Error
from runbox.readiness import ready


class ReadinessTests(unittest.TestCase):
    def test_rotation_pending_blocks_without_changing_approval_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            state = root / "state.json"
            profile = {
                "execution": {
                    "readiness": {
                        "file": "{state}/state.json",
                        "field": "status",
                        "equals": "ready",
                    }
                }
            }
            runtime = {"directories": {"state": {"path": str(root), "private": True}}}
            state.write_text(json.dumps({"status": "ready"}))
            state.chmod(0o600)
            self.assertTrue(ready(root, profile, runtime, root / "runbox.pyz"))
            state.write_text(json.dumps({"status": "copied_pending_check"}))
            self.assertFalse(ready(root, profile, runtime, root / "runbox.pyz"))
            state.write_text('{"status":"pending","status":"ready"}')
            with self.assertRaises((Error, ValueError)):
                ready(root, profile, runtime, root / "runbox.pyz")
