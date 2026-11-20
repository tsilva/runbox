import contextlib
import io
import json
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch
import zipfile


BUILD = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/build.py"))[
    "build"
]


class ReleaseBuildTests(unittest.TestCase):
    def test_shared_python_bytecode_never_changes_a_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            resources = source / "runbox/resources"
            nested = resources / "nested"
            nested.mkdir(parents=True)
            (source / "LICENSE").write_text("test license")
            (source / "runbox/staging.sb").write_text("test policy")
            (nested / "example.py").write_text("print('fixture')\n")
            clean, cached = root / "clean", root / "cached"
            with (
                patch.dict(BUILD.__globals__, ROOT=source),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                BUILD(clean)
                cache = nested / "__pycache__"
                cache.mkdir()
                (cache / "example.cpython-314.pyc").write_bytes(b"unreviewed bytes")
                (cache / "stale.txt").write_bytes(b"incidental file")
                (resources / "old.pyc").write_bytes(b"legacy bytecode")
                (resources / "old.pyo").write_bytes(b"optimized bytecode")
                BUILD(cached)
            manifest = json.loads((cached / "checksums.json").read_bytes())
            self.assertEqual(
                set(manifest),
                {"runbox.pyz", "staging.sb", "resources/nested/example.py"},
            )
            self.assertEqual(
                sorted(
                    path.relative_to(cached).as_posix()
                    for path in cached.rglob("*")
                    if path.is_file()
                ),
                sorted([*manifest, "checksums.json"]),
            )
            for name in (*manifest, "checksums.json"):
                self.assertEqual(
                    (clean / name).read_bytes(), (cached / name).read_bytes(), name
                )
            with zipfile.ZipFile(cached / "runbox.pyz") as archive:
                self.assertIn("runbox/resources/nested/example.py", archive.namelist())
                self.assertFalse(
                    any(
                        "__pycache__" in name or name.endswith((".pyc", ".pyo"))
                        for name in archive.namelist()
                    )
                )
