from pathlib import Path
import sys
import tempfile
import time
import unittest

from runbox.config import Error
from runbox.services import Session, validate


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="runbox-service-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.runtime = {
            "python": str(Path(sys.executable).resolve()),
            "python-root": str(Path(sys.executable).resolve().parent.parent),
            "directories": {"service-base": {"path": str(self.root), "private": True}},
        }
        self.archive = self.root / "runbox.pyz"
        self.spec = {
            "lock": "{service-base}/session.lock",
            "processes": [
                {
                    "argv": [
                        "{python}",
                        "-I",
                        "-S",
                        "-u",
                        "-c",
                        "import json,time;print(json.dumps({'ready':True,'port':12456}),flush=True);time.sleep(40)",
                    ],
                    "cwd": "{service-base}",
                    "timeout": 2,
                    "ready": {"ready": True, "port": 12456},
                }
            ],
        }

    def session(self):
        return Session(self.root, {"services": self.spec}, self.runtime, self.archive)

    def test_owned_service_stops_and_lock_releases(self):
        with self.session() as session:
            process = session.processes[0]
            session.healthy()
            with self.assertRaises(Error):
                with self.session():
                    pass
            self.assertIsNone(process.poll())
        self.assertIsNotNone(process.poll())
        with self.session():
            pass

    def test_wrong_readiness_stops_process_without_echoing_body(self):
        self.spec["processes"][0]["ready"]["port"] = 9999
        session = self.session()
        with self.assertRaisesRegex(Error, "approved binding"):
            with session:
                pass
        self.assertEqual(session.processes, [])
        self.assertIsNone(session.lock)

    def test_dead_service_fails_health(self):
        with self.session() as session:
            session.processes[0].terminate()
            session.processes[0].wait(timeout=3)
            with self.assertRaisesRegex(Error, "required local service stopped"):
                session.healthy()

    def test_existing_database_is_preserved_and_owned_database_stops(self):
        binary = self.root / "pgctl"
        binary.write_text(
            "#!"
            + str(Path(sys.executable).resolve())
            + "\n"
            + """import pathlib,sys
base=pathlib.Path(__file__).parent
state=base/'database-running';events=base/'events'
action=sys.argv[-1]
with events.open('a') as out:out.write(action+'\\n')
if action=='status':raise SystemExit(0 if state.exists() else 3)
if action=='start':state.write_text('started')
if action=='stop':state.unlink()
"""
        )
        binary.chmod(0o700)
        self.runtime["binaries"] = {"pgctl": str(binary)}
        self.spec["postgres"] = {
            "binary": "{pgctl}",
            "data": "{service-base}",
            "log": "{service-base}/postgres.log",
            "timeout": 3,
        }
        marker = self.root / "database-running"
        marker.write_text("pre-existing")
        with self.session():
            pass
        self.assertTrue(marker.exists())
        self.assertNotIn("stop", (self.root / "events").read_text().splitlines())
        marker.unlink()
        (self.root / "events").unlink()
        with self.session():
            self.assertTrue(marker.exists())
        self.assertFalse(marker.exists())
        self.assertEqual(
            (self.root / "events").read_text().splitlines(),
            ["status", "start", "status", "stop"],
        )

    def test_partial_readiness_and_unpinned_program_fail_closed(self):
        self.spec["processes"][0]["argv"][-1] = (
            "import sys,time;sys.stdout.write('partial');sys.stdout.flush();time.sleep(40)"
        )
        start = time.monotonic()
        with self.assertRaisesRegex(Error, "readiness"):
            with self.session():
                pass
        self.assertLess(time.monotonic() - start, 4)
        self.spec["processes"][0]["argv"][0] = "/bin/sh"
        with self.assertRaisesRegex(Error, "not runtime-pinned"):
            with self.session():
                pass

    def test_existing_only_database_never_starts_a_server(self):
        self.spec["processes"] = []
        self.spec["postgres"] = {
            "binary": "{python}",
            "data": "{service-base}",
            "log": "{service-base}/postgres.log",
            "timeout": 3,
            "start-if-stopped": False,
        }
        from unittest.mock import patch

        with patch.object(Session, "postgres", return_value=3) as postgres:
            with self.assertRaisesRegex(
                Error, "existing local PostgreSQL server is stopped"
            ):
                with self.session():
                    pass
            postgres.assert_called_once_with("status")

    def test_credentials_and_unsafe_transient_paths_rejected(self):
        self.spec["processes"][0]["environment"] = {"API_KEY": "fake-raw-key"}
        with self.assertRaises(Error):
            validate(self.spec)
        self.spec["processes"][0].pop("environment")
        self.spec["transient-files"] = ["{service-base}/source.py"]
        with self.assertRaises(Error):
            validate(self.spec)

    def test_public_argument_is_passed_only_as_data_with_missing_sentinel(self):
        self.spec["processes"][0]["argv"].append("{argument-2}")
        session = Session(
            self.root,
            {"services": self.spec},
            self.runtime,
            self.archive,
            arguments=["publish", "workspace", "logical-item"],
        )
        self.assertEqual(session.values["argument-2"], "logical-item")
        self.assertEqual(self.session().values["argument-2"], "/dev/null")
        self.spec["processes"][0]["cwd"] = "{argument-2}"
        with self.assertRaises(Error):
            validate(self.spec)
