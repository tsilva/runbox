import copy
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from runbox.config import Error, online_profile, profile
from runbox.runner import command
from runbox.trust import approve, source_pins, verified
from tests.support import PROFILE, fixture


def selected():
    value = copy.deepcopy(PROFILE)
    http = value.pop("http")
    value["execution"] = {"sandbox": "none"}
    value["probe"] = {
        "execution": {
            "sandbox": "macos-command",
            "command": "identity-check",
            "argv": ["{python}", "-I", "-S", "{release}/runbox.pyz", "--command-child"],
            "probe-argv": [
                "{python}",
                "-I",
                "-S",
                "{release}/runbox.pyz",
                "--command-child",
            ],
            "arguments": [[]],
            "integrity": {"files": ["src/example/cli.py"]},
            "permissions": {
                "read": [
                    {"file": "{release}/runbox.pyz"},
                    {"directory": "{python-root}"},
                ],
                "write": [{"file": "/dev/null"}],
                "execute": ["{python}", "{python-real}"],
                "deny-all-writes": True,
            },
            "client": {"type": "python", "probe": {"checks": []}},
        },
        "http": http,
    }
    return value


class IndependentProbeTests(unittest.TestCase):
    def test_optional_probe_preserves_bare_runs_and_session_policy(self):
        value = selected()
        original = copy.deepcopy(value)
        profile(value)
        effective = online_profile(value)
        self.assertEqual(value, original)
        self.assertEqual(value["execution"], {"sandbox": "none"})
        for key in ("provider", "session", "environment"):
            self.assertEqual(effective[key], value[key])
        with tempfile.TemporaryDirectory() as temporary:
            root, runtime, archive = fixture(Path(temporary).resolve())
            argv, cwd = command(
                root, value, runtime, archive, "run", ["ordinary", "argument"]
            )
            self.assertEqual(cwd, root)
            self.assertEqual(argv[-2:], ["ordinary", "argument"])
            self.assertNotIn("--command-child", argv)
        self.assertIs(online_profile(PROFILE), PROFILE)

    def test_online_policy_does_not_inherit_normal_http_guard(self):
        value = selected()
        value["execution"] = copy.deepcopy(value["probe"]["execution"])
        value["http"] = value["probe"].pop("http")
        value["probe"]["execution"]["client"] = {
            "type": "python",
            "entrypoint": "example.cli:main",
            "probe-arguments": [],
        }
        profile(value)
        self.assertNotIn("http", online_profile(value))
        self.assertIn("http", value)

    def test_scope_overrides_interactive_ops_and_sandbox_downgrades_fail(self):
        for field in ("provider", "session", "environment", "services", "probe"):
            value = selected()
            value["probe"][field] = {}
            with self.subTest(field=field), self.assertRaises(Error):
                profile(value)
        for field in ("inputs", "outputs", "handoff", "readiness"):
            value = selected()
            value["probe"]["execution"][field] = {}
            with self.subTest(field=field), self.assertRaises(Error):
                profile(value)
        value = selected()
        value["execution"] = copy.deepcopy(PROFILE["execution"])
        value["http"] = copy.deepcopy(PROFILE["http"])
        value["probe"]["execution"]["sandbox"] = "none"
        with self.assertRaises(Error):
            profile(value)
        value = selected()
        del value["probe"]["execution"]["probe-argv"]
        with self.assertRaises(Error):
            profile(value)

    def test_probe_query_requires_exact_primary_get_route(self):
        value = selected()
        http = value["probe"]["http"]
        http["routes"][0]["queries"] = ["fields=spreadsheetId&includeGridData=false"]
        http["probe-query"] = "fields=spreadsheetId&includeGridData=false"
        profile(value)
        for query in ("", "fields=gridData", True):
            http["probe-query"] = query
            with self.subTest(query=query), self.assertRaises(Error):
                profile(value)

    def test_probe_sources_and_shared_resources_are_attested_for_bare_runs(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            root, runtime, archive = fixture(home)
            value = selected()
            resource = archive.parent / "resources/probe.py"
            resource.parent.mkdir()
            resource.write_text("# synthetic fixed resource")
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("runbox/resources/probe.py", resource.read_bytes())
            self.assertEqual(
                set(source_pins(root, value)), {"probe:src/example/cli.py"}
            )
            with patch("pathlib.Path.home", return_value=home):
                approve(root, "test", value, runtime, archive)
                verified(root, "test", value, archive)
                for path in (root / "src/example/cli.py", resource):
                    old = path.read_bytes()
                    path.write_bytes(old + b"changed")
                    with self.subTest(path=path.name), self.assertRaises(Error):
                        verified(root, "test", value, archive)
                    path.write_bytes(old)
