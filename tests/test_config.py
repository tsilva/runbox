import copy
import json
import tempfile
import unittest
from pathlib import Path

from runbox.config import Error, load, profile
from tests.support import PROFILE, config


class ConfigTests(unittest.TestCase):
    def test_supported_profile_and_unsandboxed_generic_command(self):
        profile(copy.deepcopy(PROFILE))
        value = copy.deepcopy(PROFILE)
        value["execution"] = {"sandbox": "none"}
        value.pop("http")
        profile(value)

    def test_invalid_scope_and_injection_rejected(self):
        mutations = [
            ("provider", "type", "unknown"),
            ("provider", "instance", "http://app.infisical.com"),
            ("provider", "instance", "https://user:password@example.com"),
            ("provider", "project-id", "invalid"),
            ("provider", "access-bundle", "../other"),
            ("session", "ttl", "31m"),
            ("session", "proxy", "0.0.0.0:8283"),
            ("session", "proxy", "127.0.0.1:99999"),
            ("environment", "EXAMPLE_API_KEY", "synthetic-real-key"),
            ("environment", "PYTHONPATH", "/untrusted"),
            ("environment", "HTTP_PROXY", "http://untrusted"),
            ("execution", "sandbox", "unknown"),
            ("execution", "workspace", "../../home"),
            ("execution", "workspace", "/tmp/example"),
            ("http", "probe", "/api/v1/chat/completions"),
            ("http", "base-url", "http://localhost/x?token=bad"),
        ]
        for section, key, replacement in mutations:
            with self.subTest(section=section, key=key):
                value = copy.deepcopy(PROFILE)
                value[section][key] = replacement
                with self.assertRaises(Error):
                    profile(value)

    def test_yaml_duplicates_aliases_tags_unknown_fields_boolean_version(self):
        bad = [
            "version: 1\nversion: 1\n",
            "x: &x []\ny: *x\n",
            "!!python/object:os.system {}",
            json.dumps({**config(), "version": True}),
            json.dumps({**config(), "extra": 1}),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / ".runbox.yaml"
            for raw in bad:
                with self.subTest(raw=raw[:30]):
                    path.write_text(raw)
                    with self.assertRaises(Error):
                        load(path)
            path.write_text(json.dumps(config()))
            self.assertEqual(load(path), config())
