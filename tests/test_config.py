import copy
import json
import tempfile
import unittest
from pathlib import Path

from runbox.config import Error, load, profile, retired_configs
from tests.support import PROFILE, config


class ConfigTests(unittest.TestCase):
    def test_explicit_node_service_routes_keep_credentials_and_origins_bound(self):
        from tests.test_sandbox import command_profile

        value = command_profile()
        value["environment"]["STORAGE_TOKEN"] = "storage_public_placeholder"
        route = {
            "method": "POST",
            "path": "/v1/storage/check",
            "origin": "http://127.0.0.1:60763",
            "credential-header": "Example-Storage-Credential",
            "placeholder": "storage_public_placeholder",
        }
        value["http"]["routes"].append(route)
        profile(value)
        value["execution"]["client"] = {"type": "node-next"}
        profile(value)
        mutations = [
            {"origin": "http://unreviewed.example"},
            {"origin": "https://example.com/"},
            {"origin": "https://EXAMPLE.com"},
            {"origin": "https://example.com:443"},
            {"origin": "https://user:password@example.com"},
            {"origin": "https://*.example.com"},
            {"origin": "https://example.com?token=synthetic"},
            {"credential-header": "Authorization"},
            {"credential-header": "Proxy-Authorization"},
            {"credential-header": "Cookie"},
            {"credential-header": "Host"},
            {"credential-header": "Bad\r\nHeader"},
            {"placeholder": "unreviewed_public_placeholder"},
            {"forward-host": "localhost:60763"},
            {"method": "GET", "path": "/v1/storage/{segment}"},
        ]
        for change in mutations:
            changed = copy.deepcopy(value)
            changed["http"]["routes"][-1].update(change)
            with self.subTest(change=change), self.assertRaises(Error):
                profile(changed)
        for missing in ("origin", "credential-header", "placeholder"):
            changed = copy.deepcopy(value)
            del changed["http"]["routes"][-1][missing]
            with self.subTest(missing=missing), self.assertRaises(Error):
                profile(changed)
        python = copy.deepcopy(PROFILE)
        python["environment"]["STORAGE_TOKEN"] = "storage_public_placeholder"
        python["http"]["routes"].append(route)
        with self.assertRaises(Error):
            profile(python)
        value["http"]["routes"].append(copy.deepcopy(route))
        with self.assertRaises(Error):
            profile(value)

    def test_service_override_cannot_be_a_primary_or_additional_probe(self):
        from tests.test_sandbox import command_profile

        value = command_profile()
        value["environment"]["STORAGE_TOKEN"] = "storage_public_placeholder"
        value["http"]["routes"].append(
            {
                "method": "GET",
                "path": "/api/v1/storage",
                "origin": "http://127.0.0.1:60763",
                "credential-header": "Example-Storage-Credential",
                "placeholder": "storage_public_placeholder",
            }
        )
        value["http"]["additional-probes"] = ["/api/v1/storage"]
        with self.assertRaises(Error):
            profile(value)
        value["http"].pop("additional-probes")
        value["http"]["probe"] = "/api/v1/storage"
        with self.assertRaises(Error):
            profile(value)

    def test_retired_sidecars_and_broken_links_are_detected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".infisical.broker.yaml").write_text("version: 1\n")
            (root / ".infisical.reader.yml").symlink_to(root / "absent")
            (root / ".runbox.yaml").write_text("version: 1\n")
            self.assertEqual(
                retired_configs(root),
                [".infisical.broker.yaml", ".infisical.reader.yml"],
            )

    def test_additional_read_checks_cannot_turn_into_model_calls(self):
        value = copy.deepcopy(PROFILE)
        value["http"]["additional-probes"] = [value["http"]["probe"]]
        profile(value)
        value["http"]["additional-probes"] = ["/api/v1/chat/completions"]
        with self.assertRaises(Error):
            profile(value)

    def test_metadata_only_bindings_and_brokers_do_not_create_command_profiles(self):
        from copy import deepcopy

        binding = {
            "type": "infisical",
            "instance": PROFILE["provider"]["instance"],
            "source": deepcopy(PROFILE["provider"]["source"]),
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / ".runbox.yaml"
            path.write_text(
                json.dumps({"version": 1, "bindings": {"default": binding}})
            )
            self.assertNotIn("profiles", load(path))
            binding["secret-value"] = "synthetic-private-value"
            path.write_text(
                json.dumps({"version": 1, "bindings": {"default": binding}})
            )
            with self.assertRaises(Error):
                load(path)

    def test_python_root_source_and_explicit_readiness_alias(self):
        value = copy.deepcopy(PROFILE)
        value["execution"]["python"]["source"] = "."
        value["http"]["probe-aliases"] = [{"method": "HEAD", "path": "/api/v1"}]
        profile(value)
        value["http"]["probe-aliases"][0]["method"] = "POST"
        with self.assertRaises(Error):
            profile(value)

    def test_supported_profile_and_unsandboxed_generic_command(self):
        profile(copy.deepcopy(PROFILE))
        extended = copy.deepcopy(PROFILE)
        extended["session"]["ttl"] = "8h"
        profile(extended)
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
            ("session", "ttl", "481m"),
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
