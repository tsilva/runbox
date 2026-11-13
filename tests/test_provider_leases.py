"""Owned finite sessions never change delegated-workload ownership."""

import contextlib
import io
import json
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from runbox.providers import Infisical
from runbox.runner import execute


class OwnedLeaseTests(unittest.TestCase):
    def setUp(self):
        self.profile = {
            "provider": {
                "instance": "https://example.invalid",
                "project-id": "p",
                "access-bundle": "b",
            },
            "session": {"proxy": "127.0.0.1:8283", "ttl": "8h"},
        }
        self.runtime = {"infisical": "/synthetic/infisical", "ca-fingerprint": "fake"}
        self.value = {
            "id": "12345678-1234-4234-8234-123456789012",
            "token": "agv_fake",
            "expiresAt": (datetime.now(timezone.utc) + timedelta(hours=8)).isoformat(),
        }

    def test_existing_probe_uses_only_environment_capability(self):
        command = Infisical.command(
            self.profile, self.runtime, ["probe"], existing_session=True
        )
        self.assertFalse(any(arg.startswith("--access-bundle=") for arg in command))
        self.assertFalse(any(arg.startswith("--project-id=") for arg in command))
        self.assertFalse(any(arg.startswith("--ttl=") for arg in command))
        self.assertNotIn("agv_fake", " ".join(command))
        self.assertEqual(
            Infisical.session_environment(self.value),
            {"INFISICAL_AGENT_VAULT_SESSION_TOKEN": "agv_fake"},
        )
        self.assertEqual(
            Infisical.proxy_url(self.profile, self.value),
            "http://x-agent-vault:agv_fake@127.0.0.1:8283",
        )

    def test_malformed_owned_response_revokes_known_id(self):
        invalid = {**self.value, "token": "invalid-private-value"}
        with patch(
            "runbox.sessions._native", side_effect=[json.dumps(invalid), ""]
        ) as native:
            with self.assertRaisesRegex(ValueError, "diagnostics withheld"):
                Infisical.create_lease(self.profile, self.runtime)
        self.assertEqual(
            native.call_args_list[-1].args[2], ["revoke", self.value["id"]]
        )

    def test_lease_preserves_original_ttl_and_scope(self):
        with patch(
            "runbox.sessions._native", return_value=json.dumps(self.value)
        ) as native:
            self.assertEqual(
                Infisical.create_lease(self.profile, self.runtime), self.value
            )
        arguments = native.call_args.args[2]
        self.assertIn("--ttl=8h", arguments)
        self.assertIn("--access-bundle=b", arguments)

    def test_failed_creation_cleanup_reports_only_finite_bound(self):
        invalid = {**self.value, "token": "invalid-private-value"}
        output = io.StringIO()
        with patch(
            "runbox.sessions._native",
            side_effect=[json.dumps(invalid), ValueError("private-diagnostics")],
        ):
            with contextlib.redirect_stderr(output), self.assertRaises(ValueError):
                Infisical.create_lease(self.profile, self.runtime)
        self.assertEqual(
            output.getvalue(),
            "Session cleanup could not be verified; finite expiry still applies\n",
        )

    def test_background_probe_is_quiet_and_cleans_up(self):
        results, errors = [], []
        record = {"ok": True, "read_only": True, "credential_mode": "none"}

        def probe():
            try:
                results.append(
                    execute(
                        [
                            sys.executable,
                            "-c",
                            "print(" + repr(json.dumps(record)) + ")",
                        ],
                        Path(tempfile.gettempdir()),
                        probe=True,
                        report_probe=False,
                    )
                )
            except BaseException as exc:
                errors.append(type(exc).__name__)

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            thread = threading.Thread(target=probe)
            thread.start()
            thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(results, [0])
        self.assertEqual(output.getvalue(), "")
