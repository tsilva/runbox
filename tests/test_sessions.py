import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from runbox.config import Error
from runbox.sessions import (
    Prepared,
    dynamic_environment,
    prepare,
    safe_output,
    validate,
)


def profile():
    return {
        "provider": {
            "type": "infisical",
            "instance": "https://app.infisical.com",
            "project-id": "5078c850-3f93-46d8-8afe-82107df8b931",
        },
        "session": {
            "ttl": "45m",
            "proxy": "127.0.0.1:28383",
            "worker": {
                "access-bundle": "local-training-worker",
                "ttl": "7h",
                "proxy": "172.17.0.1:28383",
                "when": [
                    ["gradlab", "experiment", "launch"],
                    ["gradlab", "experiment", "retry"],
                ],
                "capability-variable": "GRADLAB_VAULT_WORKER_CAPABILITY_TOKEN",
                "context-variable": "GRADLAB_VAULT_WORKER_CONTEXT",
                "secret-prefix": "GRADLAB_VAULT_SESSION_",
            },
        },
    }


class SessionsTests(unittest.TestCase):
    def setUp(self):
        self.profile = profile()
        self.runtime = {
            "infisical": "/reviewed/infisical",
            "binaries": {"ssh": "/usr/bin/ssh"},
        }
        self.session = {
            "id": "11111111-2222-4333-8444-555555555555",
            "token": "agv_synthetic-never-print",
            "expiresAt": (datetime.now(timezone.utc) + timedelta(hours=7)).isoformat(),
        }

    def test_worker_capability_only_in_environment_and_retained_after_start_attempt(
        self,
    ):
        calls = []

        def native(_profile, _runtime, args):
            calls.append(args)
            return json.dumps(self.session)

        with patch("runbox.sessions._native", native):
            with prepare(
                self.profile, self.runtime, ["gradlab", "experiment", "launch"]
            ) as session:
                self.assertNotIn(self.session["token"], repr(calls))
                self.assertIn(
                    "agv_synthetic",
                    session.environment["GRADLAB_VAULT_WORKER_CAPABILITY_TOKEN"],
                )
                with patch.dict(os.environ, session.environment, clear=True):
                    self.assertEqual(
                        dynamic_environment(self.profile), session.environment
                    )
                session.mark_started()
        self.assertEqual(len(calls), 1)

    def test_prestart_failure_revokes_created_worker(self):
        calls = []

        def native(_profile, _runtime, args):
            calls.append(args)
            return json.dumps(self.session)

        with (
            patch("runbox.sessions._native", native),
            self.assertRaisesRegex(RuntimeError, "before start"),
        ):
            with prepare(
                self.profile, self.runtime, ["gradlab", "experiment", "retry"]
            ):
                raise RuntimeError("before start")
        self.assertEqual(calls[-1], ["revoke", self.session["id"]])

    def test_nonadmitting_commands_create_no_worker(self):
        with patch("runbox.sessions._native") as native:
            with prepare(
                self.profile, self.runtime, ["gradlab", "experiment", "status"]
            ) as session:
                self.assertEqual(session.environment, {})
            native.assert_not_called()

    def test_only_owned_managed_forward_is_cancelled(self):
        self.profile["session"]["tunnel"] = {
            "host": "beast-3",
            "local": "127.0.0.1:28383",
            "remote": "172.17.0.1:28383",
        }
        with (
            patch("runbox.sessions.socket.create_connection", side_effect=OSError),
            patch.object(Prepared, "_ssh") as ssh,
        ):
            with prepare(
                self.profile, self.runtime, ["gradlab", "experiment", "status"]
            ):
                pass
            self.assertEqual(
                [c.args[0] for c in ssh.call_args_list],
                [
                    ["-O", "check", "beast-3"],
                    [
                        "-O",
                        "forward",
                        "-L",
                        "127.0.0.1:28383:172.17.0.1:28383",
                        "beast-3",
                    ],
                    [
                        "-O",
                        "cancel",
                        "-L",
                        "127.0.0.1:28383:172.17.0.1:28383",
                        "beast-3",
                    ],
                ],
            )
        with (
            patch("runbox.sessions.socket.create_connection"),
            patch.object(Prepared, "_ssh") as ssh,
        ):
            with prepare(
                self.profile, self.runtime, ["gradlab", "experiment", "status"]
            ):
                pass
            ssh.assert_not_called()

    def configure_shared_forward(self):
        self.runtime["shared-tunnel"] = True
        self.profile["session"]["tunnel"] = {
            "host": "beast-3",
            "local": "127.0.0.1:28383",
            "remote": "172.17.0.1:28383",
        }

    def test_shared_forward_survives_first_consumer_close_and_rejects_other_binding(self):
        self.configure_shared_forward()
        calls = []
        owns_listener = False

        def ssh(arguments):
            nonlocal owns_listener
            action = arguments[1]
            calls.append(action)
            if action == "forward":
                owns_listener = True
            elif action == "cancel":
                owns_listener = False
            return subprocess.CompletedProcess(arguments, 0, b"", b"Master running (pid=123)\r\n")

        with (
            tempfile.TemporaryDirectory() as directory,
            patch("runbox.tunnels.state", return_value=Path(directory).resolve()),
            patch("runbox.tunnels.SharedForward.listening", side_effect=lambda: owns_listener),
            patch.object(Prepared, "_ssh", side_effect=ssh),
        ):
            first = Prepared(self.profile, self.runtime, [])
            second = Prepared(self.profile, self.runtime, [])
            try:
                first.open()
                second.open()
                conflict = json.loads(json.dumps(self.profile))
                conflict["session"]["tunnel"]["remote"] = "172.17.0.2:28383"
                with self.assertRaisesRegex(Error, "no longer matches"):
                    Prepared(conflict, self.runtime, []).open()
                first.close()
                self.assertTrue(owns_listener)
                self.assertNotIn("cancel", calls)
                second.close()
                self.assertFalse(owns_listener)
                self.assertEqual(calls.count("forward"), 1)
                self.assertEqual(calls.count("cancel"), 1)
            finally:
                first.close()
                second.close()

    def test_shared_forward_does_not_adopt_an_unowned_listener(self):
        self.configure_shared_forward()
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("runbox.tunnels.state", return_value=Path(directory).resolve()),
            patch("runbox.tunnels.SharedForward.listening", return_value=True),
            patch.object(Prepared, "_ssh") as ssh,
        ):
            with self.assertRaisesRegex(Error, "unowned listener"):
                Prepared(self.profile, self.runtime, []).open()
            ssh.assert_not_called()

    def test_shared_forward_never_cancels_after_master_replacement(self):
        self.configure_shared_forward()
        actions = []
        pid = 123
        owns_listener = False

        def ssh(arguments):
            nonlocal owns_listener
            actions.append(arguments[1])
            if arguments[1] == "forward":
                owns_listener = True
            return subprocess.CompletedProcess(arguments, 0, b"", f"Master running (pid={pid})\n".encode())

        with (
            tempfile.TemporaryDirectory() as directory,
            patch("runbox.tunnels.state", return_value=Path(directory).resolve()),
            patch("runbox.tunnels.SharedForward.listening", side_effect=lambda: owns_listener),
            patch.object(Prepared, "_ssh", side_effect=ssh),
        ):
            session = Prepared(self.profile, self.runtime, []).open()
            pid = 124
            with self.assertRaisesRegex(Error, "master changed"):
                session.close()
            self.assertEqual(actions, ["check", "forward", "check"])

    def test_invalid_capability_response_is_revoked_without_echo(self):
        self.session["token"] = "not-native-secret"
        calls = []

        def native(_profile, _runtime, args):
            calls.append(args)
            return json.dumps(self.session)

        with (
            patch("runbox.sessions._native", native),
            self.assertRaises(Error) as caught,
        ):
            with prepare(
                self.profile, self.runtime, ["gradlab", "experiment", "launch"]
            ):
                pass
        self.assertNotIn("not-native-secret", str(caught.exception))
        self.assertEqual(calls[-1], ["revoke", self.session["id"]])

    def test_dynamic_environment_rejects_scope_or_context_substitution(self):
        with patch("runbox.sessions._native", return_value=json.dumps(self.session)):
            session = Prepared(
                self.profile, self.runtime, ["gradlab", "experiment", "launch"]
            ).open()
        for key, value in [
            (
                "GRADLAB_VAULT_WORKER_CAPABILITY_TOKEN",
                "http://x-agent-vault:agv_bad@1.1.1.1:443",
            ),
            ("GRADLAB_VAULT_WORKER_CONTEXT", "{}"),
        ]:
            with (
                patch.dict(os.environ, {**session.environment, key: value}, clear=True),
                self.assertRaises((Error, ValueError)),
            ):
                dynamic_environment(self.profile)

    def test_tunnel_and_reserved_environment_validation(self):
        for endpoint in ("1.1.1.1:28383", "0.0.0.0:28383", "127.0.0.1:22"):
            value = profile()
            value["session"]["worker"]["proxy"] = endpoint
            with self.assertRaises(Error):
                validate(value["session"])
        value = profile()
        value["session"]["worker"]["capability-variable"] = "HTTPS_PROXY"
        with self.assertRaises(Error):
            validate(value["session"])

    def test_diagnostics_redact_urls_and_unadorned_capabilities(self):
        text = safe_output(
            "failed http://x-agent-vault:agv_synthetic@172.17.0.1:28383 or agv_synthetic-other"
        )
        self.assertNotIn("agv_", text)
        self.assertNotIn("x-agent-vault:", text)
