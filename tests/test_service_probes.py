import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from runbox.config import Error
from runbox.service_probes import _isolated, _session, huggingface_read, wandb


class ServiceProbeTests(unittest.TestCase):
    def test_unreviewed_marker_fails_before_sdk_import_or_network(self):
        for probe, variable in (
            (huggingface_read, "HF_TOKEN"),
            (wandb, "WANDB_API_KEY"),
        ):
            with (
                self.subTest(variable=variable),
                patch.dict(os.environ, {variable: "ordinary-secret"}, clear=True),
            ):
                with (
                    patch.object(
                        sys,
                        "argv",
                        [
                            "probe",
                            "--account",
                            "synthetic-user",
                            "--token-name",
                            "synthetic-token",
                        ],
                    ),
                    self.assertRaises(Error),
                ):
                    probe()

    def test_expected_identity_must_be_explicit_public_identifiers(self):
        for arguments in (
            [],
            ["--account", "user", "--token-name", "bad\nname"],
            ["--account", "../user", "--token-name", "token"],
        ):
            with (
                patch.object(sys, "argv", ["probe", *arguments]),
                self.assertRaises(Error),
            ):
                huggingface_read()

    def test_proxy_requires_loopback_capability_and_exact_native_instance(self):
        with tempfile.TemporaryDirectory() as directory:
            ca = Path(directory) / "ca.pem"
            ca.write_text("synthetic public CA")
            base = {
                "HF_TOKEN": "huggingface_read_proxy_placeholder",
                "INFISICAL_AGENT_VAULT_URL": "https://app.infisical.com",
                "SSL_CERT_FILE": str(ca),
            }
            for proxy in (
                "http://remote.invalid:8283",
                "http://127.0.0.1:8283",
                "https://u:p@127.0.0.1:8283",
                "http://u:p@127.0.0.1:8283/extra",
            ):
                with (
                    self.subTest(proxy=proxy),
                    patch.dict(
                        os.environ,
                        {**base, "HTTP_PROXY": proxy, "HTTPS_PROXY": proxy},
                        clear=True,
                    ),
                ):
                    with self.assertRaises(Error):
                        _session("HF_TOKEN", "huggingface_read_proxy_placeholder")
            proxy = "http://u:p@127.0.0.1:8283"
            with patch.dict(
                os.environ,
                {**base, "HTTP_PROXY": proxy, "HTTPS_PROXY": proxy},
                clear=True,
            ):
                self.assertEqual(
                    _session("HF_TOKEN", "huggingface_read_proxy_placeholder"),
                    (proxy, str(ca)),
                )
            with patch.dict(
                os.environ,
                {
                    **base,
                    "HTTP_PROXY": proxy,
                    "HTTPS_PROXY": proxy,
                    "INFISICAL_AGENT_VAULT_URL": "https://alternate.invalid",
                },
                clear=True,
            ):
                with self.assertRaises(Error):
                    _session("HF_TOKEN", "huggingface_read_proxy_placeholder")

    def test_isolation_uses_disposable_cache_and_restores_parent_environment(self):
        original = dict(os.environ)
        with _isolated():
            home = Path(os.environ["HOME"])
            self.assertTrue(home.is_dir())
            self.assertEqual(os.environ["NETRC"], "/dev/null")
            self.assertEqual(os.environ["HF_HUB_DISABLE_IMPLICIT_TOKEN"], "1")
            (home / "synthetic-cache").write_text("no credentials")
        self.assertFalse(home.exists())
        self.assertEqual(dict(os.environ), original)
