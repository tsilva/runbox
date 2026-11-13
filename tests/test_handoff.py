import unittest
from unittest.mock import patch

from runbox.config import Error
from runbox.handoff import preflight, provider_environment, validate


class HandoffTests(unittest.TestCase):
    def fixture(self):
        return {
            "environment": {"EXAMPLE_API_KEY": "example_proxy_placeholder"},
            "execution": {
                "handoff": {
                    "proxy-variable": "EXAMPLE_PROXY_URL",
                    "ca-variable": "EXAMPLE_CA_FILE",
                    "require-stopped": ["127.0.0.1:8082"],
                }
            },
        }

    def test_transport_stays_provider_local(self):
        profile = self.fixture()
        env = provider_environment(
            profile,
            {"ca-file": "/synthetic/public.pem"},
            {
                "HTTPS_PROXY": "http://synthetic:agv_fake@127.0.0.1:8283",
                "INFISICAL_TOKEN": "never-copy",
                "SSL_CERT_FILE": "/wrong",
                "OPENAI_API_KEY": "never-copy",
            },
        )
        self.assertEqual(
            set(env),
            {"HOME", "PATH", "EXAMPLE_API_KEY", "EXAMPLE_PROXY_URL", "EXAMPLE_CA_FILE"},
        )
        self.assertEqual(env["EXAMPLE_CA_FILE"], "/synthetic/public.pem")

    def test_running_service_blocks_before_session_creation(self):
        with patch("runbox.handoff.socket.socket") as factory:
            factory.return_value.__enter__.return_value.connect_ex.return_value = 0
            with self.assertRaises(Error):
                preflight(self.fixture())

    def test_no_global_transport_override(self):
        value = self.fixture()["execution"]["handoff"]
        for field, replacement in (
            ("proxy-variable", "HTTP_PROXY"),
            ("ca-variable", "SSL_CERT_FILE"),
            ("require-stopped", ["0.0.0.0:8082"]),
        ):
            with self.assertRaises(Error):
                validate({**value, field: replacement})
