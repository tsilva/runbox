import unittest

from runbox.output import safe_output


class OutputTests(unittest.TestCase):
    def test_session_and_provider_secrets_are_removed(self):
        raw = (
            "http://synthetic:agv_fake_session@127.0.0.1:8283/ "
            "postgresql://reader:synthetic-password@localhost/db "
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.synthetic_signature "
            "sk_test_syntheticKey sk-or-v1-syntheticOpenRouter"
        )
        output = safe_output(raw)
        for value in (
            "agv_fake_session",
            "synthetic-password",
            "synthetic_signature",
            "syntheticKey",
            "syntheticOpenRouter",
        ):
            self.assertNotIn(value, output)
        self.assertIn("127.0.0.1:8283", output)

    def test_capability_and_sensitive_queries_are_removed(self):
        raw = (
            "/objects/"
            + "x" * 43
            + "?nonce=synthetic&code=secret&state=private&limit=1&__clerk_ticket=other"
        )
        self.assertEqual(
            safe_output(raw),
            "/objects/[redacted-capability]?nonce=[redacted]&code=[redacted]&state=[redacted]&limit=1&__clerk_ticket=[redacted]",
        )

    def test_exact_runtime_redactions_and_terminal_escapes(self):
        self.assertEqual(
            safe_output(
                "value=syntheticExact \x1b[31msk_test_split\x1b[0m", ["syntheticExact"]
            ),
            "value=[redacted] [redacted-key]",
        )

    def test_normal_development_output_is_preserved(self):
        raw = "Local: http://127.0.0.1:3011\nCompiled /settings in 32ms\n"
        self.assertEqual(safe_output(raw), raw)
