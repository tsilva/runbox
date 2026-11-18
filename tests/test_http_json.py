import io
import json
import unittest
from contextlib import contextmanager

from runbox.config import Error
from runbox.http_json import (
    MAX_INPUT,
    MAX_RESPONSE,
    execute,
    request_group,
    validate_request,
)

POLICY = {
    "base-url": "https://sheets.googleapis.com",
    "placeholder": "finite_public_placeholder",
    "routes": [
        {"method": "GET", "path": "/v4/spreadsheets/fixture"},
        {"method": "POST", "path": "/v4/spreadsheets/fixture:batchUpdate"},
    ],
}


class HttpJsonTests(unittest.TestCase):
    def test_batch_preflights_all_routes_before_domain_reads_or_writes(self):
        profile = {
            "http": POLICY,
            "environment": {},
            "execution": {"client": {"validator": "fixture:validate"}},
        }
        valid = {
            "method": "POST",
            "url": POLICY["base-url"] + "/v4/spreadsheets/fixture:batchUpdate",
            "body": {},
        }
        for members in (
            [valid, {**valid, "url": "https://other.test/"}],
            [valid] * 4,
            [{**valid, "context": {}}],
            [{**valid, "method": "GET"}],
        ):
            with self.subTest(members=members), self.assertRaises(Error):
                validate_request(
                    json.dumps({"requests": members}).encode(),
                    profile,
                    {},
                    lambda *args: self.fail(
                        "Validator ran before complete route preflight"
                    ),
                )

    def test_batch_requires_validator_and_preserves_original_sequence(self):
        member = {
            "method": "POST",
            "url": POLICY["base-url"] + "/v4/spreadsheets/fixture:batchUpdate",
            "body": {"requests": []},
        }
        raw = json.dumps(
            {"requests": [member, member], "context": {"fixture": True}}
        ).encode()
        profile = {"http": POLICY, "environment": {}, "execution": {"client": {}}}
        with self.assertRaises(Error):
            validate_request(raw, profile, {"fixture": True})
        profile["execution"]["client"]["validator"] = "fixture:validate"

        def validator(payload, read, environment):
            self.assertEqual(payload["requests"], [member, member])
            payload["requests"].clear()

        validate_request(raw, profile, {"fixture": True}, validator)
        payload, members = request_group(raw, POLICY, {"fixture": True})
        self.assertEqual(len(members), 2)
        self.assertEqual(payload["requests"], [member, member])

    def test_consumer_validator_has_only_guarded_gets_and_a_fixed_read_budget(self):
        profile = {
            "http": POLICY,
            "environment": {},
            "execution": {"client": {"validator": "fixture:validate"}},
        }
        raw = json.dumps(
            {
                "method": "POST",
                "url": POLICY["base-url"] + "/v4/spreadsheets/fixture:batchUpdate",
                "body": {},
            }
        ).encode()
        calls = []

        @contextmanager
        def transport(request, timeout):
            calls.append(request.get_method())
            response = io.BytesIO(b"{}")
            response.status = 200
            yield response

        def validator(payload, read, environment):
            for _ in range(5):
                read(POLICY["base-url"] + "/v4/spreadsheets/fixture")

        with self.assertRaises(Error):
            validate_request(raw, profile, {}, validator, transport)
        self.assertEqual(calls, ["GET"] * 4)

    def test_public_context_must_match_exactly_before_transport(self):
        for supplied in [
            {},
            {"principal": "other"},
            {"principal": "fixture", "extra": True},
            {"principal": True},
        ]:
            with self.subTest(context=supplied), self.assertRaises(Error):
                execute(
                    json.dumps(
                        {
                            "method": "GET",
                            "url": POLICY["base-url"] + "/v4/spreadsheets/fixture",
                            "context": supplied,
                        }
                    ).encode(),
                    POLICY,
                    lambda *args, **kwargs: self.fail("Transport opened"),
                    context={"principal": "fixture"},
                )

    def test_exact_body_and_owned_headers_cross_transport_without_credentials_in_input(
        self,
    ):
        calls = []

        @contextmanager
        def transport(request, timeout):
            calls.append(request)
            self.assertEqual(timeout, 30)
            response = io.BytesIO(b'{"spreadsheetId":"fixture"}')
            response.status = 200
            yield response

        payload = {
            "method": "POST",
            "url": POLICY["base-url"] + "/v4/spreadsheets/fixture:batchUpdate",
            "body": {"requests": [{"fixture": "private worksheet data"}]},
        }
        result = execute(json.dumps(payload).encode(), POLICY, transport)
        self.assertEqual(result, {"status": 200, "body": {"spreadsheetId": "fixture"}})
        self.assertEqual(json.loads(calls[0].data), payload["body"])
        self.assertEqual(
            calls[0].get_header("Authorization"), "Bearer finite_public_placeholder"
        )

    def test_malformed_payload_headers_wrong_method_or_workbook_never_reach_transport(
        self,
    ):
        for value in [
            b"{}",
            b"[]",
            b'{"method":"GET","method":"POST"}',
            b'{"method":"GET","url":"https://sheets.googleapis.com/v4/spreadsheets/fixture","headers":{}}',
            json.dumps(
                {"method": "GET", "url": POLICY["base-url"] + "/v4/spreadsheets/other"}
            ).encode(),
            json.dumps(
                {
                    "method": "DELETE",
                    "url": POLICY["base-url"] + "/v4/spreadsheets/fixture",
                }
            ).encode(),
            json.dumps(
                {
                    "method": "GET",
                    "url": POLICY["base-url"] + "/v4/spreadsheets/fixture",
                    "body": {},
                }
            ).encode(),
            b"x" * (MAX_INPUT + 1),
        ]:
            with (
                self.subTest(length=len(value)),
                self.assertRaises((Error, ValueError)),
            ):
                execute(
                    value, POLICY, lambda *args, **kwargs: self.fail("Transport opened")
                )

    def test_redirect_invalid_json_and_oversized_response_are_rejected(self):
        for status, body in [
            (302, b"{}"),
            (401, b'{"private":"not diagnostic"}'),
            (200, b"not-json"),
            (200, b"x" * (MAX_RESPONSE + 1)),
        ]:

            @contextmanager
            def transport(*args, **kwargs):
                response = io.BytesIO(body)
                response.status = status
                yield response

            with (
                self.subTest(status=status, size=len(body)),
                self.assertRaises((Error, ValueError)),
            ):
                execute(
                    json.dumps(
                        {
                            "method": "GET",
                            "url": POLICY["base-url"] + "/v4/spreadsheets/fixture",
                        }
                    ).encode(),
                    POLICY,
                    transport,
                )
