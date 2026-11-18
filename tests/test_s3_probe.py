from copy import deepcopy
import json
import unittest
from unittest.mock import Mock

from runbox.config import Error
from runbox.s3_probe import execute, select, validate


def client():
    return {
        "type": "s3-head",
        "targets": [
            {
                "bucket": "example-models",
                "endpoint-variable": "MODELS_ENDPOINT",
                "access-variable": "MODELS_ACCESS_KEY",
                "secret-variable": "MODELS_SECRET_KEY",
            },
            {
                "bucket": "example-public",
                "endpoint-variable": "PUBLIC_ENDPOINT",
                "access-variable": "PUBLIC_ACCESS_KEY",
                "secret-variable": "PUBLIC_SECRET_KEY",
            },
        ],
    }


def environment():
    return {
        f"{role}_{name}": value
        for role, port in (("MODELS", 19404), ("PUBLIC", 19405))
        for name, value in (
            ("ENDPOINT", f"http://127.0.0.1:{port}"),
            ("ACCESS_KEY", role.lower() + "_access_placeholder"),
            ("SECRET_KEY", role.lower() + "_secret_placeholder"),
        )
    }


class S3ProbeTests(unittest.TestCase):
    def test_profile_schema_requires_all_public_targets_without_bearer_policy(self):
        from runbox.config import profile
        from tests.test_sandbox import command_profile

        value = command_profile()
        value.pop("http")
        value["environment"] = environment()
        value["execution"]["client"] = client()
        profile(value)
        value["environment"]["PUBLIC_ENDPOINT"] = "https://other.test"
        with self.assertRaises(Error):
            profile(value)
        value["environment"] = environment()
        value["http"] = {"fixture": True}
        with self.assertRaises(Error):
            profile(value)

    def test_complete_inventory_preflights_before_sdk_creation(self):
        for name, value in (
            ("PUBLIC_ENDPOINT", "https://other.test"),
            ("PUBLIC_ACCESS_KEY", "secret-canary"),
            ("PUBLIC_SECRET_KEY", ""),
        ):
            current = environment()
            current[name] = value
            factory = Mock()
            with self.subTest(name=name), self.assertRaises(Error):
                execute(client(), current, [], factory, Mock())
            factory.assert_not_called()

    def test_unsafe_endpoints_and_missing_placeholders_are_rejected(self):
        for endpoint in (
            "http://127.0.0.1:80",
            "http://localhost:19404",
            "http://127.0.0.1:bad",
            "http://x:y@127.0.0.1:19404",
            "http://127.0.0.1:19404/other",
            "http://127.0.0.1:19404?key=x",
            "http://127.0.0.1:19404#fragment",
            "http://127.0.0.1:19404/",
        ):
            current = environment()
            current["MODELS_ENDPOINT"] = endpoint
            with self.subTest(endpoint=endpoint), self.assertRaises(Error):
                select(client(), current)
        current = environment()
        del current["MODELS_SECRET_KEY"]
        with self.assertRaises(Error):
            select(client(), current)

    def test_closed_schema_bucket_bounds_and_unique_targets(self):
        for mutation in (
            "extra",
            "empty",
            "duplicate",
            "many",
            "traversal",
            "variable",
        ):
            value = client()
            if mutation == "extra":
                value["entrypoint"] = "other:main"
            elif mutation == "empty":
                value["targets"] = []
            elif mutation == "duplicate":
                value["targets"].append(deepcopy(value["targets"][0]))
            elif mutation == "many":
                value["targets"] *= 3
            elif mutation == "traversal":
                value["targets"][0]["bucket"] = "../other"
            else:
                value["targets"][0]["secret-variable"] = "HOME"
            if mutation == "variable":
                # A syntactically valid selector still cannot select a real value.
                with self.assertRaises(Error):
                    select(value, {**environment(), "HOME": "/private/home"})
            else:
                with self.subTest(mutation=mutation), self.assertRaises(Error):
                    validate(value)

    def test_only_head_bucket_with_explicit_credentials_and_no_retry(self):
        sdk = Mock()
        sdk.head_bucket.return_value = {"ResponseMetadata": {"HTTPStatusCode": 200}}
        factory = Mock(return_value=sdk)
        configuration = Mock()
        result = execute(client(), environment(), [], factory, configuration)
        self.assertEqual(result["item_count"], 2)
        self.assertEqual(
            sdk.head_bucket.call_args_list[0].kwargs, {"Bucket": "example-models"}
        )
        self.assertEqual(
            sdk.head_bucket.call_args_list[1].kwargs, {"Bucket": "example-public"}
        )
        self.assertEqual(sdk.close.call_count, 2)
        self.assertEqual(
            [call[0] for call in sdk.method_calls], ["head_bucket", "close"] * 2
        )
        self.assertEqual(
            configuration.call_args.kwargs["retries"]["total_max_attempts"], 1
        )
        self.assertTrue(
            all(
                call.kwargs["aws_secret_access_key"].endswith("_placeholder")
                for call in factory.call_args_list
            )
        )
        self.assertNotIn("example-models", json.dumps(result))

    def test_failure_stops_before_second_bucket_closes_client_and_redacts_error(self):
        sdk = Mock()
        sdk.head_bucket.side_effect = RuntimeError("private-provider-canary")
        factory = Mock(return_value=sdk)
        with self.assertRaises(Error) as error:
            execute(client(), environment(), [], factory, Mock())
        self.assertNotIn("canary", str(error.exception))
        factory.assert_called_once()
        sdk.close.assert_called_once()

    def test_non_success_metadata_fails_and_arguments_cannot_add_operations(self):
        sdk = Mock()
        sdk.head_bucket.return_value = {"ResponseMetadata": {"HTTPStatusCode": 403}}
        factory = Mock(return_value=sdk)
        with self.assertRaises(Error):
            execute(client(), environment(), [], factory, Mock())
        sdk.close.assert_called_once()
        factory.reset_mock()
        with self.assertRaises(Error):
            execute(client(), environment(), ["delete"], factory, Mock())
        factory.assert_not_called()

    def test_sdk_failures_expose_only_valid_numeric_status_and_close(self):
        class Failure(Exception):
            pass
        for status, expected in ((403, "HTTP 403"), (502, "HTTP 502"),
                                 ("private-status-canary", "S3 bucket"),
                                 (True, "S3 bucket"), (200, "S3 bucket")):
            sdk = Mock()
            failure = Failure("private-provider-canary")
            failure.response = {"ResponseMetadata": {"HTTPStatusCode": status,
                                "HTTPHeaders": {"authorization": "private-header-canary"}},
                                "Error": {"Message": "private-body-canary"}}
            sdk.head_bucket.side_effect = failure
            factory = Mock(return_value=sdk)
            with self.subTest(status=status), self.assertRaises(Error) as caught:
                execute(client(), environment(), [], factory, Mock())
            self.assertIn(expected, str(caught.exception))
            self.assertNotIn("canary", str(caught.exception))
            factory.assert_called_once(); sdk.close.assert_called_once()

    def test_signer_stage_is_a_closed_header_value_with_no_provider_text(self):
        class Failure(Exception):
            pass
        for header, expected in (({"x-runbox-s3-stage": "request-signing"}, "S3 stage request-signing"),
                                 ({"X-Runbox-S3-Stage": "upstream-tls"}, "S3 stage upstream-tls"),
                                 ({"x-runbox-s3-stage": "private-canary"}, None),
                                 ({"x-runbox-s3-stage": ["private-canary"]}, None),
                                 ({"x-runbox-s3-stage": "upstream-tls", "X-Runbox-S3-Stage": "upstream-tls"}, None)):
            failure = Failure("private-provider-canary")
            failure.response = {"ResponseMetadata": {"HTTPStatusCode": 502, "HTTPHeaders": header}}
            sdk = Mock(); sdk.head_bucket.side_effect = failure
            with self.subTest(header=header), self.assertRaises(Error) as caught:
                execute(client(), environment(), [], Mock(return_value=sdk), Mock())
            text = str(caught.exception)
            self.assertIn("HTTP 502", text); self.assertNotIn("canary", text)
            if expected is None:self.assertNotIn("S3 stage", text)
            else:self.assertIn(expected, text)
            sdk.close.assert_called_once()

    def test_numeric_upstream_status_requires_exact_signer_stage_and_never_becomes_success(self):
        class Failure(Exception):
            pass
        for original, stage, expected in (("301", "upstream-status", 301), ("401", "upstream-status", 401),
                                          ("503", "upstream-status", 503), ("200", "upstream-status", 502),
                                          ("private-canary", "upstream-status", 502), ("301", "request-signing", 502)):
            error = Failure("private-provider-canary")
            error.response = {"ResponseMetadata": {"HTTPStatusCode": 502, "HTTPHeaders": {
                "x-runbox-s3-stage": stage, "x-runbox-s3-upstream-status": original}}}
            sdk = Mock(); sdk.head_bucket.side_effect = error
            with self.subTest(original=original, stage=stage), self.assertRaises(Error) as caught:
                execute(client(), environment(), [], Mock(return_value=sdk), Mock())
            self.assertIn(f"HTTP {expected}", str(caught.exception))
            self.assertNotIn("canary", str(caught.exception)); sdk.close.assert_called_once()
