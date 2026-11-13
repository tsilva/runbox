import unittest

from runbox.config import Error
from runbox.python_client import response_result


class ResponseTests(unittest.TestCase):
    def test_only_verified_identity_and_count_are_emitted(self):
        result = response_result(
            {"name": "expected", "private": "never emitted", "data": [1, 2]},
            {"checks": [{"path": ["name"], "equals": "expected"}], "count": ["data"]},
        )
        self.assertEqual(
            result,
            {
                "ok": True,
                "read_only": True,
                "credential_mode": "public-placeholder",
                "item_count": 2,
            },
        )

    def test_identity_shape_and_type_must_match(self):
        for body in ({}, {"name": "wrong"}, {"name": True}):
            with self.assertRaises(Error):
                response_result(
                    body, {"checks": [{"path": ["name"], "equals": "expected"}]}
                )

    def test_boolean_is_not_an_integer_status(self):
        with self.assertRaises(Error):
            response_result(
                {"code": True}, {"checks": [{"path": ["code"], "equals": 1}]}
            )
