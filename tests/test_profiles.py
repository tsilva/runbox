import copy
import unittest

from runbox.__main__ import select_profile
from runbox.config import Error, argument_policy, arguments_match
from tests.support import PROFILE


class ProfileSelectionTests(unittest.TestCase):
    def test_typed_argument_patterns_keep_report_routes_separate(self):
        historical = [["report.py", "--request-json", {"pattern": "[0-9]{9}"}]]
        realtime = [["report.py", "--request-realtime-json", {"pattern": "[0-9]{9}"}]]
        argument_policy(historical)
        self.assertTrue(
            arguments_match(historical, ["report.py", "--request-json", "123456789"])
        )
        self.assertFalse(
            arguments_match(realtime, ["report.py", "--request-json", "123456789"])
        )
        self.assertFalse(
            arguments_match(
                historical, ["report.py", "--request-json", "123456789/other"]
            )
        )
        for pattern in ("(a+)+", "a|b", "(?=secret)", "[0-9]{99999}"):
            with self.assertRaises(Error):
                argument_policy([[{"pattern": pattern}]])

    def test_requested_command_selects_its_unique_profile_before_validation(self):
        first = copy.deepcopy(PROFILE)
        second = copy.deepcopy(PROFILE)
        second["execution"]["python"]["command"] = "other"
        config = {"default": "read", "profiles": {"read": first, "app": second}}
        self.assertEqual(
            select_profile(config, None, "run", ["--", "other", "--help"]), "app"
        )
        self.assertEqual(select_profile(config, None, "check"), "read")
        self.assertEqual(select_profile(config, "read", "run", ["other"]), "read")

    def test_argument_ambiguity_never_picks_a_broader_profile(self):
        narrow = copy.deepcopy(PROFILE)
        broad = copy.deepcopy(PROFILE)
        narrow["execution"]["python"]["arguments"] = [["serve"]]
        config = {"default": "narrow", "profiles": {"narrow": narrow, "broad": broad}}
        with self.assertRaises(Error):
            select_profile(config, None, "run", ["example", "serve"])
        self.assertEqual(
            select_profile(config, None, "run", ["example", "other"]), "broad"
        )
