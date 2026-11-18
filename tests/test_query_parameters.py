import copy
import unittest
from urllib.parse import urlencode

from runbox.config import Error, profile, query_matches
from runbox.guard import Guard, PolicyError
from tests.test_independent_probes import selected


class QueryParameterTests(unittest.TestCase):
    def test_repeated_fields_require_explicit_bounded_count_and_each_value_is_checked(self):
        value = self.policy()
        route = value["probe"]["http"]["routes"][0]
        route["query-parameters"]["ranges"] = {"pattern": "Watchlist![A-Z0-9:]{1,32}", "max-count": 2}
        profile(value)
        self.assertTrue(query_matches(route, "alt=json&ranges=Watchlist!A1:B2&ranges=Watchlist!C1:D2"))
        self.assertFalse(query_matches(route, "alt=json&ranges=Watchlist!A1:B2&ranges=Private!C1:D2"))
        self.assertFalse(query_matches(route, "alt=json&ranges=Watchlist!A1&ranges=Watchlist!B1&ranges=Watchlist!C1"))
        self.assertFalse(query_matches(route, "alt=json&alt=json"))
        for count in (0, 17, True, "2"):
            route["query-parameters"]["ranges"]["max-count"] = count
            with self.subTest(count=count), self.assertRaises(Error):
                profile(value)

    def policy(self):
        value = selected()
        http = value["probe"]["http"]
        http["routes"][0]["query-parameters"] = {
            "alt": {"pattern": "json", "required": True},
            "fields": {"pattern": "emailAddress"},
            "pageToken": {"pattern": "[A-Za-z0-9_-]{1,512}"},
        }
        http["probe-query"] = "fields=emailAddress&alt=json"
        return value

    def test_python_get_schema_and_fixed_probe_are_validated(self):
        value = self.policy()
        profile(value)
        route = value["probe"]["http"]["routes"][0]
        self.assertTrue(query_matches(route, "alt=json&fields=emailAddress"))
        self.assertTrue(query_matches(route, "alt=json&pageToken=next-page_2"))
        self.assertFalse(query_matches(route, "fields=emailAddress"))

    def test_guard_rejects_duplicate_unknown_malformed_and_overlong_values(self):
        http = self.policy()["probe"]["http"]
        headers = {"Authorization": "Bearer " + http["placeholder"]}
        for query in ["", "alt=json&access_token=synthetic", "alt=json&alt=json",
                      "alt=json&%61lt=json", "alt=json&fields=messages", "alt=json&pageToken=%ZZ",
                      "alt=json&pageToken=%FF", "alt=json&pageToken=bad%0Avalue",
                      "alt=json&invalid", "alt=json&pageToken=" + "a" * 4096]:
            with self.subTest(query_length=len(query)), self.assertRaises(PolicyError):
                Guard(http).validate("GET", http["base-url"] + "/models?" + query, headers)
        self.assertTrue(query_matches(http["routes"][0], urlencode({"alt": "json", "fields": "emailAddress"})))

    def test_bad_schema_cannot_widen_node_post_or_exact_query_policies(self):
        original = self.policy()
        for mutation in ["node", "post", "mixed", "regex", "required", "empty", "name"]:
            value = copy.deepcopy(original)
            route = value["probe"]["http"]["routes"][0]
            if mutation == "node":
                value["probe"]["execution"]["client"] = {"type": "node-http"}
            elif mutation == "post":
                route["method"] = "POST"
            elif mutation == "mixed":
                route["queries"] = [""]
            elif mutation == "regex":
                route["query-parameters"]["alt"]["pattern"] = "["
            elif mutation == "required":
                route["query-parameters"]["alt"]["required"] = "yes"
            elif mutation == "empty":
                route["query-parameters"] = {}
            else:
                route["query-parameters"]["bad&key"] = {"pattern": "json"}
            with self.subTest(mutation=mutation), self.assertRaises(Error):
                profile(value)

    def test_existing_exact_queries_keep_exact_order_and_do_not_accept_extra_parameters(self):
        route = {"queries": ["a=1&b=2"]}
        self.assertTrue(query_matches(route, "a=1&b=2"))
        self.assertFalse(query_matches(route, "b=2&a=1"))
        self.assertFalse(query_matches(route, "a=1&b=2&c=3"))
