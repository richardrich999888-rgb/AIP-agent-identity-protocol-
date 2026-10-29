#!/usr/bin/env python3
"""Portable regressions for the exact pinned SPIRE 1.15.3 CLI response."""
import contextlib
import importlib.util
import io
from pathlib import Path
import unittest


SCRIPT = Path(__file__).resolve().parents[2] / "integrations/interoperability/examples/spire_jwt_live.py"
SPEC = importlib.util.spec_from_file_location("spire_jwt_live", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SpireTokenResponseTests(unittest.TestCase):
    def test_missing_spiffe_id_warning_is_not_part_of_the_join_token(self):
        # Exact upstream v1.15.3 generate_test.go fixture, not a live credential.
        response = "Token: token\nWarning: Missing SPIFFE ID.\n"
        self.assertEqual(MODULE.parse_join_token(response), "token")

    def test_token_line_without_a_warning_is_accepted(self):
        self.assertEqual(MODULE.parse_join_token("Token: token\n"), "token")

    def test_missing_duplicate_or_malformed_token_is_refused_without_echo(self):
        responses = [
            "",
            "Warning: Missing SPIFFE ID.\n",
            "Token: \n",
            "Token: token\nToken: other\n",
            "Token: token\nToken: \n",
            "Token: token with spaces\n",
            "Token: token\tvalue\n",
            "Token: token\x00value\n",
            "Token: tokené\n",
            "Token: " + "a" * 1025 + "\n",
        ]
        for index, response in enumerate(responses):
            with self.subTest(case=index):
                output = io.StringIO()
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                    with self.assertRaisesRegex(ValueError, "^invalid SPIRE join-token response$"):
                        MODULE.parse_join_token(response)
                self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
