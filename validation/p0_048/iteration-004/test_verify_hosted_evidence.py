#!/usr/bin/env python3
"""Regression: repeated batch/event probe IDs must not break tamper setup."""
import json
import unittest

from verify_hosted_evidence import one_byte_modification


class MutationTests(unittest.TestCase):
    def test_unique_probe_id(self):
        raw = b'{"probe_id":"probe-host-1"}'
        self.assertEqual(one_byte_modification(raw), b'{"probe_id":"probe-host-2"}')

    def test_repeated_probe_id_changes_only_first(self):
        raw = b'{"probe_id":"probe-host-1","events":[{"probe_id":"probe-host-1"}]}'
        changed = one_byte_modification(raw)
        self.assertEqual(sum(a != b for a, b in zip(raw, changed)), 1)
        self.assertEqual(json.loads(changed)["events"][0]["probe_id"], "probe-host-1")
        self.assertEqual(json.loads(raw)["probe_id"], "probe-host-1")

    def test_missing_field_refuses_fake_tamper(self):
        with self.assertRaises(AssertionError):
            one_byte_modification(b'{"different":"record"}')


if __name__ == "__main__":
    unittest.main()
