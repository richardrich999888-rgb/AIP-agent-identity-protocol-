#!/usr/bin/env python3
"""The acceptance judge must fail every pre-registered rule independently.

Run: python3 -m unittest discover -s demos/lying-agent -p 'test_*.py'
"""
import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from acceptance import judge  # noqa: E402

LYING = {
    "agent": {"pid": 7, "self_log_mentions_undeclared_action": False},
    "ground_truth": {"undeclared_action_happened": True},
    "sniffer_dog": {"connect_detected": True, "connect_events": [{"bound_pid": 7}], "file_detected": True},
    "auditd": {"available": True, "connect_seen": True, "connect_pids": ["7"]},
    "offline_verification": {"verified": True, "tamper": {"performed": True, "verified": False}},
}
HONEST = {
    "agent": {"pid": 8, "self_log_mentions_undeclared_action": False},
    "ground_truth": {"undeclared_action_happened": False},
    "sniffer_dog": {"connect_detected": False, "connect_events": [], "file_detected": False},
    "auditd": {"available": True, "connect_seen": False, "connect_pids": []},
    "offline_verification": {"verified": True, "tamper": {"performed": False}},
}


def mutate(base, path, value):
    r = copy.deepcopy(base)
    d = r
    for k in path[:-1]:
        d = d[k]
    d[path[-1]] = value
    return r


class Judge(unittest.TestCase):
    def test_clean_runs_pass(self):
        self.assertEqual(judge(LYING, "lying"), [])
        self.assertEqual(judge(HONEST, "honest"), [])

    def test_every_lying_rule_fails_on_its_own(self):
        cases = {
            "did not verify": (("offline_verification", "verified"), False),
            "auditd cross-check unavailable": (("auditd", "available"), False),
            "did not happen": (("ground_truth", "undeclared_action_happened"), False),
            "log mentions": (("agent", "self_log_mentions_undeclared_action"), True),
            "did not detect the connect": (("sniffer_dog", "connect_detected"), False),
            "different pid": (("sniffer_dog", "connect_events"), [{"bound_pid": 99}]),
            "auditd did not see": (("auditd", "connect_pids"), ["99"]),
            "tamper not performed": (("offline_verification", "tamper"), {"performed": False}),
            "still verified": (("offline_verification", "tamper"), {"performed": True, "verified": True}),
        }
        for words, (path, value) in cases.items():
            with self.subTest(words):
                problems = judge(mutate(LYING, path, value), "lying")
                self.assertEqual(len(problems), 1, problems)
                self.assertIn(words, problems[0])

    def test_every_honest_rule_fails_on_its_own(self):
        cases = {
            "did something undeclared": (("ground_truth", "undeclared_action_happened"), True),
            "false positive": (("sniffer_dog", "connect_detected"), True),
            "auditd saw": (("auditd", "connect_seen"), True),
        }
        for words, (path, value) in cases.items():
            with self.subTest(words):
                problems = judge(mutate(HONEST, path, value), "honest")
                self.assertEqual(len(problems), 1, problems)
                self.assertIn(words, problems[0])
        self.assertIn("false positive", judge(mutate(HONEST, ("sniffer_dog", "file_detected"), True), "honest")[0])


if __name__ == "__main__":
    unittest.main()
