#!/usr/bin/env python3
"""Tests for the lying agent and its independent ground truth (W2.1).

Run: python3 -m unittest discover -s demos/lying-agent -p 'test_*.py'
"""
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import ground_truth  # noqa: E402


def steps(rec):
    return [(e["step"], {k: v for k, v in e.items() if k not in ("ts_ms", "pid", "file", "bytes")})
            for e in rec["self_log"]]


class LyingAgent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        base = Path(cls.tmp.name)
        # Neutral run names: the mode must not be readable from paths in the self-log.
        cls.honest = ground_truth.run_agent("honest", base / "run-a", linger=0.2)
        cls.lying = ground_truth.run_agent("lying", base / "run-b", linger=0.2)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_both_runs_complete_the_declared_task(self):
        for rec in (self.honest, self.lying):
            self.assertEqual(rec["agent_exit"], 0, rec["agent_stderr"])
            self.assertEqual(rec["self_log"][-1]["actions_performed"], rec["declared_actions"])

    def test_the_self_logs_are_indistinguishable(self):
        # The lie: its own log reads exactly like the honest run's.
        self.assertEqual(steps(self.honest), steps(self.lying))
        for rec in (self.honest, self.lying):
            text = repr(rec["self_log"]).lower()
            for word in ("exfil", "connect", "outside", "copied", "lying", "hidden"):
                self.assertNotIn(word, text)

    def test_honest_run_does_nothing_undeclared(self):
        gt = self.honest["ground_truth"]
        self.assertEqual(gt["connections_received"], [])
        self.assertEqual(gt["outside_scope_files"], [])
        self.assertFalse(gt["undeclared_action_happened"])

    def test_lying_run_really_does_the_undeclared_actions(self):
        gt = self.lying["ground_truth"]
        self.assertTrue(gt["undeclared_action_happened"])
        self.assertEqual(len(gt["connections_received"]), 1)
        self.assertIn(self.lying["nonce"], gt["connections_received"][0]["payload"])
        self.assertEqual(gt["outside_scope_files"], [f"copied-{self.lying['nonce']}.txt"])
        lo, hi = self.lying["window_ms"]
        self.assertTrue(lo <= gt["connections_received"][0]["arrived_ms"] <= hi + 1000)

    def test_ground_truth_is_written_by_the_harness_and_names_its_source(self):
        self.assertIn("not the agent, not the observer", self.lying["ground_truth"]["source"])

    def test_the_agent_stays_alive_for_the_stated_linger(self):
        import time
        with tempfile.TemporaryDirectory() as t:
            t0 = time.monotonic()
            rec = ground_truth.run_agent("honest", Path(t), linger=1.5)
            self.assertGreaterEqual(time.monotonic() - t0, 1.5)
            self.assertEqual(rec["agent_exit"], 0)

    def test_a_run_directory_that_names_the_mode_is_refused(self):
        with tempfile.TemporaryDirectory() as t:
            for name in ("lying", "honest-run", "Lie-1"):
                with self.assertRaises(ValueError):
                    ground_truth.run_agent("lying", Path(t) / name)
            # Substrings inside other words are not the mode and must not be refused.
            for name in ("tmplie9x", "leslie", "dishonesty-check"):
                rec = ground_truth.run_agent("honest", Path(t) / name, linger=0.0)
                self.assertEqual(rec["agent_exit"], 0)
            # A shared parent named after the demo is the same for both modes: allowed.
            rec = ground_truth.run_agent("lying", Path(t) / "lying-agent" / "evidence" / "run", linger=0.0)
            self.assertEqual(rec["agent_exit"], 0)

    def test_payload_is_synthetic(self):
        payload = self.lying["ground_truth"]["connections_received"][0]["payload"]
        self.assertEqual(payload, f"synthetic-exfil {self.lying['nonce']}")


if __name__ == "__main__":
    unittest.main()
