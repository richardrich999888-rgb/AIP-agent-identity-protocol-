"""Tests for finops_report, including adversarial #12 (missing cost telemetry)."""

import unittest

import finops_report as r


def ev(agent="a1", wf="wf", owner="alice", tokens=8, cost=1.0e-5, t=1000, status="success"):
    e = {"kind": "llm.usage", "label": "TEST DATA", "agent_id": agent, "workflow": wf, "owner": owner,
         "total_tokens": tokens, "cost_usd": cost, "status": status}
    if t is not None:
        e["observed_at_ms"] = t
    return e


class ByKey(unittest.TestCase):
    def test_complete(self):
        g = r.by_key([ev(), ev(tokens=2, cost=2.0e-5)], "agent_id")["a1"]
        self.assertEqual((g["calls"], g["tokens"], g["status"], g["sums_are_lower_bounds"]), (2, 10, "COMPLETE", False))
        self.assertAlmostEqual(g["cost_usd_estimated"], 3.0e-5)

    def test_all_unmeasured_is_no_telemetry_not_zero(self):
        # Adversarial #12: an agent whose every call lacked telemetry never shows 0.
        g = r.by_key([ev(tokens=None, cost=None), ev(tokens=None, cost=None, status="failure")], "agent_id")["a1"]
        self.assertEqual((g["status"], g["tokens"], g["cost_usd_estimated"]), ("NO_TELEMETRY", None, None))
        self.assertEqual((g["calls"], g["failed_calls"], g["calls_without_token_telemetry"]), (2, 1, 2))

    def test_mixed_is_partial_lower_bound(self):
        g = r.by_key([ev(), ev(tokens=None, cost=None)], "owner")["alice"]
        self.assertEqual((g["status"], g["tokens"], g["sums_are_lower_bounds"], g["calls_without_cost"]), ("PARTIAL", 8, True, 1))

    def test_tokens_without_price_is_partial_and_cost_counted_missing(self):
        g = r.by_key([ev(cost=None)], "agent_id")["a1"]
        self.assertEqual((g["status"], g["tokens"], g["cost_usd_estimated"], g["calls_without_cost"]), ("PARTIAL", 8, None, 1))

    def test_genuine_zero_cost_is_measured(self):
        g = r.by_key([ev(cost=0.0)], "agent_id")["a1"]
        self.assertEqual((g["status"], g["cost_usd_estimated"]), ("COMPLETE", 0.0))

    def test_unattributed_never_merged(self):
        got = r.by_key([ev(agent=None), ev(agent=""), ev(agent="a1")], "agent_id")
        self.assertEqual((got[None]["calls"], got["a1"]["calls"]), (2, 1))

    def test_bad_values_are_unmeasured(self):
        g = r.by_key([ev(tokens=True, cost=-1.0), ev(tokens="8", cost=True)], "agent_id")["a1"]
        self.assertEqual(g["status"], "NO_TELEMETRY")

    def test_other_kinds_ignored_and_key_checked(self):
        self.assertEqual(r.by_key([{"kind": "observer.batch"}], "agent_id"), {})
        with self.assertRaises(ValueError):
            r.by_key([], "model")


class Budgets(unittest.TestCase):
    def test_fraction_and_lower_bound(self):
        b = r.budgets([ev(cost=0.5), ev(cost=None)], {"alice": 2.0, "bob": 1.0})
        self.assertEqual((b["alice"]["used_fraction"], b["alice"]["used_is_lower_bound"]), (0.25, True))
        self.assertEqual((b["bob"]["spent_usd_estimated"], b["bob"]["used_fraction"], b["bob"]["calls"]), (None, None, 0))

    def test_no_measured_cost_fraction_is_none(self):
        self.assertIsNone(r.budgets([ev(cost=None)], {"alice": 1.0})["alice"]["used_fraction"])

    def test_bad_budget(self):
        for bad in (0, -1, True, "1"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                r.budgets([], {"alice": bad})


class Trend(unittest.TestCase):
    def test_buckets_and_untimed(self):
        t = r.trend([ev(t=1000), ev(t=1999), ev(t=2000), ev(t=None)], 1000)
        self.assertEqual({k: v["calls"] for k, v in t["buckets"].items()}, {1000: 2, 2000: 1})
        self.assertEqual(t["untimed"]["calls"], 1)

    def test_bad_bucket(self):
        for bad in (0, -5, 1.5, True):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                r.trend([], bad)


if __name__ == "__main__":
    unittest.main()
