"""Unit tests for finops_events (pure)."""

import datetime as dt
import unittest

import finops_events as f
from llm_capture import COST_ESTIMATED, COST_NO_USAGE, UsageRecord


def rec(**kw):
    base = dict(label="TEST DATA", call_id="c1", status="success", model="mock-1", provider="openai",
                agent_id="recon-reporter", workflow="wf-1", owner="alice", attribution_missing=(),
                prompt_tokens=3, completion_tokens=5, total_tokens=8, cost_usd=1.3e-05, cost_basis=COST_ESTIMATED)
    base.update(kw)
    return UsageRecord(**base)


class UsageEvent(unittest.TestCase):
    def test_fields(self):
        e = f.usage_event(rec(), 1234)
        self.assertEqual((e["kind"], e["subject"], e["observed_at_ms"], e["price_source"]),
                         ("llm.usage", "agent:recon-reporter", 1234, "declared test price"))
        self.assertEqual((e["total_tokens"], e["cost_usd"], e["label"]), (8, 1.3e-05, "TEST DATA"))

    def test_none_stays_none(self):
        e = f.usage_event(rec(prompt_tokens=None, completion_tokens=None, total_tokens=None, cost_usd=None,
                              cost_basis=COST_NO_USAGE), 1)
        self.assertIsNone(e["total_tokens"])
        self.assertIsNone(e["cost_usd"])
        self.assertEqual(e["cost_basis"], COST_NO_USAGE)

    def test_unattributed_has_no_subject(self):
        e = f.usage_event(rec(agent_id=None, attribution_missing=("agent_id",)), 1)
        self.assertNotIn("subject", e)
        self.assertEqual(e["attribution_missing"], ["agent_id"])

    def test_unknown_time_omitted(self):
        self.assertNotIn("observed_at_ms", f.usage_event(rec(), None))


class ToMs(unittest.TestCase):
    def test_aware_datetime(self):
        t = dt.datetime(2026, 11, 20, 15, 0, 0, 250000, tzinfo=dt.timezone.utc)
        self.assertEqual(f.to_ms(t), 1795186800250)

    def test_naive_refused(self):
        self.assertIsNone(f.to_ms(dt.datetime(2026, 11, 20)))

    def test_epoch_seconds(self):
        self.assertEqual(f.to_ms(1.5), 1500)

    def test_bad(self):
        for v in (None, "1", True, -1.0):
            with self.subTest(v=v):
                self.assertIsNone(f.to_ms(v))


if __name__ == "__main__":
    unittest.main()
