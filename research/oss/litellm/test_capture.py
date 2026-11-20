"""Unit tests for capture.to_record (pure; no LiteLLM)."""

import json
import unittest

import capture as c

RAW_WITH_USAGE = json.dumps({"id": "x", "usage": {"prompt_tokens": 3, "completion_tokens": 5, "total_tokens": 8}})
RAW_NO_USAGE = json.dumps({"id": "x"})
MD = {"agent_id": "recon-reporter", "workflow": "wf-1", "owner": "alice"}


def kw(raw=RAW_WITH_USAGE, md=MD, **slo):
    base = {"id": "call-1", "model": "mock-1", "custom_llm_provider": "openai",
            "prompt_tokens": 3, "completion_tokens": 5, "total_tokens": 8,
            "response_cost": 1.3e-05, "response_cost_failure_debug_info": None}
    base.update(slo)
    return {"standard_logging_object": base, "original_response": raw, "litellm_params": {"metadata": md}}


class ToRecord(unittest.TestCase):
    def test_priced_success(self):
        r = c.to_record(kw(), True)
        self.assertEqual((r.prompt_tokens, r.completion_tokens, r.total_tokens), (3, 5, 8))
        self.assertEqual(r.cost_usd, 1.3e-05)
        self.assertEqual(r.cost_basis, c.COST_ESTIMATED)
        self.assertEqual((r.agent_id, r.workflow, r.owner, r.attribution_missing), ("recon-reporter", "wf-1", "alice", ()))
        self.assertEqual(r.label, "TEST DATA")

    def test_unknown_price_is_none_not_zero(self):
        r = c.to_record(kw(response_cost=0.0, response_cost_failure_debug_info={"error_str": "not mapped"}), True)
        self.assertIsNone(r.cost_usd)
        self.assertEqual(r.cost_basis, c.COST_PRICE_UNKNOWN)
        self.assertEqual(r.total_tokens, 8)  # tokens were reported; only price is unknown

    def test_no_usage_is_none_not_zero(self):
        r = c.to_record(kw(raw=RAW_NO_USAGE, prompt_tokens=0, completion_tokens=0, total_tokens=0, response_cost=0.0), True)
        self.assertEqual((r.prompt_tokens, r.completion_tokens, r.total_tokens, r.cost_usd), (None, None, None, None))
        self.assertEqual(r.cost_basis, c.COST_NO_USAGE)

    def test_failure_is_none_not_zero(self):
        r = c.to_record(kw(prompt_tokens=0, completion_tokens=0, total_tokens=0, response_cost=0.0), False)
        self.assertEqual((r.status, r.total_tokens, r.cost_usd, r.cost_basis), ("failure", None, None, c.COST_FAILED))

    def test_genuine_zero_cost_is_kept(self):
        # A declared price of 0 is a measurement, not missing telemetry.
        r = c.to_record(kw(response_cost=0.0), True)
        self.assertEqual((r.cost_usd, r.cost_basis), (0.0, c.COST_ESTIMATED))

    def test_unparseable_raw_counts_as_no_usage(self):
        self.assertEqual(c.to_record(kw(raw="{not json"), True).cost_basis, c.COST_NO_USAGE)
        self.assertEqual(c.to_record(kw(raw=None), True).cost_basis, c.COST_NO_USAGE)

    def test_raw_dict_accepted(self):
        self.assertTrue(c.provider_reported_usage({"usage": {}}))
        self.assertFalse(c.provider_reported_usage({"usage": None}))

    def test_missing_attribution_is_recorded_not_dropped(self):
        r = c.to_record(kw(md={"agent_id": "a", "owner": ""}), True)
        self.assertEqual((r.agent_id, r.workflow, r.owner), ("a", None, None))
        self.assertEqual(r.attribution_missing, ("workflow", "owner"))
        self.assertEqual(r.total_tokens, 8)

    def test_non_string_attribution_rejected(self):
        self.assertEqual(c.to_record(kw(md={"agent_id": 7, "workflow": ["x"], "owner": "o"}), True).attribution_missing, ("agent_id", "workflow"))

    def test_bad_token_types_become_none(self):
        r = c.to_record(kw(prompt_tokens=True, completion_tokens=-1, total_tokens="8"), True)
        self.assertEqual((r.prompt_tokens, r.completion_tokens, r.total_tokens), (None, None, None))

    def test_negative_or_bool_cost_is_unknown(self):
        self.assertIsNone(c.to_record(kw(response_cost=-1.0), True).cost_usd)
        self.assertIsNone(c.to_record(kw(response_cost=True), True).cost_usd)

    def test_empty_kwargs(self):
        r = c.to_record({}, True)
        self.assertEqual((r.cost_usd, r.cost_basis, r.attribution_missing), (None, c.COST_NO_USAGE, c.ATTRIBUTION_KEYS))

    def test_json_is_canonical(self):
        a = c.to_record(kw(), True).to_json()
        self.assertEqual(a, json.dumps(json.loads(a), sort_keys=True))


if __name__ == "__main__":
    unittest.main()
