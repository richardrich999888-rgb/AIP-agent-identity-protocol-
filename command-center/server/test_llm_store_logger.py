"""Live test: LiteLLM → StoreUsageLogger → EventStore, against the loopback mock.

Needs `litellm` importable (the pinned core venv from research/oss/litellm).
Without it the tests are SKIPPED. Run offline as:

    unshare -n sh -c 'python3 netns_lo_up.py && LITELLM_LOCAL_MODEL_COST_MAP=True VENV/bin/python -m unittest test_llm_store_logger'
"""

import importlib.util
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

HAVE_LITELLM = importlib.util.find_spec("litellm") is not None
MOCK_DIR = Path(__file__).resolve().parents[2] / "research" / "oss" / "litellm"
WAIT_S, POLL_S = 10.0, 0.05
TEST_PRICE_IN, TEST_PRICE_OUT = 1e-6, 2e-6
MSGS = [{"role": "user", "content": "hello there agent"}]


@unittest.skipUnless(HAVE_LITELLM, "litellm not importable: live LiteLLM tests SKIPPED")
class Live(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(MOCK_DIR))
        import litellm
        import mock_openai

        import llm_store_logger

        cls.litellm = litellm
        cls.srv = mock_openai.serve(0)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}/v1"
        litellm.register_model({"openai/mock-1": {"input_cost_per_token": TEST_PRICE_IN,
                                                  "output_cost_per_token": TEST_PRICE_OUT,
                                                  "litellm_provider": "openai", "mode": "chat"}})

        class Recording(llm_store_logger.StoreUsageLogger):
            def _handle(self, kwargs, end_time, ok):
                self.calls.append((kwargs, end_time, ok))
                super()._handle(kwargs, end_time, ok)

        cls.Recording = Recording

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        import eventstore

        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "events.db"
        self.store = eventstore.EventStore(self.path)
        self.tick = iter(range(10_000, 20_000))
        self.log = self.Recording(self.store, lambda: next(self.tick))
        self.log.calls = []
        self.litellm.callbacks = [self.log]

    def tearDown(self):
        self.litellm.callbacks = []
        self.store.close()
        self.tmp.cleanup()

    def call(self, model, metadata):
        n = self.log.seen
        try:
            self.litellm.completion(model="openai/" + model, api_base=self.base, api_key="sk-test-not-a-secret",
                                    messages=MSGS, metadata=metadata, num_retries=0)
        except Exception:
            pass  # the error scenario raises by design
        deadline = time.monotonic() + WAIT_S
        while self.log.seen == n and time.monotonic() < deadline:
            time.sleep(POLL_S)
        self.assertEqual(self.log.seen, n + 1, "hook did not run: usage would be silently lost")

    def test_usage_lands_in_store(self):
        md = {"agent_id": "recon-reporter", "workflow": "wf-1", "owner": "alice"}
        self.call("mock-1", md)
        self.call("mock-no-usage", md)
        self.call("mock-error", md)
        self.call("mock-1", {"workflow": "wf-2", "owner": "bob"})
        evs = [e.event for e in self.store.events(kind="llm.usage")]
        self.assertEqual(len(evs), 4)
        priced, no_usage, failed, unattributed = evs
        self.assertEqual((priced["subject"], priced["total_tokens"]), ("agent:recon-reporter", 8))
        self.assertAlmostEqual(priced["cost_usd"], 3 * TEST_PRICE_IN + 5 * TEST_PRICE_OUT, places=15)
        self.assertEqual((priced["label"], priced["price_source"]), ("TEST DATA", "declared test price"))
        self.assertIsInstance(priced["observed_at_ms"], int)
        self.assertEqual((no_usage["total_tokens"], no_usage["cost_usd"]), (None, None))
        self.assertEqual((failed["status"], failed["cost_usd"]), ("failure", None))
        self.assertNotIn("subject", unattributed)
        self.assertEqual(unattributed["attribution_missing"], ["agent_id"])
        self.assertEqual(self.store.last_observed_ms("agent:recon-reporter"),
                         max(priced["observed_at_ms"], no_usage["observed_at_ms"], failed["observed_at_ms"]))
        self.assertEqual(self.store.verify(), [])

    def test_finops_report_over_live_events(self):
        # 4.2a: aggregate exactly what LiteLLM put in the store.
        import finops_report

        md = {"agent_id": "recon-reporter", "workflow": "wf-1", "owner": "alice"}
        self.call("mock-1", md)
        self.call("mock-no-usage", md)
        self.call("mock-1", {"workflow": "wf-2", "owner": "bob"})
        evs = [e.event for e in self.store.events(kind="llm.usage")]
        agents = finops_report.by_key(evs, "agent_id")
        rr = agents["recon-reporter"]
        self.assertEqual((rr["calls"], rr["tokens"], rr["status"], rr["calls_without_token_telemetry"]), (2, 8, "PARTIAL", 1))
        self.assertEqual(agents[None]["calls"], 1)  # unattributed stays separate
        b = finops_report.budgets(evs, {"alice": 1.0})
        self.assertTrue(b["alice"]["used_is_lower_bound"])

    def test_replayed_hook_is_deduplicated_and_survives_restart(self):
        import eventstore

        self.call("mock-1", {"agent_id": "orchestrator", "workflow": "wf-1", "owner": "alice"})
        kwargs, end, ok = self.log.calls[0]
        self.log._handle(kwargs, end, ok)  # the same LiteLLM event delivered twice
        self.assertEqual((self.log.seen, self.log.stored, self.store.count()), (2, 1, 1))
        self.store.close()
        self.store = eventstore.EventStore(self.path)
        self.assertEqual(self.store.count(), 1)
        self.assertEqual(self.store.last_observed_ms("agent:orchestrator"),
                         self.store.events()[0].observed_at_ms)


if __name__ == "__main__":
    unittest.main()
