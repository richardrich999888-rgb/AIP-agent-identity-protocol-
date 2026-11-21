"""Unit tests for inventory (pure) and a check over a real live_gate event store."""

import json
import os
import unittest
from pathlib import Path

import inventory as inv

KEY = "11" * 32
A = {"framework": "scripted-test-agent", "host": "lab", "runtime": "python3.11", "owner": "alice",
     "responsible_human": "alice", "parent": None, "public_key_hex": KEY}
AGENTS = {"recon-reporter": A, "payments-agent": {**A, "parent": "recon-reporter"}, "idle-agent": A}


def gd(agent, outcome="ALLOW", reasons=(), stage="policy", t=1000, approved_by=None):
    return {"kind": "gate.decision", "agent_id": agent, "outcome": outcome, "reasons": list(reasons),
            "stage": stage, "observed_at_ms": t, "approved_by": approved_by}


def rows(events):
    return {r["agent_id"]: r for r in inv.build(AGENTS, events)}


class Inventory(unittest.TestCase):
    def test_registry_fields_and_fingerprint_not_key(self):
        r = rows([])["payments-agent"]
        self.assertEqual((r["parent"], r["owner"], r["framework"]), ("recon-reporter", "alice", "scripted-test-agent"))
        self.assertEqual(r["key_fingerprint"], inv.fingerprint(KEY))
        self.assertNotIn(KEY, json.dumps(r))

    def test_never_seen_is_unknown_not_low_and_last_seen_none(self):
        r = rows([])["idle-agent"]
        self.assertEqual((r["risk"], r["last_seen_ms"], r["decisions"]), ("UNKNOWN", None, 0))

    def test_low_medium_high(self):
        got = rows([gd("recon-reporter", t=5), gd("payments-agent", "DENY", ["tool explicitly denied"]),
                    gd("idle-agent", "DENY", ["authority revoked"])])
        self.assertEqual((got["recon-reporter"]["risk"], got["payments-agent"]["risk"], got["idle-agent"]["risk"]),
                         ("LOW", "MEDIUM", "HIGH"))
        self.assertEqual(got["recon-reporter"]["last_seen_ms"], 5)

    def test_signature_failure_is_a_claim_not_activity(self):
        r = rows([gd("recon-reporter", "DENY", ["request signature invalid"], stage="pre-auth", t=99)])["recon-reporter"]
        self.assertEqual((r["signature_failures"], r["decisions"], r["last_seen_ms"], r["risk"]), (1, 0, None, "HIGH"))

    def test_auth_stage_denials_are_not_policy_denials(self):
        r = rows([gd("recon-reporter", "DENY", ["replayed nonce"], stage="auth")])["recon-reporter"]
        self.assertEqual((r["policy_denials"], r["risk"]), (0, "LOW"))

    def test_auth_stage_non_replay_denial_is_not_policy(self):
        r = rows([gd("payments-agent", "DENY", ["approval retry for a request that is not pending"], stage="auth")])["payments-agent"]
        self.assertEqual((r["policy_denials"], r["decisions"], r["risk"]), (0, 1, "LOW"))

    def test_engine_outage_and_replay_do_not_raise_risk(self):
        r = rows([gd("recon-reporter", "DENY", ["policy engine unavailable: binary not found"]),
                  gd("recon-reporter", "DENY", ["replayed nonce"], stage="auth")])["recon-reporter"]
        self.assertEqual((r["engine_unavailable"], r["replays"], r["policy_denials"], r["risk"]), (1, 1, 0, "LOW"))

    def test_invalid_approval_is_medium_and_hold_counted(self):
        r = rows([gd("payments-agent", "PENDING_APPROVAL"),
                  gd("payments-agent", "APPROVAL_INVALID", ["approval signature invalid"], stage="auth")])["payments-agent"]
        self.assertEqual((r["held_for_approval"], r["invalid_approvals"], r["risk"]), (1, 1, "MEDIUM"))

    def test_approvals_and_llm_usage(self):
        r = rows([gd("payments-agent", approved_by="ops-1"),
                  {"kind": "llm.usage", "agent_id": "payments-agent", "observed_at_ms": 7}])["payments-agent"]
        self.assertEqual((r["approvals_used"], r["llm_calls"], r["last_seen_ms"]), (1, 1, 1000))

    def test_unregistered_ids_listed(self):
        got = rows([gd("ghost", "DENY", ["unknown agent"], stage="pre-auth")])
        self.assertEqual((got["ghost"]["status"], got["ghost"]["risk"]), ("UNREGISTERED", "HIGH"))

    def test_other_kinds_and_bad_rows_ignored(self):
        self.assertEqual(rows([{"kind": "observer.batch"}, {"kind": "gate.decision"}, {"agent_id": 5}])["recon-reporter"]["decisions"], 0)


LIVE = os.environ.get("VANIAN_LIVE_GATE_DIR")


@unittest.skipUnless(LIVE and Path(LIVE, "events.db").is_file(), "VANIAN_LIVE_GATE_DIR not set: live inventory check SKIPPED")
class OverLiveGateRun(unittest.TestCase):
    def test_inventory_over_real_gate_events(self):
        import eventstore
        reg = json.loads(Path(LIVE, "registry.json").read_text())["agents"]
        s = eventstore.EventStore(Path(LIVE, "events.db"))
        evs = [e.event for e in s.events(kind="gate.decision", limit=1000)]
        s.close()
        got = {r["agent_id"]: r for r in inv.build(reg, evs)}
        rr, pa, orch = got["recon-reporter"], got["payments-agent"], got["orchestrator"]
        self.assertEqual(rr["signature_failures"], 1)       # the forged-identity step
        self.assertEqual(rr["revoked_authority_uses"], 1)   # the revoked-authority step
        self.assertEqual(rr["risk"], "HIGH")
        # Policy denials: the denied tool and the revoked authority (OPA denies revocation at the policy stage).
        self.assertEqual((rr["policy_denials"], rr["engine_unavailable"], rr["replays"]), (2, 1, 1))
        self.assertEqual((pa["approvals_used"], pa["held_for_approval"], pa["invalid_approvals"]), (1, 2, 1))
        self.assertEqual(orch["risk"], "UNKNOWN")            # registered, never seen
        self.assertIsNone(orch["last_seen_ms"])


if __name__ == "__main__":
    unittest.main()
