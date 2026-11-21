"""Unit tests: signing, registry/revocations, and the gate's enforcement order."""

import shutil
import tempfile
import unittest
from pathlib import Path

import agent_registry as ar
import eventstore as es
import gate as g
import opa_gate
import signing
from opa_gate import GateDecision

NOW = 1_800_000_000_000


def keys():
    return {n: signing.generate() for n in ("recon-reporter", "payments-agent", "orchestrator", "ops-1", "mallory")}


def registry_doc(k):
    agent = lambda n, parent=None: {"public_key_hex": k[n][1].hex(), "owner": "alice", "framework": "scripted-test-agent",
                                   "host": "lab", "runtime": "python3.11", "parent": parent, "responsible_human": "alice"}
    return {"agents": {"orchestrator": agent("orchestrator"), "recon-reporter": agent("recon-reporter", "orchestrator"),
                       "payments-agent": agent("payments-agent", "orchestrator")},
            "operators": {"ops-1": {"public_key_hex": k["ops-1"][1].hex()}}}


def revocations(k, jtis, op="ops-1", signer="ops-1"):
    lst = {"revoked_jtis": jtis, "issued_at_ms": NOW - 1000, "operator_id": op}
    return {"list": lst, "signature_hex": signing.sign(signing.DOMAIN_REVOCATIONS, lst, k[signer][0])}


def req(agent="recon-reporter", tool="read_file", server="fs", nonce="00" * 8, at=NOW, jtis=("root-1", "hop-1")):
    return {"agent_id": agent, "server": server, "tool": tool, "args": {"path": "/report.txt"},
            "authority_jtis": list(jtis), "delegation_depth": 1, "nonce": nonce, "issued_at_ms": at}


def env(k, r, signer=None):
    return {"request": r, "signature_hex": signing.sign(signing.DOMAIN_REQUEST, r, k[signer or r["agent_id"]][0])}


class StubOpa:
    def __init__(self, outcome="ALLOW", reasons=()):
        self.outcome, self.reasons, self.calls = outcome, tuple(reasons), []

    def decide(self, i):
        self.calls.append(i)
        return GateDecision(self.outcome, self.reasons, "b" * 64, "i" * 64, True)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.k = keys()
        self.reg = ar.parse(registry_doc(self.k))
        self.store = es.EventStore(self.tmp / "e.db")
        self.forwarded = []
        self.opa = StubOpa()

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.tmp)

    def gate(self, revoked=(), opa=None, forward=None):
        fwd = forward or (lambda s, t, a: self.forwarded.append((s, t, a)) or {"ok": True})
        return g.Gate(self.reg, list(revoked), opa or self.opa, self.store, fwd, lambda: NOW)

    def decisions(self):
        return [e.event for e in self.store.events(kind=g.DECISION_KIND)]


class Enforcement(Base):
    def test_allow_is_forwarded_and_recorded(self):
        r = self.gate().handle(env(self.k, req()))
        self.assertEqual((r.outcome, r.forwarded, r.upstream), ("ALLOW", True, {"ok": True}))
        self.assertEqual(self.forwarded, [("fs", "read_file", {"path": "/report.txt"})])
        d = self.decisions()[0]
        self.assertEqual((d["outcome"], d["forwarded"], d["bundle_sha256"], d["subject"]), ("ALLOW", True, "b" * 64, "agent:recon-reporter"))
        self.assertIsNotNone(d["upstream_sha256"])

    def test_policy_deny_not_forwarded(self):
        r = self.gate(opa=StubOpa("DENY", ["tool explicitly denied"])).handle(env(self.k, req()))
        self.assertEqual((r.outcome, r.forwarded, self.forwarded), ("DENY", False, []))
        self.assertEqual(self.decisions()[0]["reasons"], ["tool explicitly denied"])

    def test_pending_not_forwarded(self):
        r = self.gate(opa=StubOpa("PENDING_APPROVAL")).handle(env(self.k, req()))
        self.assertEqual((r.outcome, r.forwarded, self.forwarded), ("PENDING_APPROVAL", False, []))

    def test_revocations_reach_opa(self):
        self.gate(revoked=["hop-1"]).handle(env(self.k, req()))
        self.assertEqual(self.opa.calls[0]["revoked_jtis"], ["hop-1"])

    def test_opa_down_denies_and_does_not_forward(self):
        down = opa_gate.OpaGate(self.tmp / "no-opa", Path(opa_gate.__file__).parent.parent / "policy")
        r = self.gate(opa=down).handle(env(self.k, req()))
        self.assertEqual((r.outcome, r.forwarded, self.forwarded), ("DENY", False, []))
        self.assertIn("policy engine unavailable", r.reasons[0])

    def test_upstream_failure_recorded_not_hidden(self):
        def boom(s, t, a):
            raise ConnectionError("tool server down")
        r = self.gate(forward=boom).handle(env(self.k, req()))
        self.assertEqual((r.outcome, r.forwarded), ("ALLOW", True))
        self.assertIn("tool server down", self.decisions()[0]["upstream_error"])


class Identity(Base):
    """Adversarial #6 at the gate: identity is proven by signature, never asserted."""

    def assertDeniedBeforePolicy(self, envelope, reason):
        r = self.gate().handle(envelope)
        self.assertEqual((r.outcome, r.reasons, r.forwarded), ("DENY", (reason,), False))
        self.assertEqual((self.forwarded, self.opa.calls), ([], []))

    def test_forged_identity_signed_with_another_key(self):
        self.assertDeniedBeforePolicy(env(self.k, req(), signer="mallory"), "request signature invalid")

    def test_another_registered_agents_key_is_not_enough(self):
        self.assertDeniedBeforePolicy(env(self.k, req(), signer="payments-agent"), "request signature invalid")

    def test_tampered_after_signing(self):
        e = env(self.k, req())
        e["request"]["tool"] = "write_file"
        self.assertDeniedBeforePolicy(e, "request signature invalid")

    def test_unknown_agent(self):
        r = req(agent="ghost")
        self.assertDeniedBeforePolicy({"request": r, "signature_hex": signing.sign(signing.DOMAIN_REQUEST, r, self.k["mallory"][0])}, "unknown agent")

    def test_signature_for_another_purpose_is_refused(self):
        r = req()
        self.assertDeniedBeforePolicy({"request": r, "signature_hex": signing.sign(signing.DOMAIN_APPROVAL, r, self.k["recon-reporter"][0])},
                                      "request signature invalid")

    def test_stale_and_future(self):
        self.assertDeniedBeforePolicy(env(self.k, req(at=NOW - g.MAX_SKEW_MS - 1)), "request outside freshness window")
        self.assertDeniedBeforePolicy(env(self.k, req(at=NOW + g.MAX_SKEW_MS + 1, nonce="11" * 8)), "request outside freshness window")

    def test_replay_refused_even_after_restart(self):
        e = env(self.k, req())
        self.assertEqual(self.gate().handle(e).outcome, "ALLOW")
        self.assertEqual(self.gate().handle(e).reasons, ("replayed nonce",))
        self.store.close()
        self.store = es.EventStore(self.tmp / "e.db")
        self.assertEqual(self.gate().handle(e).reasons, ("replayed nonce",))
        self.assertEqual(len(self.forwarded), 1)

    def test_malformed(self):
        for bad in (None, [], {}, {"request": req()}, {"request": {"agent_id": "x"}, "signature_hex": "00"},
                    {"request": {**req(), "nonce": "short"}, "signature_hex": "00"},
                    {"request": {**req(), "args": "x"}, "signature_hex": "00"},
                    {"request": {**req(), "issued_at_ms": True}, "signature_hex": "00"},
                    {"request": {**req(), "extra": 1}, "signature_hex": "00"}):
            with self.subTest(bad=str(bad)[:50]):
                self.assertEqual(self.gate().handle(bad).outcome, "DENY")
        self.assertEqual((self.forwarded, self.opa.calls), ([], []))


class RegistryTests(Base):
    def test_valid_revocations(self):
        jtis, _ = ar.verified_revocations(revocations(self.k, ["b", "a", "a"]), self.reg)
        self.assertEqual(jtis, ["a", "b"])

    def test_revocations_bad_signature_or_signer(self):
        for doc in (revocations(self.k, ["a"], signer="mallory"), revocations(self.k, ["a"], op="nobody"),
                    {**revocations(self.k, ["a"]), "list": {"revoked_jtis": ["b"], "issued_at_ms": NOW - 1000, "operator_id": "ops-1"}}):
            with self.subTest(), self.assertRaises(ar.RegistryError):
                ar.verified_revocations(doc, self.reg)

    def test_registry_validation(self):
        doc = registry_doc(self.k)
        bad = [{}, {**doc, "x": 1}]
        d1 = registry_doc(self.k); d1["agents"]["orchestrator"]["public_key_hex"] = "zz"; bad.append(d1)
        d2 = registry_doc(self.k); d2["agents"]["recon-reporter"]["parent"] = "nobody"; bad.append(d2)
        d3 = registry_doc(self.k); del d3["agents"]["orchestrator"]["owner"]; bad.append(d3)
        d4 = registry_doc(self.k); d4["operators"]["orchestrator"] = {"public_key_hex": "a" * 64}; bad.append(d4)
        for b in bad:
            with self.subTest(), self.assertRaises(ar.RegistryError):
                ar.parse(b)

    def test_load_refuses_unreadable(self):
        with self.assertRaises(ar.RegistryError):
            ar.load(self.tmp / "missing.json", self.tmp / "missing2.json")


class Signing(unittest.TestCase):
    def test_verify_rejects_malformed(self):
        priv, pub = signing.generate()
        s = signing.sign(signing.DOMAIN_REQUEST, {"a": 1}, priv)
        self.assertTrue(signing.verify(signing.DOMAIN_REQUEST, {"a": 1}, s, pub.hex()))
        for sig, key in ((s[:-2], pub.hex()), ("zz", pub.hex()), (None, pub.hex()), (s, "00"), (s, "zz" * 32)):
            self.assertFalse(signing.verify(signing.DOMAIN_REQUEST, {"a": 1}, sig, key))
        self.assertFalse(signing.verify(signing.DOMAIN_REQUEST, {"a": 2}, s, pub.hex()))

    def test_key_order_does_not_change_signature_validity(self):
        priv, pub = signing.generate()
        s = signing.sign(signing.DOMAIN_REQUEST, {"a": 1, "b": 2}, priv)
        self.assertTrue(signing.verify(signing.DOMAIN_REQUEST, {"b": 2, "a": 1}, s, pub.hex()))


if __name__ == "__main__":
    unittest.main()
