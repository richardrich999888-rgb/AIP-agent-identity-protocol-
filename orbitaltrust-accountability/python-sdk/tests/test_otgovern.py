"""Behavioral tests for the otgovern SDK: the runtime lifecycle law, the
sealing rules, and chain self-consistency. Cross-language byte proof lives
in crates/ot-verifier/tests/python_sdk.rs, which verifies chains this SDK
builds with the Rust verifier.

Run:  python3 -m unittest discover sdks/python/tests
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from otgovern import (  # noqa: E402
    GENESIS_HASH,
    GovernedAgent,
    LifecycleError,
    canonical_json,
    seal_hash,
)
from otgovern.selftest import build  # noqa: E402


def _ticks():
    counter = iter(range(1000))
    return lambda: f"2026-08-27T01:00:{next(counter) % 60:02d}.000Z"


def _agent():
    return GovernedAgent.born(
        did="did:syntriass:agent:AGT-T",
        supervisor_did="did:syntriass:officer:OFF-1",
        model_digest="b" * 64,
        clock=_ticks(),
    )


def _verify_chain(records, prev_field, hash_field, chain_fields):
    previous = GENESIS_HASH
    for i, record in enumerate(records):
        assert record["sequenceNumber"] == i + 1
        assert record[prev_field] == previous
        payload = {k: v for k, v in record.items() if k not in chain_fields}
        assert seal_hash(previous, canonical_json(payload)) == record[hash_field]
        previous = record[hash_field]


class LifecycleLaw(unittest.TestCase):
    def test_execute_before_delegation_raises(self):
        with self.assertRaises(LifecycleError):
            _agent().execute("anything", lambda: None)

    def test_nothing_seals_after_terminal_revocation(self):
        agent = _agent().delegate(["t"], "SECRET")
        agent.revoke("drill")
        with self.assertRaises(LifecycleError):
            agent.execute("t", lambda: None)
        with self.assertRaises(LifecycleError):
            agent.revoke("twice")
        self.assertEqual(agent.anchors[-1]["anchorType"], "AUTHORITY_REVOCATION")

    def test_out_of_scope_seals_blocked_with_post_equal_pre(self):
        agent = _agent().delegate(["allowed"], "SECRET")
        with self.assertRaises(LifecycleError):
            agent.execute(
                "forbidden",
                lambda: None,
                pre_state={"x": 1},
                post_state=lambda: {"x": 999},  # a lying caller
            )
        packet = agent.packets[-1]
        self.assertEqual(packet["toolExecuted"]["status"], "BLOCKED_BY_POLICY")
        self.assertEqual(packet["preStateHash"], packet["postStateHash"])

    def test_a_raising_tool_seals_failed_and_reraises(self):
        agent = _agent().delegate(["t"], "SECRET")

        def boom():
            raise ValueError("tool broke")

        with self.assertRaises(ValueError):
            agent.execute("t", boom)
        self.assertEqual(agent.packets[-1]["toolExecuted"]["status"], "FAILED")


class ChainConsistency(unittest.TestCase):
    def test_the_selftest_chain_self_verifies(self):
        agent = build()
        _verify_chain(
            agent.anchors,
            "previousAnchorHash",
            "anchorHash",
            ("previousAnchorHash", "anchorHash"),
        )
        _verify_chain(
            agent.packets,
            "previousPacketHash",
            "packetHash",
            ("previousPacketHash", "packetHash"),
        )
        # Genesis-first, every execution acknowledged by a seal anchor.
        self.assertEqual(agent.anchors[0]["anchorType"], "AGENT_GENESIS")
        sealed = {
            a["payload"]["packetHash"]
            for a in agent.anchors
            if a["anchorType"] == "ACTION_EXECUTION_SEAL"
        }
        self.assertEqual(sealed, {p["packetHash"] for p in agent.packets})

    def test_canonical_json_matches_the_shared_contract(self):
        # Sorted keys, compact separators, raw unicode, shortest floats.
        self.assertEqual(
            canonical_json({"b": 1.5, "a": 12000000, "s": "héllo", "t": True}),
            '{"a":12000000,"b":1.5,"s":"héllo","t":true}',
        )


if __name__ == "__main__":
    unittest.main()
