"""The SDK's negative space: what it must be unable to do.

Skill 12 lists six things the Python boundary must never do. Five of them are
enforced by *absence* — there is no method, so there is no test that calls
one. A test suite cannot assert the non-existence of an API by calling it, so
this file asserts it by introspection: if someone later adds ``prove()`` or
``load_observer_identity()``, these tests fail and the reviewer is forced to
justify it.

The sixth — silent identity regeneration — is a behaviour, and is tested
directly.
"""

from __future__ import annotations

import os
import pathlib
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import vanian_airi as airi  # noqa: E402
from vanian_airi import (  # noqa: E402
    AiriEmitter,
    ContextUnavailable,
    FrameworkIdentity,
    IdentityUnavailable,
    ListSink,
    ReportedOutcome,
    bind,
    load_agent_identity,
    new_execution,
)

FRAMEWORK = FrameworkIdentity("langgraph", "0.2.0", "vanian-airi-adapter/1")


def write_key(dirpath: str, mode: int = 0o600, size: int = 32) -> str:
    p = os.path.join(dirpath, "agent.key")
    with open(p, "wb") as fh:
        fh.write(os.urandom(size))
    os.chmod(p, mode)
    return p


class TestForbiddenSurface(unittest.TestCase):
    """The SDK must expose no way to self-authorize or self-prove."""

    FORBIDDEN = [
        "prove",
        "set_evidence_strength",
        "set_strength",
        "issue_warrant",
        "warrant",
        "authorize",
        "self_authorize",
        "contain",
        "load_observer_identity",
        "load_observer_key",
        "observer_key",
        "attest",
        "verdict",
        "mark_verified",
    ]

    def test_package_exports_nothing_forbidden(self) -> None:
        for name in self.FORBIDDEN:
            self.assertNotIn(
                name,
                airi.__all__,
                f"SECURITY: the SDK exports `{name}`. The agent is the party "
                "under scrutiny and must not be able to author the evidence "
                "used to judge it.",
            )

    def test_emitter_has_no_forbidden_method(self) -> None:
        for name in self.FORBIDDEN:
            self.assertFalse(
                hasattr(AiriEmitter, name),
                f"SECURITY: AiriEmitter grew a `{name}` method.",
            )

    def test_identity_module_refuses_observer_keys(self) -> None:
        # The placeholder exists so the absence is documented in code rather
        # than only in prose. Calling it must raise, never return a key.
        from vanian_airi.identity import _reject_observer_key

        with self.assertRaises(NotImplementedError):
            _reject_observer_key()

    def test_no_event_kind_asserts_independent_observation(self) -> None:
        # MODEL_INVOCATION_OBSERVED is named "observed" by the specification
        # but is a framework self-report. No kind may imply independence.
        names = [k.name for k in airi.AiriEventKind]
        for n in names:
            self.assertNotIn("INDEPENDENT", n)
            self.assertNotIn("PROVEN", n)
            self.assertNotIn("VERIFIED", n)


class TestFailClosedIdentity(unittest.TestCase):
    """A key that cannot be loaded is fatal. It is never regenerated."""

    def test_missing_key_raises_and_does_not_create_one(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            missing = os.path.join(d, "nope.key")
            with self.assertRaises(IdentityUnavailable):
                load_agent_identity("aip1abc", missing)
            self.assertFalse(
                os.path.exists(missing),
                "SECURITY: a missing key file was created. A process that mints "
                "a replacement identity has silently become a different "
                "principal (forensic audit, finding B-6).",
            )

    def test_malformed_key_raises_rather_than_regenerating(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            p = write_key(d, size=7)  # not a 32-byte seed
            before = pathlib.Path(p).read_bytes()
            with self.assertRaises(IdentityUnavailable):
                load_agent_identity("aip1abc", p)
            self.assertEqual(
                pathlib.Path(p).read_bytes(),
                before,
                "SECURITY: the SDK overwrote a malformed key with a new one",
            )

    def test_world_readable_key_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            p = write_key(d, mode=0o644)
            with self.assertRaises(IdentityUnavailable) as cm:
                load_agent_identity("aip1abc", p)
            self.assertIn("readable beyond its owner", str(cm.exception))

    def test_the_permission_check_can_be_waived_only_explicitly(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            p = write_key(d, mode=0o644)
            ident = load_agent_identity("aip1abc", p, require_owner_only=False)
            self.assertEqual(ident.aip_id, "aip1abc")

    def test_empty_aip_id_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            p = write_key(d)
            with self.assertRaises(IdentityUnavailable):
                load_agent_identity("", p)

    def test_repr_never_leaks_the_key(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            p = write_key(d)
            ident = load_agent_identity("aip1abc", p)
            r = repr(ident)
            self.assertIn("redacted", r)
            self.assertNotIn("Ed25519PrivateKey", r)


class TestEmitterDiscipline(unittest.TestCase):
    def _emitter(self, d: str) -> tuple[AiriEmitter, ListSink, str]:
        p = write_key(d)
        ident = load_agent_identity("aip1abc", p)
        sink = ListSink()
        return AiriEmitter(ident, FRAMEWORK, sink=sink), sink, ident.aip_id

    def test_emitting_without_a_context_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            em, _, _ = self._emitter(d)
            with self.assertRaises(ContextUnavailable):
                em.completed()

    def test_an_emitter_refuses_a_context_for_another_agent(self) -> None:
        # Otherwise agent A's emitter could sign statements filed under agent
        # B's execution — attribution laundering with a valid signature.
        with tempfile.TemporaryDirectory() as d:
            em, _, _ = self._emitter(d)
            with bind(new_execution("aip1someone-else")):
                with self.assertRaises(airi.AiriError):
                    em.completed()

    def test_events_form_a_chain_with_monotonic_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            em, sink, aid = self._emitter(d)
            with bind(new_execution(aid)):
                em.agent_started()
                em.tool_requested("http.post", "http.post", {"url": "x"})
                em.completed()
            seqs = [e.sequence for e in sink.events]
            self.assertEqual(seqs, [0, 1, 2])
            self.assertEqual(sink.events[0].prev_event_hash, bytes(32))
            for prev, cur in zip(sink.events, sink.events[1:]):
                self.assertEqual(cur.prev_event_hash, prev.event_hash())

    def test_every_emitted_event_is_signed(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            em, sink, aid = self._emitter(d)
            with bind(new_execution(aid)):
                em.agent_started()
            self.assertTrue(all(e.signature is not None for e in sink.events))
            self.assertEqual(len(sink.events[0].signature), 64)

    def test_parameters_are_committed_not_carried(self) -> None:
        # The secret must not appear anywhere in the signed bytes.
        with tempfile.TemporaryDirectory() as d:
            em, sink, aid = self._emitter(d)
            secret = "sk-live-DO-NOT-LOG-abc123"
            with bind(new_execution(aid)):
                em.tool_requested(
                    "http.post", "http.post", {"api_key": secret, "url": "x"}
                )
            blob = sink.events[0].signing_preimage()
            self.assertNotIn(secret.encode(), blob)
            self.assertNotIn(b"api_key", blob)

    def test_commitment_is_order_independent_for_equivalent_arguments(self) -> None:
        # Two dicts with the same content in different insertion order are the
        # same arguments and must commit identically — otherwise a verifier
        # sees a parameter substitution that never happened.
        from vanian_airi import commit_json

        self.assertEqual(
            commit_json({"a": 1, "b": 2}),
            commit_json({"b": 2, "a": 1}),
        )

    def test_denied_is_distinguishable_from_failure(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            em, sink, aid = self._emitter(d)
            with bind(new_execution(aid)):
                em.denied("policy stop")
                em.failed("network error")
            self.assertEqual(sink.events[0].payload.outcome, ReportedOutcome.DENIED)
            self.assertEqual(sink.events[1].payload.outcome, ReportedOutcome.FAILURE)


if __name__ == "__main__":
    unittest.main(verbosity=2)
