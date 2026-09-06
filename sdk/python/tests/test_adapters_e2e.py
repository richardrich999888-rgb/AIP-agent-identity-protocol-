"""End-to-end: a Python agent drives the adapters and produces a valid chain.

The events produced here are handed to the Rust verifier by
``aip-airi/tests/python_interop.rs``, which is the test that actually proves
the two sides agree. This file proves the Python half is internally coherent:
one execution, one chain, correct sequence, correct linkage, and the three
tool layers kept apart.
"""

from __future__ import annotations

import json
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from vanian_airi import (  # noqa: E402
    AiriEmitter,
    ExecutionContext,
    AiriEventKind,
    FrameworkIdentity,
    ListSink,
    ProcessInstance,
    PropagationBoundary,
    ReportedOutcome,
    RuntimeBinding,
    bind,
    child_execution,
    load_agent_identity,
    new_execution,
)
from vanian_airi.adapters import FrameworkAdapter, ModelAdapter, ToolAdapter  # noqa: E402

FRAMEWORK = FrameworkIdentity("langgraph", "0.2.0", "vanian-airi-adapter/1")
AGENT = "aip1testagent"


def make_emitter(
    tmp: str, bound: bool = True, clock_ms: object = None
) -> tuple[AiriEmitter, ListSink, object]:
    key = os.path.join(tmp, "agent.key")
    with open(key, "wb") as fh:
        fh.write(bytes(range(32)))
    os.chmod(key, 0o600)
    ident = load_agent_identity(AGENT, key)
    sink = ListSink()
    rb = (
        RuntimeBinding(
            agent_id=AGENT,
            process=ProcessInstance(
                pid=4321, pid_start_time_ticks=4242, boot_id=bytes([0x7] * 16)
            ),
            exe_content_sha256=bytes([0x33] * 32),
        )
        if bound
        else None
    )
    kw = {} if clock_ms is None else {"clock_ms": clock_ms}
    return (
        AiriEmitter(ident, FRAMEWORK, sink=sink, runtime_binding=rb, **kw),  # type: ignore[arg-type]
        sink,
        ident,
    )


class TestEndToEnd(unittest.TestCase):
    def test_a_full_agent_run_produces_one_intact_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            em, sink, ident = make_emitter(tmp)
            fw = FrameworkAdapter(em)
            model = ModelAdapter(em)
            tools = ToolAdapter(em)

            decision = bytes([0xD1] * 16)
            with bind(new_execution(ident.aip_id, decision_id=decision)):
                fw.on_agent_start(role="refund-bot", run_id="run-1")
                model.requested(
                    "claude-opus-5", runtime="hosted-api", prompt={"q": "refund?"}
                )
                model.returned("claude-opus-5", output={"tool": "http.post"})
                call = tools.request(
                    "http.post",
                    "http.post",
                    {"url": "https://payments.internal/refund", "amount": 5},
                    target="payments.internal",
                )
                tools.report(call, ReportedOutcome.SUCCESS, transport_status=200)
                fw.on_agent_end("refund issued")

            kinds = [e.kind for e in sink.events]
            self.assertEqual(
                kinds,
                [
                    AiriEventKind.AGENT_EXECUTION_STARTED,
                    AiriEventKind.MODEL_INVOCATION_REQUESTED,
                    AiriEventKind.MODEL_INVOCATION_OBSERVED,
                    AiriEventKind.TOOL_INVOCATION_REQUESTED,
                    AiriEventKind.TOOL_EXECUTION_REPORTED,
                    AiriEventKind.EXECUTION_COMPLETED,
                ],
            )
            self.assertEqual([e.sequence for e in sink.events], list(range(6)))
            for prev, cur in zip(sink.events, sink.events[1:]):
                self.assertEqual(cur.prev_event_hash, prev.event_hash())
            # One execution, one decision, throughout.
            self.assertEqual(len({e.execution_id for e in sink.events}), 1)
            self.assertTrue(all(e.decision_id == decision for e in sink.events))

    def test_the_request_and_the_report_commit_to_the_same_parameters(self) -> None:
        # The binding between layers 1 and 2 is the parameter commitment. If
        # the adapter let them drift, a verifier would see a substitution.
        with tempfile.TemporaryDirectory() as tmp:
            em, sink, ident = make_emitter(tmp)
            tools = ToolAdapter(em)
            with bind(new_execution(ident.aip_id)):
                call = tools.request("http.post", "http.post", {"amount": 5})
                tools.report(call, ReportedOutcome.SUCCESS, transport_status=200)
            req, rep = sink.events[0].payload, sink.events[1].payload
            self.assertEqual(req.parameter_commitment, rep.parameter_commitment)

    def test_a_failed_call_still_records_the_request(self) -> None:
        # Emitting the request before the call is what makes a missing or
        # failed report meaningful rather than invisible.
        with tempfile.TemporaryDirectory() as tmp:
            em, sink, ident = make_emitter(tmp)
            tools = ToolAdapter(em)
            with bind(new_execution(ident.aip_id)):
                call = tools.request("http.post", "http.post", {"amount": 5})
                tools.report(call, ReportedOutcome.FAILURE)
            self.assertEqual(sink.events[0].kind, AiriEventKind.TOOL_INVOCATION_REQUESTED)
            self.assertEqual(sink.events[1].payload.outcome, ReportedOutcome.FAILURE)

    def test_a_subprocess_handoff_records_both_sides(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            em, sink, ident = make_emitter(tmp)
            fw = FrameworkAdapter(em)
            parent = new_execution(ident.aip_id, decision_id=bytes([0xD1] * 16))
            child = child_execution(parent)
            with bind(parent):
                fw.on_handoff(PropagationBoundary.SUBPROCESS, child.execution_id)
            ev = sink.events[0]
            self.assertEqual(ev.kind, AiriEventKind.EXECUTION_CONTEXT_PROPAGATED)
            self.assertEqual(ev.payload.to_execution_id, child.execution_id)
            self.assertEqual(child.parent_execution_id, parent.execution_id)

    def test_no_prompt_or_output_plaintext_reaches_the_signed_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            em, sink, ident = make_emitter(tmp)
            model = ModelAdapter(em)
            secret_prompt = "PATIENT NAME: Jane Doe, SSN 000-00-0000"
            with bind(new_execution(ident.aip_id)):
                model.requested("claude-opus-5", prompt={"text": secret_prompt})
            blob = sink.events[0].signing_preimage()
            self.assertNotIn(b"Jane Doe", blob)
            self.assertNotIn(b"SSN", blob)

    def test_hosted_inference_records_no_model_digest(self) -> None:
        # The honest answer for a hosted model is "no digest", not a digest of
        # something the agent happens to have on disk.
        with tempfile.TemporaryDirectory() as tmp:
            em, sink, ident = make_emitter(tmp)
            with bind(new_execution(ident.aip_id)):
                ModelAdapter(em).requested("claude-opus-5", runtime="hosted-api")
            self.assertIsNone(sink.events[0].payload.model_digest)

    def test_events_serialise_for_the_rust_interop_fixture(self) -> None:
        """Write the fixture the Rust interop test consumes.

        Deterministic on purpose. ``new_execution()`` draws a random
        execution id — correct for a real agent, wrong for a committed
        fixture, which would then be rewritten on every test run and show as
        a spurious diff forever. A fixed id means the file changes only when
        the *encoding* changes, which is exactly when a reviewer should see a
        diff and look at it.

        The emitter's clock is pinned for the same reason.
        """
        fixed_exec = ExecutionContext(
            agent_id=AGENT,
            execution_id=bytes([0xE1] * 16),
            decision_id=bytes([0xD1] * 16),
        )
        with tempfile.TemporaryDirectory() as tmp:
            em, sink, ident = make_emitter(tmp, clock_ms=lambda: 1_700_000_000_000)
            fw, model, tools = FrameworkAdapter(em), ModelAdapter(em), ToolAdapter(em)
            with bind(fixed_exec):
                fw.on_agent_start(role="refund-bot")
                model.requested("claude-opus-5", prompt={"q": "x"})
                call = tools.request("http.post", "http.post", {"amount": 5})
                tools.report(call, ReportedOutcome.SUCCESS, transport_status=200)
                fw.on_agent_end()

            out = {
                "agent_id": ident.aip_id,
                "public_key": ident.public_key_bytes.hex(),
                "events": [
                    {
                        "sequence": e.sequence,
                        "preimage": e.signing_preimage().hex(),
                        "signature": e.signature.hex(),
                    }
                    for e in sink.events
                ],
            }
            dest = pathlib.Path(__file__).parent / "python_events.json"
            rendered = json.dumps(out, indent=2)

            # A committed fixture that is rewritten on every run is a
            # permanent spurious diff. Regenerating identical bytes is the
            # property that stops that, so it is asserted, not assumed.
            if dest.exists():
                self.assertEqual(
                    dest.read_text(),
                    rendered,
                    "the interop fixture is not byte-stable across runs; a "
                    "committed fixture must regenerate identically or it "
                    "shows as a diff forever",
                )
            dest.write_text(rendered)
            self.assertEqual(len(out["events"]), 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
