"""Regression tests for the SDK's execution and commitment boundaries.

These test self-reported evidence integrity, not independent observation or
whether an external tool actually performed an effect.
"""

from concurrent.futures import ThreadPoolExecutor
import pathlib
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from vanian_airi import ReportedOutcome, bind, new_execution
from vanian_airi.adapters import ToolAdapter
from vanian_airi.commitment import commit_json
from vanian_airi.errors import AiriError, CommitmentError
from test_adapters_e2e import make_emitter


class TestCommitmentFailures(unittest.TestCase):
    def test_nonfinite_numbers_cannot_enter_json_commitments(self):
        # Python's permissive JSON encoder otherwise emits NaN/Infinity,
        # which cannot be represented by a JSON parser such as serde_json.
        for number in (float("nan"), float("inf"), -float("inf")):
            with self.subTest(number=number):
                with self.assertRaises(CommitmentError):
                    commit_json({"arguments": [{"amount": number}]})

    def test_invalid_unicode_raises_the_public_commitment_error(self):
        with self.assertRaises(CommitmentError):
            commit_json({"text": "\ud800"})

    def test_invalid_parameters_do_not_consume_a_sequence_number(self):
        with tempfile.TemporaryDirectory() as tmp:
            emitter, sink, identity = make_emitter(tmp)
            with bind(new_execution(identity.aip_id)):
                first = emitter.agent_started()
                with self.assertRaises(CommitmentError):
                    emitter.tool_requested("transfer", "transfer", {"bad": object()})
                last = emitter.completed()
            self.assertEqual([event.sequence for event in sink.events], [0, 1])
            self.assertEqual(last.prev_event_hash, first.event_hash())


class TestExecutionIsolation(unittest.TestCase):
    def test_an_emitter_refuses_a_second_execution_without_damaging_the_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            emitter, sink, identity = make_emitter(tmp)
            original = new_execution(identity.aip_id)
            with bind(original):
                first = emitter.agent_started()
            with bind(new_execution(identity.aip_id)):
                with self.assertRaises(AiriError):
                    emitter.agent_started()
            with bind(original):
                last = emitter.completed()
            self.assertEqual([event.sequence for event in sink.events], [0, 1])
            self.assertTrue(all(e.execution_id == original.execution_id for e in sink.events))
            self.assertEqual(last.prev_event_hash, first.event_hash())

    def test_concurrent_emission_produces_one_verifiable_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            emitter, sink, identity = make_emitter(tmp)
            context = new_execution(identity.aip_id)
            barrier = threading.Barrier(8)

            def emit(worker):
                with bind(context):
                    barrier.wait(timeout=10)
                    for index in range(8):
                        emitter.tool_requested("read", "read", {"worker": worker, "index": index})

            with ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(emit, range(8)))
            events = sorted(sink.events, key=lambda event: event.sequence)
            self.assertEqual([event.sequence for event in events], list(range(64)))
            public = Ed25519PublicKey.from_public_bytes(identity.public_key_bytes)
            previous_hash = bytes(32)
            for event in events:
                self.assertEqual(event.execution_id, context.execution_id)
                self.assertEqual(event.prev_event_hash, previous_hash)
                public.verify(event.signature, event.signing_preimage())
                previous_hash = event.event_hash()

    def test_sink_failure_is_visible_to_the_caller(self):
        # Do not silently report successful evidence delivery.
        class FailingSink:
            def emit(self, event):
                raise OSError("collector unavailable")

        from vanian_airi import AiriEmitter
        from test_adapters_e2e import FRAMEWORK

        with tempfile.TemporaryDirectory() as tmp:
            _, _, identity = make_emitter(tmp)
            emitter = AiriEmitter(identity, FRAMEWORK, sink=FailingSink())
            with bind(new_execution(identity.aip_id)):
                with self.assertRaisesRegex(OSError, "collector unavailable"):
                    emitter.agent_started()


class TestToolParameterLifetime(unittest.TestCase):
    def test_mutating_the_callers_nested_arguments_does_not_rewrite_the_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            emitter, sink, identity = make_emitter(tmp)
            adapter = ToolAdapter(emitter)
            arguments = {"transfers": [{"amount": 5}], "metadata": {"tags": ["initial"]}}
            expected = commit_json(arguments)
            with bind(new_execution(identity.aip_id)):
                call = adapter.request("transfer", "transfer", arguments)
                arguments["transfers"][0]["amount"] = 500
                arguments["metadata"]["tags"].append("changed")
                adapter.report(call, ReportedOutcome.SUCCESS)
            self.assertEqual(len(sink.events), 2)
            self.assertEqual(sink.events[0].payload.parameter_commitment, expected)
            self.assertEqual(sink.events[1].payload.parameter_commitment, expected)

    def test_mutating_the_returned_call_is_rejected_before_emission(self):
        with tempfile.TemporaryDirectory() as tmp:
            emitter, sink, identity = make_emitter(tmp)
            adapter = ToolAdapter(emitter)
            with bind(new_execution(identity.aip_id)):
                call = adapter.request("transfer", "transfer", {"amounts": [5]})
                call.parameters["amounts"][0] = 500
                with self.assertRaises(AiriError):
                    adapter.report(call, ReportedOutcome.SUCCESS)
                self.assertEqual(len(sink.events), 1)
                call.parameters["amounts"][0] = 5
                adapter.report(call, ReportedOutcome.FAILURE)
            self.assertEqual([event.sequence for event in sink.events], [0, 1])
            self.assertEqual(
                sink.events[0].payload.parameter_commitment,
                sink.events[1].payload.parameter_commitment,
            )


if __name__ == "__main__":
    unittest.main()
