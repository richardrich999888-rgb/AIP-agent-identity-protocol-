"""Tests for observer_ingest. Pure coverage tests always run.

The live tests use the real verifier at VANIAN_OBSERVE_VERIFY_BIN and real
signed archives from validation/final_acceptance/same-run-qualified. They
are SKIPPED when the binary is not set.
"""

import gzip
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

import eventstore as es
import observer_ingest as oi

REPO = Path(__file__).resolve().parents[2]
RUNS = REPO / "validation" / "final_acceptance" / "same-run-qualified" / "originals"
VERIFIER = os.environ.get("VANIAN_OBSERVE_VERIFY_BIN")
# Task windows recorded by the runs themselves (corroboration-*.json, observer-interruption.json).
HEALTHY_TASK = (1793268578504, 1793268603570)
INTERRUPTED_TASK = (1793268722075, 1793268747076)


def w(seq, a, b, run="r1", dropped=0):
    return oi.Window(seq, a, b, run, dropped)


class CoverageTests(unittest.TestCase):
    def test_no_data(self):
        c = oi.coverage([], 100)
        self.assertEqual(c.state, "NO_DATA")
        self.assertFalse(oi.window_covered(c, 0, 1))

    def test_contiguous_is_one_span(self):
        c = oi.coverage([w(1, 0, 10), w(2, 10, 20), w(3, 20, 30)], 31)
        self.assertEqual((c.state, c.spans, c.gaps, c.covered_to_ms), ("COVERED", [(0, 30)], [], 30))
        self.assertTrue(oi.window_covered(c, 5, 25))

    def test_gap_between_batches(self):
        c = oi.coverage([w(1, 0, 10), w(2, 15, 20)], 21)
        self.assertEqual(c.spans, [(0, 10), (15, 20)])
        self.assertEqual(c.gaps, [{"from_ms": 10, "to_ms": 15, "reason": "no batch covers this interval"}])
        self.assertFalse(oi.window_covered(c, 5, 17))

    def test_slack(self):
        self.assertEqual(oi.coverage([w(1, 0, 10), w(2, 12, 20)], 20, slack_ms=2).gaps, [])

    def test_probe_restart_breaks_span_even_if_contiguous(self):
        c = oi.coverage([w(1, 0, 10), w(2, 10, 20, run="r2")], 20)
        self.assertEqual(c.gaps[0]["reason"], "probe restarted")
        self.assertFalse(oi.window_covered(c, 5, 15))

    def test_silence_degrades_with_open_gap(self):
        c = oi.coverage([w(1, 0, 10)], 10 + oi.DEFAULT_MAX_SILENCE_MS + 1)
        self.assertEqual(c.state, "DEGRADED")
        self.assertEqual(c.gaps[-1]["reason"], "observer silent: no batch since")

    def test_silence_at_threshold_is_not_degraded(self):
        self.assertEqual(oi.coverage([w(1, 0, 10)], 10 + oi.DEFAULT_MAX_SILENCE_MS).state, "COVERED")

    def test_losses(self):
        c = oi.coverage([w(1, 0, 10, dropped=3), w(2, 10, 20, dropped=None)], 20)
        self.assertEqual([x["reason"] for x in c.losses], ["3 events dropped", "loss not countable (CANNOT_PROVE)"])
        self.assertFalse(oi.window_covered(c, 1, 2))  # loss means not clean

    def test_order_by_sequence_not_input(self):
        self.assertEqual(oi.coverage([w(2, 10, 20), w(1, 0, 10)], 20).spans, [(0, 20)])

    def test_inverted_query(self):
        self.assertFalse(oi.window_covered(oi.coverage([w(1, 0, 10)], 10), 8, 2))


def rec(seq=1, frm=0, to=10, att=12, run=(1,) * 16, dropped=0):
    return {"sequence": seq, "attested_at_ms": att, "observer_id": "o", "key_version": 1,
            "batch": {"probe_id": "p", "batch_id": [2] * 16, "probe_run_id": list(run),
                      "claimed_from_ms": frm, "claimed_to_ms": to, "dropped_events": dropped,
                      "kernel_events": [{}] * 3, "observations": []}}


class Mapping(unittest.TestCase):
    def test_window_clipped_at_attestation(self):
        self.assertEqual(oi.window_of(rec(to=50, att=20)).to_ms, 20)

    def test_batch_event(self):
        e = oi.batch_event(rec())
        self.assertEqual((e["kind"], e["subject"], e["sequence"], e["kernel_events"], e["dropped_events"]),
                         ("observer.batch", "probe:p", 1, 3, 0))
        self.assertEqual(e["probe_run_id"], "01" * 16)

    def test_malformed(self):
        for r in (rec(seq=-1), rec(frm=20, to=30, att=10), rec(dropped=-1), rec(dropped=True), {"batch": {}}):
            with self.subTest(r=str(r)[:50]), self.assertRaises(ValueError):
                oi.window_of(r)
        bad = rec()
        bad["batch"]["probe_run_id"] = "x"
        with self.assertRaises(ValueError):
            oi.window_of(bad)

    def test_complete_lines(self):
        self.assertEqual(oi.complete_lines(b'{"a":1}\n\n{"b":2}\n{"partial'), [b'{"a":1}', b'{"b":2}'])
        self.assertEqual(oi.complete_lines(b""), [])


class FailClosedWithoutVerifier(unittest.TestCase):
    def test_missing_verifier_ingests_nothing(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            (tmp / "a.jsonl").write_text(json.dumps(rec()) + "\n")
            store = es.EventStore(tmp / "e.db")
            r = oi.ArchiveIngestor(store, tmp / "a.jsonl", str(tmp / "no-verifier"),
                                   oi.Anchor("o", 1, tmp / "k.pub"), lambda: 0).poll()
            self.assertEqual((r.verified, r.reason, r.inserted, store.count()), (False, "verifier not found", 0, 0))
            store.close()
        finally:
            shutil.rmtree(tmp)


@unittest.skipUnless(VERIFIER and Path(VERIFIER).is_file(), "VANIAN_OBSERVE_VERIFY_BIN not set: live verifier tests SKIPPED")
class LiveArchives(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.store = es.EventStore(self.tmp / "events.db")

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.tmp)

    def ingestor(self, run, content=None):
        pub = RUNS / run / "public"
        arch = self.tmp / f"{run}.jsonl"
        arch.write_bytes(content if content is not None else gzip.decompress((pub / "attested.archive.jsonl.gz").read_bytes()))
        anchor = oi.Anchor("collector.same-run", 1, pub / "observer.pub")
        return oi.ArchiveIngestor(self.store, arch, VERIFIER, anchor, lambda: 1), arch

    def test_healthy_run_task_window_covered(self):
        ing, _ = self.ingestor("same-run")
        r = ing.poll()
        self.assertEqual((r.verified, r.lines, r.inserted), (True, 37, 37))
        c = oi.coverage(ing.windows(), HEALTHY_TASK[1])
        self.assertEqual((c.state, c.gaps, c.losses), ("COVERED", [], []))
        self.assertTrue(oi.window_covered(c, *HEALTHY_TASK))
        self.assertEqual(self.store.verify(), [])

    def test_interrupted_run_task_window_is_a_gap_not_clean(self):
        # Adversarial #10/#15 on real evidence: the probe was killed before the task.
        ing, _ = self.ingestor("same-run-interruption")
        self.assertEqual(ing.poll().inserted, 11)
        c = oi.coverage(ing.windows(), INTERRUPTED_TASK[1])
        self.assertEqual(c.state, "DEGRADED")
        self.assertFalse(oi.window_covered(c, *INTERRUPTED_TASK))
        open_gap = c.gaps[-1]
        self.assertLessEqual(open_gap["from_ms"], INTERRUPTED_TASK[0])
        self.assertEqual(open_gap["to_ms"], INTERRUPTED_TASK[1])
        self.assertEqual(c.covered_to_ms, 1793268719091)  # equals the run's own frozen coverage end

    def test_repoll_is_idempotent(self):
        ing, _ = self.ingestor("same-run")
        ing.poll()
        self.assertEqual(ing.poll().inserted, 0)
        self.assertEqual(self.store.count(), 37)

    def test_tampered_line_ingests_nothing(self):
        raw = gzip.decompress((RUNS / "same-run" / "public" / "attested.archive.jsonl.gz").read_bytes())
        lines = raw.split(b"\n")
        r5 = json.loads(lines[4])
        r5["batch"]["dropped_events"] = 0 if r5["batch"]["dropped_events"] else 1
        lines[4] = json.dumps(r5, separators=(",", ":")).encode()
        ing, _ = self.ingestor("same-run", b"\n".join(lines))
        r = ing.poll()
        self.assertFalse(r.verified)
        self.assertGreaterEqual(r.findings or 0, 1)
        self.assertEqual((r.inserted, self.store.count()), (0, 0))

    def test_deleted_middle_batch_ingests_nothing(self):
        raw = gzip.decompress((RUNS / "same-run" / "public" / "attested.archive.jsonl.gz").read_bytes())
        lines = raw.split(b"\n")
        del lines[10]
        ing, _ = self.ingestor("same-run", b"\n".join(lines))
        self.assertEqual((ing.poll().verified, self.store.count()), (False, 0))

    def test_wrong_key_ingests_nothing(self):
        ing, arch = self.ingestor("same-run")
        ing._anchor = oi.Anchor("collector.same-run", 1, RUNS / "same-run-interruption" / "public" / "observer.pub")
        self.assertEqual((ing.poll().verified, self.store.count()), (False, 0))

    def test_partial_trailing_line_waits(self):
        raw = gzip.decompress((RUNS / "same-run" / "public" / "attested.archive.jsonl.gz").read_bytes())
        lines = raw.rstrip(b"\n").split(b"\n")
        partial = b"\n".join(lines[:20]) + b"\n" + lines[20][:40]
        ing, arch = self.ingestor("same-run", partial)
        self.assertEqual(ing.poll().inserted, 20)
        arch.write_bytes(raw)  # the writer finishes
        self.assertEqual(ing.poll().inserted, 17)


if __name__ == "__main__":
    unittest.main()
