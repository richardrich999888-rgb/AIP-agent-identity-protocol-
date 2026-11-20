"""Tests for eventstore.py: happy path, adversarial #13 and #14, and tampering."""

import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import eventstore as es

E1 = {"kind": "process.exec", "subject": "agent:recon-reporter", "observed_at_ms": 1000, "pid": 4242}
E2 = {"kind": "tool.call", "subject": "agent:recon-reporter", "observed_at_ms": 2000, "tool": "fs.read_file"}
E3 = {"kind": "tool.call", "subject": "agent:orchestrator", "observed_at_ms": 1500}


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = Path(self.dir.name) / "events.db"
        self.s = es.EventStore(self.path)

    def tearDown(self):
        self.s.close()
        self.dir.cleanup()

    def raw(self):
        return sqlite3.connect(str(self.path), isolation_level=None)


class HappyPath(Base):
    def test_append_and_read_in_order(self):
        a, b = self.s.append(E1, 10), self.s.append(E2, 11)
        self.assertEqual((a.seq, a.inserted, b.seq, b.inserted), (1, True, 2, True))
        got = self.s.events()
        self.assertEqual([g.event for g in got], [E1, E2])
        self.assertEqual([g.ingested_at_ms for g in got], [10, 11])

    def test_filters_and_paging(self):
        for i, e in enumerate((E1, E2, E3)):
            self.s.append(e, i)
        self.assertEqual([g.seq for g in self.s.events(kind="tool.call")], [2, 3])
        self.assertEqual([g.seq for g in self.s.events(subject="agent:orchestrator")], [3])
        self.assertEqual([g.seq for g in self.s.events(after_seq=1, limit=1)], [2])

    def test_last_observed(self):
        self.s.append(E1, 0)
        self.s.append(E2, 0)
        self.assertEqual(self.s.last_observed_ms("agent:recon-reporter"), 2000)

    def test_never_observed_is_none_not_zero(self):
        self.assertIsNone(self.s.last_observed_ms("agent:nobody"))

    def test_verify_clean(self):
        for e in (E1, E2, E3):
            self.s.append(e, 0)
        self.assertEqual(self.s.verify(), [])

    def test_empty_head(self):
        self.assertEqual(self.s.head(), (0, es.GENESIS))
        self.assertEqual(self.s.verify(), [])


class Duplicates(Base):
    """Adversarial #14: duplicate ingestion is a no-op."""

    def test_same_event_twice(self):
        a = self.s.append(E1, 10)
        b = self.s.append(E1, 99)  # later ingestion time: still the same event
        self.assertEqual((b.seq, b.idem, b.inserted), (a.seq, a.idem, False))
        self.assertEqual(self.s.count(), 1)
        self.assertEqual(self.s.events()[0].ingested_at_ms, 10)

    def test_key_order_does_not_matter(self):
        reordered = dict(reversed(list(E1.items())))
        self.assertEqual(self.s.append(E1, 0).idem, self.s.append(reordered, 0).idem)
        self.assertEqual(self.s.count(), 1)

    def test_any_field_change_is_a_new_event(self):
        self.s.append(E1, 0)
        self.assertTrue(self.s.append({**E1, "pid": 4243}, 0).inserted)
        self.assertEqual(self.s.count(), 2)

    def test_duplicate_does_not_extend_chain(self):
        self.s.append(E1, 0)
        h = self.s.head()
        self.s.append(E1, 0)
        self.assertEqual(self.s.head(), h)


class Restart(Base):
    """Adversarial #13: a restart preserves state."""

    def test_reopen_keeps_events_and_dedup(self):
        self.s.append(E1, 0)
        self.s.append(E2, 0)
        head = self.s.head()
        self.s.close()
        self.s = es.EventStore(self.path)
        self.assertEqual(self.s.count(), 2)
        self.assertEqual(self.s.head(), head)
        self.assertFalse(self.s.append(E1, 5).inserted)
        self.assertEqual(self.s.append(E3, 5).seq, 3)
        self.assertEqual(self.s.verify(), [])

    def test_separate_process_writes_survive(self):
        # A different OS process appends, exits; this one sees the rows.
        code = (
            "import sys, eventstore as es; s = es.EventStore(sys.argv[1]); "
            "s.append({'kind':'k','subject':'x','observed_at_ms':7}, 1); s.close()"
        )
        here = str(Path(es.__file__).parent)
        subprocess.run([sys.executable, "-c", code, str(self.path)], cwd=here, check=True)
        self.assertEqual(self.s.last_observed_ms("x"), 7)
        self.assertEqual(self.s.verify(), [])


class AppendOnly(Base):
    def test_update_refused(self):
        self.s.append(E1, 0)
        with self.raw() as db, self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
            db.execute("UPDATE events SET body = '{}' WHERE seq = 1")

    def test_delete_refused(self):
        self.s.append(E1, 0)
        with self.raw() as db, self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
            db.execute("DELETE FROM events WHERE seq = 1")


class Tamper(Base):
    """Edits made with the triggers dropped are still detected by verify()."""

    def tamper(self, *sql):
        db = self.raw()
        db.execute("DROP TRIGGER events_no_update")
        db.execute("DROP TRIGGER events_no_delete")
        for q in sql:
            db.execute(q)
        db.close()

    def fill(self):
        for e in (E1, E2, E3):
            self.s.append(e, 0)

    def test_edited_body(self):
        self.fill()
        self.tamper("""UPDATE events SET body = replace(body, '4242', '9999') WHERE seq = 1""")
        self.assertIn("seq 1: body does not match its key", self.s.verify())

    def test_body_and_key_rewritten_together(self):
        self.fill()
        forged = es.idempotency_key(es.canonical({**E1, "pid": 9999}))
        self.tamper(f"UPDATE events SET body = '{es.canonical({**E1, 'pid': 9999})}', idem = '{forged}' WHERE seq = 1")
        p = self.s.verify()
        self.assertIn("seq 1: row_hash mismatch", p)

    def test_deleted_middle_row(self):
        self.fill()
        self.tamper("DELETE FROM events WHERE seq = 2")
        p = self.s.verify()
        self.assertIn("seq 3: gap after 1", p)
        self.assertIn("seq 3: prev_hash does not link to the previous row", p)

    def test_deleted_first_row(self):
        self.fill()
        self.tamper("DELETE FROM events WHERE seq = 1")
        self.assertIn("seq 2: prev_hash does not link to the previous row", self.s.verify())

    def test_truncated_tail_needs_a_held_head(self):
        # Known limit: dropping the newest row leaves a valid shorter chain.
        self.fill()
        held = self.s.head()
        self.tamper("DELETE FROM events WHERE seq = 3")
        self.assertEqual(self.s.verify(), [])
        self.assertNotEqual(self.s.head(), held)  # only a held head reveals it


class Invalid(Base):
    def test_rejected_inputs_write_nothing(self):
        bad = [
            [], "x", None, {}, {"kind": ""}, {"kind": 1}, {"kind": "k", "subject": ""},
            {"kind": "k", "observed_at_ms": -1}, {"kind": "k", "observed_at_ms": True},
            {"kind": "k", "observed_at_ms": 1.5}, {"kind": "k", "v": float("nan")},
            {"kind": "k", "v": [float("inf")]}, {"kind": "k", "v": {1: "x"}}, {"kind": "k", "v": object()},
            {"kind": "k", "v": "x" * (es.MAX_BODY_BYTES + 1)},
        ]
        for e in bad:
            with self.subTest(e=repr(e)[:60]), self.assertRaises(es.InvalidEvent):
                self.s.append(e, 0)
        self.assertEqual(self.s.count(), 0)

    def test_bad_ingest_time(self):
        for t in (-1, True, 1.0, None):
            with self.subTest(t=t), self.assertRaises(es.InvalidEvent):
                self.s.append(E1, t)

    def test_bad_paging(self):
        for kw in ({"limit": 0}, {"limit": es.MAX_PAGE + 1}, {"after_seq": -1}):
            with self.subTest(kw=kw), self.assertRaises(ValueError):
                self.s.events(**kw)


if __name__ == "__main__":
    unittest.main()
