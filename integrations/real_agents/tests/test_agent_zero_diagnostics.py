"""Controlled diagnostic fixtures only; no model, agent task or kernel proof."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest

ADAPTERS = Path(__file__).resolve().parents[1] / "adapters"
sys.path.insert(0, str(ADAPTERS))
from agent_zero_runtime import diagnostic_settings
from launch import DiagnosticJournal, FrameworkLogCursor, run_logged_task


class FixtureLog:
    """A controlled producer with the pinned public log surface, not an agent."""
    def __init__(self):
        self.guid = "ordinary-fixture-epoch"
        self.updates = []
        self.items = []
        self.calls = []

    def put(self, content, number=None):
        number = len(self.items) if number is None else number
        item = {"no": number, "type": "info", "content": content}
        if number == len(self.items):
            self.items.append(item)
        else:
            self.items[number] = item
        self.updates.append(number)

    def output(self, start=None, end=None):
        start = 0 if start is None else start
        end = len(self.updates) if end is None else end
        self.calls.append((start, end))
        numbers = dict.fromkeys(self.updates[start:end])
        return SimpleNamespace(start=start, end=end,
                               items=[copy.deepcopy(self.items[n]) for n in numbers])


class FixtureTask:
    def __init__(self, ready=False, error=None):
        self.ready, self.error = ready, error

    def is_ready(self):
        return self.ready

    def result_sync(self, timeout):
        if self.error:
            raise self.error
        return "ordinary fixture result; no software acceptance"


class FixtureContext:
    def __init__(self, task=None):
        self.log = FixtureLog()
        self.log.put("ordinary fixture event")
        self.task = task or FixtureTask()
        self.killed = False

    def communicate(self, message):
        return self.task

    def kill_process(self):
        self.killed = True


def read(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


class AgentZeroDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / "adapter.jsonl"

    def tearDown(self):
        self.temp.cleanup()

    def test_updated_item_number_keeps_actual_update_cursor_and_original_prefix(self):
        log = FixtureLog(); log.put("first fixture value")
        with DiagnosticJournal(self.path) as journal:
            cursor = FrameworkLogCursor(journal, "fixture-source-commit")
            self.assertTrue(cursor.flush(log))
            prefix = self.path.read_bytes()
            log.put("updated fixture value", number=0)
            self.assertTrue(cursor.flush(log))
        rows = [r for r in read(self.path) if r["kind"] == "framework_log_update"]
        self.assertEqual([r["value"]["item"]["no"] for r in rows], [0, 0])
        self.assertEqual([r["value"]["update_start"] for r in rows], [0, 1])
        self.assertEqual([r["value"]["update_end"] for r in rows], [1, 2])
        self.assertTrue(self.path.read_bytes().startswith(prefix))
        self.assertTrue(all(r["provenance"] == "SELF_REPORTED" for r in rows))
        self.assertTrue(all(r["value"]["snapshot_atomic"] is False for r in rows))
        self.assertEqual(rows[-1]["value"]["upstream_source_commit"], "fixture-source-commit")

    def test_page_budget_and_new_log_epoch_do_not_skip_or_merge_cursors(self):
        log = FixtureLog()
        for number in range(40):
            log.put(str(number))
        with DiagnosticJournal(self.path) as journal:
            cursor = FrameworkLogCursor(journal, "fixture-source")
            self.assertTrue(cursor.flush(log))
            self.assertEqual(log.calls, [(0, cursor.PAGE_UPDATES)])
            self.assertEqual(cursor.position, cursor.PAGE_UPDATES)
            log.guid = "new-fixture-epoch"; log.updates = []; log.items = []
            log.put("new epoch")
            self.assertTrue(cursor.flush(log))
        rows = read(self.path)
        self.assertEqual([r["value"]["log_guid"] for r in rows if r["kind"] == "framework_log_epoch"],
                         ["ordinary-fixture-epoch", "new-fixture-epoch"])
        self.assertEqual(rows[-1]["value"]["update_start"], 0)
        self.assertEqual(rows[-1]["value"]["item"]["content"], "new epoch")

    def test_total_byte_limit_reserves_explicit_marker_and_does_not_trim_prefix(self):
        with DiagnosticJournal(self.path, max_bytes=8192, max_record_bytes=1024) as journal:
            self.assertTrue(journal.emit("fixture", {"text": "original fixture record"}))
            prefix = self.path.read_bytes()
            for _ in range(100):
                if not journal.emit("fixture", {"text": "x" * 400}):
                    break
            self.assertTrue(journal.stopped)
            self.assertFalse(journal.emit("ignored", {"text": "after declared limit"}))
        self.assertLessEqual(self.path.stat().st_size, 8192)
        self.assertTrue(self.path.read_bytes().startswith(prefix))
        self.assertEqual(read(self.path)[-1]["kind"], "diagnostic_limit")
        self.assertIs(read(self.path)[-1]["value"]["journal_complete"], False)

    def test_single_oversized_record_is_not_partially_published(self):
        with DiagnosticJournal(self.path, max_bytes=8192, max_record_bytes=1024) as journal:
            self.assertFalse(journal.emit("fixture", {"never_publish_this_payload": "z" * 2000}))
        self.assertEqual(len(read(self.path)), 1)
        self.assertNotIn("never_publish_this_payload", self.path.read_text())
        self.assertEqual(read(self.path)[0]["value"]["reason"], "record_limit")

    def test_snapshot_fault_retains_type_without_exception_text(self):
        class FaultLog(FixtureLog):
            def output(self, start=None, end=None):
                raise RuntimeError("never publish fixture credential text")
        log = FaultLog(); log.put("fixture")
        with DiagnosticJournal(self.path) as journal:
            self.assertFalse(FrameworkLogCursor(journal, "fixture").flush(log))
        self.assertEqual(read(self.path)[-1]["kind"], "diagnostic_fault")
        self.assertEqual(read(self.path)[-1]["value"]["exception_type"], "RuntimeError")
        self.assertNotIn("fixture credential", self.path.read_text())

    def test_short_writes_are_completed_before_durable_record_accounting(self):
        class ShortWriter:
            def __init__(self, stream):
                self.stream, self.calls = stream, 0
            def write(self, value):
                self.calls += 1
                return self.stream.write(value[:7])
            def fileno(self):
                return self.stream.fileno()
            def close(self):
                self.stream.close()
        with DiagnosticJournal(self.path) as journal:
            writer = ShortWriter(journal.stream); journal.stream = writer
            self.assertTrue(journal.emit("fixture", {"text": "short writes retain all bytes"}))
            self.assertGreater(writer.calls, 1)
            self.assertEqual(journal.bytes_written, self.path.stat().st_size)
        self.assertEqual(read(self.path)[0]["value"]["text"], "short writes retain all bytes")

    def test_no_progress_write_is_a_failure_without_false_byte_accounting(self):
        class NoProgressWriter:
            def __init__(self, stream):
                self.stream = stream
            def write(self, value):
                return None
            def close(self):
                self.stream.close()
        with DiagnosticJournal(self.path) as journal:
            journal.stream = NoProgressWriter(journal.stream)
            with self.assertRaises(OSError):
                journal.emit("fixture", {"text": "must not count a failed write"})
            self.assertEqual(journal.bytes_written, 0)
        self.assertEqual(self.path.read_bytes(), b"")

    def test_existing_or_symlink_journal_is_refused_without_overwrite(self):
        original = self.root / "existing"; original.write_bytes(b"ordinary existing bytes")
        self.path.symlink_to(original)
        with self.assertRaises(FileExistsError):
            DiagnosticJournal(self.path)
        self.assertEqual(original.read_bytes(), b"ordinary existing bytes")

    def test_task_exception_and_timeout_propagate_without_acceptance(self):
        for index, task in enumerate((FixtureTask(ready=True, error=ValueError("private fixture error")),
                                      FixtureTask(ready=False))):
            with self.subTest(index=index):
                path = self.root / f"failure-{index}.jsonl"
                context = FixtureContext(task)
                with DiagnosticJournal(path) as journal:
                    with self.assertRaises((ValueError, TimeoutError)):
                        run_logged_task(context, "ordinary fixture", 0.01, journal, "fixture")
                self.assertTrue(context.killed)
                self.assertIn("task_failed", [r["kind"] for r in read(path)])
                self.assertNotIn("task_returned", [r["kind"] for r in read(path)])
                self.assertNotIn("private fixture error", path.read_text())

    def test_outer_sigkill_before_finally_keeps_flushed_original_records(self):
        # Independent parent kills a real process while its controlled task is
        # pending. No finally handler or model/network/container is required.
        script = """
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from test_agent_zero_diagnostics import FixtureContext, DiagnosticJournal, run_logged_task
path, marker = Path(sys.argv[2]), Path(sys.argv[3])
try:
    with DiagnosticJournal(path) as journal:
        run_logged_task(FixtureContext(), 'controlled pending task', 30, journal, 'fixture-source')
finally:
    marker.write_text('finally ran')
"""
        marker = self.root / "finally-ran"
        process = subprocess.Popen([sys.executable, "-c", script, str(Path(__file__).parent),
                                    str(self.path), str(marker)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if self.path.exists() and b'"framework_log_update"' in self.path.read_bytes():
                    break
                if process.poll() is not None:
                    self.fail(process.communicate()[1].decode())
                time.sleep(0.01)
            else:
                self.fail("controlled producer did not flush a record")
            prefix = self.path.read_bytes()
            process.kill(); process.wait(timeout=5)
            self.assertFalse(marker.exists())
            self.assertTrue(self.path.read_bytes().startswith(prefix))
            rows = read(self.path)
            self.assertIn("framework_log_update", [r["kind"] for r in rows])
            self.assertNotIn("task_returned", [r["kind"] for r in rows])
            self.assertTrue(all(r["provenance"] == "SELF_REPORTED" for r in rows))
        finally:
            if process.poll() is None:
                process.kill(); process.wait(timeout=5)
            process.communicate()

    def test_configuration_allowlist_excludes_credentials_endpoints_and_arbitrary_kwargs(self):
        slot = {"provider": "ollama", "name": "public-fixture-model", "ctx_length": 8192,
                "api_key": "never publish key", "api_base": "https://private-endpoint/",
                "headers": {"Authorization": "never publish header"},
                "kwargs": {"temperature": 0, "num_ctx": 8192, "num_predict": 1024,
                           "response_format": {"type": "json_object"},
                           "arbitrary_key": "never publish extra", "top_p": "never publish value"}}
        value = diagnostic_settings({"chat_model": slot, "utility_model": slot}, True)
        raw = json.dumps(value)
        for forbidden in ("never publish", "private-endpoint", "api_key", "api_base", "headers", "arbitrary_key"):
            self.assertNotIn(forbidden, raw)
        self.assertTrue(value["chat"]["native_json_object_requested"])
        self.assertEqual(value["chat"]["num_predict"], 1024)
        self.assertEqual(value["memory"], "DISABLED_UNVALIDATED")
        self.assertEqual(value["embedding_validation"], "NOT_ESTABLISHED")

    def test_configuration_allowlist_does_not_copy_nested_or_nonfinite_values(self):
        slot = {"provider": {"secret": "never publish nested"},
                "name": "unprintable\nidentifier", "ctx_length": True,
                "kwargs": {"temperature": float("nan"), "num_ctx": 10 ** 1000,
                           "num_predict": "never publish numeric string"}}
        value = diagnostic_settings({"chat_model": slot, "utility_model": slot}, False)
        self.assertEqual(value["chat"], {"native_json_object_requested": False})
        self.assertNotIn("never publish", json.dumps(value))



if __name__ == "__main__":
    unittest.main()
