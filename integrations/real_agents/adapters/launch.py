#!/usr/bin/env python3
"""Runs upstream agents. All outputs here are SELF_REPORTED, including tools.

This script runs inside the untrusted workload sandbox and has no observer
key, signed-archive mount, Docker socket, or access to the control directory.
"""
import asyncio
import json
import os
import sys
import threading
import time
from pathlib import Path


def emit(kind, value):
    with Path("/work/adapter.jsonl").open("a") as out:
        out.write(json.dumps({"provenance": "SELF_REPORTED", "kind": kind,
                              "value": value, "time_ms": time.time_ns() // 1_000_000},
                             default=str) + "\n")


class DiagnosticJournal:
    """Bounded original SELF_REPORTED records, durable before task completion.

    This is an untrusted workload diagnostic, never independent execution or
    task acceptance. Reserve room for a limit/fault marker without truncating
    an existing record or copying an unbounded framework log.
    """
    MAX_BYTES = 4 * 1024 * 1024
    MAX_RECORD_BYTES = 64 * 1024
    MARKER_RESERVE = 2048

    def __init__(self, path, *, max_bytes=MAX_BYTES, max_record_bytes=MAX_RECORD_BYTES):
        if max_bytes < 2 * self.MARKER_RESERVE or not 1 <= max_record_bytes <= max_bytes:
            raise ValueError("invalid diagnostic journal bounds")
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             getattr(os, "O_NOFOLLOW", 0), 0o600)
        self.stream = os.fdopen(descriptor, "wb", buffering=0)
        self.max_bytes = max_bytes
        self.max_record_bytes = max_record_bytes
        self.bytes_written = 0
        self.stopped = False
        self.lock = threading.Lock()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.stream.close()

    @staticmethod
    def _record(kind, value):
        return (json.dumps({"provenance": "SELF_REPORTED", "kind": kind,
                            "value": value, "time_ms": time.time_ns() // 1_000_000},
                           ensure_ascii=False, allow_nan=False, default=str) + "\n").encode()

    def _write(self, data):
        remaining = memoryview(data)
        while remaining:
            written = self.stream.write(remaining)
            if not written:
                raise OSError("diagnostic write made no progress")
            remaining = remaining[written:]
        os.fsync(self.stream.fileno())
        self.bytes_written += len(data)

    def _stop(self, kind, value):
        # Marker content is owned metadata, never the rejected payload/error.
        data = self._record(kind, {**value, "journal_complete": False})
        if len(data) > self.MARKER_RESERVE or self.bytes_written + len(data) > self.max_bytes:
            raise RuntimeError("diagnostic marker reservation exhausted")
        self._write(data)
        self.stopped = True

    def emit(self, kind, value):
        with self.lock:
            if self.stopped:
                return False
            data = self._record(kind, value)
            if (len(data) > self.max_record_bytes or
                    self.bytes_written + len(data) > self.max_bytes - self.MARKER_RESERVE):
                self._stop("diagnostic_limit", {
                    "reason": "record_limit" if len(data) > self.max_record_bytes else "journal_limit",
                    "limit_bytes": self.max_bytes, "next_record_bytes": len(data),
                    "source_kind": kind})
                return False
            self._write(data)
            return True

    def fault(self, error):
        with self.lock:
            if not self.stopped:
                self._stop("diagnostic_fault", {"exception_type": type(error).__name__})


class FrameworkLogCursor:
    """Read the pinned public Log.output API in bounded update pages.

    Upstream copies its update indices/list under a lock but reads each item's
    fields later. These are live, self-reported snapshots, not atomic state.
    A repeated item number is a real update and must not be discarded.
    """
    PAGE_UPDATES = 16

    def __init__(self, journal, source_commit):
        self.journal = journal
        self.source_commit = source_commit
        self.guid = None
        self.position = 0

    def flush(self, log):
        if self.journal.stopped:
            return False
        try:
            guid = log.guid
            if self.guid != guid:
                self.journal.emit("framework_log_epoch", {
                    "upstream_source_commit": self.source_commit, "log_guid": guid,
                    "previous_update_cursor": self.position, "previous_log_guid": self.guid})
                self.guid, self.position = guid, 0
            # updates is a public upstream version list (also used by
            # AgentContext snapshots). The public output method owns locking.
            end = min(self.position + self.PAGE_UPDATES, len(log.updates))
            if end <= self.position:
                return False
            page = log.output(start=self.position, end=end)
            if log.guid != guid:
                # A reset raced this read. Retain the new epoch next poll;
                # never attach mixed-epoch items to an old cursor.
                return True
            metadata = {"upstream_source_commit": self.source_commit,
                        "log_guid": guid, "update_start": page.start,
                        "update_end": page.end, "snapshot_atomic": False}
            for index, item in enumerate(page.items):
                if not self.journal.emit("framework_log_update", {
                        **metadata, "page_item_index": index, "item": item}):
                    return False
            self.position = page.end
            return True
        except Exception as error:
            self.journal.fault(error)
            return False


def run_logged_task(context, message, timeout_s, journal, source_commit):
    """Poll without extending the existing inner or root workload deadline."""
    cursor = FrameworkLogCursor(journal, source_commit)
    task = None
    try:
        journal.emit("task_started", {"timeout_s": timeout_s})
        task = context.communicate(message)
        deadline = time.monotonic() + timeout_s
        while not task.is_ready():
            cursor.flush(context.log)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("framework task exceeded its existing runtime budget")
            time.sleep(min(0.25, remaining))
        result = task.result_sync(timeout=0)
        journal.emit("task_returned", {"independent_task_acceptance": False})
        return result
    except Exception as error:
        # Exception text/tracebacks can contain credentials. Preserve only
        # the type here; failure still propagates and cannot become success.
        journal.emit("task_failed", {"exception_type": type(error).__name__})
        raise
    finally:
        # This is opportunistic only: the unchanged root deadline can kill
        # the process before finally. Earlier flushed pages remain durable.
        for _ in range(4):
            if not cursor.flush(context.log):
                break
        context.kill_process()


def main():
    request = json.loads(Path("/input/request.json").read_text())
    while not Path("/input/start").exists():
        time.sleep(0.1)
    name, prompt = request["framework"], request["prompt"]
    if name == "agent_zero":
        from agent_zero_runtime import configure
        with DiagnosticJournal("/work/adapter.jsonl") as journal:
            journal.emit("start", {"framework": name, "model": request["model"],
                                  "logical_agent": "lead"})
            journal.emit("configure_started", {})
            try:
                context = configure(json.loads(Path("/model-config/agent-zero.json").read_text()),
                                    request["model"], on_configured=lambda value:
                                    journal.emit("configuration_verified", value))
            except Exception as error:
                journal.emit("configure_failed", {"exception_type": type(error).__name__})
                raise
            journal.emit("configure_ready", {})
            from agent import UserMessage
            result = run_logged_task(context, UserMessage(prompt), request["timeout_s"], journal,
                                     request.get("framework_source_commit", "UNSPECIFIED"))
            Path("/work/response.json").write_text(json.dumps(result, default=str, indent=2))
            journal.emit("returned", {"framework": name, "independent_task_acceptance": False})
        return
    emit("start", {"framework": name, "model": request["model"], "logical_agent": "lead"})
    if name == "deerflow":
        os.chdir("/opt/framework/backend")
        from deerflow.client import DeerFlowClient

        client = DeerFlowClient(config_path="/model-config/deerflow.yaml",
                               model_name=request["model"], subagent_enabled=True)
        result = []
        for event in client.stream(prompt, thread_id=request["run_id"]):
            emit("framework_event", {"type": event.type, "data": event.data})
            result.append({"type": event.type, "data": event.data})
    elif name == "openhands":
        os.chdir("/work")
        from openhands.sdk import LLM, Agent, Conversation, Tool
        from openhands.tools.file_editor import FileEditorTool
        from openhands.tools.task_tracker import TaskTrackerTool
        from openhands.tools.terminal import TerminalTool

        llm = LLM(model=request["model"], api_key=os.environ["LLM_API_KEY"],
                  base_url=os.environ["LLM_BASE_URL"])
        agent = Agent(llm=llm, tools=[Tool(name=t.name) for t in
                                     (TerminalTool, FileEditorTool, TaskTrackerTool)])
        conversation = Conversation(agent=agent, workspace="/work")
        conversation.send_message(prompt)
        conversation.run()
        # Completion is a framework assertion. The controller requires an
        # independently inspected patch, tests and signed kernel evidence.
        result = "Conversation.run returned; inspect /work outputs"
    else:
        raise ValueError("unsupported framework")
    Path("/work/response.json").write_text(json.dumps(result, default=str, indent=2))
    emit("returned", {"framework": name})


if __name__ == "__main__":
    main()
