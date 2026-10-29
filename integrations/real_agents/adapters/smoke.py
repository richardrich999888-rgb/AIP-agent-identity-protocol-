"""Offline container compatibility check. This is NOT an autonomous workload."""
import asyncio
import errno
import json
import os
from pathlib import Path
from agent_zero_runtime import configure

for path in (os.environ["HOME"], "/tmp/framework", "/tmp/framework-logs"):
    Path(path).mkdir(parents=True, exist_ok=True)
assert os.geteuid() == 10001
assert not Path("/var/run/docker.sock").exists()
try:
    Path("/opt/framework/.write-check").touch()
except OSError as exc:
    if exc.errno not in (errno.EACCES, errno.EROFS):
        raise
else:
    raise AssertionError("framework source must be read-only")
slot = {"provider": "openai", "name": "offline-smoke-no-model-call",
        "api_base": "http://127.0.0.1:9/v1"}
context = configure({"preset": {"name": "Default", "chat": slot, "utility": slot,
                               "embedding": {**slot, "name": "offline-embedding-no-call"}}}, slot["name"])
from plugins._code_execution.helpers.shell_local import LocalInteractiveSession

async def check_shell():
    shell = LocalInteractiveSession(cwd="/work")
    await shell.connect()
    try:
        await shell.send_command("python -c 'from pathlib import Path; Path(\"/work/smoke.txt\").write_text(\"real local tool\")'")
        for _ in range(20):
            await shell.read_output(timeout=0.25)
            if Path("/work/smoke.txt").exists():
                break
        assert Path("/work/smoke.txt").read_text() == "real local tool"
    finally:
        await shell.close()

asyncio.run(check_shell())
# Actual pinned public API compatibility, with no inference or agent task.
from launch import DiagnosticJournal, FrameworkLogCursor
with DiagnosticJournal("/work/smoke-adapter.jsonl") as journal:
    cursor = FrameworkLogCursor(journal, "ff2a5b9c9c4e490ba38dd7c313e779510bb2071a")
    item = context.log.log(type="info", content="offline diagnostic cursor check")
    for _ in range(4):
        if not cursor.flush(context.log):
            break
    first_cursor = cursor.position
    item.update(content="offline diagnostic cursor update")
    assert cursor.flush(context.log)
    assert cursor.position > first_cursor
pages = [json.loads(line) for line in Path("/work/smoke-adapter.jsonl").read_text().splitlines()]
items = [row["value"]["item"] for row in pages if row["kind"] == "framework_log_update"]
assert any(row["no"] == item.no and row["content"] == "offline diagnostic cursor update" for row in items)
assert all(row["provenance"] == "SELF_REPORTED" for row in pages)
context.kill_process()
print(json.dumps({"status": "PASS", "kind": "offline container/tool smoke",
                  "autonomous_workload_executed": False, "model_calls": 0,
                  "pinned_incremental_log_api": "PASS"}))
