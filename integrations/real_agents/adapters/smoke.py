"""Actual upstream compatibility checks; never an autonomous/model workload."""
import asyncio
import json
import os
from pathlib import Path

from framework_smokes import (_command_for, child_hold_seconds, container_boundary,
                              framework_metadata, smoke_deerflow, smoke_openhands,
                              wait_start_gate)


def smoke_agent_zero():
    from agent_zero_runtime import configure
    slot = {"provider": "openai", "name": "offline-smoke-no-model-call",
            "api_base": "http://127.0.0.1:9/v1"}
    context = configure({"preset": {"name": "Default", "chat": slot, "utility": slot,
                                   "embedding": {**slot, "name": "offline-embedding-no-call"}}}, slot["name"])
    from plugins._code_execution.helpers.shell_local import LocalInteractiveSession

    async def check_shell():
        shell = LocalInteractiveSession(cwd="/work")
        await shell.connect()
        try:
            await shell.send_command(_command_for("/work/smoke.txt", text="real local tool"))
            for _ in range(20):
                await shell.read_output(timeout=0.25)
                if Path("/work/smoke.txt").exists():
                    break
            assert Path("/work/smoke.txt").read_text() == "real local tool"
            if child_hold_seconds():
                await asyncio.sleep(child_hold_seconds())
        finally:
            await shell.close()

    asyncio.run(check_shell())
    # Actual pinned public API compatibility, with no inference or agent task.
    from launch import DiagnosticJournal, FrameworkLogCursor
    with DiagnosticJournal("/work/smoke-adapter.jsonl") as journal:
        cursor = FrameworkLogCursor(journal, os.environ["FRAMEWORK_COMMIT"])
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
    # Resolve the reviewed upstream profile/tool/prompt policy without asking
    # any model to act. The later real capability test is a separate gate.
    tiny = configure({"reviewed_profile": "tiny-local-coding-v1", "disable_memory": True,
                      "preset": {"name": "Default", "chat": slot, "utility": slot,
                                 "embedding": {**slot, "name": "offline-embedding-no-call"}}}, slot["name"])
    try:
        assert tiny.config.profile == "tiny-local"
    finally:
        tiny.kill_process()
    return {"pinned_incremental_log_api": "PASS", "terminal_and_file": "PASS",
            "reviewed_tiny_local_profile_policy": "PASS"}


def main():
    framework = os.environ["FRAMEWORK"]
    checks = {"agent_zero": smoke_agent_zero, "deerflow": smoke_deerflow,
              "openhands": smoke_openhands}
    if framework not in checks:
        raise ValueError("unsupported framework")
    gate = wait_start_gate()
    hold = child_hold_seconds()
    container_boundary(framework)
    result = checks[framework]()
    print(json.dumps({"status": "PASS", "kind": "offline container/tool smoke",
          "framework": framework, "autonomous_workload_executed": False,
          "model_calls": 0, "delegation": "UNVALIDATED",
          "logical_agent_attribution": "CANNOT_PROVE",
          "browser_and_frontend": "NOT_EXERCISED", "checks": result,
          "start_gate": gate, "component_child_hold_seconds": hold,
          "performance_measurement": "NOT_ESTABLISHED_COMPONENT_HOLD_IS_EXPLICIT",
          **framework_metadata(framework)}))


if __name__ == "__main__":
    main()
