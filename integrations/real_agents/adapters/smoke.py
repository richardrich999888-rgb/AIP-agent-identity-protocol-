"""Actual upstream compatibility checks; never an autonomous/model workload."""
import asyncio
import json
import os
import sys
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

    async def check_python_tool():
        # Exercise the actual runtime=python dispatch, which invokes IPython in
        # this upstream version. No model loop or inference is involved.
        from plugins._code_execution.tools.code_execution_tool import CodeExecution
        target = Path("/work/smoke-python.txt")
        target.unlink(missing_ok=True)
        code = ("from pathlib import Path; import sys,time; "
                f"assert Path(sys.prefix).resolve()==Path({sys.prefix!r}).resolve(); "
                "Path('/work/smoke-python.txt').write_text('real upstream python tool'); "
                f"time.sleep({child_hold_seconds()!r}); print('python-tool-smoke-complete')")
        tool = CodeExecution(agent=context.agent0, name="code_execution_tool", method=None,
                             args={"runtime": "python", "code": code, "session": "0", "reset": True},
                             message="offline Python runtime component check",
                             loop_data=context.agent0.loop_data)
        try:
            await tool.before_execution()
            response = await asyncio.wait_for(tool.execute(), timeout=60)
            assert target.read_text() == "real upstream python tool"
            assert "python-tool-smoke-complete" in response.message
            await tool.after_execution(response)
        finally:
            state = getattr(tool, "state", None)
            if state:
                for shell in state.shells.values():
                    await shell.session.close()

    asyncio.run(check_shell())
    asyncio.run(check_python_tool())
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
            "actual_code_execution_python_runtime": "PASS",
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
