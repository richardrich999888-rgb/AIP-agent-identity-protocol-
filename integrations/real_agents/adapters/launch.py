#!/usr/bin/env python3
"""Runs upstream agents. All outputs here are SELF_REPORTED, including tools.

This script runs inside the untrusted workload sandbox and has no observer
key, signed-archive mount, Docker socket, or access to the control directory.
"""
import asyncio
import json
import os
import sys
import time
from pathlib import Path


def emit(kind, value):
    with Path("/work/adapter.jsonl").open("a") as out:
        out.write(json.dumps({"provenance": "SELF_REPORTED", "kind": kind,
                              "value": value, "time_ms": time.time_ns() // 1_000_000},
                             default=str) + "\n")


def main():
    request = json.loads(Path("/input/request.json").read_text())
    while not Path("/input/start").exists():
        time.sleep(0.1)
    name, prompt = request["framework"], request["prompt"]
    emit("start", {"framework": name, "model": request["model"], "logical_agent": "lead"})
    if name == "agent_zero":
        os.chdir("/opt/framework")
        sys.path.insert(0, os.getcwd())
        from helpers import settings
        from initialize import initialize_agent
        from agent import AgentContext, UserMessage

        # Runtime settings persist only in this disposable container. Secrets
        # remain restricted model credentials; never collector signing keys.
        overrides = json.loads(Path("/model-config/agent-zero.json").read_text())
        settings.set_settings_delta(overrides)
        context = AgentContext(initialize_agent())
        result = context.communicate(UserMessage(prompt)).result_sync(timeout=request["timeout_s"])
        emit("framework_log", context.log.logs)
        context.kill_process()
    elif name == "deerflow":
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
