#!/usr/bin/env python3
"""A real pydantic-ai agent, the third M3 observed subject.

The framework's own agent loop runs: the model turn returns a tool call, the
framework validates it against the registered tool's schema, dispatches the
tool, feeds the result back, and the next model turn ends the run. The tool
spawns `child_action.py` as a real separate process (file write + one TCP
connect).

The model is pydantic-ai's own `FunctionModel` — the framework's supported
way to run an agent against a deterministic function instead of an LLM. No
language model is involved and none is claimed: what this subject exercises
is the framework's tool-dispatch path, which is what puts a process on the
kernel the observer watches.

Prints `AGENT_RESULT parent_pid=… child_pid=…` for the harness.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from pydantic_ai import Agent
from pydantic_ai.messages import ModelMessage, ModelResponse, TextPart, ToolCallPart, ToolReturnPart
from pydantic_ai.models.function import AgentInfo, FunctionModel

CHILD = Path(__file__).resolve().parents[2] / "child_action.py"
MARKED = sys.argv[1] if len(sys.argv) > 1 else "/tmp/aip_m3_pa_marker"


def decide(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
    """First turn: call the tool. After its result comes back: finish."""
    returned = [p for m in messages for p in getattr(m, "parts", []) if isinstance(p, ToolReturnPart)]
    if not returned:
        return ModelResponse(parts=[ToolCallPart("spawn_child", {"marked_path": MARKED})])
    return ModelResponse(parts=[TextPart(str(returned[-1].content))])


agent = Agent(FunctionModel(decide))


@agent.tool_plain
def spawn_child(marked_path: str) -> str:
    """Run the child sub-agent as a real process."""
    proc = subprocess.Popen(
        [sys.executable, str(CHILD), marked_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    out, _ = proc.communicate(timeout=30)
    print(out, end="", flush=True)
    return f"child_pid={proc.pid} exit_code={proc.returncode}"


if __name__ == "__main__":
    print(f"PARENT pid={os.getpid()} framework=pydantic-ai", flush=True)
    result = agent.run_sync("perform the marked action")
    fields = dict(kv.split("=") for kv in result.output.split())
    print(
        f"AGENT_RESULT parent_pid={os.getpid()} child_pid={fields['child_pid']} "
        f"exit_code={fields['exit_code']} marked_path={MARKED}",
        flush=True,
    )
