#!/usr/bin/env python3
"""A real LlamaIndex Workflows agent, the second M3 observed subject.

Same contract as integrations/agents/agent_subject.py (LangGraph): the
framework's own orchestration — here an event-driven `Workflow` whose steps
are dispatched by the LlamaIndex runtime — reaches an `act` step that spawns
`child_action.py` as a real separate process (file write + one TCP connect).
No language model: the observer watches kernel execution, not model I/O, and
the declared workflow is the independent ground truth for what should run.

Prints `AGENT_RESULT parent_pid=… child_pid=…` for the harness.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from pathlib import Path

from workflows import Workflow, step
from workflows.events import Event, StartEvent, StopEvent

CHILD = Path(__file__).resolve().parents[2] / "child_action.py"


class Planned(Event):
    marked_path: str


class Acted(Event):
    child_pid: int
    exit_code: int
    marked_path: str


class SubjectWorkflow(Workflow):
    @step
    async def plan(self, ev: StartEvent) -> Planned:
        print(f"PARENT pid={os.getpid()} step=plan marked_path={ev.marked_path}", flush=True)
        return Planned(marked_path=ev.marked_path)

    @step
    async def act(self, ev: Planned) -> Acted:
        proc = subprocess.Popen(
            [sys.executable, str(CHILD), ev.marked_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        out, _ = proc.communicate(timeout=30)
        print(out, end="", flush=True)
        return Acted(child_pid=proc.pid, exit_code=proc.returncode, marked_path=ev.marked_path)

    @step
    async def report(self, ev: Acted) -> StopEvent:
        print(
            f"AGENT_RESULT parent_pid={os.getpid()} child_pid={ev.child_pid} "
            f"exit_code={ev.exit_code} marked_path={ev.marked_path}",
            flush=True,
        )
        return StopEvent(result=ev.exit_code)


async def main(marked_path: str) -> int:
    return await SubjectWorkflow(timeout=60).run(marked_path=marked_path)


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/aip_m3_li_marker")))
