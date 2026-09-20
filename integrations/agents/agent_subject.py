#!/usr/bin/env python3
"""A real LangGraph agent, used as the observed subject for Phase 1.

# Why LangGraph, and why no LLM

The observer watches *execution from the kernel*. It does not read model inputs
or outputs, so an LLM is not needed to exercise it — and adding one would make
the run depend on an API key and a non-deterministic model, which is the
opposite of what a reproducible observation demonstrates. What LangGraph
provides that matters here is an **explicit directed graph**: the parent's
call chain is declared, not narrated by the agent about itself, so it is an
independent ground truth to reconcile the kernel observation against (Phase 3).

The graph is three nodes: `plan` → `act` → `report`. The `act` node is the one
with a consequential effect: it spawns the child sub-agent
(`child_action.py`) as a **real separate process**, which writes a marked file
and opens one outbound TCP connection. The observer, running independently,
should see that fork/exec and that connection with no help from this code.

This process prints its own pid and the child's pid so the harness can bind
the observed execution to this specific agent run.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

HERE = Path(__file__).resolve().parent
CHILD = HERE / "child_action.py"


class AgentState(TypedDict):
    """What flows along the graph edges. Deliberately minimal."""

    marked_path: str
    child_pid: int
    exit_code: int


def plan(state: AgentState) -> AgentState:
    """The decision node. In a real deployment this is where an LLM would
    decide to act; here it just records intent, because the observer does not
    watch this node — it watches what `act` causes the kernel to do."""
    print(f"PARENT pid={os.getpid()} node=plan marked_path={state['marked_path']}", flush=True)
    return state


def act(state: AgentState) -> AgentState:
    """The consequential node: spawn the child sub-agent as a real process."""
    proc = subprocess.Popen(
        [sys.executable, str(CHILD), state["marked_path"]],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    out, _ = proc.communicate(timeout=30)
    print(out, end="", flush=True)
    state["child_pid"] = proc.pid
    state["exit_code"] = proc.returncode
    print(f"PARENT pid={os.getpid()} node=act child_pid={proc.pid} exit={proc.returncode}", flush=True)
    return state


def report(state: AgentState) -> AgentState:
    """The terminal node. Emits the machine-readable line the harness parses."""
    print(
        f"AGENT_RESULT parent_pid={os.getpid()} child_pid={state['child_pid']} "
        f"exit_code={state['exit_code']} marked_path={state['marked_path']}",
        flush=True,
    )
    return state


def build_graph():
    """The explicit graph — this structure is the ground-truth call chain."""
    g = StateGraph(AgentState)
    g.add_node("plan", plan)
    g.add_node("act", act)
    g.add_node("report", report)
    g.add_edge(START, "plan")
    g.add_edge("plan", "act")
    g.add_edge("act", "report")
    g.add_edge("report", END)
    return g.compile()


def main() -> int:
    marked_path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/aip_agent_child_marker"
    graph = build_graph()
    final = graph.invoke(
        {"marked_path": marked_path, "child_pid": 0, "exit_code": -1}
    )
    return 0 if final["exit_code"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
