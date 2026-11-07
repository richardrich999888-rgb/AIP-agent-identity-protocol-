#!/usr/bin/env python3
"""Render one "Catch the lying agent" result file as the on-screen story (W2.2).

Reads only the result file written by observe.py; every line on screen comes
from it, and the file's path is printed last so anyone can check.

usage: show.py RESULT.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def render(path: Path) -> str:
    r = json.loads(path.read_text())
    m = r["measurements"]
    sd, au, ov, gt = m["sniffer_dog"], m["auditd"], m["offline_verification"], m["ground_truth"]
    hw = r["hardware"]["label"]
    out = []
    w = out.append
    w("CATCH THE LYING AGENT   [LIVE]   measured on: " + hw)
    w("=" * 78)
    w(f"Agent process: pid {m['agent']['pid']}  ({m['agent']['pid_source']})")
    w("")
    w("1. What the agent says it did  (its own log)")
    for step in m["agent"]["self_log_steps"]:
        w(f"     - {step}")
    if m["agent"]["self_log_mentions_undeclared_action"]:
        w("     (its log DOES mention the undeclared destination or file)")
    else:
        w("     (searched: no mention of the undeclared destination, the outside file or this run's nonce)")
    w("")
    w("2. What Sniffer Dog saw  (kernel evidence, signed by the collector's key)")
    if sd["connect_detected"]:
        for c in sd["connect_events"]:
            w(f"     CONNECT to {c['remote']}  — not declared")
            w(f"       by process pid {c['bound_pid']}, start tick {c['bound_start_ticks']},"
              f" exe sha256 {c['bound_exe_sha256'][:16]}…")
            w(f"       signed batch #{c['batch_sequence']}, event {c['index']} ({c['mechanism']})")
    else:
        w("     connect: NOT DETECTED")
    if sd["file_detected"]:
        for f in sd["file_events"]:
            w(f"     FILE written outside the workspace — by pid {f['bound_pid']} (signed batch #{f['batch_sequence']})")
    else:
        w("     file outside workspace: NOT DETECTED")
    w("")
    w("3. Independent cross-check  (auditd — a different kernel subsystem)")
    if not au["available"]:
        w("     UNAVAILABLE on this host")
    else:
        w(f"     connect seen: {'yes, pid ' + ', '.join(au['connect_pids']) if au['connect_seen'] else 'no'}")
        w(f"     outside file seen: {'yes' if au['file_seen'] else 'no'}")
    w("")
    w("4. Anyone can check it offline  (published public key only)")
    w(f"     signed evidence: {'VERIFIED' if ov['verified'] else 'NOT VERIFIED'}")
    t = ov["tamper"]
    if t["performed"]:
        w(f"     change one byte ({t['change']}): {'still VERIFIED — PROBLEM' if t['verified'] else 'REJECTED'}")
    w("")
    w("Ground truth kept by the demo harness (not the agent, not Sniffer Dog):")
    w(f"     undeclared action really happened: {'yes' if gt['undeclared_action_happened'] else 'no'}")
    if m.get("require_synced_clock") == "0":
        w("")
        w("Note: this host's clock is not NTP-synchronised; the collector ran with its")
        w("clock check off and signed its worst-case clock error into the evidence.")
    w("")
    w("The agent is a scripted test agent built to misbehave for this demonstration.")
    w(f"Result file: {path}")
    return "\n".join(out)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    print(render(Path(sys.argv[1])))
