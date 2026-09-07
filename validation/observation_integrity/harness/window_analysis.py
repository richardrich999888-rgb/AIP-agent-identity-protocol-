#!/usr/bin/env python3
"""Resolve whether suppression during attachment is TOTAL or SELECTIVE.

The question cannot be answered from the observer under test alone: its own
timestamps are on a different clock from the harness, and a naive "events
between the last P1 and first P3 marker" interval includes the attach
transition and the detach drain, where the gate is not yet — or no longer —
effective.

So a THIRD observer's order is used as the reference. The audit subsystem sees
every exec, including the two anchor execs the harness runs immediately after
attach is confirmed and immediately before detach. Audit therefore fixes the
confirmed-attached window as a span in ITS OWN event order, and the only
question asked of the observer under test is, per exec audit placed inside that
span, matched on pid: did you see it too?

No clock is used. The join key is a pid both observers recorded.
"""
import argparse
import json
import pathlib
import re
import sys


def decode(text):
    out = [text]
    for run in re.findall(r"(?<![0-9A-Za-z])([0-9A-F]{16,})(?![0-9A-Za-z])", text):
        if len(run) % 2 == 0:
            try:
                out.append(bytes.fromhex(run).decode("utf-8", "replace"))
            except ValueError:
                pass
    return "\n".join(out)


def audit_ordered(path):
    """Execs in audit order, each as (pid, label, argv0). SYSCALL/EXECVE joined
    on the shared serial; SYSCALL carries the pid, EXECVE the argv."""
    serial_pid, rows = {}, []
    for line in path.read_text(errors="replace").splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        t = r.get("kernel_record", "")
        m = re.search(r"audit\([\d.]+:(\d+)\)", t)
        if not m:
            continue
        sn = m.group(1)
        if r.get("type") == 1300:
            pm = re.search(r"\bpid=(\d+)", t)
            if pm:
                serial_pid[sn] = int(pm.group(1))
        elif r.get("type") == 1309:
            rows.append((sn, t))
    out = []
    for sn, t in rows:
        d = decode(t)
        label = None
        if "ANCHOR-ATTACHED" in d:
            label = "ANCHOR-ATTACHED"
        elif "ANCHOR-DETACHED" in d:
            label = "ANCHOR-DETACHED"
        else:
            for p in ("P1", "P2", "P3"):
                if re.search(rf"OI001-[0-9A-Za-z-]+-{p}-", d):
                    label = p
                    break
        argv0 = re.search(r'a0="([^"]*)"', t)
        out.append((serial_pid.get(sn), label, argv0.group(1) if argv0 else "?"))
    return out


def sd_pids(path):
    pids = set()
    for line in path.read_text(errors="replace").splitlines():
        if line.startswith("#") or not line.strip():
            continue
        r = json.loads(line)
        if r.get("kind") == "exec" and r.get("pid") is not None:
            pids.add(r["pid"])
    return pids


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    args = ap.parse_args()
    d = pathlib.Path(args.dir)

    audit = audit_ordered(d / "audit_ground_truth.jsonl")
    seen = sd_pids(d / "sniffer_dog.jsonl")
    labels = [a[1] for a in audit]
    if "ANCHOR-ATTACHED" not in labels or "ANCHOR-DETACHED" not in labels:
        print(json.dumps({"result": "NO_ANCHORS",
                          "note": "this arm attached no interferer, or anchors "
                                  "were not recorded by ground truth"}))
        return 0
    ai = labels.index("ANCHOR-ATTACHED")
    di = len(labels) - 1 - labels[::-1].index("ANCHOR-DETACHED")
    window = audit[ai:di + 1]
    rows = [{"pid": p, "label": lab, "argv0": a0, "seen_by_observer": p in seen}
            for p, lab, a0 in window]
    n_seen = sum(r["seen_by_observer"] for r in rows)
    n_missed = len(rows) - n_seen
    result = ("TOTAL_SUPPRESSION" if n_seen == 0 else
              "NO_SUPPRESSION" if n_missed == 0 else
              "SELECTIVE_SUPPRESSION")
    out = {
        "reference_observer": "linux-audit (sees every exec; fixes the window order)",
        "confirmed_attached_window_execs": len(rows),
        "seen_by_observer_under_test": n_seen,
        "missed_by_observer_under_test": n_missed,
        "result": result,
        "detail": rows,
    }
    json.dump(out, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
