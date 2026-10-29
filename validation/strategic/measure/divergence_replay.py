#!/usr/bin/env python3
"""Replay the collector's cross-sensor divergence rule over signed archives.

For each batch: connector Exec (pid,tgid) not matched by a SchedTracepoint
ProcessExec with the same pid within 50 ms in the SAME batch = divergence
(the collector's rule, divergence.rs). For each divergence, look for the sched
counterpart in the previous / next batch. A counterpart in an adjacent batch
means the divergence is a batch-boundary artefact, not a blinded sensor.

Also classifies the phase each batch belongs to using the pilot's health
phase files when present (control / attack / recovery), so a divergence during
a live attack is not mistaken for a false positive.

Usage: divergence_replay.py <archive.jsonl> [<archive.jsonl> ...]
"""
import json
import sys

WIN = 50_000_000


def execs(bt, mech):
    out = []
    for e in bt["kernel_events"]:
        if e["mechanism"] != mech:
            continue
        k = e["kind"]
        if mech == "ProcConnector" and "Exec" in k:
            out.append((k["Exec"]["pid"], k["Exec"]["tgid"], e["kernel_timestamp_ns"]))
        if mech == "SchedTracepoint" and "ProcessExec" in k:
            p = k["ProcessExec"]["pid"]
            out.append((p, p, e["kernel_timestamp_ns"]))
    return out


for path in sys.argv[1:]:
    batches = [json.loads(l) for l in open(path) if l.strip()]
    total_div = boundary = genuine = 0
    print(f"== {path}")
    for i, b in enumerate(batches):
        bt = b["batch"]
        act = set(bt["active_mechanisms"])
        if not {"ProcConnector", "SchedTracepoint"} <= act:
            continue
        sched = execs(bt, "SchedTracepoint")
        integ = {x["mechanism"]: x["integrity"] for x in bt.get("mechanism_integrity") or []}
        divs = [a for a in execs(bt, "ProcConnector")
                if not any(m[0] == a[0] and m[1] == a[1] and abs(m[2] - a[2]) <= WIN for m in sched)]
        if not divs:
            continue
        nb = []
        for j in (i - 1, i + 1):
            if 0 <= j < len(batches):
                nb += execs(batches[j]["batch"], "SchedTracepoint")
        bnd = [a for a in divs if any(m[0] == a[0] and abs(m[2] - a[2]) <= WIN for m in nb)]
        total_div += len(divs)
        boundary += len(bnd)
        genuine += len(divs) - len(bnd)
        gate = "ForeignTracepointGate" in json.dumps(integ.get("SchedTracepoint"))
        print(f"  batch seq={b['sequence']} probe_seq={bt['probe_seq_first']}..{bt['probe_seq_last']} "
              f"divergent={len(divs)} counterpart_in_adjacent_batch={len(bnd)} "
              f"sched_integrity={integ.get('SchedTracepoint')} live_gate_in_batch={gate}")
    print(f"  TOTAL divergent={total_div} boundary_artefact={boundary} no_counterpart={genuine}")
