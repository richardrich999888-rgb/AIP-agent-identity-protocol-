#!/usr/bin/env python3
"""Analyze measure.sh trials under the matching rules fixed in measure.sh.

Writes <out>/results.json and <out>/per_trial.csv. Prints a summary.
Nothing here is tuned after the fact: every rule mirrors the header of
measure.sh, and every denominator is printed beside its ratio.
"""
import csv
import json
import os
import re
import statistics as st
import sys

OUT = sys.argv[1]
FTRE = re.compile(r"sched_process_exec:\s*filename=(\S+)\s+pid=(\d+)")


def trials():
    for d in sorted(os.listdir(OUT)):
        if d.startswith("trial_") and os.path.exists(os.path.join(OUT, d, "on.json")):
            yield d, os.path.join(OUT, d)


def ratio(n, d):
    return (n / d) if d else None


rows, agg = [], {"latency_capture_ms": [], "latency_exec_to_signed_ms": [], "overhead_ratio": []}
for name, td in trials():
    on = json.load(open(os.path.join(td, "on.json")))
    off = json.load(open(os.path.join(td, "off.json")))
    marker_dir = os.path.join(td, "bins_on")
    W = {e["path"]: e for e in on["execs"] if e["exit"] == 0}            # exec definitely occurred
    ft = {}
    if os.path.exists(os.path.join(td, "ftrace.trace")):
        for line in open(os.path.join(td, "ftrace.trace")):
            m = FTRE.search(line)
            if m and m.group(1).startswith(marker_dir):
                ft.setdefault(m.group(1), int(m.group(2)))
    GT = {p: e for p, e in W.items() if p in ft}                          # kernel-confirmed
    w_not_ft = len(W) - len(GT)

    sched, conn, dropped, states, cov, integ, verified = [], [], 0, [], 0, [], None
    arch = os.path.join(td, "attested.archive.jsonl")
    if os.path.exists(arch):
        for line in open(arch):
            if not line.strip():
                continue
            b = json.loads(line)
            bt = b["batch"]
            dropped += int(bt.get("dropped_events", 0) or 0)
            integ += [f"{x['mechanism']}:{x['integrity']}" for x in (bt.get("mechanism_integrity") or [])]
            a = bt["clock_anchor"]
            for e in bt["kernel_events"]:
                k = e["kind"]
                rt_ns = a["realtime_ms"] * 1_000_000 + (e["kernel_timestamp_ns"] - a["monotonic_ns"])
                if "ProcessExec" in k:
                    sched.append((k["ProcessExec"]["filename"], k["ProcessExec"]["pid"], rt_ns, b["attested_at_ms"]))
                elif "Exec" in k:
                    conn.append((k["Exec"]["pid"], rt_ns, b["attested_at_ms"]))
    hp = os.path.join(td, "health.archive.jsonl")
    if os.path.exists(hp):
        for line in open(hp):
            if line.strip():
                h = json.loads(line)["health"]
                states.append(h["state"])
                cov += 1 if h.get("attested_coverage") else 0
    vp = os.path.join(td, "verify.txt")
    if os.path.exists(vp):
        v = open(vp).read()
        verified = ("verify_exit=0" in v) and bool(re.search(r"^VERIFIED", v, re.M))

    sched_marker = [s for s in sched if s[0].startswith(marker_dir)]
    by_path = {}
    for s in sched_marker:
        by_path.setdefault(s[0], []).append(s)
    sched_matched = [p for p in GT if p in by_path]
    sched_dups = sum(len(v) - 1 for v in by_path.values() if len(v) > 1)
    sched_records_matched = sum(len(by_path[p]) for p in by_path if p in GT)
    sched_records_unmatched = sum(len(by_path[p]) for p in by_path if p not in GT)
    sched_records_not_real = sum(len(by_path[p]) for p in by_path if p not in W)   # fabrication check
    attr_ok = sum(1 for p in sched_matched if any(s[1] == GT[p]["pid"] for s in by_path[p]))

    gt_pids = {e["pid"]: p for p, e in GT.items()}
    conn_matched = {pid for (pid, _, _) in conn if pid in gt_pids}

    for p in sched_matched:
        s = by_path[p][0]
        agg["latency_capture_ms"].append((s[2] - GT[p]["launch_rt_ns"]) / 1e6)
        agg["latency_exec_to_signed_ms"].append(s[3] - s[2] / 1e6)
    drain = {}
    dp = os.path.join(td, "drain.txt")
    if os.path.exists(dp):
        drain = dict(kv.split("=") for kv in open(dp).read().split())
    ovh = ratio(on["wall_ms"], off["wall_ms"])
    if ovh:
        agg["overhead_ratio"].append(ovh)

    rows.append({
        "trial": name, "workload_execs_ok": len(W), "ftrace_confirmed_GT": len(GT),
        "workload_not_in_ftrace": w_not_ft,
        "sched_matched": len(sched_matched), "sched_recall": ratio(len(sched_matched), len(GT)),
        "sched_records_marker": len(sched_marker), "sched_records_matched": sched_records_matched,
        "sched_records_unmatched": sched_records_unmatched, "sched_records_not_real_exec": sched_records_not_real,
        "sched_duplicates": sched_dups,
        "sched_precision": ratio(sched_records_matched, len(sched_marker)),
        "conn_matched": len(conn_matched), "conn_recall": ratio(len(conn_matched), len(GT)),
        "attribution_ok": attr_ok, "attribution_acc": ratio(attr_ok, len(sched_matched)),
        "dropped_events": dropped, "verified_offline": verified,
        "drained": drain.get("drained"), "drain_ms": drain.get("drain_ms"),
        "health_states": "|".join(sorted(set(states))), "health_records_with_coverage": cov,
        "mechanism_integrity": "|".join(sorted(set(integ))),
        "wall_ms_off": round(off["wall_ms"], 1), "wall_ms_on": round(on["wall_ms"], 1),
        "overhead_ratio": round(ovh, 4) if ovh else None,
    })

if not rows:
    print("ANALYZE: no completed trials"); sys.exit(1)

with open(os.path.join(OUT, "per_trial.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)


def tot(k):
    return sum(r[k] for r in rows)


def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))] if xs else None


summary = {
    "trials_completed": len(rows),
    "GT_total": tot("ftrace_confirmed_GT"),
    "workload_execs_ok_total": tot("workload_execs_ok"),
    "workload_not_in_ftrace_total": tot("workload_not_in_ftrace"),
    "sched_recall": ratio(tot("sched_matched"), tot("ftrace_confirmed_GT")),
    "sched_precision": ratio(tot("sched_records_matched"), tot("sched_records_marker")),
    "sched_records_not_real_exec_total": tot("sched_records_not_real_exec"),
    "sched_duplicates_total": tot("sched_duplicates"),
    "conn_recall": ratio(tot("conn_matched"), tot("ftrace_confirmed_GT")),
    "attribution_acc": ratio(tot("attribution_ok"), tot("sched_matched")),
    "dropped_events_total": tot("dropped_events"),
    "all_trials_verified_offline": all(r["verified_offline"] for r in rows),
    "trials_not_drained": sum(1 for r in rows if r["drained"] not in (None, "1")),
    "latency_capture_ms": {"p50": pct(agg["latency_capture_ms"], .5), "p95": pct(agg["latency_capture_ms"], .95),
                           "max": max(agg["latency_capture_ms"]) if agg["latency_capture_ms"] else None},
    "latency_exec_to_signed_ms": {"p50": pct(agg["latency_exec_to_signed_ms"], .5),
                                  "p95": pct(agg["latency_exec_to_signed_ms"], .95),
                                  "max": max(agg["latency_exec_to_signed_ms"]) if agg["latency_exec_to_signed_ms"] else None},
    "overhead_ratio_on_over_off": {"mean": st.mean(agg["overhead_ratio"]) if agg["overhead_ratio"] else None,
                                   "median": st.median(agg["overhead_ratio"]) if agg["overhead_ratio"] else None,
                                   "per_trial": agg["overhead_ratio"],
                                   "note": "ON includes probe+collector+ftrace reference: an UPPER BOUND for the pipeline alone"},
}
json.dump({"summary": summary, "trials": rows}, open(os.path.join(OUT, "results.json"), "w"), indent=2)
print(json.dumps(summary, indent=2))
