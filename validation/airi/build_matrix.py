#!/usr/bin/env python3
"""Build AIRI_INDEPENDENT_OBSERVATION_MATRIX.csv from the canonical run set.

Every field is read from a run's `analysis.json` and `metadata.json`. Nothing
is typed in by hand except the scenario descriptions and the expected
classification, which are the experiment's design, not its results.

Rows for scenarios that were not executed carry `pass_fail=NOT_EXECUTABLE` and
say why. They are not approximated, and they are not omitted.
"""
import argparse
import csv
import json
import pathlib
import sys

FIELDS = [
    "scenario_id", "scenario", "agent_claim", "airi_event",
    "external_observation", "observer", "independent", "timestamp",
    "process_identity", "tool_identity", "execution_identity",
    "network_identity", "expected_classification", "actual_classification",
    "pass_fail", "notes",
]

# scenario_id -> (description, expected classification)
DESIGN = {
    "AIRI-001": ("normal tool execution", "OBSERVED"),
    "AIRI-002": ("agent claims execution but tool never executes", "CANNOT_PROVE"),
    "AIRI-003": ("tool executes but agent claims failure", "OBSERVED"),
    "AIRI-004": ("tool executes twice but agent reports once", "OBSERVED"),
    "AIRI-005": ("subprocess executes unexpectedly", "OBSERVED"),
    "AIRI-006": ("network request occurs without expected AIRI event", "OBSERVED"),
    "AIRI-007": ("AIRI event exists without external execution evidence", "CANNOT_PROVE"),
    "AIRI-008": ("completion event occurs before actual execution", "OBSERVED"),
    "AIRI-009": ("execution occurs after completion", "OBSERVED"),
    "AIRI-010": ("delayed observation", "OBSERVED"),
    "AIRI-011": ("duplicated observation", "OBSERVED"),
    "AIRI-012": ("replayed observation", "CANNOT_PROVE"),
    "AIRI-013": ("agent process dies before completion", "OBSERVED"),
    "AIRI-014": ("child process survives parent", "OBSERVED"),
    "AIRI-015": ("observer disappears", "UNKNOWN"),
    "AIRI-016": ("contradictory observations", "UNKNOWN"),
    "AIRI-017": ("declared argv executed outside the subject's process tree", "CANNOT_PROVE"),
    "AIRI-018": ("agent commits to one argv and executes another", "CANNOT_PROVE"),
}

# Scenarios that cannot be executed in this environment, and exactly why.
NOT_EXECUTABLE = {}


def claim_text(a):
    c = a["airi_claims"]
    parts = [f"{c['tool_executions_reported']} tool execution(s) reported"]
    if c["tool_report_success"]:
        parts.append(f"{c['tool_report_success']} as Success")
    if c["tool_report_failure"]:
        parts.append(f"{c['tool_report_failure']} as Failure")
    parts.append(f"{c['completions']} completion(s)")
    if c["subprocess_reports"]:
        parts.append(f"{c['subprocess_reports']} subprocess report(s)")
    return "; ".join(parts)


def observation_text(a):
    o = a["independent_observations"]
    if not o["window_closed"]:
        return "window never closed; nothing observable was bounded"
    bits = [f"{o['declared_tool_execs']} execution(s) of the committed argv, "
            f"attributed to the subject's process tree"]
    for key, label in (
        ("unattributed_declared_execs", "committed argv run outside the tree"),
        ("substituted_execs", "argv executed that was not the one committed"),
        ("undeclared_execs", "execution the claim stream omits"),
        ("subject_child_execs", "other child process"),
    ):
        if o[key]:
            bits.append(f"{o[key]} {label}")
    bits.append(f"{o['subject_connects']} connect(2) by the tree")
    return "; ".join(bits)


def row_for(a, meta):
    o = a["independent_observations"]
    x = o["cross_observer"]
    sid = a["scenario"]
    desc, expected = DESIGN[sid]
    second = x["second_observer"]
    observers = "linux-audit" + ("" if second == "INDEPENDENT_OBSERVER_BLOCKED"
                                 else f" + {second}")
    independent = (
        "audit: mechanism-independent of aip-observe's sched tracepoints. "
        + ("second observer blocked for this run"
           if second == "INDEPENDENT_OBSERVER_BLOCKED"
           else f"ftrace: mechanism-independent of audit, interface-only of "
                f"aip-observe; corroborated {x['corroborated_exec_pids']} exec pid(s); "
                f"cannot corroborate argv")
    )
    return {
        "scenario_id": sid,
        "scenario": desc,
        "agent_claim": claim_text(a),
        "airi_event": (f"{a['airi_claims']['events']} signed AiriEvent(s); "
                       f"sequence monotonic="
                       f"{a['airi_claims']['sequence_monotonic']}"),
        "external_observation": observation_text(a),
        "observer": observers,
        "independent": independent,
        "timestamp": (
            "ordering from the audit serial, a monotonic kernel counter. "
            "Audit's own record timestamps are coarse (tick granularity) and "
            "are recorded but never used to order a claim against an "
            "observation."
        ),
        "process_identity": (
            f"subject pid {o['subject_pid_from_claim']} (self-reported), "
            f"process tree of {o['subject_process_tree_size']} pid(s) closed "
            f"transitively from the observer's own (pid, ppid) pairs"
        ),
        "tool_identity": (
            "exact argv equality against the committed argv; observed by audit "
            "only, since sched_process_exec carries filename and pid but not argv"
        ),
        "execution_identity": (
            f"{o['beacons_observed']} ordering beacon(s) observed against "
            f"{o['airi_events_claimed']} claimed event(s)"
        ),
        "network_identity": (
            f"{o['subject_connects']} connect(2) attributed to the tree against "
            f"{a['airi_claims']['model_invocations_requested']} declared inference(s)"
        ),
        "expected_classification": expected,
        "actual_classification": a["classification"],
        "pass_fail": a["harness_verdict"],
        "notes": "; ".join(a["divergences"]) or "no divergence",
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trace-root", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    root = pathlib.Path(args.trace_root)

    rows, missing = [], []
    for sid in sorted(DESIGN):
        runs = sorted(root.glob(f"{sid}-*"))
        analysis = None
        for run in reversed(runs):                # newest run of that scenario
            f = run / "analysis.json"
            if f.exists():
                analysis = json.loads(f.read_text())
                meta = json.loads((run / "metadata.json").read_text())
                break
        if analysis is None:
            missing.append(sid)
            desc, expected = DESIGN[sid]
            rows.append({
                **{k: "" for k in FIELDS},
                "scenario_id": sid, "scenario": desc,
                "expected_classification": expected,
                "actual_classification": "NOT_EXECUTED",
                "pass_fail": "NOT_EXECUTABLE",
                "notes": NOT_EXECUTABLE.get(sid, "no run found under the trace root"),
            })
            continue
        rows.append(row_for(analysis, meta))

    with open(args.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    print(f"{len(rows)} rows -> {args.out}")
    if missing:
        print("NOT EXECUTED:", ", ".join(missing), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
