#!/usr/bin/env python3
"""Count what each observer saw, per phase, and say what that supports.

This is a COUNTER, not a reconciler. It builds no Vanian object and produces
no Vanian verdict. Its `verdict` field answers exactly one question: does the
evidence support tracepoint interference, as distinct from lifecycle ordering
or ring-buffer loss?

Phase attribution comes from the executed binary's own path, which every
observer records. No clock is used to attribute any event to any phase.
"""
import argparse
import json
import pathlib
import re
import sys

PHASES = ("P1", "P2", "P3")


def sniffer_dog(path, short, phase_pids):
    """Count exec and fork events per phase from the recorder's output.

    EXEC is attributed by `filename`: each phase runs its own copy of
    /bin/true at a distinct path, so the phase is in the record's own content.

    FORK cannot be attributed that way. `sched_process_fork` fires before the
    child execs, so the child's `comm` is still the PARENT's — the new binary's
    name does not exist yet. Forks are therefore attributed by matching
    `child_pid` against the pids the GROUND-TRUTH observer recorded for each
    phase. Still no clock: the join key is a pid both observers wrote down.

    Counting forks matters because the fork and exec tracepoints are separate
    `trace_event_call`s. An interferer attached to only one of them
    distinguishes "this tracepoint is gated" from "the observer is blind".
    """
    by_phase = {p: 0 for p in PHASES}
    fork_by_phase = {p: 0 for p in PHASES}
    lost_total, summary, events, errors = 0, None, 0, []
    if not path.exists():
        return {"present": False, "exec_by_phase": by_phase,
                "fork_by_phase": fork_by_phase, "lost_total": None}
    for line in path.read_text(errors="replace").splitlines():
        if line.startswith("#") or not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        kind = rec.get("kind")
        if kind == "summary":
            summary = rec
        elif kind == "loss":
            lost_total += int(rec.get("count", 0))
        elif kind == "source_error":
            errors.append(rec.get("detail"))
        elif kind == "exec":
            events += 1
            fn = rec.get("filename", "")
            for p in PHASES:
                if fn.endswith(f"oi{p}{short}"):
                    by_phase[p] += 1
        elif kind == "spawn":
            child = rec.get("child_pid")
            for p in PHASES:
                if child in phase_pids.get(p, ()):
                    fork_by_phase[p] += 1
    return {
        "present": True,
        "exec_by_phase": by_phase,
        "fork_by_phase": fork_by_phase,
        "exec_events_total": events,
        # The reported loss counter is the ONLY coverage signal aip-observe's
        # health model consumes: ObserverState::Degraded requires a
        # ProbeStreamFault, and ProbeStreamFault::EventsLost comes from this
        # number being nonzero (aip-observe/src/attest.rs).
        "lost_total": summary["lost"] if summary else lost_total,
        "summary": summary,
        "source_errors": errors,
    }


def audit_ground_truth(path, tag):
    """See `_audit`. Split so the pid map can be built before the recorder is
    parsed, since fork attribution depends on it."""
    return _audit(path, tag)


def _audit(path, tag):
    """Count execs per phase from the audit stream.

    Audit hooks the syscall path in kernel/auditsc.c and delivers over
    NETLINK_AUDIT. It is not on the perf submission path, so it establishes
    that the phase-2 executions HAPPENED, independently of whether the
    observer under test saw them.
    """
    by_phase = {p: 0 for p in PHASES}
    pids = {p: [] for p in PHASES}
    if not path.exists():
        return {"present": False, "by_phase": by_phase, "pids": pids}
    total = 0
    # Audit emits SYSCALL and EXECVE records for one execve under a shared
    # serial, SYSCALL first. The pid lives on SYSCALL and the argv on EXECVE,
    # so they are joined on the serial rather than on arrival order.
    serial_pid = {}
    records = []
    for line in path.read_text(errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        text = rec.get("kernel_record", "")
        m = re.search(r"audit\([\d.]+:(\d+)\)", text)
        if not m:
            continue
        serial = m.group(1)
        if rec.get("type") == 1300:                      # AUDIT_SYSCALL
            pm = re.search(r"\bpid=(\d+)", text)
            if pm:
                serial_pid[serial] = int(pm.group(1))
        elif rec.get("type") == 1309:                    # AUDIT_EXECVE
            records.append((serial, text))
    for serial, text in records:
        # The kernel hex-encodes arguments containing characters it will not
        # print. Both encodings are searched; nothing is guessed.
        decoded = [text]
        for run in re.findall(r"(?<![0-9A-Za-z])([0-9A-F]{16,})(?![0-9A-Za-z])", text):
            if len(run) % 2 == 0:
                try:
                    decoded.append(bytes.fromhex(run).decode("utf-8", "replace"))
                except ValueError:
                    pass
        joined = "\n".join(decoded)
        for p in PHASES:
            if f"{tag}-{p}" in joined:
                by_phase[p] += 1
                total += 1
                if serial in serial_pid:
                    pids[p].append(serial_pid[serial])
                break
    return {"present": True, "by_phase": by_phase, "pids": pids,
            "exec_events_total": total}


def a3s(path, tag):
    """Count the interferer's own exec events per phase, from its argv."""
    by_phase = {p: 0 for p in PHASES}
    if not path.exists():
        return {"present": False, "by_phase": by_phase}
    total = 0
    for line in path.read_text(errors="replace").splitlines():
        if "ToolExec" not in line:
            continue
        for p in PHASES:
            if f"{tag}-{p}" in line:
                by_phase[p] += 1
                total += 1
                break
    return {"present": True, "by_phase": by_phase, "exec_events_total": total}


# Which of the observer's two streams the interferer targeted in each arm.
# The verdict is evaluated on that stream: judging the fork_only arm by its
# exec counts would report "not reproduced" for a run in which suppression was
# reproduced exactly as predicted, on the stream that was attacked.
TARGET_STREAM = {
    "both": "exec",
    "exec_only": "exec",
    "fork_only": "fork",
    "none": "exec",
}


def verdict(sd, gt, expected, arm):
    """What the counts support, stated conservatively.

    Every branch that is not the interference signature returns something
    weaker than INTERFERENCE_REPRODUCED. A run that does not reproduce the
    effect must say so rather than be argued into it.
    """
    if not sd["present"]:
        return "INCONCLUSIVE_NO_OBSERVER_OUTPUT", "the observer under test produced no file"
    if not gt["present"]:
        return "INCONCLUSIVE_NO_GROUND_TRUTH", (
            "without independent evidence that the phase-2 executions occurred, "
            "an absence in the observer is not distinguishable from an absence "
            "in the world"
        )
    if any(gt["by_phase"][p] < expected for p in PHASES):
        return "INCONCLUSIVE_GROUND_TRUTH_INCOMPLETE", (
            f"ground truth recorded {gt['by_phase']} of {expected} per phase; "
            "the executions cannot be assumed to have happened"
        )
    stream = TARGET_STREAM.get(arm, "exec")
    counts = sd["exec_by_phase"] if stream == "exec" else sd["fork_by_phase"]
    p1, p2, p3 = (counts[p] for p in PHASES)

    if arm == "none":
        # Negative control. The point is that the harness does NOT produce the
        # signature when nothing is attached — without this arm, a suppression
        # result could be an artefact of the harness itself.
        if p1 == p2 == p3 == expected:
            return "NEGATIVE_CONTROL_CLEAN", (
                "no interferer attached; the observer saw every execution in "
                "all three phases, so the harness does not manufacture the "
                "signature on its own"
            )
        return "NEGATIVE_CONTROL_DIRTY", (
            f"with no interferer attached the observer still saw {counts}; "
            "no suppression result from this harness can be trusted until this "
            "is explained"
        )

    if p1 == 0 and p3 == 0:
        return "INCONCLUSIVE_OBSERVER_NEVER_WORKED", (
            f"the observer saw no {stream} events in any phase; this run says "
            "nothing about interference"
        )
    if p2 > 0:
        return "NOT_REPRODUCED", (
            f"the observer saw {p2} phase-2 {stream} event(s) with the "
            "interferer attached; suppression did not occur in this run"
        )
    if p1 > 0 and p3 == 0:
        return "ONE_WAY_FAILURE", (
            "the observer stopped seeing events and did not recover after "
            "detach; consistent with the observer having died, which is NOT "
            "the same finding and must not be reported as interference"
        )
    if p1 > 0 and p2 == 0 and p3 > 0:
        if sd["lost_total"]:
            return "SUPPRESSION_WITH_REPORTED_LOSS", (
                f"{stream} events were suppressed and the observer DID report "
                f"loss ({sd['lost_total']}); the coverage gap is therefore "
                "visible to the existing health model"
            )
        return "INTERFERENCE_REPRODUCED_SILENTLY", (
            f"one observer process, no restart: {stream} events observed "
            "before attach, none during, observed again after detach, and zero "
            "reported loss throughout. Lifecycle ordering is excluded by "
            "construction and ring-buffer overflow is excluded by the loss "
            "counter"
        )
    return "UNCLASSIFIED", f"phase counts {counts} match no expected pattern"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--short", required=True)
    ap.add_argument("--arm", required=True)
    ap.add_argument("--execs-per-phase", type=int, required=True)
    args = ap.parse_args()
    d = pathlib.Path(args.dir)

    gt = audit_ground_truth(d / "audit_ground_truth.jsonl", args.tag)
    sd = sniffer_dog(d / "sniffer_dog.jsonl", args.short,
                     {p: set(v) for p, v in gt.get("pids", {}).items()})
    a3 = a3s(d / "a3s_events.ndjson", args.tag)
    v, why = verdict(sd, gt, args.execs_per_phase, args.arm)
    # Per-tracepoint isolation. Only meaningful when the interferer was
    # attached to exactly one of the two sched tracepoints.
    e2, f2 = sd["exec_by_phase"]["P2"], sd["fork_by_phase"]["P2"]
    if args.arm == "fork_only":
        isolation = ("PER_TRACEPOINT_CONFIRMED"
                     if e2 > 0 and f2 == 0 else
                     "PER_TRACEPOINT_REFUTED" if e2 == 0 and f2 == 0 else
                     f"INCONCLUSIVE exec={e2} fork={f2}")
    elif args.arm == "exec_only":
        isolation = ("PER_TRACEPOINT_CONFIRMED"
                     if f2 > 0 and e2 == 0 else
                     "PER_TRACEPOINT_REFUTED" if e2 == 0 and f2 == 0 else
                     f"INCONCLUSIVE exec={e2} fork={f2}")
    else:
        isolation = "NOT_TESTED_IN_THIS_ARM"

    out = {
        "experiment": "OBSERVATION-INTEGRITY-001",
        "metadata": json.loads((d / "metadata.json").read_text()),
        "expected_execs_per_phase": args.execs_per_phase,
        "target_stream": TARGET_STREAM.get(args.arm, "exec"),
        "sniffer_dog": sd,
        "audit_ground_truth": gt,
        "a3s": a3,
        "arm": args.arm,
        "verdict": v,
        "verdict_reason": why,
        "per_tracepoint_isolation": isolation,
        "what_this_does_not_establish": [
            "nothing about whether the interference was deliberate",
            "nothing about a root or kernel adversary beyond this one mechanism",
            "nothing about mechanisms other than perf_event_open on a tracepoint",
            "nothing about Vanian's reconciler, which this harness never invokes",
        ],
    }
    json.dump(out, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
