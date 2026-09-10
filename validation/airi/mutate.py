#!/usr/bin/env python3
"""Mutation harness: prove the AIRI experiment's checks can fail.

A suite where every check passes is worthless until you have shown the checks
are capable of failing for the right reason. Each mutation here injects one
specific defect, asserts the bytes on disk actually changed, re-runs the
scenarios that are supposed to catch it, and requires at least one of them to
stop reporting PASS.

WHY "STOP REPORTING PASS" AND NOT "REPORT FAIL"
----------------------------------------------
PASS is the only verdict that asserts anything. A defect that drives the
harness to UNKNOWN has been caught — the harness refused to conclude, which is
the conservative behaviour the model requires — so UNKNOWN kills a mutation
just as FAIL does. The two are recorded separately because they mean different
things: FAIL is "the check ran and the property is absent", UNKNOWN is "the
experiment could not be interpreted".

WHY A SET OF SCENARIOS AND NOT ONE
----------------------------------
M-OBS-4 first survived against AIRI-008 alone: forcing every execution to
count as "after the completion claim" leaves AIRI-008's expectation
(after >= 1, before == 0) satisfied. The mutation was killed only by AIRI-009,
which requires executions on BOTH sides of the claim. A single-scenario guard
could not distinguish "the ordering is computed" from "the ordering is always
after", so the guard is a set.

A mutation that SURVIVES is reported as a survivor, not quietly rescoped.
Nothing is interpreted unless `patch_applied` is true.
"""
import hashlib
import json
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
ANALYZE = REPO / "validation/airi/analyze.py"
OBSERVER = REPO / "validation/airi/observers/audit_observer.py"
RUNNER = REPO / "validation/airi/run_airi_validation.sh"

MUTATIONS = [
    {
        "id": "M-OBS-1",
        "file": ANALYZE,
        "kills": "the classification is driven by the observer, not by the claim",
        "scenarios": ["AIRI-002"],
        "old": '        "declared_tool_execs": len(declared_execs),',
        "new": '        "declared_tool_execs": claims["tool_executions_reported"],',
    },
    {
        "id": "M-OBS-2",
        "file": OBSERVER,
        "kills": "the netlink length convention (records truncated by 16 bytes)",
        "scenarios": ["AIRI-001"],
        "old": "        if ln == avail:\n            body, conv = data[16:], \"payload\"      # audit's convention",
        "new": "        if False:\n            body, conv = data[16:], \"payload\"      # audit's convention",
    },
    {
        "id": "M-OBS-3",
        "file": ANALYZE,
        "kills": "observer-side parentage attribution (pid/ppid from the SYSCALL record)",
        "scenarios": ["AIRI-014"],
        "old": '                (r"\\bppid=(\\d+)", "ppid", int),',
        "new": '                (r"\\bZZppid=(\\d+)", "ppid", int),',
    },
    {
        "id": "M-OBS-4",
        "file": ANALYZE,
        "kills": "beacon ordering (a completion claimed before the execution it describes)",
        "scenarios": ["AIRI-008", "AIRI-009"],
        "old": '            if ev["serial"] > completion_serial:',
        "new": '            if ev["serial"] >= 0:',
    },
    {
        "id": "M-OBS-6",
        "file": ANALYZE,
        "kills": "the stated boundary tolerance; without it two observers that "
                 "order events at different points in the syscall report "
                 "contradictions on an honest run",
        "scenarios": ["AIRI-001"],
        "old": "BOUNDARY_TOLERANCE_MS = 100",
        "new": "BOUNDARY_TOLERANCE_MS = 0",
    },
    {
        "id": "M-OBS-7",
        "file": ANALYZE,
        "kills": "detection of two observers contradicting each other",
        "scenarios": ["AIRI-016"],
        "old": '        if x["compared_second_observer_only"] or x["compared_audit_only"]:',
        "new": '        if False:',
    },
    {
        "id": "M-OBS-8",
        "file": ANALYZE,
        "kills": "the refusal to assert a divergence from an uninterpretable "
                 "window (absence of observation read as non-execution)",
        "scenarios": ["AIRI-015"],
        "old": '    divs = divergences(claims, observed) if window["window_closed"] else []',
        "new": '    divs = divergences(claims, observed)',
    },
    {
        "id": "M-OBS-9",
        "file": ANALYZE,
        "kills": "collapsing a duplicated observation onto its audit serial",
        "scenarios": ["AIRI-011"],
        "old": "        serial = int(m.group(3))",
        "new": "        serial = len(order)",
    },
    {
        "id": "M-OBS-5",
        "file": RUNNER,
        "kills": "the result's dependence on the independent observer watching the "
                 "right syscalls at all",
        "scenarios": ["AIRI-001"],
        "old": "  --syscalls execve,execveat,connect \\",
        "new": "  --syscalls openat \\",
    },
]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_scenario(scenario):
    """Run one scenario and return its harness verdict, or None."""
    proc = subprocess.run(
        ["bash", str(REPO / "validation/airi/run_airi_validation.sh"), scenario],
        capture_output=True, text=True, cwd=REPO,
    )
    for line in proc.stdout.splitlines():
        if line.startswith("/"):
            trace = pathlib.Path(line.strip())
            f = trace / "analysis.json"
            if f.exists():
                try:
                    return json.loads(f.read_text())["harness_verdict"]
                except Exception:
                    return None
    return None


def main():
    results = []
    for m in MUTATIONS:
        path = m["file"]
        original = path.read_text()
        before = sha256(path)
        base = {k: m[k] for k in ("id", "kills", "scenarios")}
        if m["old"] not in original:
            results.append({**base, "patch_applied": False,
                            "result": "ANCHOR_NOT_FOUND — mutation not evaluated"})
            continue
        path.write_text(original.replace(m["old"], m["new"], 1))
        after = sha256(path)
        applied = before != after
        verdicts = {}
        try:
            if applied:
                for scenario in m["scenarios"]:
                    verdicts[scenario] = run_scenario(scenario)
        finally:
            path.write_text(original)
            assert sha256(path) == before, f"failed to restore {path}"
        killers = {s: v for s, v in verdicts.items() if v != "PASS"}
        results.append({
            **base,
            "patch_applied": applied,
            "sha256_before": before[:16],
            "sha256_after": after[:16],
            "verdicts_under_mutation": verdicts,
            "killed_by": sorted(killers),
            "result": ("KILLED" if applied and killers else
                       "SURVIVED" if applied else
                       "NOT_EVALUATED"),
        })
    out = {
        "mutations": results,
        "survivors": [r["id"] for r in results if r["result"] != "KILLED"],
        "note": (
            "A mutation is KILLED when at least one guard scenario stops "
            "reporting PASS. UNKNOWN counts: the harness refusing to conclude "
            "is the correct response to a broken observer, and it is recorded "
            "as UNKNOWN rather than silently as FAIL."
        ),
    }
    json.dump(out, sys.stdout, indent=2)
    print()
    return 1 if out["survivors"] else 0


if __name__ == "__main__":
    sys.exit(main())
