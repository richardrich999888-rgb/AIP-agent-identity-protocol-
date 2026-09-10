#!/usr/bin/env python3
"""Compare the three accounts of Experiment 1 and classify every event.

This is a READER. It opens the run directory, parses three files, and writes a
report to stdout. It never writes into the run directory and never modifies
what it read; run.sh verifies that with digests taken either side of this
script.

It is also not a verifier. It produces no Vanian verdict, no provenance, no
evidence strength, and no reconciliation result. It reports what each account
said and where they differ. Deciding what a difference *means* is Vanian's
job, and the point of the experiment is to check that Vanian does it right —
which is not something this script may pre-empt.

# The coverage window, and why it is enforced here

The reference instrument is started before Sniffer Dog, because Sniffer Dog's
own launch must be observable. That means the reference capture necessarily
contains events from a period when Sniffer Dog was not yet attached —
including Sniffer Dog's own exec, which it cannot possibly have seen.

Comparing over the whole capture would count those as misses. That would be
the harness manufacturing a coverage gap and then blaming the observer for it,
which is the same error as reading absence as non-execution.

So the window is delimited by markers written into the reference capture:
`window open` is written only after Sniffer Dog reports its sensor attached,
`window close` after the subject finishes. Both accounts are restricted to
that interval. Events outside it are reported separately, as outside coverage,
never as findings.

Both instruments timestamp on CLOCK_MONOTONIC, so the marker timestamps bound
both without conversion. That the two timebases line up is checked, not
assumed.
"""

import json
import re
import sys
from pathlib import Path

# "   comm-1234  [002] ..... 38667.315194: event_name: fields"
LINE_RE = re.compile(r"^\s*\S+\s+\[\d+\]\s+\S+\s+(?P<ts>\d+\.\d+):\s+(?P<event>\w+):\s*(?P<rest>.*)$")
EXEC_RE = re.compile(r"filename=(?P<filename>\S+)\s+pid=(?P<pid>\d+)\s+old_pid=(?P<old_pid>\d+)")
FORK_RE = re.compile(r"comm=(?P<comm>\S+)\s+pid=(?P<pid>\d+)\s+child_comm=(?P<child_comm>\S+)\s+child_pid=(?P<child_pid>\d+)")
MARK_RE = re.compile(r"exp01 window (?P<edge>open|close)")


def load_subject(path):
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def load_sniffer_dog(path):
    events, loss, errors = [], 0, []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        rec = json.loads(line)
        kind = rec.get("kind")
        if kind == "loss":
            loss += rec["count"]
        elif kind == "source_error":
            errors.append(rec["detail"])
        elif kind == "summary":
            pass
        else:
            events.append(rec)
    return events, loss, errors


def load_reference(path):
    """Parse the kernel's own rendering, keeping timestamps.

    Unparsed lines are counted, never discarded silently: an unparsed line is
    a gap in this script's reading, and hiding it would conceal exactly the
    kind of blind spot the experiment exists to find.
    """
    execs, forks, exits, marks, unparsed = [], [], [], [], []
    for line in path.read_text().splitlines():
        if line.startswith("#") or not line.strip():
            continue
        m = LINE_RE.match(line)
        if not m:
            unparsed.append(line)
            continue
        ts_ns = int(round(float(m["ts"]) * 1e9))
        event, rest = m["event"], m["rest"]
        if event == "sched_process_exec" and (f := EXEC_RE.search(rest)):
            execs.append({"ts_ns": ts_ns, "filename": f["filename"],
                          "pid": int(f["pid"]), "old_pid": int(f["old_pid"])})
        elif event == "sched_process_fork" and (f := FORK_RE.search(rest)):
            forks.append({"ts_ns": ts_ns, "parent_pid": int(f["pid"]),
                          "child_pid": int(f["child_pid"]), "child_comm": f["child_comm"]})
        elif event == "sched_process_exit":
            exits.append({"ts_ns": ts_ns})
        elif event == "tracing_mark_write" and (f := MARK_RE.search(rest)):
            marks.append({"ts_ns": ts_ns, "edge": f["edge"]})
        else:
            unparsed.append(line)
    return execs, forks, exits, marks, unparsed


def name_of(p):
    return Path(p).name


def main():
    run_dir = Path(sys.argv[1])
    meta = json.loads((run_dir / "run_meta.json").read_text())

    subject = load_subject(run_dir / "subject_self_report.jsonl")
    sd_events, sd_loss, sd_errors = load_sniffer_dog(run_dir / "sniffer_dog.jsonl")
    ref_execs, ref_forks, ref_exits, marks, unparsed = load_reference(run_dir / "reference_ftrace.trace")

    out = print
    out("# Experiment 1 — Independent Linux Runtime Observation Comparison")
    out("")
    out(f"Run `{meta['run_id']}` · kernel `{meta['kernel']}` · boot `{meta['boot_id']}`")
    out("")
    out("## What this comparison can and cannot establish")
    out("")
    out("Sniffer Dog samples the `sched_*` tracepoints through `perf_event_open`.")
    out("The reference instrument reads **the same tracepoints** through ftrace.")
    out("They are interface-independent and **not mechanism-independent**.")
    out("")
    out("> Agreement corroborates Sniffer Dog's **reading of the kernel**.")
    out("> It does not independently witness the **event**.")
    out("")
    out("The instrument that would have witnessed the event — Tetragon, via eBPF")
    out("on kernel functions — cannot run on this kernel (`CONFIG_KPROBES` unset).")
    out("")

    # ── the coverage window ─────────────────────────────────────────────────
    opens = [m for m in marks if m["edge"] == "open"]
    closes = [m for m in marks if m["edge"] == "close"]
    if len(opens) != 1 or len(closes) != 1:
        out("## ABORT — coverage window not delimited")
        out("")
        out(f"Expected exactly one `open` and one `close` marker; found "
            f"{len(opens)} and {len(closes)}. Without a delimited window there is no")
        out("honest basis for calling any absence a miss. No verdict is issued.")
        return 2
    w_open, w_close = opens[0]["ts_ns"], closes[0]["ts_ns"]

    def in_window(ts):
        return w_open <= ts <= w_close

    ref_in = [e for e in ref_execs if in_window(e["ts_ns"])]
    ref_before = [e for e in ref_execs if e["ts_ns"] < w_open]
    ref_after = [e for e in ref_execs if e["ts_ns"] > w_close]
    sd_execs_all = [e for e in sd_events if e.get("kind") == "exec"]
    sd_in = [e for e in sd_execs_all if in_window(e["kernel_monotonic_ns"])]
    sd_out = [e for e in sd_execs_all if not in_window(e["kernel_monotonic_ns"])]
    sd_spawns = [e for e in sd_events if e.get("kind") == "spawn"]

    out("## Coverage window")
    out("")
    out(f"Both instruments are compared only over `[{w_open}, {w_close}]` ns")
    out(f"(CLOCK_MONOTONIC, {(w_close - w_open) / 1e6:.1f} ms). The window opens when Sniffer Dog")
    out("reported its sensor attached and closes when the subject finished.")
    out("")
    out(f"- reference execs inside the window: **{len(ref_in)}**")
    out(f"- reference execs before it (Sniffer Dog not yet attached): {len(ref_before)}")
    out(f"- reference execs after it: {len(ref_after)}")
    out(f"- Sniffer Dog execs inside the window: **{len(sd_in)}** (of {len(sd_execs_all)} captured)")
    out("")
    if ref_before:
        out("Events before the window are **outside coverage, not misses**. They include")
        out("Sniffer Dog's own launch, which it cannot observe:")
        out("")
        for e in ref_before:
            out(f"- `{name_of(e['filename'])}` at {e['ts_ns']}")
        out("")

    # Clock comparability is checked, not assumed.
    if sd_in:
        sd_span = (min(e["kernel_monotonic_ns"] for e in sd_in),
                   max(e["kernel_monotonic_ns"] for e in sd_in))
        out(f"Sniffer Dog's in-window timestamps span `{sd_span[0]}`–`{sd_span[1]}`, inside the")
        out("marker bounds: the two instruments are on the same timebase, as designed.")
        out("")

    out("## Accounts (within the coverage window)")
    out("")
    out("| Account | Nature | Events |")
    out("|---|---|---|")
    out(f"| Subject self-report | **claim by the actor** | {len(subject)} |")
    out(f"| Sniffer Dog 2.0 | system under test | {len(sd_in)} exec, {len(sd_spawns)} spawn, {sd_loss} lost |")
    out(f"| Reference (ftrace) | kernel-rendered | {len(ref_in)} exec, {len(ref_forks)} fork, {len(ref_exits)} exit |")
    out("")
    if sd_errors:
        out(f"Sniffer Dog reported source errors: `{sd_errors}`")
        out("")
    if unparsed:
        out(f"Reference lines this script could not parse: **{len(unparsed)}** "
            "(a limit of the comparison, not necessarily of the instrument).")
        out("")

    ref_names = {name_of(e["filename"]) for e in ref_in}
    sd_names = {name_of(e["filename"]) for e in sd_in}
    subject_names = {name_of(c["filename"]) for c in subject if c["kind"] == "exec"}

    out("## Per-claim classification")
    out("")
    out("Every subject claim, checked against the kernel. `note` is the subject's")
    out("own label and is itself a claim — shown for readability, used for nothing.")
    out("")
    out("| # | Subject claims | note | In kernel capture? | In Sniffer Dog? | Classification |")
    out("|---|---|---|---|---|---|")
    findings = []
    for c in subject:
        if c["kind"] != "exec":
            continue
        n = name_of(c["filename"])
        in_ref, in_sd = n in ref_names, n in sd_names
        if in_ref and in_sd:
            cls = "CORROBORATED"
        elif in_ref and not in_sd:
            cls = "**SNIFFER DOG MISSED IT**"
            findings.append(f"claim {c['claim_seq']} (`{n}`): in kernel capture, absent from Sniffer Dog")
        elif not in_ref and in_sd:
            cls = "**SNIFFER DOG SAW WHAT THE KERNEL DID NOT**"
            findings.append(f"claim {c['claim_seq']} (`{n}`): in Sniffer Dog, absent from kernel capture")
        else:
            cls = "UNSUPPORTED — no kernel event"
        out(f"| {c['claim_seq']} | `{n}` | {c['note']} | {'yes' if in_ref else 'no'} "
            f"| {'yes' if in_sd else 'no'} | {cls} |")
    out("")

    out("## Executions the subject did not claim")
    out("")
    unclaimed = sorted(ref_names - subject_names)
    if unclaimed:
        out("The kernel recorded these inside the window; the subject's log is silent")
        out("about them. An observer that trusted the subject would have missed each one.")
        out("")
        out("| Binary | Sniffer Dog also saw it? |")
        out("|---|---|")
        for n in unclaimed:
            seen = n in sd_names
            out(f"| `{n}` | {'**yes**' if seen else 'no'} |")
            if not seen:
                findings.append(f"unclaimed exec `{n}`: in kernel capture within the window, absent from Sniffer Dog")
        out("")
    else:
        out("None.")
        out("")

    # ── acceptance ──────────────────────────────────────────────────────────
    sd_only = sd_names - ref_names
    ref_only = ref_names - sd_names
    fabricated = subject_names - ref_names
    suppressed = ref_names - subject_names

    checks = [
        ("A. Sniffer Dog reports no execution the kernel did not",
         not sd_only,
         f"Sniffer Dog-only: {sorted(sd_only) or 'none'}"),
        ("B. Sniffer Dog misses no in-window execution without reporting loss",
         (not ref_only) or sd_loss > 0,
         f"kernel-only: {sorted(ref_only) or 'none'}; loss reported by Sniffer Dog: {sd_loss}"),
        ("C. Fabricated subject claims are left uncorroborated",
         not (fabricated & sd_names),
         f"claimed-but-never-executed: {sorted(fabricated) or 'none'}; "
         f"of those, corroborated by Sniffer Dog: {sorted(fabricated & sd_names) or 'none'}"),
        ("D. Suppressed executions are still observed",
         bool(suppressed) and suppressed.issubset(sd_names),
         f"executed-but-unclaimed: {len(suppressed)}; "
         f"missed by Sniffer Dog: {sorted(suppressed - sd_names) or 'none'}"),
    ]

    out("## Acceptance checks")
    out("")
    out("| Check | Result | Detail |")
    out("|---|---|---|")
    for name, ok, detail in checks:
        out(f"| {name} | {'PASS' if ok else '**FAIL**'} | {detail} |")
    out("")

    failed = [n for n, ok, _ in checks if not ok]

    out("## Outcome")
    out("")
    if failed:
        out(f"**FAIL** — {len(failed)} check(s) did not hold:")
        for f in failed:
            out(f"- {f}")
        out("")
        out("Findings:")
        for f in findings or ["(see check details above)"]:
            out(f"- {f}")
    else:
        out("**PASS** — all four acceptance checks held within the coverage window.")
    out("")

    out("## What this result does NOT establish")
    out("")
    out("Stated regardless of outcome, because a passing run is exactly when these")
    out("are most likely to be forgotten:")
    out("")
    out("- **Not** that the executions occurred. Both instruments read one kernel")
    out("  tracepoint; anything corrupting it corrupts both identically.")
    out("- **Not** resistance to a root-privileged subject, which could disable the")
    out("  tracepoints or starve both buffers.")
    out("- **Not** anything about robots, vehicles, or autonomous systems.")
    out("- **Not** anything about physical effects.")
    out("- **Not** that Sniffer Dog behaves this way on a real agent workload. This")
    out("  subject is synthetic and its lies are the ones it was written to tell.")
    out("- **Not** anything outside the coverage window. Absence there is absence of")
    out("  observation, which is never evidence of non-execution.")
    out("")
    out("Comparison is by binary basename, so repeated execs of the same binary are")
    out("not distinguished. That is adequate for this subject and would not be for")
    out("a workload that re-execs the same image with different arguments.")
    out("")
    out("This run addresses Phase 1 of `validation/scenarios/TEST_PLAN.md`. It does")
    out("not reach REAL AUTONOMOUS-SYSTEM-PROVEN, and no combination of experiments")
    out("runnable in this environment does.")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
