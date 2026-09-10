# Experiment 1 — Independent Linux Runtime Observation Comparison

Three accounts of one execution window, compared.

| Account | What it is |
|---|---|
| `subject_workload.sh` | the **subject**: an agent-shaped workload that keeps its own log — and lies in it, on purpose |
| `recorder/` | **Sniffer Dog 2.0**, the system under test, driven through its real live sensor (`aip_observe::ProcessTracer`) |
| `../../linux/ftrace_observer.sh` | the **reference instrument**: the kernel's own rendering of the same tracepoints |

The question is not "do the two observers agree". It is: **does Sniffer Dog
correctly classify the cases where the subject's claim differs from what the
kernel reported?**

## Run it

```sh
sudo ./run.sh            # ~5 s; builds the recorder on first use
```

Evidence lands in `../../traces/exp01-<run>/`, the report in
`../../reports/exp01-<run>.md`. Exit 0 = all checks held, 1 = a check failed,
2 = the coverage window could not be delimited and no verdict was issued.

## The four lies the subject tells

| Label | What happens | What must follow |
|---|---|---|
| `TRUTHFUL` | executes and logs it | both accounts contain it |
| `SUPPRESSED` | executes `wc`, logs nothing | Sniffer Dog reports it despite the silence |
| `MISREPORTED` | executes `basename`, logs `dirname` | the accounts are detected as disagreeing |
| `FABRICATED` | logs `sha256sum`, executes nothing | Sniffer Dog does **not** corroborate it |

The lies are in the log only. Nothing attacks the kernel, the observer or the
host. This is a workload that misreports *itself*, which is exactly the threat
Vanian's independence claim is about.

## The coverage window, and a harness bug worth remembering

The reference instrument starts first, so that Sniffer Dog's own launch is
observable. That guarantees the reference capture contains events from before
Sniffer Dog attached — including Sniffer Dog's own `exec`, which it cannot
possibly have seen.

The first version of `compare.py` compared across the whole capture. It
reported two failures: three binaries "missed" by Sniffer Dog. They were
`exp01-recorder`, `seq` and `tee`, all executed **~74 ms before the window
opened**.

That was the harness manufacturing a coverage gap and then blaming the
observer for it — the same error as reading absence as non-execution, which is
the one thing Vanian is most explicit about. The fix was to the harness: both
accounts are now bounded by markers written into the reference capture, with
`window open` written only after Sniffer Dog reports its sensor attached.

The assertions were not weakened. They were made to ask the right question.
Events outside the window are still reported — as outside coverage, never as
findings.

## Evidence discipline

- Everything is written once into the run directory, then made read-only.
- `SHA256SUMS` is taken before the comparison and verified after it. If the
  analysis touched the evidence, the run is declared invalid.
- `compare.py` is a pure reader. It issues no Vanian verdict, no provenance,
  no evidence strength and no reconciliation result — deciding what a
  difference *means* is Vanian's job, and pre-empting it would defeat the
  experiment.

## Results so far

Three consecutive runs, all PASS, 19 in-window execs seen by both accounts
each time, zero reported loss. The suppressed `wc`, the misreported
`basename`/`dirname` pair and the fabricated `sha256sum` were classified
correctly in every run.

## What a PASS does not mean

Both instruments read **the same kernel tracepoint**. Agreement corroborates
Sniffer Dog's *reading of the kernel*; it does not independently witness the
*event*. The instrument that would have — Tetragon, via eBPF on kernel
functions — cannot run here (`CONFIG_KPROBES` unset).

A PASS says nothing about robots, vehicles, physical effects, or resistance to
a root-privileged subject. The full list is printed at the bottom of every
report, on purpose, because a passing run is exactly when it gets forgotten.
