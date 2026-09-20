# RED suite (R19)

One command that reproduces every row in
`docs/security/ADVERSARIAL_RESULTS.md` on the host it runs on.

```
validation/red_suite/run.sh          # print the table, exit non-zero on any failure
validation/red_suite/run.sh --json   # also write report.json beside the script
```

## What it is for

The adversarial ledger records, per attack, the classification the stack
actually emitted and whether that counts as a detection. A ledger is only
worth the attacks behind it, and an attack is only worth re-running. This
harness makes "reproducible by script" a checked fact rather than a claim:
`manifest.tsv` maps each ledger row to the exact command that reproduces its
recorded outcome, and `run.sh` runs them and reports, per row:

| status | meaning |
|---|---|
| `REPRODUCED` | the row's test ran and asserted the ledger's outcome |
| `RUNNABLE` | a kernel-gate row whose host has the capability; run the live harness |
| `NOTE` | a boundary, not a detection (e.g. what a key holder can and cannot do); its test still runs |
| `BLOCKED` | the host lacks a capability, or the row is deferred; the reason is named |
| `FAILED` | a row the ledger claims but the code no longer delivers |

The exit code is the contract: **non-zero if any row FAILED.** A `BLOCKED`
row is not a failure — the ledger already records it from a host that had
the capability, and the suite says plainly which rows it could and could
not run here rather than pretending it ran them.

## The one trap this harness avoids

A `cargo test` filter that matches nothing runs zero tests and exits 0 —
success, vacuously. A harness that trusted cargo's exit code would let a
stale selector read as a reproduced detection. So `run.sh` is stricter than
cargo: a row passes only if the output shows at least one test passed and
zero failed. A selector that matches no test is a `FAILED` row, because the
ledger claims a detection the harness could not exercise. That property is
itself tested: rename a selector in the manifest and the suite goes red.

## Capabilities

The live foreign-eBPF rows (`OI-01`..`OI-06`) attach a BPF program to a
tracepoint the observer samples; that needs `CAP_BPF`, `CAP_PERFMON` (or
root) and a `tracefs`. Absent any of these the rows are `BLOCKED` with the
reason named, and are already sealed in the ledger from a host that had them
(Linux 6.18.44). The **off-host half of the same integrity property**
(`OI-09`..`OI-12` — the collector refusing to sign `Active` over a probe's
gate finding, or over silence) runs with none of those capabilities and is
reproduced everywhere. `OI-08` is `deferred`: it needs an off-host or
hardware observer that does not exist yet, and the ledger names it.

## Adding a row

Add the ledger entry, then a line to `manifest.tsv`: the row id, what it
`requires` (`none`, `cap_bpf`, `note`, or `deferred`), the cargo package,
the selector that runs exactly the asserting test, and the ledger outcome.
Keep the selector narrow: it should run the one test that asserts the row,
so a red suite points at the row that regressed.
