# P0-049 rehearsal ledger

**Required-mode acceptance: NOT READY.** This teaching branch had no master demo
rehearsal log. Historical W results remain in the original log at AIP commit
`6ad92ae`, `docs/demos/REHEARSAL_LOG.md`; they were not merged or overwritten.

| Historical W run | What was retained | P0-049 credit |
|---|---|---|
| Quantum 10/10, security 10/10, PQ 10/10 (7 Nov UTC) | Summary records and partial archives; original OVERLAY source unavailable | No final-release consecutive-pass credit |
| Pull-the-plug 10/10 (8 Nov UTC) | Log row; referenced full run directory not in tracked tree | No independent-host acceptance credit |
| Discarded banking 10/10 | Log says dirty-tree batch discarded | No credit; keep failure/re-run history |

New iteration-1 runs test only C1, not the full teaching or investor mode. They
contribute **zero** to the required ten/twenty consecutive rehearsal totals.

Iteration 2 (`9e3909e`) also contributes zero: dependency/gate checks and the C1
regression are not full teaching/investor modes. Its 19 namespace sandbox tests
exercise authorized tool execution, not a live Sniffer Dog observation acceptance
run. No packet captures, verified model weights or clean-machine install resulted
from these checks. Previous failed attempts and raw records remain retained.

| Bounded run | Immutable source / state | Actual result | Retention |
|---|---|---|---|
| Local, 11 Nov 19:49:39 UTC | `84d889f0c045a998150900e433541a976fdd1d69`, clean | Recorder exit 0; 14/14, expected 11/12 rejection, 12/12; 2.7071336839999276 s | `evidence/p0-049-iteration-1/scoreboard/` |
| CI, 11 Nov 19:49:51 UTC | Merge `71ab878a1824364ac424b9895a6ffe12818ec842`, clean; same tree as source | Recorder exit 0; same counts and hashes; 0.45960819999999103 s | `evidence/p0-049-iteration-1/scoreboard-ci/`, run `43090681318` |

Each row is one observation on its labelled host, with debug binaries. It is not
a range. Per-case exit statuses, binary hashes, host details, CPU/RSS, namespace
counters and timings are retained in each `result.json`. Suites are signed;
diagnostics are unsigned. No model, packet capture, full offline install, fresh
live sensor run or external evaluator was involved.

Development failures retained:

1. Recorder supplied `expected` to `suite-sign`, which requires `label`; CLI
   refused with `case.label`. Corrected the recorder, not the CLI contract.
2. Recorder used a non-existent corrected transformer fixture path. Corrected to
   the tracked `results/v02/postfix/` fixture; did not reconstruct missing data.
3. Recorder assumed cgroup-v2 files exist. This host exposes no such files.
   Hardware evidence now records UNAVAILABLE with the actual error instead of
   crashing or inventing resource limits.

The later successful recording retains the intentionally failed transformer
candidate (exit 3) alongside the passing motor and corrected transformer cases.
That is expected diagnostic acceptance, not a passed live teaching rehearsal.

`development-failure-*.txt` retains the available failure output; the initial
suite-field error was transcribed from its console and is explicitly labelled as
such. Source CI failures are retained separately (Trivy SARIF and the supply-chain
job excerpt). No failed result was removed from a consecutive-pass count.

Next qualifying run must retain exact source/binary/model hashes, host details,
full signed evidence, verification outputs, captures, counters, CPU/memory, timing,
exit status and failures/recovery. Reset each mode's consecutive count on failure.
W3 additionally requires twenty passes and a fresh offline install every fifth run
on supported CPU-only clean hardware.

## P0-049 iteration 3 — rejected engineering acceptance, zero rehearsal credit

Source `4d002accbf6759fe1845872ac5579815c8081631`; clean CI merge
`192acf0ee9aa00378caa315721aad46dc0de660d` has the same tree. Both are bounded
teaching-session checks, not complete W3/investor/customer rehearsals.

| Run | Actual result | Wall seconds | Child CPU seconds | Peak child RSS KiB |
|---|---|---:|---:|---:|
| Local clean source, 9-CPU development host, new network namespace | Exit 3; holdout 12/12, expanded attacks 25/26 | 0.8565336249998836 | 0.450454 | 15616 |
| Connected 4-CPU CI runner, run 43164083237 | Exit 3; same outcomes and capability hashes | 0.26487211500000285 | 0.166703 | 22956 |

Full metadata and signed suites are under `evidence/p0-049-iteration-3/`, with
separate `local/` and `ci/` results. No model was used. Local counters show only
loopback and zero deltas; no packet captures or sensor observation were performed.
Neither host installed the completed offline kit. These timings are individual
observations, not a performance range or a three-minute show.

Development attempts are retained rather than counted as passes:

1. `b3-dev.log`: the initial recorder raised at the unexpected attack failure.
   The outer shell then ran `cat`, so its exit 0 did not measure the Python exit.
   The exception is retained; complete failed stdout was not retained that time.
2. `development-failure-2/`, `b3-dev-2.log`: after preserving stdout before
   checking its status, the recorder retained the failing fa-3 suite/report and
   exited 1. This identified the battery-cell applicability failure.
3. `b3-dev-3.log`: baseline attack comparison proved the failure pre-existed;
   the recorder now completes the evidence and reports partial progress, exit 3.
4. `b3-stdlib.log`: execution with only the Python standard library also exits 3.
5. `b3-clean.log` and CI: final clean-source reproduction still rejects fa-3.
   This defect was not recovered or waived in this iteration.

All 16 explicit word-form probes and four whole-word controls pass; the frozen
false-activation set is 5/6. The original copied-plural candidate remains 11/12,
and its broader attack control remains 17/26. Eight local/CI suite signatures
verify with the separate Python implementation; the tampered control exits 1.
No approval or activation was performed. Consecutive full-mode counts remain
unchanged at zero for this work; a future qualifying failure resets its count.
