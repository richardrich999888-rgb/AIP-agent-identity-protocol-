# P0-049 / P0-050 / P0-051 rehearsal ledger

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

## P0-050 iteration 1 — bounded applicability accepted, zero rehearsal credit

Implementation `ef3d9d434e5ed55e5994331abc91c03833f997ff`, tree
`d8e21fc9b2fa8ae4ad981036f0c082916fc51e86`. CI merge `de0786e2` has the same
tree. All rows are component checks, not complete W3/investor/customer modes.

| Run | Source / state | Result | Wall seconds | CPU seconds | Peak child RSS KiB |
|---|---|---|---:|---:|---:|
| Rejected parent, local namespace | `925432b`, clean | 25/26 attacks; recorder exit 3 | 1.1971525059998385 | 0.524794 | 15604 |
| Development candidate, local namespace | `925432b`, dirty | 26/26 attacks; recorder exit 0 | 0.5467602559992883 | 0.330729 | 15604 |
| Clean source, prior prebuilt binary | `ef3d9d4`, clean | 26/26 attacks; recorder exit 0 | 0.9466386320000311 | 0.42060600000000004 | 15604 |
| Clean source, fresh local build | `ef3d9d4`, clean | 26/26 attacks; recorder exit 0 | 0.4039170820005893 | 0.168796 | 15604 |
| Connected four-CPU CI | `de0786e`, clean | 26/26 attacks; recorder exit 0 | 0.22955532699999992 | 0.136628 | 22596 |

Evidence: `../assurance/evidence/p0-050-iteration-1/`. The clean parent retains
fa-3 INSUFFICIENT_INPUT; the corrected runs return NOT_APPLICABLE. Holdout remains
12/12; copied-plural control remains rejected. Eight synthetic suite signatures
verify separately; a changed signed label is rejected. Diagnostic JSON is unsigned.

The prior prebuilt binary and fresh build have different hashes, so both runs
are retained and labelled; the final local row uses the fresh source build.
Local host: nine CPUs, Linux 6.18.57; CI: four CPUs, Linux 7.0.0-1017-azure.
Full per-host/binary/resource/network metadata is retained. Model hashes are empty
because no model ran. No packet capture or sensor operation occurred.

The first evidence comparison incorrectly expected independent session IDs to
have the same questions digest; that failed attempt is retained. Recovery compares
actual questions and choices while checking each session binding. Frozen labels
were not changed. No qualifying full-mode run occurred, so consecutive counts
remain zero. No clean-machine, Mac hardware or external-evaluator credit.

## P0-050 applicability replay continuation — zero full-mode credit

12 November 2026. The compiler repair already existed at `ef3d9d4`; this
continuation adds a reusable verifier and negative controls. The concurrent
documentation/evidence checkpoint `975b245` was preserved. All original local
signed suites, rejected controls, replay outputs, logs and exact command receipts
are under `../assurance/evidence/p0-050-replay/`.

| Bounded check | Result | Measured duration |
|---|---|---|
| Fresh local recorder, source `ef3d9d4` clean | 12/12 holdout, 26/26 attacks, 6/6 subset; controls still rejected | 0.272866667 s recorder body; 0.405602888 s enclosing command |
| OpenSSL + native replay of local packet | Both signatures and all 38 outcomes pass | Exact enclosing duration in `replay-local-final.json` |
| Same replay of original CI packet | Both signatures and all 38 outcomes pass | Exact enclosing duration in `replay-ci-final.json` |
| Full Python / runtime regression | 375 / 187 pass; no skipped/ignored tests | Original command receipts; overlapping counts |

The replay uses a separately selected build hash recorded in trust material;
Cargo test rebuilt the CLI after the local recorder. The original CI ZIP and
every extracted member match the earlier retained originals byte-for-byte and
are referenced rather than counted twice. Signature checks use OpenSSL; outcomes
use the existing trusted native engine. No authenticated expert, separate
administrator, model, live sensor, clean-machine kit install or complete commercial
mode is proved. The initial uncached offline Cargo failures and host-plugin
warning remain recorded. Required ten-/twenty-run full-mode counts remain zero.

Published replay source `91df9e9`, connected CI **43174778630**: holdout 12/12,
attacks 26/26, frozen 6/6 subset; copied-plural controls still rejected. Recorder
body **0.190935002 s**, not the full show. Fresh signed ZIP and extracted originals
are retained in `p0-050-replay/post-push/`; both corrected suites pass subsequent
OpenSSL/native replay. CI adds zero to full-mode rehearsal totals.

## P0-051 iteration 1 — session diagnostic, zero full-mode credit

Implementation `5bc0c5f68690e5d2656716a97c2cfbb2ce105e08`; hosted merge
`9892299fbbb4d76c8dfe62665a8ddd950221fe18`; identical tree
`751702c7f6472d52062040b942132c88341a31b5`. Both recordings have clean source.

| Observation | Actual result | Wall seconds | Child CPU seconds | Peak child RSS KiB |
|---|---|---:|---:|---:|
| Local Linux development host, 9 logical CPUs | Original control 11/12 rejected; corrected 12/12 and 26/26; exact question links | 0.9302947449996282 | 0.645871 | 62592 |
| Hosted CI, run 43215328974 | Same outcomes and capability hashes; separate binary/hardware | 0.7274345790000041 | 0.632221 | 67416 |

Original archives, signed suites/public keys, raw stdout/stderr, runtime/source
hashes, hardware/counters and verification outputs are in
`evidence/p0-051-iteration-1/`. Three signatures per host verify separately.
The existing frozen applicability evidence also replays 12/12 and 26/26; six
nonactivation cases are a subset. Do not add overlapping counts.

Failed attempts are kept: original parent sandbox regression; superseded local
repair; two initial ineffective test mutations; an initial full Python run with
two skipped tests due to an unstaged default release binary. Later runs explicitly
select the built binary (408 passed, no skips). No failing frozen label changed.

The adopted `6764c7e` sandbox recorder also ran locally and on CI, retaining real
signed original bundles and one-byte mutations. Local verification of the original
CI bundle passes; its tampered copy fails. Observation remains CANNOT_PROVE. No
native sensor, independent collector administrator, model or final kit ran here.
No packet captures or clean-machine installation are claimed. Consecutive final
full-mode counts remain zero; these timings are individual component observations.

## P0-050 S2 sandbox continuation — zero full-mode credit

12 November 2026, source `6764c7e`, hosted teaching run `43212899727`.
Local scoped Rust tests: 289; hosted same 289 plus 197 focused Python tests.
Original signed CLI packets retained under `../assurance/evidence/p0-050-sandbox/`.
Authorized output verifies, unauthorized tool refuses, one-byte mutation and
wrong anchor reject; independent observation remains CANNOT_PROVE. Post-download
verification uses a separate local build without the original private state.
All 38 signed teaching cases replay, including the six-case nonactivation subset.

Local CLI command: 8.157518536 s including initialization and negative checks,
not a commercial demonstration. Hosted durations are per-command values in
`ci/original/sandbox-evidence/receipt.json`; no extrapolated show duration.
The failed baseline and the failed first post-download helper attempt are retained.
No model or fresh Sniffer Dog sensor ran; no install or independent-administrator
credit. Required ten-/twenty-run consecutive complete-mode counts stay zero.
