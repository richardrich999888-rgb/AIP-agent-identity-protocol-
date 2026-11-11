# P0-049 iteration 1 delivery report

**Overall release: NOT READY.** This report closes one bounded iteration, not the
P0-049 release. No independent machine or external evaluator acceptance occurred.

## Change

Added `syntriass cap-scoreboard`: a read-only teaching homework diagnostic using
the existing validator. It displays independent expert counts, counterexamples as
a subset, generated-case counts, failed gates, exact probe inputs, expected/actual
outcomes, the executed rule/guard and suggested questions to revisit. It never
accepts an imported pass result or changes approval/activation state. It refuses
tampered stored capability bytes and reports current lifecycle state separately.

Exit 0 means validation passed, 3 means validation failed with diagnostic JSON,
and 2 means unusable inputs/trust/configuration. No validator/lifecycle rule or
signed validation-report format changed. No dependencies were added to Cargo.lock.
No expert-guided learning is described as model fine-tuning.

The recorder runs on two existing synthetic maintenance domains, retaining signed
suites and public keys but no private keys. The scoreboard itself is unsigned and
does not substitute for the still-missing signed answer receipts or packs.

## Reconciliation findings

- T and W diverge by 27/37 commits. Three overlapping changed paths differ; no
  automatic merge was attempted.
- W6.1 already has `rerun.sh` and `compare.py`; its checklist is stale. The
  one-command wrapper has not yet established full offline acceptance.
- The kit omits AIRON, model weights, inference runtime, teaching content and
  complete local dependencies. Same-host namespace tests are not clean-machine
  acceptance, and the host-netns security exception does not prove offline safety.
- The requested investor sequence is not implemented: W uses plug → liar → quantum.
- OVERLAY's approved base is accessible, but six local-only W4/W5 revisions are
  unavailable. No unavailable commit was invented or reconstructed.
- Reverified retained Sniffer Dog signatures and a negative tamper case. The
  retained health record says ContinuityUnverified, not full coverage.

## Local verification

| Check | Observed result |
|---|---|
| Runtime baseline before change | 173 passed, 0 failed, 0 skipped |
| Runtime after change | 187 passed, 0 failed, 0 skipped (includes 14 new scoreboard cases) |
| Formatting / clippy | Passed; warnings denied |
| Existing Python capability-learning suite | 293 passed; 2 initially skipped because release binary absent |
| Those two CLI tests with explicit built binary | 2 passed; no skipped result counted as a pass |
| Recorded motor / original transformer / corrected transformer | 14/14 pass; 11/12 rejection; 12/12 pass |
| Retained observer archive | 7 batches, 86 events, 1 health record; tampered archive exit 1 |
| Scope of acceptance | One development host, deterministic cases; no model or new kernel-sensor run |

Final source SHA, binary hash, exact timings, hardware, CPU/RSS, raw outputs and
check logs are retained under `evidence/p0-049-iteration-1/` in the evidence commit.
No measurement from this host is combined with historical 2-vCPU/8-GB results.
Single executions are not presented as performance ranges.

The recorder initially failed on its suite input field, fixture path and missing
cgroup files. Those attempts and their fixes are documented in `REHEARSAL_LOG.md`.
The unchanged transformer scope bug remains visible as a rejected case.

## Review and release boundary

Self-review covers the added CLI path, immutable validator schema, expert trust,
tenant checks, duplicate case IDs, tampered artifacts, no lifecycle mutation and
failure messages. This is not an external security review. Existing workflows and
security findings are preserved. The new workflow records bounded C1 acceptance
on CI; its status must be read at the actual pushed commit.

The branch is `feature/airon-teach-demo`; delivery is a draft PR into
`feature/syntriass-runtime-v02`, never an automatic merge to main. CI observation
and final commit references will be recorded with the evidence update.

All remaining requirements are mapped in `P0-049-COMPLETION-MATRIX.md` and
`OPEN-GAPS.md`. In particular: complete W3, complete offline kit, fresh OVERLAY
demos, initial-netns isolation/capture proof, second-machine benchmarks, the exact
investor/customer sequences, required rehearsals and external acceptance.
