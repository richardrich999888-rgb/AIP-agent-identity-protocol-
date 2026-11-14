# P0-049 delivery report

**Release NOT READY.** Latest implementation:
`4d002accbf6759fe1845872ac5579815c8081631` (iteration 3), continuing draft PR #21.
Explicit, source-linked exclusion variants fix the Cable holdout failure while
retaining quoted forms and literal runtime matching. Actual teaching-session
answers now compile to a capability that passes the original 12/12 holdout.

The expanded attack gate remains **FAILED**: 25/26, versus 17/26 before the fix.
A battery-cell request still returns INSUFFICIENT_INPUT instead of NOT_APPLICABLE.
That pre-existing failure reproduces on CI; the recorder and CI retain exit 3.
Local regression tests: 324 Python and 187 runtime passes, no failures/skips.
Eight local/CI suite signatures independently verified; an altered suite was
rejected. No approval, activation or release acceptance occurred.

See [iteration 3](P0-049-ITERATION-3.md), its retained evidence, and the updated
completion matrix. Next dependency: cross-domain applicability, then general C1
session/question linkage. The offline kit, OVERLAY demonstrations, second-host
benchmarks, required rehearsals and external evaluation remain incomplete.

## Iteration 2 historical record

Implementation:
`9e3909eea8328d7e81a5887a6e80430237642616` (iteration 2), continuing draft PR #21.
Patched the SQLite and rustix dependencies and corrected a Security workflow
pipeline that could hide a failed audit behind a successful `tee`.

| Iteration 2 check | Observed local result |
|---|---|
| Runtime/corpus tests, including old-database compatibility | 284 passed; 0 failed/skipped |
| Other rustix consumer tests | 144 passed; 0 failed/skipped |
| Audit failure-propagation tests | 4 passed; old-shell control reproduces false success |
| cargo-audit 0.23.0, identical pinned advisory snapshot, no ignores | Before: 1 vulnerability and 1 warning, exit 1. After: 0/0, exit 0 |
| cargo-deny 0.20.2 | Passed; policy unchanged |
| Formatting / targeted clippy | Passed; warnings denied |

The linked SQLite is 3.54.1. The previous engine's database fixture retains search,
tenant/clearance restrictions, quarantine and document dependency hashes, and
supports safe re-ingest/reopen. See [iteration 2](P0-049-ITERATION-2.md) and its
retained evidence. This is compatibility/security-gate testing, not exploit
reproduction or full offline-kit acceptance. Source CI was queued at first
inspection. The four retained-render Trivy findings and all release-level gaps
remain open. No advisory or Trivy suppression was added.

## Iteration 1 historical record

**Overall release: NOT READY.** This report closes one bounded iteration, not the
P0-049 release. The bounded diagnostic reproduced on a separate CI runner; no
complete offline installation or external evaluator acceptance occurred.

Implementation: `84d889f0c045a998150900e433541a976fdd1d69`. Delivery:
[draft PR #21](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/pull/21).
The following documentation/evidence commit does not change the runtime.

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
| Second implementation of suite verification | Python cryptography 50.0.0 verified all six local/CI suites; modified suite refused |
| Scope of acceptance | Deterministic cases on development host and CI; no model or new kernel-sensor run |

Source SHA, binary hash, exact timings, hardware, CPU/RSS, raw outputs and check
logs are retained under `evidence/p0-049-iteration-1/`, with nested and aggregate
SHA-256 manifests. These manifests and diagnostics are unsigned. Only the expert
suites and pre-existing observer records have the signatures described here.

| Single recorder execution (debug binary) | Hardware exposed to process | Wall seconds | Child CPU seconds | Peak child RSS KiB |
|---|---|---:|---:|---:|
| Local clean source, isolated network namespace | Linux 6.18.57, 9 logical/affinity CPUs, MemTotal 10206472 kB | 2.7071336839999276 | 1.037143 | 12288 |
| CI clean merge checkout, network connected | Linux 7.0.0-1017-azure, 4 logical/affinity CPUs, MemTotal 16367524 kB | 0.45960819999999103 | 0.37376599999999993 | 18416 |

Both runs produced the same capability hashes and 14/14, 11/12, 12/12 outcomes.
These are separate observations of a bounded recorder, not a performance range,
model benchmark or three-minute investor measurement. Cgroup limits were unavailable
and are labelled accordingly. Local interface counters showed only loopback and
zero byte/packet increments; no packet capture was taken. CI had traffic and is
not offline proof. No sensor was disabled to obtain these results.

The recorder initially failed on its suite input field, fixture path and missing
cgroup files. Those attempts and their fixes are documented in `REHEARSAL_LOG.md`.
The unchanged transformer scope bug remains visible as a rejected case.

## Review and release boundary

Self-review covers the added CLI path, immutable validator schema, expert trust,
tenant checks, duplicate case IDs, tampered artifacts, no lifecycle mutation and
failure messages. This is not an external security review. Existing workflows and
security findings are preserved. C1 is still partial at the teaching-workflow
level: session/answered-IR integration and exact B1 question IDs remain unproven.

At implementation commit `84d889f`:

- [Scoreboard CI](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/43090681318)
  passed. Its merge checkout `71ab878a1824364ac424b9895a6ffe12818ec842`
  has exactly the source tree `557935e887f10328fb60355968503d8a619e3c1f`.
  Raw CI evidence was downloaded, hash-checked and retained separately.
- The real-agent contract workflow passed; it makes no live-agent claim.
- [Security](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/43090681099)
  failed. Retained Trivy SARIF reports four HIGH findings (KSV0009, KSV0010,
  KSV0118, KSV0121), all in the existing historical Helm render
  `validation/enterprise/results/HELM_20261028T103133Z/template-enabled.yaml`.
- [Main CI](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/43090681089)
  has a failed supply-chain job: `cargo audit` and `cargo deny` report
  `libsqlite3-sys 0.30.1`, RUSTSEC-2026-0459. Audit also reports a rustix 1.1.5
  unsoundness warning, RUSTSEC-2026-0486. The lockfile is unchanged by this iteration.
  See `ci-supplychain-failure.txt`; this is scanner evidence, not a new exploit
  validation. Other still-running jobs are not counted as passed.

The branch is `feature/airon-teach-demo`; delivery is a draft PR into
`feature/syntriass-runtime-v02`. No merge to main occurred. Source CI snapshots
are in `remote-state.json`; inspect the PR for checks on the later evidence-only
head rather than assuming these source-commit statuses apply to it.

All remaining requirements are mapped in `P0-049-COMPLETION-MATRIX.md` and
`OPEN-GAPS.md`. In particular: complete W3, complete offline kit, fresh OVERLAY
demos, initial-netns isolation/capture proof, second-machine benchmarks, the exact
investor/customer sequences, required rehearsals and external acceptance.
