# Final report — pre-YC sprint (SYNTRIASS Air-Gap Native Intelligence)

Branch `feature/syntriass-intelligence-runtime-v01`. Hardware for every
number: 2 vCPU Xeon, 8 GB RAM, no GPU, no power counters; Qwen2.5 0.5B/1.5B
GGUF; everything offline. All data is synthetic and written by one author
(who also wrote the system). Raw results: `research/capability-learning/results/`
(`sprint/summary.json`, `economics.json`), `research/intelligence-runtime/results/`.

## 1. What improved, what did not

| Question | Answer |
|---|---|
| Can the local model now propose a valid capability without manual correction? | **No.** 0 valid across 3 methods × 2 families (Qwen2.5-1.5B Q8_0, 3 rounds each). |
| Did the constrained compiler help? | **Structure, yes; meaning, no.** Compiling rounds: old proposer 3/9, typed-IR single form 6/6. Demonstration agreement stayed low (0/6 fresh family, 2/6 earlier family); the decomposed variant was worse (3/6 compiling, 0/6 demos). |
| Is a wrong candidate stopped? | **Yes, twice over.** The new evidence gate flags every model draft (1–10 numbers per draft not stated in the procedure → `NEEDS_EXPERT_CORRECTION`); the signed expert suite would also reject them. No candidate reached approval. |
| Fewer manual corrections? | **Not demonstrated.** Correcting the fresh-family draft took 49 of 87 typed fields across 6 sections. Human time was not measured. |
| Does the engineer-taught workflow work on a fresh task family? | **Yes.** Battery float acceptance (bt-tasks-v1, sealed until the approach was frozen): signed suite 12/12 (5/5 counterexamples), approved, active; **26/30 strict, 29/30** with withhold-for-contradiction counted for AMBIGUOUS items (mapping applied after the strict score was seen; both reported); **0 incorrect positive decisions**; 0/6 false activations; 0/18 unauthorized uses; 0 model calls; 0.2 ms median. |
| Product defects fixed | Grounded answers that restate a formula instead of the requested value are withheld with "calculation not completed" (demo Scene 1). Consequential capabilities are disabled until AIP action authorization is integrated. |

## 2. Cost per correctly completed task (CPU-only research measurement)

Fresh family, 30 unseen decisions (+ 6 probes), same machine and items:

| System | Correct | Wrong positive decisions | False act. | Model calls | CPU-s / task | Peak RAM |
|---|---|---|---|---|---|---|
| Local model alone (B1) | 2 | 3 | 0 | 36 | 3.7 | 3.7 GB |
| + conventional RAG (B2) | 1 | 20 | 2 | 36 | 8.3 | 3.7 GB |
| + prompt-based skills (B3) | 7 | 4 | 3 | 36 | 13.5 | 3.7 GB |
| SYNTRIASS with validated capability | 26 (strict) / 29 | 0 | 0 | 0 | ≤ 0.01 | runtime 6 MB + sidecar 154 MB |

Earlier family (ir-tasks-v1, 32 unseen): capability 29/32 vs 3–5/32 for
B1–B3. Adaptive runtime **without** capabilities: 8/40 on that family
(refuses tasks it has no strategy for); on fresh maintenance reports
(hard-reports-v5) it scored 29/37 with 0 model calls vs 19/37 for a local
model on every report.

**Acquisition and break-even.** Fresh family: 481 model CPU-s (one
proposer run) + 6 demonstrations + 49 field corrections + 12 signed expert
cases + 1 approval. Compute-only break-even: **36 uses vs B3, 59 vs B2, 129
vs B1**. Earlier family: 31 / 54 / 151. These are **inference-compute**
figures; human engineering time was not measured, so no total enterprise
cost saving is claimed.

## 3. Security status

Demonstrated by executed tests at the final commit: no self-certification
(signed independent expert suites), no self-approval, forged/untrusted
approvals rejected, tampering disables a capability, cross-tenant and
lower-clearance use refused, stale evidence/policy/model forces
re-validation, consequential capabilities disabled, integrated cross-tenant
cache attack 0 violations, all model paths offline (no external route).
Not provided: authentication beyond the OS uid map, separated key custody,
independent observation (every record is `CannotProve`), AIP action
authorization inside the runtime.

## 4. Tests (executed at the final commit)

| Suite | Result |
|---|---|
| `cargo test -p syntriass-runtime` | 70 passed |
| `cargo test -p vanian-sovereign -p aip-authorize -p aip-core -p aip-reconcile` | 580 passed |
| `cargo fmt --check`, `cargo clippy --all-targets -D warnings` (runtime, sovereign) | clean |
| pytest system-one / compute-memory / bittorrent-p2p / capability-learning | 18 / 32 / 9 / 19 passed |
| integrated cache attack (`run_cache_attack.py`) | 0 violations |
| offline demo (`run_demo.sh`) | exit 0, audit chain verifies |

Not run: the full 40+-crate workspace (needs SoftHSM2 and crates outside this
runtime's dependency set). Failed tests: none.

## 5. Known failures kept on record

Autonomous proposal (all methods); decimal comma "2,23 V" read as 23 V
(fresh family t-26); a word between a cue and its number not read ("SG only
1.185"); fused units ("3.3kV"); applicability-term gaps (earlier family
test-024/026); router partial-coverage defect (fixed after the held-out
run); interpreter releases on must-abstain reports. Full list:
`FAILURE_ANALYSIS.md`.

## 6. Demo (offline, ~25 s with a warm page cache)

```sh
cargo build --offline --release -p syntriass-runtime
research/intelligence-runtime/demo/run_demo.sh /tmp/syntriass-demo      # six scenes, real runtime
xdg-open /tmp/syntriass-demo/demo.html                                   # one-page view of the run
```

Recorded run: `research/intelligence-runtime/demo/DEMO_OUTPUT.txt`,
`demo.html`, `demo.png`. Two-minute script: (1) a confidential question
answered from cited local documents, and a calculation question correctly
marked "not completed"; (2) a report decided by exact rules in ~3 ms with no
model; (3) the model's draft fails, an engineer's corrections, independent
signed validation, approval; (4) a new request decided in 0.5 ms with no
model call; (5) measured cost table, labelled CPU-only; (6) no network route;
(7) other organisation and lower clearance refused, tampered capability
disabled.

## 7. What can truthfully be claimed to YC

May say: we built an offline private-AI runtime combining local models,
permission-controlled retrieval and exact execution; an engineer can teach it
a procedure without changing model weights; the procedure becomes a
validated, approved, reusable capability; on tested tasks reuse avoids LLM
inference entirely and was far more accurate than local-model baselines at
under 1 % of their per-task compute; CPU, memory and latency trade-offs are
measured.

Must not say: that it learns new procedures autonomously (a 1.5B model could
not); anything about GPUs, large models, energy or concurrency; general
reasoning parity with frontier models; defence certification or commercial
deployment; verified execution; any percentage reduction in enterprise cost.
