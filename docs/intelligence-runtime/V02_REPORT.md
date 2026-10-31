# SYNTRIASS Air-Gap Native Intelligence v0.2 — sprint report

Branch `feature/syntriass-runtime-v02`, started from `7bf697b` (unchanged;
v0.1 evidence kept). Hardware for every number: 2 vCPU Xeon (AVX-512), 8 GB
RAM, no GPU, no power counters; Qwen2.5 0.5B and 1.5B GGUF (Q8_0/Q4_K_M);
every model call inside a network namespace with no route. All data is
synthetic and written by one author, who also wrote the system. Summary file:
`research/capability-learning/results/v02/summary.json`.

## 1. Answer first

| Question | Answer |
|---|---|
| Did the local models acquire an approvable capability on their own? | **No.** On the fresh holdout the atomic-claim pipeline produced a procedure whose executable logic is identical to the engineer's, but it was blocked twice — first by its own boundary probe (a runtime parser defect), then by the signed expert suite (plural exclusion terms did not match singular requests). |
| How much human correction did it need? | **3 typed leaf edits** after the suite failure, vs **68** leaves authored by hand for the engineer-taught version and 49/87 corrected leaves in v0.1. With them it validated 12/12 and matched the engineer's results exactly. The edits were informed by a suite failure and re-validated on the same suite (disclosed). Human time was not measured. |
| Did the pipeline stop wrong candidates? | Yes. Dev EP-114 candidate: rejected by its suite (val-010). Holdout candidate as proposed: would have released 2 out-of-scope requests (dry run, never deployed); rejected by the suite. |
| Accuracy on the fresh family (30 unseen decisions) | Validated capability: **25/30 strict** (27/30 with the v0.1 withhold-for-AMBIGUOUS mapping), **0 wrong release decisions**, 1/6 false activation, 0/18 unauthorized uses, 0 model calls, 0.2 ms median. Local 1.5B: **1/30, 3/30, 4/30** (alone / RAG / prompt skills) with 1/13/14 wrong ACCEPT-or-MONITOR decisions. |
| Primary (pre-fix) result | Neither the engineer-taught nor the atomic capability passed validation: the runtime did not read negative temperatures ("-2 C"). The atomic pipeline's generated boundary probe flagged the same defect **before** expert validation. Fixed at root (`quantity.rs`), regression-tested; post-fix numbers above are secondary. |

## 2. Phase 1 — atomic-claim acquisition (`harness/atomic.py`, `propose_atomic.py`)

Document → sentence clauses with character spans → numbers typed by unit →
per-clause claims whose numeric fields are JSON-schema enums of **that
clause's** numbers (an unsupported constant cannot be expressed) → fixed
lexicon checks: each field is *evidence* (clause determines it, model
agreed), *repaired* (clause determines it, model disagreed), *hypothesis*
(several values possible; model's kept) or an *issue* → assembly into the
existing IR with rule-precedence simplification → consistency checks in
exact rationals (unit kinds, variable definitions, unreachable rules,
contradictions, min ≤ max, missing-data, every document outcome reachable)
→ deterministic boundary probes around every threshold (unlabelled), run
through the compiled artifact and compared with a reference evaluator →
triage (`CANDIDATE_FOR_EXPERT_VALIDATION` only with zero issues, 6/6 demos,
no unsupported number, no probe mismatch). Validation, approval and
activation are the unchanged runtime lifecycle.

Development (two dev families only), three bounded attempts, all kept in
`results/v02/attempt*`:

| Attempt | Change | EP-114 | HU-BT-4 |
|---|---|---|---|
| 1 | model classifies every clause | aborted: 0.5B assigned the first schema kinds to almost every clause | — |
| 2 | claim-kind evidence gates; inputs completed from unit words | blocked, 0/6 demos | blocked, 0/6 |
| 3 | abbreviation cues; one condition per comparator; limit template from wording; exact probe text | **candidate**, 6/6 demos — later rejected by its suite | blocked 5/6 (known parser gap "SG only 1.185"); logic identical to engineer's |

Frozen at `b4371a1`; holdout run afterwards. Holdout acquisition: 16 model
calls, 69 CPU-s, 39.6 s wall, 2.2 s model load (cold-cache loads were up to
75 s earlier in this sprint). The model agreed with the clause on 32 of 52
clause-determined fields; without repairs (ablation) the same models made 20
field errors in 34 calls / 272 CPU-s. **Most of the gain is deterministic
evidence checking, not model capability** — the honest framing is "a small
model proposes; the document constrains; an expert approves".

Known pipeline limits: English, sentence-level lexicons written against two
dev documents; the holdout document was written by the same author with
similar phrasing (it tests little paraphrase generalisation); no conjunctions
beyond what precedence removes; morphology of scope terms (the defect above).

## 3. Phase 2 — small and large models

No model larger than 1.5B is present and none was downloaded; **no
large-model benchmark exists**. Implemented model-agnostically:
optional `large` model in the runtime config (hash-verified, loaded on
demand); `controller::escalate` retries a small-tier model strategy **once**
on the large tier only when output was withheld for a model-quality reason
(never for "no authorized source", never for capabilities or exact rules);
both attempts and the large load are charged (`Cost.escalations`; tests).
Acquisition uses the same split: 0.5B per claim, 1.5B for kind choices and
failed claims (≤ 3 attempts per claim). The large tier in this sprint is the
1.5B model — a stand-in, not a large model.

## 4. Phase 3 — capability memory

Experience is stored, never applied: `exp-record` (OS-uid principal,
tenant/domain admission, no self-verification, immutable, 0600) →
`cap-review` (active version vs verified same-tenant experience, read-only)
→ engineer proposes v(n+1) → expert signs old + new cases → `cap-upgrade-check`
(regressions, fixes, every changed case, blocking scope changes, reported
applicability changes) → unchanged validation and signed approval →
`cap-activate --supersede` (one ACTIVE version per id) → `cap-rollback`
(approver re-activates the superseded, still-approved version; new
`SUPERSEDED → ACTIVE` edge, approver only) → `cap-history` (versions,
transitions, audited uses per version). Demo Scene 7 runs all of it
offline: 2 field disagreements found, v2 passes 16/16 (v1 14/16), 0
regressions, decision in 0.5 ms with no model, rollback leaves v1 active.

## 5. Phase 4/5 — cost per correctly completed, authorized task

tx-tasks-v1, 30 unseen + 6 probes, same host and items:

| System | Strict correct | Wrong release decisions | False act. | Model calls | CPU-s / task | CPU-s / correct |
|---|---|---|---|---|---|---|
| Local 1.5B Q8_0 alone (B1) | 1 | 1 | 0 | 36 | 4.28 | 154 |
| + conventional RAG (B2) | 3 | 13 | 0 | 36 | 8.68 | 104 |
| + prompt-based skills (B3) | 4 | 14 | 1 | 36 | 15.84 | 143 |
| Engineer-taught SYNTRIASS (post-fix) | 25 | 0 | 1 | 0 | ≤ 0.01 | ≤ 0.01 |
| Atomic pipeline + 3 expert edits (post-fix) | 25 | 0 | 1 | 0 | ≤ 0.01 | ≤ 0.01 |

Peak RSS: baselines 3690 MiB (llama-server); capability reuse 6 MiB runtime +
154 MiB sidecar. Compute-only break-even of the atomic acquisition (69
CPU-s): **4 uses vs B3, 8 vs B2, 16 vs B1**. These count model CPU only;
expert time (signing 12 cases, 3 edits, approval) was not measured, so no
total-cost or enterprise saving is claimed.

## 6. Phase 6 — deployment

`deploy/syntriass/` (`bundle.sh`, `install.sh`, `README.md`) and
`syntriass health`. Verified in a no-route namespace: tampered bundle
refused, routed host refused, release directories with atomic `current`
symlink for binary rollback, state never modified by install, health exit 0
when idle and a correct memory failure while other model servers were
running. No orchestration platform; BitTorrent not required.

## 7. Security and failure report

Preserved and re-tested: tenant and clearance isolation (0/18 unauthorized
uses on the holdout), signed independent expert suites, independent approval,
tamper detection (demo Scene 5), scope-bound cache isolation (cache attack
re-run), offline operation, consequential capabilities disabled,
`CannotProve` on every audit record. New surfaces: experience log (admission
rules, immutability, tests), rollback (approver-only edge; role is still a
claimed CLI argument — authentication beyond the OS uid map remains absent),
large-tier escalation (bounded to one retry).

Failures kept on record: attempt 1 (garbage classification); EP-114 dev
candidate rejected (val-010) and its latent exclusion term "motors" (seen after
the freeze, not fixed); holdout negative-temperature parser defect (fixed
after the primary run); plural scope terms (corrected by an expert, not by the
pipeline); thousands separator "1,200 megohms" decided as 200 (t-27, a wrong
DRY_OUT); multi-asset request decided instead of withheld (t-23); "Not a
cable" negation treated as cable (t-29, OUT_OF_SCOPE); battery probe activated
the transformer capability (fa-3, INSUFFICIENT_INPUT); "SG only 1.185"
unread (dev).

## 8. What may and may not be claimed

May: a small local model plus deterministic evidence checks drafted a
procedure whose logic matched an engineer's on a fresh family, and the
system's own probe and an expert's signed suite stopped it until 3 typed
edits were made; validated capabilities were far more accurate than 1.5B
local-model baselines (25 vs 1–4 of 30, 0 vs 1–14 wrong releases) at under
1 % of their per-task compute; capabilities version, regress-check, approve
and roll back without retraining; installation is offline and verifiable.

Must not: autonomous learning of procedures (it did not pass alone);
anything about GPUs, large models, energy or concurrency; parity with
frontier models; defence certification; commercial deployment; verified or
independently observed execution; enterprise cost reductions; generality
beyond the two phrasing styles tested.

## 9. Tests (executed at the final commit)

| Suite | Result |
|---|---|
| `cargo test -p syntriass-runtime` | **85 passed** (70 at v0.1) |
| `cargo test -p vanian-sovereign -p aip-authorize -p aip-core -p aip-reconcile` | 580 passed |
| `cargo fmt --check`, `cargo clippy --all-targets -D warnings` (runtime, sovereign) | clean |
| pytest system-one / compute-memory / bittorrent-p2p / capability-learning | 18 / 32 / 9 / 53 passed |
| integrated cache attack (`results/v02/cache_attack_v02.json`) | 0 violations |
| offline demo, 7 scenes (`demo/DEMO_OUTPUT.txt`) | exit 0, audit chain verifies (8 records) |
| offline install + `syntriass health` (`results/v02/install_health_idle.json`) | exit 0 |

Not run: the full 40+-crate workspace (needs SoftHSM2). Failed tests: none.
Final commit SHA: reported in the session reply (this file is part of it).
