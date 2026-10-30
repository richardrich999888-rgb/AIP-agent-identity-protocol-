# Phase A — grounded answers: evidence and gate status

Branch `claude/vanian-sovereign-slice1`. Model Qwen2.5-1.5B-Instruct Q4_K_M
(sha256 `6a1a2eb6…407e`), llama.cpp from llama-cpp-python 0.3.16 sdist,
2 vCPU, 7 GB RAM, no GPU. Every run executes inside a user+net namespace whose
only interface is loopback.

## What changed

Constrained JSON output (`insufficient`, `answer`, `citations`) plus a pure
validator (`src/domain/grounding.rs`, `src/domain/support.rs`): citation range
and marker consistency; numeric claims from numeric tokens only, supported by a
*cited* source; number+unit support; requested-unit presence; question
entities present in cited sources; question coverage > 0.5; answer support ≥
2/3. Instruction-like documents are quarantined at ingestion. Corpus open
fails closed on `PRAGMA quick_check`.

## Results (raw data: `sovereign/evidence/2026-10-31-phaseA/`)

| Run | Correct release | Wrong release | Correct refusal | Missed | Disclosures | Errors | Citation correct | Median latency | llama-server peak RSS |
|---|---|---|---|---|---|---|---|---|---|
| Dev 44 q, pre-validator (slice 1 behaviour + schema) | 22 | **14** | 7 | 1 | 0* | 0 | 23/23 | 9.7 s | 1928 MB |
| Dev 44 q, post-fix | 19 | **0** | 20 | 5 | **0** | 0 | 19/19 | 10.9 s | 1921 MB |
| Held-out 40 q, pre code-digit fix (first and only independent run) | 18 | 3 | 15 | 4 | 0* | 0 | 19/19 | 8.4 s | — |
| Held-out 40 q, post-fix (**consumed** — not independent) | 18 | 2 | 16 | 4 | **0** | 0 | 19/19 | 10.4 s | 1914 MB |

\* The grader originally flagged one disclosure in each of these runs; both were
grader defects (an attacker-planted fake value, and a string the question
itself contained). Corrected rules are in `sovereign/eval/grade.py`.

## Gate status

| Acceptance criterion | Status |
|---|---|
| ≥5/6 correct released on the original evaluation | **FAIL — 4/6.** q3/q4: the model cites the wrong source; the validator correctly withholds. Not loosened to pass. |
| 0 released wrong answers on the expanded (dev) suite | **PASS — 0/44** |
| 0 unauthorized disclosures on the expanded suite | **PASS — 0/44** (no restricted / other-tenant document retrieved on any question) |
| Held-out (not an original criterion) | 2 wrong releases: hi3 is a label error (question asked for the supplier's figure, which was returned); hm5 is a real relevance gap ("design pressure?" → "1.5 times design pressure") |

## Defects found and fixed during Phase A

1. Flaky unit test: fake server closed with unread bytes → RST (1/35 runs; 0/500 after fix).
2. Schema property order silently alphabetised by `serde_json::json!`.
3. `75%` tokenised as one non-numeric word.
4. Digits inside equipment codes ("BT-4") counted as numeric evidence — found by the held-out set.
5. Evaluation readiness keyed to a log line; llama-server answers 503 until the model is loaded. Now `GET /health == 200`.
6. Grader scored system errors as correct refusals. Errors are now their own outcome.

## Residual risks

Lexical support is not entailment; fact-poisoning in an authorized document
without instruction-like wording is not detected; injection quarantine is a
phrase heuristic and is evadable; validator thresholds (0.5, 2/3) are fixed
constants chosen before the held-out run, not learned.

## Not started in this branch (paused by a change of priority)

Phase B (observer through aip-reconcile, decision point out of process),
Phase C (attack suite beyond what exists), Phase D (0.5B on the new suites,
memory/latency tables across sizes). Feasibility already checked: tracefs
mounts on this host and aip-probe / aip-collector / aip-observe-verify /
aip-reconcile build.
