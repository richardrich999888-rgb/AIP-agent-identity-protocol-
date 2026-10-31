# Learning benchmark — acquiring a capability without fine-tuning

Task family (new; absent from all System One data): motor winding
insulation-resistance acceptance under a fictional organisation's confidential
procedure, Koravi EP-114 rev C (temperature correction to 40 °C, a
voltage-dependent minimum, polarization-index bands, scope and validity
rules). A second fictional organisation (Tarvel) has a conflicting procedure.
Data `ir-tasks-v1`, frozen in 46485eb before any learner or controller code:
6 demonstrations, 14 validation cases (the expert's suite), 32 unseen test
requests, 8 false-activation probes. All raw results:
`research/capability-learning/results/`.

**Disclosures.** (1) One person wrote the procedure, all data, the
quantity parser, the corrections and the system. (2) The quantity parser's
unit kinds (kV, MΩ, °C, cued numbers) were written for this task family.
(3) Two of the 32 unseen requests were printed once to a terminal while the
data format was inspected, before any evaluation. (4) No model weights were
updated in any phase.

## Phases

| Phase | What ran | Result |
|---|---|---|
| A — before learning | runtime, no capability (= baseline 4) | 8/40; 29 refused (no applicable strategy), 10 grounded answers, none decided |
| B — demonstrations and corrections | 6 expert demonstrations; 7 engineer corrections to the model draft, each citing the EP-114 sentence it implements (`harness/correct.py`) | — |
| C — capability construction | **model proposal**: Qwen2.5-1.5B Q8_0 drafts the procedure (`harness/propose.py`), repair feedback from demos only | **failed**: 2 prompt variants × 3 rounds, 0 compiling candidates, identical output across repair rounds |
| C — after corrections | propose → signed expert suite validation → signed approval → activation via the CLI | 14/14 expert cases, 4/4 counterexamples, signature and independence checks pass |
| D — unseen requests | runtime with the ACTIVE capability | **37/40**; 0 false activations; 30 items decided by the capability with 0 model calls |
| E — model replacement | serving model Q4 → Q8 | all 40 outputs identical; a model-bound variant is refused as stale 8/8 after the swap |
| F — regression | hard-reports-v5 with and without the capability | decisions and strategies identical on all 37; the capability never activated |

## Baselines (same hardware, same 40 items, principal koravi-process/restricted)

| System | Correct /40 | Decision items /32 | False act. | CPU-s per task | Δ vs candidate (paired, 95 % CI) |
|---|---|---|---|---|---|
| B1 local model (1.5B Q8) without organisational memory | 11 | 3 | 0 | 3.2 | −0.650 [−0.800, −0.500] |
| B2 + conventional RAG (FTS5 BM25, ACL-filtered, k = 2) | 12 | 4 | 0 | 9.1 | −0.625 [−0.800, −0.450] |
| B3 + prompt-based skill library (6 demos with working) | 13 | 5 | 0 | 15.9 | −0.600 [−0.775, −0.425] |
| B4 adaptive runtime without learned capabilities | 8 | 0 | 0 | — (refuses or answers in prose) | −0.725 [−0.850, −0.575] |
| **Candidate: runtime + validated capability** | **37** | **29** | **0** | **≤ 0.01** | — |

Baselines are favoured: their output is constrained to the label vocabulary
(every answer scoreable), and they use the larger Q8 model. B1–B3 wall times
may be slightly inflated by a concurrent test build for ~1 min; CPU-seconds
are per-process and unaffected.

## Cost

| Item | Value |
|---|---|
| Acquisition — model | 484 CPU-s, 260 s wall (both proposer runs, 6 rounds) |
| Acquisition — validation | 379 µs |
| Acquisition — human | 6 demonstrations, 7 corrections, 14 signed expert cases, 1 approval; **time not measured** |
| Per use (capability path) | median 0.4 ms wall, below /proc CPU resolution (bounded at 0.01 CPU-s) |
| Peak memory (capability path) | runtime ~6 MB + sidecar ~153 MB; no model resident |
| Peak memory (baselines) | llama-server 3.7 GB (Q8) |
| Cold-task cost per correct answer | 534 CPU-s after 1 use |
| Amortised per correct answer | 53 (10 uses), 16.7 (32), 5.4 (100), 0.55 CPU-s (1,000) |
| Compute break-even | 31 uses vs B3, 54 vs B2, 151 vs B1 |

Because the baselines are far less accurate, on cost per *correct* answer
the capability is cheaper than B2 (72.6 CPU-s) from ~8 uses and than B3
(101.5) from ~6, counting acquisition. Human effort is excluded from these
figures because it was not measured.

## What this does and does not show

- **Shown, in scope:** an organisation's procedure became a typed, validated,
  approved capability without changing model weights; on 32 unseen requests
  it was correct on 29 (3 failures, none a positive decision on bad evidence);
  it never activated on 8 probes or 37 other-task reports; it was invisible to
  other tenants and lower clearances; its execution is model-independent.
- **Not shown:** that the system *learns by itself* — the 1.5B model could not
  draft a valid procedure, and an engineer's corrections were required; that
  the approach transfers to a task needing units or operations the parser and
  language do not have; any result with data written by someone other than
  the system's author.
