# Failure analysis — everything that failed, kept on record

| # | Failure | Where | Root cause | Status |
|---|---|---|---|---|
| F1 | Capabilities could certify themselves | validation (found at session start) | expert cases inside the artifact with an unauthenticated author string | **fixed** c15c3f2 (signed suites) + regression tests |
| F2 | Module doc cited a parity test that did not exist | `domain/maintenance.rs` | claim written before the test | **fixed** b6c8bf0 (150-item parity test) |
| F3 | 838 MB RSS spike on model start | supervisor | one-shot hash of the whole file | **fixed** b54795a (streamed) |
| F4 | 1.5B model cannot propose a valid capability | Phase C | precedence, undefined names, wrong outcomes; ignores repair feedback (identical output) | **open**; required 7 engineer corrections |
| F5 | Unseen test-002 wrong (INSUFFICIENT_INPUT, expected PASS) | Phase D | parser does not read a unit fused to its number ("3.3kV"); cue list lacks British "polarisation" | **open**; fixing it and re-scoring the same set would contaminate it |
| F6 | test-024, test-026 refused instead of decided | Phase D | applicability terms lack "resistance" and "GΩ" (correction C7 incomplete) | **open**, safe refusals |
| F7 | Router decided multi-asset reports on partial rule coverage | fresh v5 (hold-020, hold-024) | rules checked before asset coverage | **fixed** 35c2d26; held-out figure stays 29/37 |
| F8 | 4 must-abstain v5 reports released by the interpreter | fresh v5 | TF-IDF interpreter maps unknown/ambiguous text onto known assets; registry gate misses codeless assets | **open** (same weakness as iteration 2) |
| F9 | Exploratory routing result (0.872) did not reproduce | v5 | derived on inspected data | recorded; 0.784 held-out |
| F10 | First grounded request took 78.8 s | runtime | real cold disk ~15 MB/s; earlier cold-load measurements were host-cache-warm | recorded; correction in COMPUTE_MEMORY_RESULTS |
| F11 | Runtime without capabilities refuses most IR requests (29/40) | Phase A | no strategy for an unknown task family; grounded QA cannot compute | expected; it is the baseline |
| F12 | Grounded answer states the rule, not the number | demo Scene 1 | 1.5B model quotes "10 times (rated kV plus 1)" instead of computing 76 MΩ | open; the validator released it because it is supported by the source |
| F13 | First speculative-decoding and side-channel runs invalid | compute-memory | `cache_prompt` required; `--slot-save-path` required | recorded on that branch |
| F14 | Earlier attempt's capability test assertion (≥ 24/32 unseen) shows the unseen set had been scored against a hand-written fixture before this session | test history | evaluation result visible to the test author | disclosed; the learned capability was derived from the model draft and document only |

Tests that fail at HEAD: none (runtime 67, Sovereign + AIP 580, Python 59).
Tests not run: full workspace (SoftHSM2 and unrelated crates).
