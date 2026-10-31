# Experiment ledger — every run, raw file, decision

Host: HARDWARE_PROFILE.md. Runtime source: llama-cpp-python 0.3.16 sdist
(vendored llama.cpp). Models: BASELINES.md (SHA-256 pinned). All LLM runs
offline (`bench/offline.sh`). Raw JSON under `results/`; tables regenerate
with `tools/summarize_main.py`. Branch `research/syntriass-compute-memory`.

| # | Iteration / question | Hypothesis (falsifiable) | Baseline | Raw results | Outcome | Decision |
|---|---|---|---|---|---|---|
| 1 | OBSERVE: where does memory go? | KV cache is the main serving-memory consumer | — | `results/kv_*.json`, llama logs | KV 56–112 MiB vs repacked weights 597–951 MiB and compute buffer 303 MiB at ctx 2–4k | **FALSIFIED** — weights layout dominates at these contexts |
| 2 | Native ISA build | Compiling for the host ISA raises prefill without changing task decisions | as-found AVX2 build | `results/e0/`, `results/quality/` | prefill 45.9 → 88.0 tok/s (1.5B); decisions identical on 39 items; p50 4.6 → 3.6 s; +9 % memory | **VALIDATED IN SCOPE** |
| 3 | Disable weight repacking | `--no-repack` cuts peak memory ≥ 30 % at acceptable quality | repack on | `results/e1r/`, `results/quality/` | 1,912 → 1,316 MB (−31 %); prefill −24…−32 %; 1 of 39 decisions differs | **VALIDATED IN SCOPE** (memory mode); quality equivalence unproven at n = 39 |
| 4 | Quantisation | Q4_K_M is faster and comparable in quality to Q8_0 | Q8_0 | `results/main/throughput_*`, `results/quality/` | Q8_0 faster (1.5B prefill 1.3×, decode 1.3×; 0.5B prefill 3×); 1.5B quality +0.051 [0.000, 0.128] p = 0.14; memory +59–73 % | **FALSIFIED** (speed) / INCONCLUSIVE (quality) |
| 5 | mmap vs no-mmap | no-mmap reduces peak RSS | mmap | `results/main/load_*` | 1.5B Q4: 2,077 → 1,277 MB peak; private 1,141 → 1,267 MB; load ±0.5 s | **VALIDATED** for peak RSS; mmap's extra pages are reclaimable file cache, so the real-pressure saving is smaller (not measured under pressure) |
| 6 | Prefix caching | Shared prefix avoids most prefill | cache off | `results/main/prefix_1.5b-q4.json` | 1,236 → 33 evaluated tokens; 14.4 → 1.36 s | **VALIDATED** |
| 7 | Cache side channel | Shared prefix cache leaks cross-tenant residency; scoping removes it | shared cache | `results/main/sidechan_1.5b-q4.json` | AUC 1.00 → 0.43 (20 trials) | **VALIDATED IN SCOPE** (both halves); first attempt failed (HTTP 501: erase needs `--slot-save-path`) and was fixed |
| 8 | KV checkpoint restore (B4) | Restore beats recompute | recompute | `results/main/restore_1.5b-q4.json` | 34 ms vs 38.4 s at 3,000 tokens; 82 MB file | **VALIDATED** (speed); confidentiality BLOCKED |
| 9 | Shared mapping (B2) | Two processes on one file share most memory | two independent loads | `results/main/shared_1.5b-q4.json` | PSS 1,607 → 1,435 MB each; 1,128 MB private each | **FALSIFIED** as a major RAM lever with repacking on |
| 10 | Speculative decoding | 0.5B draft speeds 1.5B decode | no draft | `results/main/specdec_1.5b-q4.json` | 11.46 → 10.76 tok/s at 79 % acceptance; +662 MB | **FALSIFIED** on this host; first run invalid (no `cache_prompt` → no speculation), kept as `*_invalid_*` |
| 11 | Adaptive routing | Rules → encoder → SLM-for-multi beats SLM-only per compute-second without losing accuracy | SLM + gate | `results/routing/` | v4 0.872 vs 0.692; 19× correct/compute-s; 2/39 SLM calls | **PROMISING** (exploratory: sets already seen) |
| 12 | Minimal context (B1) | Minimal evidence context cuts prefill without losing correctness | full authorised corpus | cost model from #2/#6 | saving ≤ ~6.6 s/question uncached; largely captured by prefix caching for a static corpus; quality not run | **INCONCLUSIVE** |

## Negative results and errors kept on record

- Speculative decoding run 1 measured nothing (draft loaded, never used).
- Side-channel run 1 crashed (slot erase unsupported without save path).
- Builds produce different greedy text; a text-equality test would have
  rejected a change that is task-equivalent. Regression tests must be
  task-level.
- Major page faults were 0 on "cold" loads; page-fault counting is not a
  usable cold-load metric on this VM.
- The 0.5B model is unusable for the extraction task in all configurations.

## Not run (and why)

GPU experiments (no GPU); energy (no power counters); models > 1.5B (RAM);
concurrency and multi-slot serving; long-context (> 3k) workloads; the brief's
ten enterprise task families beyond extraction; a fresh held-out set for
routing; quality of minimal vs full context.
