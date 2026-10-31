# "LLM" experiments — Qwen2.5-1.5B (the largest model this host can run)

**Scope warning.** 1.5B is not a large language model by any current
standard. Everything here is "the bigger of two small models on 2 CPUs". No
result transfers to 7B–70B models or to GPUs without re-measurement.

## Where memory goes (KV arithmetic verified against llama.cpp's allocation)

| Component (Q4_K_M, ctx 4096) | MiB | Source |
|---|---|---|
| Weights, file-mapped | 1,060 (877 after native repack) | llama log `CPU_Mapped` |
| Weights, repacked private copy | 597 (AVX2 build) / 951 (native AMX) | llama log `CPU_REPACK` / `AMX` |
| KV cache, f16 | 112 (= 28 KiB × 4,096) | `tools/kvcalc.py`; log matches exactly |
| Compute buffer | 303 | llama log |

At this context length the **repacked weight copy and the compute buffer
each exceed the KV cache** (5–8×). KV only dominates beyond ~20k tokens
(28 KiB/token → 896 MiB at 32k). KV-cache optimisation is therefore not the
lever on this hardware at these contexts; weight layout is.

## Compute / memory configurations (1.5B Q4_K_M, ctx 4096)

| Config | Prefill @1.5k | Decode | Peak RSS MB | Private MB |
|---|---|---|---|---|
| as-found build, repack (baseline) | 45.9 | 10.6 | 1,912 | 843 |
| as-found build, `--no-repack` | 31.2 | 9.5 | **1,316** | 247 |
| **native build, repack** | **88.0** | 11.0 | 2,086 | 1,198 |
| native build, `--no-repack` | 35.1 | 10.1 | **1,318** | 247 |
| native, Q8_0, repack | 118.1 | 13.9 | 3,613 | 1,995 |
| native, `--no-mmap` (load profile) | — | — | 1,277 | 1,267 |

Decode is nearly flat across builds (10–11 tok/s): it is bound by streaming
weights through memory per token, not by arithmetic. Prefill is compute-bound
and doubles with the native ISA.

## Quality (System One held-out v4, 39 items, registry gate applied)

| Config | Decision acc | Wrong releases | p50 / p95 s | Peak RSS MB |
|---|---|---|---|---|
| as-found build, repack (iteration 2) | 0.692 | 12 | 4.6 / 6.1 | 1,827 |
| native, repack | 0.692 (item-for-item identical) | 12 | **3.6 / 5.2** | 2,076 |
| either build, `--no-repack` | 0.667 (1 item differs) | 13 | 5.7–6.0 / 8.4–8.5 | **1,231–1,234** |
| native, Q8_0 | 0.744 (+0.051 [0.000, 0.128], p = 0.14 vs Q4) | 10 | **2.3 / 3.6** | 3,304 |

Greedy *text* differs between builds (different kernels, different float
rounding), yet task decisions were identical for the native build. Any build
change therefore needs a task-level regression run, not a text diff.

## Speculative decoding (1.5B target, 0.5B Q4 draft, draft-max 8)

| Mode | Decode tok/s | Draft tokens accepted | Peak RSS MB |
|---|---|---|---|
| no draft | 11.46 | — | 2,074 |
| draft | 10.76 (**−6 %**) | 199 / 251 (79 %) | 2,736 (+662) |

**FALSIFIED on this host**: 79 % acceptance still loses, because verifying a
batch of drafted tokens is not free on 2 cores and the draft model competes
for the same cores and memory bandwidth. Outputs were not identical to plain
greedy decoding (0/3) — batched verification changes float rounding. First
run was invalid (llama-server only speculates when `cache_prompt` is true;
kept as `results/main/specdec_1.5b-q4_invalid_no_cache_prompt.json`).

## Prefix caching (1,203-token shared prefix + 33-token suffix)

| | Evaluated tokens | Prefill ms | Wall s |
|---|---|---|---|
| cache off | 1,236 | 13,623 | 14.39 |
| cache on (requests 2..n) | **33** | **668** | **1.36** (10.6×) |

The largest single latency lever measured, and the one with a security cost
(CACHE_SECURITY.md).
