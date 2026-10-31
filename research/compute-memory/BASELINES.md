# Baselines — unmodified configurations, reproducible

Every optimisation in this directory is compared against these. Host:
HARDWARE_PROFILE.md. Tables regenerate with `python3 tools/summarize_main.py`
(output: `results/TABLES.md`).

## B0 — serving runtime as found

| Item | Value |
|---|---|
| Runtime | llama.cpp `llama-server`, vendored in llama-cpp-python 0.3.16 (sdist sha `34ed0f9b…`) |
| Build as found | `build-llama/`: Release, `GGML_NATIVE=OFF` → **AVX2 only** (AVX-512, VNNI, AMX unused) |
| Candidate build | `build-llama-native/`: same source, `GGML_NATIVE=ON` → AVX-512, AVX-512 VNNI/BF16, AVX-VNNI, **AMX-INT8** |
| Defaults | mmap on, weight repacking on, 2 threads, f16 KV cache, 1 slot, greedy decoding |
| Offline | every run inside `bench/offline.sh` (user+net namespace, loopback only; refuses to run if an external route exists) |

## Models (SHA-256 pinned in `bench/run_all.sh`, verified against Hugging Face LFS etags)

| File | Size | Params | KV bytes/token (f16) | SHA-256 |
|---|---|---|---|---|
| qwen2.5-0.5b-instruct-q4_k_m.gguf | 469 MiB | 0.63 B | 12 KiB | `74a4da8c…` |
| qwen2.5-0.5b-instruct-q8_0.gguf | 644 MiB | 0.63 B | 12 KiB | `ca59ca7f…` |
| qwen2.5-1.5b-instruct-q4_k_m.gguf | 1,066 MiB | 1.78 B | 28 KiB | `6a1a2eb6…` |
| qwen2.5-1.5b-instruct-q8_0.gguf | 1,807 MiB | 1.78 B | 28 KiB | `d7efb072…` |

The 0.5B "Q4_K_M" file is mostly Q5_0/Q8_0 tensors (GGUF metadata); its name
overstates its compression.

## Baseline numbers (as-found build, 1.5B Q4_K_M, ctx 4096)

| Metric | Value |
|---|---|
| Prefill at 1.5k tokens | 45.9 tok/s |
| Decode | 10.6 tok/s |
| Peak RSS (serving, after requests) | 1,912 MB (843 private + 1,069 file-backed) |
| Held-out extraction (System One v4, 39 items) | 0.564 decision accuracy, 17 wrong releases; with registry gate 0.692 / 12 |
| Extraction latency p50 / p95 | 4.6 s / 6.1 s |

Non-LLM baselines (System One iteration 2, same 39 items): exact rules 0.538
/ 0 wrong; TF-IDF + gate 0.795 / 4; bge-small encoder + gate 0.821 / 4.

## Workloads used

| Workload | Purpose | Source |
|---|---|---|
| Synthetic seeded report text, exact token counts (128–3,000) | prefill/decode rates, cache experiments | `bench/profile.py` (seed 20261031) |
| System One hard-reports-v4 (39 hand-written items, sha `fba32fd2…`) | task quality per configuration | `research/system-one` |

Not covered (brief §10 lists ten task families): multi-document reasoning,
long-context summarisation, source-code understanding, tool workflows, and
any task that genuinely needs a model larger than 1.5B. This host cannot run
such a model, so no "LLM necessary" workload exists here.
