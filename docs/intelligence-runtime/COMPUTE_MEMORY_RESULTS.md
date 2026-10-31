# Compute and memory results — integrated runtime

Host: 2 vCPU Xeon (AVX-512, AMX-INT8), 8 GB RAM, no GPU, no power counters.
Metric of record: **cost per correctly completed, authorized task**. Every
figure below comes from the runtime's own per-request cost record (/proc CPU
and RSS per process, tokens, cached tokens, model load) unless marked.

## Cost by strategy (measured in the integrated runtime)

| Strategy | Example | Wall | CPU-s | Model calls | Resident (runtime + helpers) |
|---|---|---|---|---|---|
| E capability | IR acceptance, unseen request | 0.4–0.5 ms | < 0.01 | 0 | 6 MB + sidecar 153 MB |
| A exact rules | single maintenance reading | 1–6 ms | < 0.01 | 0 | same |
| B compact interpreter (TF-IDF) | descriptive report | ~ms | < 0.01 | 0 | same |
| C model extraction (1.5B Q4) | multi-asset report (v5) | 4.6–5.2 s (12.0 s on first use incl. 4.9 s load) | 9–10 (20 on first use) | 1 | + llama 2.1–2.2 GB |
| C grounded QA (1.5B Q4) | document question | 3.8 s (cached prefix) – 14 s (first) | ~24 first | 1 | + llama ~2.2 GB |

## Adaptive vs conventional local inference (fresh hard-reports-v5, 37 items)

| System | Correct | Wrong releases | Model calls | Model CPU |
|---|---|---|---|---|
| Adaptive runtime (held-out run) | 29 | 7 | 0 | 0 |
| Model-only extraction, 1.5B Q4 | 19 | 18 | 37 | wall 3.76 s median per item, 154.7 s total (CPU not recorded by that harness) |
| Model-only + registry gate | 23 | 14 | 37 | same |

Runtime − model-only: +0.27 [0.08, 0.46] (paired bootstrap, p ≈ 0.0005).
Runtime − encoder+gate (no router): +0.00 — on v5 the router's value is that
it avoids the model, not that it beats a good interpreter. The earlier
exploratory 0.872 routing figure did not reproduce (0.784 held-out; 0.811
after the post-inspection router fix).

## Learned capability vs model baselines (ir-tasks-v1)

Per task: capability ≤ 0.01 CPU-s vs 3.2 / 9.1 / 15.9 CPU-s for B1/B2/B3 at
far higher accuracy (29/32 vs 3–5/32). Break-even including the 484 CPU-s
acquisition: 31–151 uses (LEARNING_BENCHMARK.md).

## Memory

- Idle (no model resident): runtime ~6 MB + sidecar ~153 MB.
- With a model: profile-dependent (ARCHITECTURE.md); models load on demand
  and stop after the batch.
- Fixed in this branch: model verification read the whole file into memory
  (runtime 6 → 838 MB); now streamed.

## Correction to earlier compute-memory figures

The compute-memory "cold load" numbers (1–2 s) evicted the model only from
the guest page cache; the host still had it. A real cold read on this VM's
disk runs at **~15 MB/s** (469 MiB in 31.3 s after `drop_caches`), so a cold
1.1 GB model costs ~75 s to load (observed: 78.8 s on the first grounded
request). Loading on demand is cheap only while the file stays in page cache.

## Not measured

GPU seconds/VRAM (no GPU), energy (no counters), concurrent requests
(`serve` is sequential), models > 1.5B, disk I/O per request.
