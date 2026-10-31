# SLM experiments — Qwen2.5-0.5B (CPU, 2 threads, native build, ctx 4096)

## Compute and memory

| Config | Prefill @128 / @1.5k tok/s | Decode tok/s | Peak RSS MB | Private MB | File-backed MB |
|---|---|---|---|---|---|
| Q4_K_M | 169 / 129 | 28.4 | 752 | 400 | 335 |
| Q8_0 | **501 / 339** | **43.3** | 1,262 | 734 | 511 |
| Q4_K_M, as-found AVX2 build | 99 (prompt ≈ 300) | 22.9 | 624 | — | — |

| Load (median of 2) | mmap cold | mmap warm | no-mmap cold | no-mmap warm |
|---|---|---|---|---|
| Q4_K_M: seconds / peak RSS MB | 0.97 / 754 | 0.47 / 754 | 0.83 / 606 | 1.01 / 606 |
| Q8_0 | 1.10 / 1,264 | 0.62 / 1,264 | 1.81 / 824 | 0.83 / 824 |

"Cold" = file evicted from the guest page cache with `posix_fadvise(DONTNEED)`
(verified with `mincore`: 0 % resident). Major page faults were 0 in every
cold run (the loader populates the mapping up front; the virtual disk is
likely host-cached), so cold-load figures are optimistic for real disks.

## Quality (System One held-out v4, 39 items)

| Config | Decision acc | With registry gate | Wrong releases (gated) | p50 latency |
|---|---|---|---|---|
| Q4_K_M, as-found build (iteration 2) | 0.205 | — | 31 (ungated) | 2.0 s |
| Q4_K_M, native | 0.179 | 0.308 | 27 | 1.35 s |
| Q8_0, native | 0.154 | 0.282 | 28 | 0.69 s |

## Findings

1. **8-bit is faster than 4-bit on this CPU** (prefill 2.6–3.0×, decode
   1.5×). Likely explanation, **not verified by profiling**: k-quant
   dequantisation costs more than the bandwidth it saves at this size, and
   Q8_0 maps onto the native build's VNNI/AMX integer paths. Either way it
   falsifies "smaller quantisation = faster" on this host. Cost: +68 % peak
   memory.
2. **The 0.5B model is not usable for this extraction task in any
   configuration** (≤ 0.31 with the gate, ≥ 27 wrong releases of 39). Faster
   kernels do not fix a capability gap.
3. For limited-memory customers the right "small model" for structured
   interpretation is not a 0.5B generator: the 33M-parameter encoder + gate
   reached 0.821 at 755 MB process memory and 57 ms p95 (iteration 2).
