# Hardware profile (measured 2026-10-31)

| Item | Value | Source |
|---|---|---|
| CPU | Intel Xeon @ 2.10 GHz, **2 vCPU**, 1 thread/core, 1 socket | `lscpu` |
| ISA extensions | AVX2, FMA, F16C, AVX-512F/VBMI/VNNI/BF16, AVX-VNNI, **AMX-INT8** | `/proc/cpuinfo`; llama.cpp native build `system_info` |
| Cache | L1d 48 KiB/core, L2 2 MiB/core, L3 260 MiB reported (virtualised; host value, not a guarantee) | `lscpu` |
| RAM | 8,027 MiB total, ~7.3 GiB available at idle | `free -m` |
| Swap | none | `swapon --show` |
| GPU / accelerator | **none** (`/dev/nvidia*` absent) | |
| Disk | virtio block, 252 GB device, ~26 GB free | `df -h` |
| Kernel | Linux 6.18.44 (Firecracker VM) | `uname -r` |
| THP | `madvise` | sysfs |
| Page faults on cold load | major faults = 0 even with the model evicted from the guest page cache (likely causes, not verified: the loader pre-populates or reads the mapping, and the virtual disk is host-cached), so cold-load times here are optimistic | `/proc/<pid>/stat` |
| Page-cache control | `posix_fadvise(DONTNEED)` on a file works; `/proc/sys/vm/drop_caches` is writable | tested |
| Power instrumentation | **none** (no RAPL exposed in the VM) — energy is not reported anywhere in this workspace | |

## Consequences for the research

1. **Every result here is CPU-only and 2-thread.** No GPU claim — KV paging,
   attention kernels, GPU batching, VRAM — is validated by anything in this
   directory. Brief §8: "Do not claim GPU optimizations have been validated."
2. **Absolute numbers do not transfer.** A customer server (16–64 cores,
   DDR5, possibly a GPU) will differ by an order of magnitude. Only ratios
   measured on the same host under the same load (A vs B) are reported as
   findings, and even ratios can change with core count (decode is
   memory-bandwidth-bound; prefill is compute-bound — they scale differently).
3. **Memory ceiling ≈ 7 GB.** The largest model run here is 1.5B (Q4_K_M
   1.1 GB, Q8_0 1.9 GB). "LLM" in this workspace therefore means "the largest
   model this host can run", not a 7B–70B reasoning model. LLM_EXPERIMENTS.md
   states this in its first line.
4. **Single host.** Multi-node results (BitTorrent) use Linux network
   namespaces with `tbf`-shaped veth links on one kernel. They show protocol
   behaviour (bytes, ordering, resume, integrity) under emulated links, not
   LAN performance.
