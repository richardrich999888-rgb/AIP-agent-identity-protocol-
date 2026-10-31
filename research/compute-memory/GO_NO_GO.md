# GO / NO-GO — compute and memory efficiency (CPU-only evidence)

## Decisions

| Technique | Decision | Evidence | Business effect |
|---|---|---|---|
| Ship llama.cpp built for the target ISA (native / per-ISA builds) | **GO** | prefill 1.9×, task decisions identical (39 items) | same hardware answers faster; zero model risk; needs task-level regression per build |
| Two documented serving profiles: *speed* (repack on) and *memory* (`--no-repack`, or `--no-mmap`) | **GO** | −31…−38 % peak memory, or +92 % prefill | lets one product fit 8 GB-class machines or exploit larger ones |
| Prefix caching **with scope-bound isolation** (`cachescope`) | **GO** (research → product) | 10.6× latency on shared prefixes; timing leak AUC 1.00 → 0.43 | the largest latency win measured; unsafe without isolation |
| Default to Q8_0 over Q4_K_M on hosts with memory headroom | **GO, conditional** | faster on this CPU; quality ≥ Q4 (not significant) | contradicts common practice; re-measure on each customer CPU class |
| Rules → compact interpreter → SLM escalation | **PROMISING → fresh held-out test before building** | 0.872 vs 0.692, 19× correct/compute-s (seen data) | biggest potential cost lever; unproven on unseen data |
| KV checkpoint save/restore | **NO-GO until encrypted and scope-bound** | 1,100× faster restore, but files are confidential derived data | recovery after interruption; must not create a leak |
| Speculative decoding on small CPU hosts | **NO-GO** | −6 % decode, +662 MB | none here; re-test on many-core or GPU hosts |
| Content addressing / Merkle structures for RAM savings | **NO-GO** | mmap already shares the shareable part | keep for distribution and snapshot IDs only |
| Minimal verifiable context | **INCONCLUSIVE** — run full-vs-minimal quality test | cost model only | likely small for static corpora once caching is on |
| A new model or inference protocol | **NO-GO** | every win came from configuration of existing tools | — |

## Final scientific questions

1. **Compute- vs memory-bound.** Prefill is compute-bound (doubles with the
   native ISA, 45.9 → 88.0 tok/s). Decode is memory-bandwidth-bound (10–11
   tok/s across builds; rises only with formats the kernels stream better —
   Q8_0 13.9). Serving *capacity* is memory-bound: weights and their repacked
   copy, not KV, dominate at ≤ 4k context.
2. **Existing methods that already solve the bottlenecks.** ISA-specific
   builds, llama.cpp repack/mmap flags, Q8_0, prefix caching. All existing;
   the only gap found was cache isolation (Gu et al. document the threat;
   llama.cpp ships no scoping).
3. **Best SLM configuration for limited memory.** For structured
   interpretation: not a generator — the 33M encoder + registry gate (0.821,
   ~0.75 GB, 57 ms). If a generator is required on ≤ 8 GB: 1.5B Q4_K_M,
   native build, `--no-repack` (~1.3 GB peak, 0.667 gated on v4).
4. **Best "LLM" configuration for offline reasoning (on this host).** 1.5B
   Q8_0, native build, repack on, prefix cache scoped per principal: best
   quality (0.744 gated) and lowest latency (2.3 s p50) at 3.3 GB. Nothing
   here measures real complex reasoning; larger models were not runnable.
5. **When cooperation beats a single larger model.** When a cheap
   deterministic signal routes most traffic away from the large model and the
   large model is loaded on demand or memory is plentiful (exploratory: 2/39
   escalations, 19× efficiency).
6. **When multiple resident models cost more than they save.** Encoder + 1.5B
   resident ≈ 2.8 GB vs 2.1 GB for the 1.5B alone; speculative decoding's
   resident draft added 662 MB and slowed decode. Resident co-models lose on
   memory-limited hosts unless they remove most large-model calls.
7. **Benefit by technique (this host).** Native ISA: 1.9× prefill. Q8_0 vs
   Q4: 1.3–3× speed, +59–73 % memory. `--no-repack`/`--no-mmap`: −31…−38 %
   memory, −24…−32 % prefill. Prefix caching: 10.6× on shared prefixes.
   Attention/KV management: negligible at ≤ 4k context (KV ≤ 112 MiB).
8. **Minimal verifiable context.** Not established: saving ≤ ~6.6 s per
   uncached question for this corpus, mostly captured by prefix caching;
   answer quality untested.
9. **Useful blockchain-derived ideas.** Version-bound state keys with
   invalidation (B3, validated); snapshot roots as cache/source identifiers;
   checkpoints (B4, fast but blocked on confidentiality). Not useful: content
   addressing for RAM, any ledger or consensus.
10. **Authenticated BitTorrent-style distribution.** Improves rollout only when
    the distribution server's link is the bottleneck (48 s vs 113 s emulated);
    slower when it is not (28.5 s vs 23.1 s); always saves source egress.
    Optional component, never an inference optimisation
    (`research/bittorrent-p2p/GO_NO_GO.md`).
11. **Failed experiments.** KV-dominates hypothesis; Q4-faster hypothesis;
    speculative decoding; shared-mapping RAM savings; first speculative and
    side-channel runs (invalid, kept); 0.5B generator for extraction.
12. **Techniques that improve correct-task throughput.** Routing structured
    work away from the generator (exploratory 19×); native ISA build (same
    decisions, −22 % latency); Q8_0 on this CPU (−36 % p50 vs Q4 native, ≥
    quality); prefix caching for shared-prefix workloads.
13. **Unvalidated for lack of hardware.** Everything GPU (paged KV, batching,
    attention kernels, VRAM), speculative decoding on many-core/GPU, models
    ≥ 7B, energy per answer, multi-socket memory bandwidth, real LAN
    distribution, concurrency.
14. **Build vs reuse.** Reuse: llama.cpp (with documented build and flag
    profiles), libtorrent, existing quantised models, sentence encoders.
    Build: `cachescope` isolation layer and its llama-server adapter, routing
    policy with escalation signals, task-level regression harness per build,
    encrypted scope-bound checkpoint storage, release manifest for
    distribution.
15. **What can truthfully be shown to YC.** See YC_TECHNICAL_SUMMARY.md.

## Ultimate question

*Can SYNTRIASS deliver high-quality private AI with substantially less
compute and memory than conventional self-hosted AI?* For **structured
decisions**, the evidence on this host says yes in scope: deterministic logic
plus a compact interpreter matched or beat a 1.5B generator at ~100× lower
latency and ~2.5× lower memory, with fewer wrong releases. For **open-ended
reasoning**, nothing here answers it: no model capable of such reasoning ran,
and no GPU was available.
