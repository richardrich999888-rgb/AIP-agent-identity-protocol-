# Prior art — where compute and memory go in local inference, and who already solved it

Purpose: before building anything, record what established projects already
do, so SYNTRIASS reuses rather than reinvents. Entries marked **[used here]**
were exercised in this workspace; others are literature only.

## 1. Weights in memory

| Technique | What it does | Established implementation | Limits |
|---|---|---|---|
| mmap of weights **[used here]** | weights are file-backed pages; load is lazy, pages are shared across processes and evictable | llama.cpp default (`--no-mmap` to disable) | first request pays page faults; under memory pressure weights are evicted and re-read (latency cliff) |
| Weight quantization **[used here]** | 2–8-bit blocks with scales; less memory and bandwidth per token | llama.cpp k-quants (Q4_K_M, Q5_K, Q6_K, Q8_0), GPTQ, AWQ | quality loss is task-dependent; "Q4_K_M" files are mixed-precision (measured: the 0.5B file is mostly Q5_0/Q8_0) |
| mlock | pin weights in RAM | llama.cpp `--mlock` | needs RLIMIT_MEMLOCK; removes the eviction cliff, removes sharing benefits under pressure |

## 2. Attention state (KV cache)

| Technique | What it does | Implementation | Limits |
|---|---|---|---|
| Grouped-query attention | fewer KV heads → smaller cache | model architecture (Qwen2.5: 2 KV heads) | fixed by the model; nothing to build |
| KV-cache quantization | 8/4-bit K and V | llama.cpp `-ctk/-ctv q8_0/q4_0`; KIVI (arXiv 2402.02750) | quality impact on long context |
| PagedAttention | KV in fixed blocks, no fragmentation, block sharing | vLLM (Kwon et al., SOSP 2023, arXiv 2309.06180) | GPU serving; benefit is concurrency/batching, small at batch 1 |
| Prefix caching **[used here]** | reuse KV of an identical prompt prefix | llama.cpp `cache_prompt`, vLLM automatic prefix caching, SGLang RadixAttention (arXiv 2312.07104) | only exact token-prefix matches; **shared across users by default** (see §4) |
| KV save/restore **[used here]** | persist a slot's KV to disk and reload | llama.cpp `--slot-save-path`, `/slots/N?action=save|restore` | the file is derived confidential data (prompt can be recovered/probed); no built-in encryption or scoping |

## 3. Arithmetic per useful answer

| Technique | What it does | Implementation | Limits |
|---|---|---|---|
| Speculative decoding **[used here]** | small draft proposes tokens; large model verifies in one batch; lossless at greedy | llama.cpp `-md`; Leviathan et al. (ICML 2023, arXiv 2211.17192); Chen et al. (arXiv 2302.01318) | needs shared tokenizer; on CPU with few cores the verification batch is not free |
| Model routing / cascades | answer with a cheap model, escalate when needed | FrugalGPT (Chen et al., arXiv 2305.05176); RouteLLM (Ong et al., arXiv 2406.18665) | router quality caps savings; multiple resident models cost memory |
| Exact logic instead of generation **[used here, System One]** | deterministic code makes the decision; models only interpret text | conventional software engineering | only for decisions that have a specification |
| Compact interpreters **[used here, System One]** | small encoder + head instead of generative extraction | sentence-transformers, GLiNER (arXiv 2311.08526) | no multi-step reasoning |

## 4. Cache safety

| Finding | Source |
|---|---|
| Shared prompt caches create a **timing side channel**: an attacker can detect that another user sent a given prefix; audits found global cache sharing in several commercial APIs | Gu et al., "Auditing Prompt Caching in Language Model APIs", ICML 2025 ([ICML](https://icml.cc/virtual/2025/poster/44473), [mlanthology](https://mlanthology.org/icml/2025/gu2025icml-auditing)) |
| Mitigation used by providers: scope cache sharing per organisation | same paper (provider responses) |

This workspace reproduces the side channel on llama.cpp and measures a
scoped-cache mitigation (CACHE_SECURITY.md).

## 5. Distribution vs execution

| Idea | Prior art | Relevance |
|---|---|---|
| Chunked P2P model distribution | BitTorrent BEP 3/52; Dragonfly (CNCF) for container images and models | install/update only — does not reduce inference compute or RAM |
| Distributed inference over peers | Petals (Borzunov et al., arXiv 2209.01188) | latency-bound; layer holders see activations (input recoverable); **out of scope** |

## 6. Blockchain-derived state techniques

Merkle trees and authenticated data structures (Merkle 1987), content-addressed
storage (Git, IPFS, OCI registries), state witnesses and stateless clients
(Ethereum research), snapshots and checkpoint sync. Assessed against measured
problems in BLOCKCHAIN_INSPIRATION.md. None requires a ledger or consensus for
a single organisation.

Sources: arXiv IDs above; [RouteLLM](https://arxiv.org/abs/2406.18665v4).
