# Prior art and established alternatives

Only facts read from the cited source are stated as facts.

| Area | System | What it already does | Consequence for SYNTRIASS |
|---|---|---|---|
| P2P model distribution | **Dragonfly** (CNCF Graduated) [1] | Splits files into pieces shared among cluster peers; `hf://` and `modelscope://` schemes; describes air-gapped/edge use with a seed peer preloaded from staging | "BitTorrent for models" exists. Do not build a new protocol. Open: the source does not discuss per-piece integrity against a signed manifest; its 99.5 % origin-traffic figure is a calculated scenario, not a measurement |
| Distributed inference | **Petals** [2] | Llama-2-70B at 2.29 steps/s on 3×T4 over 1 Gbit/s; 1.57 at 100 ms RTT; local 3×A100 NVLink 2.46; "degrades with higher latency"; servers on early blocks "may use their inputs to recover client data" | Partitioning helps only versus offloading on GPUs too small for the model. Partitions leak inputs, so confidential data needs every partition inside the same trust domain |
| Distributed inference | llama.cpp RPC backend; Megatron/DeepSpeed pipeline and tensor parallelism | Established model-sharding mechanisms | No new mechanism needed if C is ever pursued |
| Typed decisions | **Jev** (TypeSafe; hosted, undisclosed) [3] | Single-pass typed choice/score/yes-no; vendor says not a calculator | Interface reference only |
| Typed decisions | **Kev** (Apache-2.0) [4][5] | Prefill-only backbone + LoRA + pointer head; packed questions; OOD Brier 0.328 (kev-4b) vs Jev 0.211 on shared items | Open baseline for decision heads |
| Compact extraction | **GLiNER** [6] | Bidirectional-encoder NER that takes entity types as input at inference (generalist, small) | Direct prior art for "compact model extracts arbitrary typed fields". A new extraction head must beat or match it to matter |
| LLM-emits-arguments, code evaluates | Function calling / tool use; semantic parsing; slot filling | Model fills a schema, program executes | IL-001's core idea is established; any novelty would be narrow |
| Retrieval | BM25, dense retrieval, hybrid, cross-encoder reranking, RAG | Standard | Sovereign slice uses BM25 (SQLite FTS5); no claim of retrieval novelty |
| Evidence | SPIFFE/SPIRE, Sigstore, in-toto, Tetragon/Falco, auditd | Workload identity, signed provenance, runtime observation | AIP already cross-checks against SPIRE, bpftrace and auditd (STATUS.md on release-completion-loop) |

## Where a narrow novelty claim might survive (unsearched; needs a patent professional)

Binding (a) an interpretation-uncertainty distribution, (b) a signed versioned
policy, (c) retrieved-evidence references and (d) an AIP authorisation and
reconciliation record into one offline-verifiable decision record. Each part
has prior art; the combination has not been searched.

[1] https://www.cncf.io/blog/2026/04/06/peer-to-peer-acceleration-for-ai-model-distribution-with-dragonfly/
[2] https://arxiv.org/html/2312.08361
[3] https://nexos.ai/blog/what-is-jev/
[4] https://github.com/jaredpalmer/kev/blob/main/README.md
[5] https://huggingface.co/jaredpalmer/kev-0.8b
[6] https://arxiv.org/abs/2311.08526
