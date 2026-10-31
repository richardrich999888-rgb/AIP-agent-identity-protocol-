# Blockchain-inspired state techniques — what solved a measured problem

Rule applied: a technique is kept only if it addresses a measured state,
storage, verification or synchronisation problem. No ledger, token or
consensus mechanism was introduced; none was needed for a single
organisation.

| ID | Hypothesis | Borrowed concept | What was measured | Verdict |
|---|---|---|---|---|
| B1 | Minimal verifiable context reduces prefill without losing evidence | state witness: carry only what the decision needs, plus a commitment to the full state | Cost model only: 1.5B prefill costs ~11 ms/token here (88 tok/s @1.5k), so dropping 600 of ~900 corpus tokens saves ~6.6 s per uncached question. **Competing measured effect: prefix caching** cuts a stable 1,203-token prefix to 33 evaluated tokens (10.6×), so for a static authorised corpus, caching captures most of B1's saving without omitting anything. Answer quality with full vs minimal context **not measured**. | **INCONCLUSIVE** |
| B2 | Content-addressed sharing avoids duplicate model memory/storage | content addressing, Merkle roots | Two llama-servers mapping one GGUF: file-backed pages shared (PSS 1,607 → 1,435 MB per process), but **1,128 MB per process is private** (repacked weights, KV, compute buffers) and cannot be shared by any addressing scheme. On disk, identical files already deduplicate by path/hardlink; BEP 52 roots give identical files identical IDs for distribution (BitTorrent work). | **VALIDATED IN SCOPE for storage/distribution; FALSIFIED as a RAM lever** (mmap already shares what is shareable; repacking defeats it; `--no-repack` raises the shareable fraction) |
| B3 | Version-bound cache with invalidation reuses compute safely | versioned state roots, invalidation on root change | `cachescope`: key over model, tokenizer, policy, snapshot, scope, domain; cross-scope timing probe AUC 1.00 → 0.43 | **VALIDATED IN SCOPE** (single slot, 20 trials) |
| B4 | Checkpoints reduce recomputation after interruption | state snapshots / checkpoint sync | Slot save/restore: 3,000 tokens restore in 34 ms vs 38.4 s recompute (~1,100×); 82 MB per checkpoint (28 KiB/token, matches kvcalc); file was page-cache-warm, so cold-disk restore is slower | **VALIDATED for speed; confidentiality BLOCKED** until checkpoints are encrypted and scope-bound (CACHE_SECURITY.md §3) |

## What cryptography adds and what it does not

- A Merkle root over the authorised corpus snapshot is a good `source_snapshot`
  field for B3: it changes exactly when content changes, and supports
  proving that a cited passage belongs to the snapshot.
- Inclusion proves membership, **not relevance, completeness or truth**
  (brief §6). B1's sufficiency question is an evaluation problem, not a
  cryptographic one.
- Hash-chained evidence of what context and model produced an answer belongs
  to the existing AIP evidence work; nothing here replaces it.
