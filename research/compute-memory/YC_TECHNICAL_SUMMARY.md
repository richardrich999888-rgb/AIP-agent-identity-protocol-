# YC technical summary — defensible claims only

Every claim below is reproducible from this repository on a 2-vCPU, 8 GB,
no-GPU Linux VM, fully offline. Ownership of the underlying IP is as stated
in the repository's existing notices; nothing here changes it.

## Claims we can make

1. **Structured decisions without trusting a generator.** On 39 hand-written,
   held-out maintenance reports, an exact policy fed by a 33M-parameter
   interpreter and an equipment-registry gate scored 0.821 with 4 wrong
   releases; a 1.5B local LLM with the same gate scored 0.692 with 12 wrong
   releases, and the model itself never abstained (0/13 must-abstain items;
   the gate supplied the 5 abstentions it got). Interpreter latency 57 ms p95
   vs 6.1 s. (Accuracy difference not statistically significant at n = 39;
   wrong-release and cost differences are large.)
2. **Measured, configuration-only efficiency gains on CPU.** Building the
   runtime for the host instruction set doubled prompt processing (45.9 →
   88.0 tok/s) with identical task decisions; a memory profile cut peak
   serving memory 31 % (1,912 → 1,316 MB) at a stated speed cost.
3. **Found and closed a confidentiality leak in shared prompt caching.** With
   llama.cpp's default cache, a co-tenant detects whether another principal's
   confidential prefix is cached with AUC 1.00 (0.16 s vs 8.4 s). Our
   scope-bound cache (model, tokenizer, policy, data snapshot, authorisation
   scope, security domain) reduced it to 0.43 (chance) in the same test, while
   keeping 10.6× prefix-cache speedups within a scope.
4. **Air-gap-native model distribution works with existing components.**
   Emulated 5-node site: 256 MiB package in 48 s instead of 113 s when the
   server link is the bottleneck; every copy hash-verified; a corrupting peer
   poisoned no copy; an unauthorised node received 0 bytes with
   release-scoped certificates (and the whole file without them).

## Claims we must not make

- Anything about GPUs, large models (≥ 7B), "Claude-level" quality, or
  energy savings — not measured.
- LAN or fleet-scale distribution performance — emulated links on one host.
- That routing/cascades are validated — results so far are on data already
  seen.
- Defence-grade or certified security — the isolation results are one
  experiment with 20 trials.

## Demo that is true today

Offline VM, network namespace with no route out:
1. A shift report goes through rules → interpreter → exact policy; an
   unknown asset is refused rather than guessed.
2. The same reports through a local 1.5B model show it inventing values.
3. Side-channel probe against a shared cache (instant hit) vs the scoped
   cache (no signal).
4. Five emulated nodes receive a model package; an intruder gets nothing.

Sources of every number: `research/compute-memory/EXPERIMENT_LEDGER.md`,
`research/system-one/REPORT_ITER2.md`,
`research/bittorrent-p2p/EXPERIMENT_RESULTS.md`.
