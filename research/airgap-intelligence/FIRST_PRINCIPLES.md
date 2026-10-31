# Fundamental bottlenecks and challenged assumptions

## Bottlenecks (in the order they limit a customer outcome)

1. **Interpretation quality on the customer's real text.** Unmeasured. Every
   number in this repository comes from synthetic data written by the same
   party that built the system. P0 of iteration 2 found the "paraphrase" split
   solvable by a 10-line (equipment, unit) rule — evidence that our own test
   design is a bottleneck.
2. **Compute per useful answer on CPU-only hosts.** Measured: Qwen2.5-1.5B Q4
   on 2 vCPU costs ~1–9 s and 1.8 GB per request. Whether cheaper interpreters
   suffice is the iteration-2 experiment.
3. **Coverage under strict grounding.** Phase A: 0 wrong released answers but
   4/6 coverage on the original six. Safety and helpfulness trade off, and the
   trade has not been measured on realistic questions.
4. **Trust boundaries.** The sovereign slice collapses decision point, runner
   and agent into one process and one uid; independent observation exists in
   AIP but is not integrated.
5. **Network/memory movement** (only relevant for P2P C): per-token activation
   transfer across machines; Petals data says latency dominates.

## Assumptions challenged

| Assumption | Challenge | Current evidence |
|---|---|---|
| Small models can replace large ones | They interpret narrow inputs; they did not reason (1.5B: "103 C is above 105 C") | Against, for decisions |
| A neural extraction head beats a conventional classifier | TF-IDF+LR reached 0.90 at 2 ms; a (equipment, unit) rule 1.00 on the same split | Untested on hard inputs |
| P2P reduces cost | A single internal artifact server may suffice; Dragonfly already exists | No measurement |
| Distributed inference uses idle workstations | Latency-bound; inputs leak to early partitions | Against (Petals) |
| Signed evidence proves execution | Proves who signed what; observation needs an independent sensor | Slice reports CannotProve correctly |
| Retrieval makes answers trustworthy | Citation ≠ entailment; poisoned authorised documents pass (Phase A hi3) | Partly against |
| A cascade saves compute | Only if cheap layers answer most traffic | Traffic mix unknown |

## What would falsify the core thesis

If, on independently written inputs, a single 1.5–4B model with ordinary
retrieval matches the cascade's correct-answer rate at equal or lower total
compute, the multi-layer architecture is not justified for that workload.
