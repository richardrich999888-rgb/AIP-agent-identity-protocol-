# YC technical claims — runtime v0.1

Each claim cites the run that supports it. Ownership of reused code and
patents is as recorded in the repository; the SYNTRIASS name changes nothing.

## Claims supported by evidence in this branch

1. **An organisation's confidential procedure can become a reusable,
   validated capability without changing model weights.** After expert
   demonstrations and 7 engineer corrections, a typed capability passed an
   expert-signed 14-case suite, was approved and activated; on 32 unseen
   requests it was right on 29, with 0 false activations on 8 probes
   (LEARNING_BENCHMARK).
2. **It beats conventional local AI on this task by a wide margin at far
   lower cost.** A 1.5B local model alone, with RAG, or with a prompt skill
   library scored 3–5 of the same 32 (paired difference ≥ +0.60, 95 % CI
   excludes 0) at 3–16 CPU-s per task; the capability runs in under a
   millisecond with no model. Break-even including acquisition: 31–151 uses.
3. **Capabilities survive a model change and are re-checked when they
   depend on one.** Replacing the serving model left all 40 outputs
   identical; a model-bound variant was refused until re-validation (8/8).
4. **Adaptive execution beats running a local model on everything** on fresh
   held-out maintenance reports: 29/37 vs 19/37, 7 vs 18 wrong releases, 0
   model calls (+0.27 [0.08, 0.46]).
5. **The system cannot be talked into authority.** Model output never reaches
   routing or authorization; capabilities cannot self-certify (fixed and
   regression-tested), self-approve, or run for another tenant or a lower
   clearance (18 probes, 0 uses); tampering disables them.
6. **Shared-cache leakage is closed in the integrated runtime.** Cross-scope
   cache reuse: 0 in the integrated attack; timing AUC 1.00 → 0.43 in the
   research harness.
7. **Every tested path runs with no network route** and verifies model
   hashes before loading.

## Claims that must not be made

- That it learns new skills autonomously (the local model's drafts all failed).
- Anything about GPUs, large models, energy, or concurrency (none measured).
- That routing itself adds accuracy over a good interpreter (+0.00 on v5).
- Verified or independently observed execution (`CannotProve` everywhere).
- Production readiness, certification or defence-grade security.
- Generality beyond tasks the quantity parser and language already cover.
- Results on customer data (all data is synthetic, single-author).
