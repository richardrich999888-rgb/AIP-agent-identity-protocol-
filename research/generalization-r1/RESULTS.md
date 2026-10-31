# Findings: a falsification result, not a breakthrough

## Existing technology and reproducibility

Starting remote commit: `2883da7bf5b8591a31bf24789c1d0722f83a6624` on `feature/syntriass-runtime-v02`. New isolated branch: `research/syntriass-generalization-r1-20261031`. Dataset/protocol freeze commit: `d44a3ee`. No production runtime, authorization, isolation or seven-scene demonstration files were changed.

The existing system supplies approved executable capabilities, strongest-fit routing, signed measurement records, local inference and lifecycle controls. Source inspection covers the recent first-principles/runtime history recorded in `results/baseline/source-history.txt`; it is not an exhaustive independent audit of every repository component.

- Regenerated IR/battery/transformer dataset manifests match their original manifests exactly.
- Strongest-fit routing reproduced **117/130** exact decisions. This combines validation and unseen sets and is consumed, not an untouched holdout.
- Historical signed-record experiment reproduced. Its missing-record hypothetical arm is not evidence of robustness with irrelevant but valid signed records.
- Null-model acquisition reproduced **NEEDS_EXPERT_CLARIFICATION in all three families**. These artifacts still require expert work. Stub `model_calls` are not actual model inference.
- Relevant Rust tests: **165 passed, 20 failed** across the runtime and Sovereign packages. One metering test and 19 agent-execution tests fail on unavailable `/proc/<pid>/stat` process identity in this host. Release build succeeds. No security check was weakened to obtain a pass.
- All research Python tests including this addition: **116 passed**. A new module-name collision initially broke collection; renamed the module and preserved both failure and successful logs.
- **42 signed-case outputs replayed** through the real Rust checker. Offline signature verification is demonstrated at this checker boundary; independent kernel observation and agent tool execution are not demonstrated by this round.
- GitHub Actions API reported **zero runs for the starting SHA**, captured in `results/baseline/ci.json`; that is not CI approval. No workflow was manually triggered.

## Experiment 1: signature versus relevant evidence

Seven existing gold-PASS examples per group, with synthetic cryptographically signed records:

| Case | Current checker PASS | Explicit binding baseline PASS |
|---|---:|---:|
| Valid context | 6/7 | 6/7 |
| Hypothetical request | 6/7 | 0/7 |
| Wrong asset | 6/7 | 0/7 |
| Stale timestamp | 6/7 | 0/7 |
| Cross-tenant record | 0/7 | 0/7 |
| Modified after signing | 0/7 | 0/7 |

The batch took **3.46 ms wall time**, including process invocation. This small correlated synthetic set is a counterexample, not a rate estimate for enterprise traffic. One valid example already fails to PASS in both methods. No unsafe tool was executed.

**Conclusion:** the stronger interpretation “signature establishes actual relevant evidence” is falsified. It authenticates an attestation. Conventional typed request/asset/freshness binding blocks these tested cases, but only if its context is trustworthy. The prototype does not infer or authenticate the user's intent. Record truth, instrument compromise, clock trust, replay and request authorization remain separate problems. This baseline is not original IP.

## Experiment 2: warehouse uncertainty and composition

New non-electrical family, frozen before implementation: 280 synthetic evaluation cases, 42 development cases, single author. Policies compose stock/capacity availability and shipment weight constraints. Typed alternatives are supplied; no natural-language extraction or learned composition is claimed.

| Method | Exact correct /280 | Correct answers | Wrong answers | Correct abstentions | Missed answerable | Median batch CPU |
|---|---:|---:|---:|---:|---:|---:|
| First-value execution | 189 | 69 | 91 | 120 | 0 | 0.115 ms |
| Refuse all ambiguity | 211 | 0 | 0 | 211 | 69 | 0.110 ms |
| Full enumeration | 280 | 69 | 0 | 211 | 0 | 55.389 ms |
| Short-circuit enumeration | 280 | 69 | 0 | 211 | 0 | 3.055 ms |
| Interval endpoints | 280 | 69 | 0 | 211 | 0 | 1.481 ms |

Table timing is the preserved control run, 30 rotating-order batches. Initial full-enumeration run is also retained. Interval/full-enumeration quality agrees on every example; exhaustive property test additionally covers 4096 small combinations. This is a narrow tested function, not a formal proof of arbitrary program soundness.

Exact accuracy Wilson 95% interval is **98.65–100%** for 280/280. Supported-answer precision is 69/69, Wilson **94.73–100%**. Answer coverage is **24.64%**, far below an 80% product target. Correct abstentions are scored only according to the frozen gold policy. The conservative baseline is weak because capacity/weight remain ambiguous; do not use it as the sole comparator.

Short-circuit/interval paired bootstrap mean CPU ratio: **2.02–2.22× (95%)**. This is a same-host, consumed-data diagnostic, not a confidence interval for real-world workload transfer. The initially larger ~40× ratio against full enumeration is a weak-baseline effect. Both are established algorithms; an optimized conventional interval solver is the candidate itself. **No novel algorithmic advantage survives that comparison.**

Initial process peak RSS: **16,272 KiB** for the complete Python benchmark. This is not per-method memory, not peak local-model memory, and establishes no 50% or 5× memory reduction. Energy and human effort are unmeasured. Independence of alternatives and monotone predicates are essential; endpoint reasoning is not sound for arbitrary non-monotone rules and can lose precision when correlations matter.

## Experiment 3: local stronger-model diagnostic

Official Qwen3-4B Q4_K_M, revision `bc640142c66e1fdd12af0bd68f40445458f3869b`, SHA256 `7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5`. llama.cpp source bundled in pinned llama-cpp-python 0.3.16; source SHA in `stage_model.sh`. CPU only, eight threads, context 4096, temperature zero, max 32 completion tokens, thinking disabled. Official model metadata declares Apache-2.0. Hardware: 8 CPU quota, 8 GiB cgroup memory; exact CPU/platform recorded in `hardware.json`.

Initial direct, supplied-policy RAG and structured-skill arms each ran the first 70 frozen examples. Every output abstained. After separately stripping only the empty `<think>` transport wrapper, each scored **50/70**, **zero answer coverage**. Strict unnormalized format score was **0/70** in every arm. All outputs are retained; no label searching or gold-dependent correction was used. Direct P50/P95 wall latency was **1.056/1.310 s**, structured skill **1.069/1.293 s**. RAG timing and all token counts are in normalized-summary.json.

Combined initial server high-water RSS was **4,826,824 KiB (~4.60 GiB)**; combined child CPU **1816.32 s**, including loading and all three arms. This is not separate memory/CPU attribution per prompt method. The server and client were in the same execution environment and used loopback. No process-tree egress audit or physically disconnected install was performed.

A conventional three-example few-shot prompt was then tested on 14 development cases: 9/14 normalized correct, five answers of which only one correct, four incorrect SHIP decisions. The unchanged prompt was replayed on the consumed evaluation subset as a diagnostic, with results recorded separately. It is not an independently confirmed tuned model. Final subset result: **61/70** normalized correct, **18 answers, 13 correct answers**, **5 incorrect SHIP decisions**; P50/P95 **1.137/1.424 s**. Its separate server peak RSS was **4,853,668 KiB**, child CPU **655.82 s**. The added prompt does not meet the quality target.

No strong matched-quality inference efficiency claim follows: the model modes fail useful answer quality, the deterministic methods consume manually specified typed evidence, and timing inputs differ in representation. Retrieval cost was excluded, no experience-memory learner or fine-tuning baseline was executed, and this is not a comprehensive prompt/server optimization study. No 7B, GPU, concurrency, energy or frontier-level result is claimed.

## Decision and customer implications

**Survives within scope:** approved typed procedures can run locally; interval semantics can avoid unnecessary enumeration; explicit evidence binding prevents the tested irrelevant-record decisions.

**Falsified:** signatures alone establish relevant present measurements; a large speed ratio versus naive enumeration establishes invention; these 4B prompts provide adequate task quality.

**Unresolved:** semantic generalization, autonomous acquisition, learned composition, expert-time savings, amortized capability economics, memory scaling, cross-model retention and strong-model optimized comparisons.

Use conventional interval evaluation where its assumptions are proved or explicitly checked. Pursue request/evidence binding as a separately reviewed product change, with trusted intent/target/time provenance. Keep the new prototypes research-only. The customer benefit is potentially fewer irrelevant-evidence decisions and cheaper execution of specified policies; no quantified enterprise savings are established here.

Defensibility: conventional algorithmic/systems engineering, not confirmed patent-candidate IP. Closest prior art includes abstract interpretation, reusable program libraries and compositional program learning (see PRIOR_ART.md). No exclusive ownership is asserted. No enabling novel invention is identified for public disclosure in this patch.

Next experiment: independently authored multi-domain text-to-context binding with unseen entities, negation, temporal qualifiers and conflicting records; compare capable optimized local models with deterministic extraction and calibrated abstention. Freeze a new holdout and measure expert acquisition effort prospectively. Stop architectural expansion until that boundary improves.
