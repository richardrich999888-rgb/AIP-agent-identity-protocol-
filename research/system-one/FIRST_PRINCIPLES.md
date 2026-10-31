# System One — first-principles record

## 1. What a "decision" requires

A typed decision maps `(state, question, policy) → distribution over K
options`. Two sub-functions are mathematically distinct:

1. **Interpretation**: turning free text into the variables the policy is
   stated over (which equipment, which quantity, what value, which unit).
2. **Policy evaluation**: applying thresholds, orderings and arithmetic to
   those variables.

Function 2 is exact and cheap when the policy is known (comparisons,
`min` over readings). Running it inside a neural network adds error and cost
and gives nothing back. Jev's own documentation says arithmetic and date
comparisons should stay in application code (nexos.ai guide). The
iteration-1 data confirms it: the rule baseline is exact at ~0.01 ms whenever
interpretation succeeds.

Function 1 is where learned representations can earn their cost: unseen
phrasing, abbreviations, typos, and the many forms one reading can take.

Inherited assumption challenged: *"the model should output the decision."*
The first-principles alternative is *"the model should output the variables
the policy needs, plus its uncertainty about them; the policy is executed
exactly."* That is Candidate 4 (neuro-symbolic). It also matches VANIAN's
security rule: model output must not override deterministic policy.

## 2. Hypotheses and their falsifiers (verdicts: REPORT_ITER1.md §2)

| ID | Hypothesis | Experiment that would falsify it | Iteration |
|---|---|---|---|
| A | A typed decision does not need autoregressive text; a single-pass readout of option probabilities matches JSON generation at a fraction of the cost | Readout accuracy below JSON accuracy on identical items (paired bootstrap CI excludes 0), or no latency gain | 1 |
| B | A cheap path solves most items; escalate only the uncertain ones | Escalated share so high, or routing errors so frequent, that total cost or error exceeds the single large model | 1 (rule→LLM cascade) |
| C | Knowledge can live outside the weights (SOP in context / in rules) | Models fail when thresholds are only in context but pass when trained in | 1 (in-context SOP) |
| D | One shared state amortises many decisions | Prefix-cache reuse brings no latency gain | 1 (cache on/off) |
| E | Memory movement dominates CPU decode cost | Latency does not scale with weights read per token | 2 |
| F | Air-gapped objective differs from cloud | — (benchmark design, not a falsifiable claim) | ongoing |

## 3. What is verified about Jev and Kev (sources in REPORT_ITER1.md)

| Property | Jev (TypeSafe) | Kev (open, Apache-2.0) |
|---|---|---|
| Access | Hosted API only; weights undisclosed | Weights on Hugging Face; code on GitHub |
| Output | Typed choice / score / yes-no, single pass, no reasoning trace | Same interface (`POST /v1/systemone`) |
| Mechanism | Undisclosed ("non-generative"); training method "RLCD" claimed, no paper | Prefill-only Qwen backbone + LoRA (r=16) + pointer head scoring option-closing hidden states against a `<decide>` state; questions packed with a block-causal mask |
| Calibration | Claimed; no published measurements | Single temperature; reported OOD ECE ≈ 0.1 |
| Reported quality | Kev's README compares on shared items: Jev OOD Brier 0.211 | kev-4b OOD Brier 0.328; confident-error rate 8.2 % vs Jev 3.7 % |
| Stated limits | Not a calculator; accuracy drops with irrelevant context | When2Call below chance; validated context 8,192 tokens |

**Unsolved for disconnected environments (neither addresses):** CPU-only
latency budgets; signed model provenance; binding a decision to deterministic
authorization; evidence of what the decision was based on; behaviour when the
input is outside the policy's vocabulary.

## 4. Candidates (iteration 1 implements the cheapest version of each)

| Candidate | Iteration-1 instance | Training | Inference cost | Expected failure |
|---|---|---|---|---|
| 1 Specialized decision model | TF-IDF + logistic regression (proxy); Kev in iteration 2 | train split, seconds | ~2 ms CPU | cannot compare numbers it has not seen; multi-reading |
| 2 Shared representation | llama-server prefix cache over the SOP context | none | measured cache on vs off | gains vanish when the state is unique per request |
| 3 Adaptive compute | rule → LLM readout on abstention | none | rule cost + LLM on escalated share | escalated share is large exactly on hard inputs |
| 4 Neuro-symbolic | rule baseline (symbolic half only) | none | ~0.01 ms | vocabulary mismatch → abstain |
