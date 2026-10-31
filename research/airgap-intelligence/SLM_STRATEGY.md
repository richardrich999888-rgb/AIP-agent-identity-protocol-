# Model hierarchy, exact computation and escalation

## The separation measured so far

Iteration 1 (research/system-one/REPORT_ITER1.md, 2 vCPU, no GPU):

| Asked of Qwen2.5-1.5B | Accuracy (maintenance priority) |
|---|---|
| "Decide the priority" | 0.34 |
| "Extract the quantity and value"; code applies the SOP | 0.98 on test_para |

Its reasoning traces assert "103 C is above 105 C". Exact comparisons belong in
code. **Caveat found in iteration 2 (P0):** test_para is solved 1.000 by a rule
on (equipment, unit), so the 0.98 does not demonstrate paraphrase
understanding. The separation principle stands; the size of the benefit is
unmeasured until a test that rules cannot solve exists (iteration 2, P2).

## Layers

| Layer | Job | Candidate implementation | Evidence |
|---|---|---|---|
| 0 Exact | thresholds, arithmetic, dates, access policy, authorisation | Rust/Python code; SQL | Built; exact by construction where the vocabulary matches |
| A Tiny specialists | classify task, extract variables, route, filter | TF-IDF/linear (~2 ms, 160 MB); small encoders (to be measured) | Research |
| B General SLM (0.5–4B) | interpret free text, extract structure, short grounded answers | Qwen2.5-1.5B Q4 via llama.cpp (~1–9 s, 1.8 GB on 2 vCPU) | Research; 0.5B at chance on decisions |
| C Larger local model | multi-step reasoning, code, synthesis | 7B+ on customer GPU | Proposed; not measurable on this host |

## Escalation rule (proposed, not built)

Go to the next layer only when the current one **abstains** — never on a model's
verbal confidence. Iteration 1 found the llama.cpp build's letter logprobs
disagree with its emitted tokens, so probability-based routing needs its own
validated confidence source before use.

## Knowledge outside the weights

Customer knowledge enters as (a) authorised retrieved passages, (b) executable
policy tables, (c) extracted structured facts — not fine-tuning. Phase A showed
retrieval + deterministic support checks released 0 wrong answers on a 44-
question suite, but at 4/6 coverage on the original six: grounding costs
coverage. Whether structured extraction beats plain RAG on real documents is
unmeasured.

## Honest limits

A cascade only saves compute if most traffic is answerable at a cheap layer.
That traffic mix is a customer property this repository has not measured.
Small models are not shown to reason; they are shown to interpret narrow inputs.
