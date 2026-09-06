# Skill 13 — LLM / JAX / PyTorch / Model Execution Provenance

## Objective
Represent model and accelerator execution as a provenance layer without pretending model-level telemetry proves external effects.

## Scope
Support metadata/provenance for:
- LLM/VLM model identifier
- model version/digest when available
- prompt/context reference or commitment
- tool-call request reference
- inference request/response correlation
- tokenizer/runtime version when available
- JAX
- PyTorch
- TensorFlow
- vLLM / inference servers
- CUDA/GPU execution metadata when independently observable
- local and hosted models

## Epistemic separation
Keep separate:
- model declaration
- model selection
- inference request
- model output
- agent interpretation
- tool invocation
- runtime execution
- external effect

A model output is not authorization.
A tool-call message is not proof of execution.
A successful framework return is not independent observation.

## JAX / accelerator requirements
Treat:
Python
→ JAX/PyTorch/TensorFlow
→ XLA/native runtime
→ CUDA/accelerator
as a multi-layer execution chain.

Where direct accelerator observation is unavailable:
- record declared/observed framework events as such;
- do not claim hardware execution from application telemetry alone;
- use CANNOT_PROVE where the distinction matters.

## Provenance identifiers
Where practical, bind:
- agent_id
- execution_id
- model_id/model_digest
- framework name/version
- inference request ID
- tool_call ID
- ExpectedExecution ID
- runtime execution binding
- parent execution ID

Avoid putting raw sensitive prompts or secrets into immutable evidence by default. Prefer cryptographic commitments/references with explicit privacy policy.

## Replay
For non-deterministic LLM execution, replay means policy/evidence equivalence, not bitwise reproduction of model outputs.

## Acceptance criteria
- Model metadata is cryptographically bound to the relevant execution event.
- Framework/model substitutions are detectable.
- A model event cannot be transplanted between agent identities or executions.
- Offline verification does not need the original LLM call to verify the integrity of the supplied provenance.
- Missing model/accelerator evidence never becomes an implicit success.
