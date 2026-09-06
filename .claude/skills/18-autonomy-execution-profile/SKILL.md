# Skill 18 — Autonomy Execution Profile

## Purpose
Define the environment-neutral execution model that connects AI-stack activity to runtime and physical execution without creating multiple security engines.

## Source of truth
AIRI execution-chain model and the audit's explicit separation of claims, model execution, tool invocation and external effects.

## Non-negotiable rules
- Separate declared capability, authorized capability, expected execution, observed execution and demonstrated effect.
- Separate model request, selected model, served model, output, interpretation, tool request, runtime execution and external effect.
- A self-reported event may describe an action but never becomes independent evidence solely because it is signed by the agent.
- Use the existing reconciliation engine; do not add a second verdict pipeline.

## Required work
- Define ExecutionProfile with AI, model, tool, runtime, process, container, device and effect layers.
- Define ExecutionUnit, ExecutionTransition, ParameterCommitment and EffectBoundary abstractions.
- Define which fields are mandatory, optional, measured, self-reported or independently observable.
- Define execution-context propagation across process, thread, worker, subprocess and container boundaries.
- Define how ExpectedExecution and ExecutionBinding attach to an execution profile.
- Add adversarial substitution tests across profile layers.

## Acceptance gate
- The same execution semantics support an enterprise API call and a drone navigation command without duplicating the reconciler.
- A model event cannot masquerade as an observed effect.
- Cross-agent, cross-execution and cross-platform transplantation is rejected.

# Claude Code Skill

## Governing discipline
- Treat repository code and executed evidence as higher authority than prose claims.
- Preserve the existing conservative epistemic model: uncertainty is not success.
- Never introduce a second reconciliation/verdict engine.
- Every security-sensitive object must be versioned, domain-separated, and encoded injectively.
- Every new claim must identify its evidence class and its observation boundary.
- Do not claim post-quantum security unless a real counterparty exchange and trust boundary are implemented and tested.

## Required workflow
1. Read the relevant existing architecture, tests, and audit findings before editing code.
2. Produce an implementation plan and invariant matrix before implementation.
3. Implement the smallest compatible change.
4. Add adversarial tests for substitution, replay, transplant, malformed input, and loss/absence as applicable.
5. Run targeted tests, then the complete required test matrix including service if in scope.
6. Produce an evidence report stating what is CODE-PROVEN, TEST-PROVEN, EXECUTION-PROVEN, DOCUMENTED, INFERRED, and UNKNOWN.
7. Do not promote or merge unless the skill acceptance gate is satisfied.

## Deliverables
- Architecture/specification changes
- Invariant matrix
- Implementation changes
- Adversarial/conformance tests
- Migration/versioning notes
- Evidence report and known limitations
