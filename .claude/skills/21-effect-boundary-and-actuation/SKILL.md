# Skill 21 — Effect Boundary and Actuation

## Purpose
Define the boundary between autonomous intent, command execution and independently established external/physical effect.

## Source of truth
AIRI limitation N-2 and the requirement that successful tool calls are not automatically proof of external effect.

## Non-negotiable rules
- Requested invocation ≠ runtime execution ≠ external effect.
- A successful tool/API response is not automatically proof that a physical or external effect landed.
- Effect confirmation requires an evidence source whose trust boundary is appropriate to the claimed effect.
- Do not add a verdict class merely to represent every physical-world uncertainty.

## Required work
- Define RequestedEffect, ExecutedCommand, ObservedEffect, EffectConfirmation and EffectUncertainty.
- Define effect observers and admissible evidence for APIs, actuators, vehicle state, robotic motion and industrial controls.
- Bind effects to execution_id, ExpectedExecution and action/parameter commitments.
- Define partial-effect, delayed-effect and no-effect cases.
- Map insufficient evidence to existing CANNOT_PROVE semantics.
- Add adversarial tests for successful-call-without-effect and effect-without-matching-request.

## Acceptance gate
- The system can state that a command was executed without incorrectly claiming that its external effect occurred.
- A physical-effect claim is traceable to a specific evidence source and observation boundary.

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
