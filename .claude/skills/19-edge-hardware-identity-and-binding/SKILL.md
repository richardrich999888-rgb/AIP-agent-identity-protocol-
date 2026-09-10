# Skill 19 — Edge Hardware Identity and Binding

## Purpose
Bind autonomous intelligence execution to the physical compute substrate while preserving distinct identity layers and conservative evidence semantics.

## Source of truth
AIP identity model, execution binding model, Sniffer Dog process-instance binding and audit limitations around self-reported runtime_binding.

## Non-negotiable rules
- AgentIdentity, ExecutionIdentity, HardwareIdentity and HostIdentity are distinct objects.
- A hardware identifier is not proof that a particular agent action occurred on that hardware.
- Self-reported runtime binding cannot raise evidence strength.
- Do not invent hardware trust where the current platform cannot measure it.

## Required work
- Define HardwareIdentity, EdgeNodeIdentity, DeviceAttestationReference and PlatformBinding.
- Bind execution instances to host/device identities using explicit, versioned commitments.
- Integrate Linux process-instance identity where available: pid + start ticks + boot identity.
- Define optional TPM/HSM/secure-boot evidence as separate evidence sources rather than implicit trust.
- Define portability semantics for the same autonomy workload moving between hosts or vehicles.
- Add migration and key-rotation scenarios.

## Acceptance gate
- The verifier can distinguish agent identity from physical compute identity.
- A process replayed on another host cannot inherit the original hardware binding.
- Unsupported hardware attestation remains CANNOT_PROVE/NotEvaluated rather than silently trusted.

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
