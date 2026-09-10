# Skill 22 — Linux Autonomous Edge Reference

## Purpose
Build the reference implementation for autonomous edge systems on Linux before creating multiple domain adapters.

## Source of truth
Existing Linux observation/runtime code and AIRI extension; audit requires the service and production boundary to be resolved first.

## Non-negotiable rules
- Linux edge is the reference execution substrate, not the permanent limitation of the protocol.
- Prefer kernel/runtime observation over application self-report where the property is externally observable.
- Do not claim kernel-level proof where the current observer cannot establish it.
- Keep the reference harness deterministic and replayable at the evidence/proof layer.

## Required work
- Create a reference Linux autonomous workload with AIP identity, AIRI, ExpectedExecution and runtime binding.
- Integrate Sniffer Dog observation for process and network classes already supported by the substrate.
- Integrate real reconciliation and warrant/containment after Skill 16 closes the path.
- Produce a reference NEXORA proof package for an observed execution.
- Define packaging for edge/offline operation, configuration, key custody and collector separation.
- Measure latency, event loss and resource overhead; do not turn measurements into security claims.

## Acceptance gate
- A single Linux reference workload demonstrates the end-to-end chain from identity through proof.
- The reference can run without cloud connectivity for verification.
- All unsupported claims are surfaced as limitations.

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
