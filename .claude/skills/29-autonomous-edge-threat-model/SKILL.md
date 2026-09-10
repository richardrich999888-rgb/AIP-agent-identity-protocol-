# Skill 29 — Autonomous Edge Threat Model

## Purpose
Create a threat model spanning AI, runtime, physical edge, observer and proof boundaries.

## Source of truth
Revised forensic audit, AIRI threat model and known non-establishments N-1 through N-11.

## Non-negotiable rules
- Model the attacker as potentially controlling the agent process, framework, model integration, tool integration or host.
- Treat self-report limitations as designed boundaries, not assumptions to hide.
- Every threat must map to prevention, detection, uncertainty, or explicit non-detectability.

## Required work
- Threat-model compromised agent, compromised framework, compromised model runtime, compromised tool, compromised process, compromised host, forged telemetry, lost connectivity, partial observation, sensor deception, observer failure, replay and stale authority.
- Map each threat to AIP/AIRI/observation/reconciliation/warrant/containment/NEXORA.
- Define trust roots, key custody, transport authenticity and recovery obligations.
- Add scenario-driven adversarial tests across UAS, robotics, industrial and disconnected environments.
- Track inherited blockers until their closure is independently verified.

## Acceptance gate
- Every high-impact threat has an explicit system response or an explicit CANNOT_PROVE boundary.
- No threat is marked mitigated merely because a log or callback exists.

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
