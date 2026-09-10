# Skill 25 — Industrial and Critical-Edge Accountability Profile

## Purpose
Adapt Vanian to industrial autonomous systems and critical-infrastructure edge workloads.

## Source of truth
Autonomous execution profile, effect boundary and independent observation model.

## Non-negotiable rules
- Safety boundaries and process effects must be represented as distinct commitments and observations.
- Industrial protocol messages are not automatically proof of physical process change.
- Containment actions must remain warrant-controlled and fail-safe.

## Required work
- Define IndustrialCommand, ControlLoopExecution, ProtocolInteraction, SafetyBoundary and PhysicalProcessEffect.
- Create adapters for representative edge protocols without hard-coding a protocol as trusted.
- Define observation coverage for compute, network and process-state evidence.
- Define operator/manual override semantics and how they appear in authority/execution lineage.
- Add replay, stale-command, sensor-gap and observer-outage test scenarios.

## Acceptance gate
- Industrial/critical-edge deployments can be modeled without modifying core reconciliation semantics.
- The verifier distinguishes command execution from physical process confirmation.

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
