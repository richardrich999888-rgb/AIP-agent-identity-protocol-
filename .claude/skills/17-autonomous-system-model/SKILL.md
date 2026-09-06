# Skill 17 — Autonomous System Model

## Purpose
Define one canonical domain model for autonomous intelligences across enterprise, edge, physical and orbital environments.

## Source of truth
AIP/AIRI architecture and revised forensic audit; preserve the existing accountability core and add an environment-neutral system model.

## Non-negotiable rules
- The protected subject is an AutonomousSystem, not a vehicle type or framework.
- Do not equate system identity, agent identity, execution identity and hardware identity.
- Do not grant authority merely because a parent/child relation exists.
- Do not introduce vertical-specific verdict classes.
- Keep identity lineage, authority lineage and process/execution lineage distinct.

## Required work
- Specify AutonomousSystem, SystemIdentity, SystemType, PlatformIdentity, HardwareIdentity, SoftwareIdentity, AgentIdentity and ExecutionIdentity.
- Specify mission/task linkage, capability profile, authority/delegation, deployment context, runtime profile, observation profile and communication profile.
- Define relationships among agent, host, device, vehicle, controller, container, model runtime and physical platform.
- Define lifecycle states without making lifecycle state itself a trust anchor.
- Define canonical identifiers, versioning and domain-separated serialization requirements.
- Produce a migration map showing how current AIP/AIRI entities project into the new model without breaking existing verification.

## Acceptance gate
- A UAS, UGV, robot, industrial edge node, spacecraft computer and enterprise agent can all be represented without schema forks of the accountability core.
- Identity/authority/execution/hardware relationships are explicit and non-confusable.
- Parent-child creation never implies authority.
- Existing AIP/AIRI artifacts remain verifiable through compatibility adapters.

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
