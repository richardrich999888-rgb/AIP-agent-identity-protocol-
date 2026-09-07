# Skill 20 — Autonomous Observation Profile

## Purpose
Generalize Sniffer Dog's independent observation contract across autonomous edge environments without weakening the independence boundary.

## Source of truth
aip-observe design and audit limitations; observer key custody and transport authenticity remain deployment obligations.

## Non-negotiable rules
- Observation is independent only when the observation root is outside the authority of the actor being judged.
- Do not treat framework callbacks, agent telemetry or self-authored logs as independent observation.
- Missing observation is not evidence of non-occurrence.
- Every observation class must state exactly what it can and cannot establish.

## Required work
- Define ObservationProfile and ObservationCapability with classes such as process, network, container, filesystem, syscall, device, sensor, actuator, mission, vehicle, robotics, industrial and space.
- Define coverage declarations and observation-health semantics.
- Preserve continuity, sequence, loss accounting and anti-rollback behavior from the existing observer model.
- Define off-host collector, transport authenticity and key-custody interfaces.
- Define evidence-strength contributions per observation class without allowing telemetry to upgrade itself.
- Create observation profile conformance tests and loss/absence tests.

## Acceptance gate
- Every profile states its evidentiary ceiling.
- A compromised actor cannot manufacture an observer assertion through the normal SDK path.
- Observation gaps produce explicit uncertainty rather than false negatives.

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
