# Skill 23 — UAS / Drone Accountability Profile

## Purpose
Create the first vertical profile for defence UAS while keeping the Vanian accountability core unchanged.

## Source of truth
Autonomous-system architecture and the Linux edge reference; no new verdict semantics.

## Non-negotiable rules
- Vanian is not the flight controller; it is the accountability layer around autonomous execution.
- Mission authority, navigation intent and actuator effects are distinct evidence objects.
- Sensor data is not automatically a trusted observer merely because it originates on the vehicle.
- Defence-specific terminology must not alter protocol security invariants.

## Required work
- Define UASSystemProfile, MissionExecution, AutonomyMode, NavigationAction, SensorAction, CommunicationAction and ActuationAction.
- Define UAS observation profile and which events can be independently observed on Linux edge compute.
- Define expected mission action commitments and mission lifecycle transitions.
- Add threat cases: stale mission, wrong model, wrong parameter, wrong vehicle, replayed command, dropped event, observer loss.
- Create a reference UAS simulator/harness before any physical-flight dependency.
- Define integration points for flight stack, companion computer and ground station without trusting any one of them unconditionally.

## Acceptance gate
- A simulated UAS mission produces identity-bound, expected-execution-bound and observation-correlated evidence.
- The same reconciler and proof pipeline is used as the Linux reference.

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
