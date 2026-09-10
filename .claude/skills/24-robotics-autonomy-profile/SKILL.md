# Skill 24 — UGV and Robotics Autonomy Profile

## Purpose
Extend the same accountability architecture to UGVs and autonomous robotics, including motion/manipulation use cases.

## Source of truth
Autonomous-system model, execution profile and effect boundary.

## Non-negotiable rules
- UGV and robotics are profiles over the same core, not separate security stacks.
- Motion, navigation, manipulation and actuator commands are execution/effect classes, not trust anchors.
- Middleware identity such as a robotics framework does not become authoritative solely because it is integrated.

## Required work
- Define MotionExecution, NavigationExecution, ManipulationExecution, ActuatorExecution and SafetyControllerInteraction.
- Provide adapter boundaries for robotics middleware without embedding middleware-specific assumptions in AIP/AIRI.
- Define observation joins between process/runtime evidence and robotics execution events.
- Add simulation-driven adversarial tests for wrong target, wrong action, delayed action, duplicate action and physical-effect mismatch.
- Define UGV/robotics deployment profiles for disconnected operation and local verification.

## Acceptance gate
- A reference robot/UGV simulation uses the same core accountability pipeline as UAS.
- Framework-specific events remain claims unless independently corroborated.

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
