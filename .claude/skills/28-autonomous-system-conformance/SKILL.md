# Skill 28 — Autonomous System Conformance

## Purpose
Create the universal conformance program proving that every environment obeys the same Vanian accountability invariants.

## Source of truth
All prior skills plus the revised audit's claim-discipline model and adversarial testing discipline.

## Non-negotiable rules
- The conformance matrix is normative: vertical adapters must satisfy it before they are considered supported.
- A green adapter-specific test suite cannot waive a failed core invariant.
- Unknown observability remains unknown; never upgrade because a vertical has more telemetry.

## Required work
- Define the universal invariant set: identity, authority, expected execution, execution binding, AIRI claim, observation, attribution, continuity, reconciliation, warrant, containment and proof.
- Create a machine-readable domain conformance matrix for Enterprise, UAS, UGV, Robotics, Industrial, Critical Edge and Space.
- Create cross-domain substitution tests for identity, execution, model, framework, parameter and observer evidence.
- Create version and compatibility tests for adapters and proof packages.
- Create an audit artifact generator that labels claims as CODE-PROVEN, TEST-PROVEN, EXECUTION-PROVEN, DOCUMENTED, INFERRED or UNKNOWN.

## Acceptance gate
- All supported domains pass the same core invariants.
- A new domain cannot silently weaken the central accountability semantics.
- Conformance output is independently reviewable.

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
