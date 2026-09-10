# Skill 26 — Disconnected and Space Autonomy Profile

## Purpose
Extend accountability into highly disconnected and delayed-verification environments such as orbital and remote autonomous systems.

## Source of truth
NEXORA offline verification model, continuity semantics and autonomous-system abstraction.

## Non-negotiable rules
- Offline operation is a first-class deployment mode, not a bypass around verification.
- Delayed arrival of evidence must not be confused with non-occurrence.
- Continuity gaps remain explicit and cannot be papered over by later evidence.
- Do not claim timing/order beyond what the trust model can establish.

## Required work
- Define SpaceExecutionProfile, AutonomyModeTransition, DelayedEvidence, StoreAndForwardBundle and GroundVerificationContext.
- Define long-duration sequence/continuity semantics and recovery from intermittent links.
- Integrate NEXORA packaging for offline reconstruction and verification.
- Model delayed ground commands and delayed observation arrival without inventing real-time certainty.
- Add adversarial tests for missing segments, delayed segments, branch/fork histories and replay across contacts.

## Acceptance gate
- A simulated disconnected mission can execute, collect evidence locally and be verified later without cloud dependence.
- Continuity failures are explicit and do not silently downgrade into success.

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
