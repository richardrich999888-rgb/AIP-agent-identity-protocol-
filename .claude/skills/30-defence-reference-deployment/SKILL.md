# Skill 30 — Defence Reference Deployment and TRL Advancement

## Purpose
Turn the validated architecture into a representative defence deployment path that can support TRL progression and customer evaluation.

## Source of truth
Forensic audit production-readiness findings and the Linux/UAS/UGV/robotics profiles.

## Non-negotiable rules
- Do not claim TRL advancement from code volume or unit tests alone.
- The demonstrator must exercise the integrated mission chain in a representative environment.
- Document all environmental limitations, observer coverage, key custody and operational dependencies.

## Required work
- Select a first reference platform: Linux-based autonomous UAS/UGV/robotics edge system.
- Build a representative mission scenario with identity, authority, expected execution, AI-stack events, runtime observation, action evidence, reconciliation, warrant, containment and NEXORA proof.
- Run both nominal and adversarial mission cases, including observer loss, replay, wrong parameters and unexpected effects.
- Measure deployment latency, CPU/memory overhead, event loss, recovery time and verification time.
- Define operator procedures, key custody, update/rollback process, evidence export and offline verification.
- Create a defence-readiness evidence package that separates test-proven properties from operational demonstrations and open limitations.

## Acceptance gate
- A representative autonomous defence workload demonstrates the integrated accountability chain end to end.
- Operational evidence is reproducible and externally reviewable.
- The report can support a defensible TRL 6/7 assessment without overclaiming.
- A customer-facing pilot package exists with explicit success criteria and failure criteria.

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
