# Skill 16 — Production Boundary and Blocker Closure

## Purpose
Close or explicitly resolve the forensic blockers identified in the revised AIP Six-Branch Forensic Audit before any new domain architecture is allowed to change the accountability core.

## Source of truth
AIP Six-Branch Forensic Audit (revised 2026-09-06), especially blocker register B-1a through B-10.

## Non-negotiable rules
- Treat the revised forensic audit as the security source of truth; do not use passing tests or branch summaries as proof of capability.
- Do not redesign the accountability semantics while closing blockers.
- Every fix must trace from constructor/input through all consumers and be pinned by adversarial tests.
- No production-promotion claim until every P0/P1 blocker is closed or explicitly accepted by an authorized security decision record.
- Bring aip-service into the primary build/test boundary or explicitly document and enforce a different supported deployment boundary.

## Required work
- Close B-1a: supply verification_time_ms and future tolerance in service verification; handlers must not decide only from result.valid when temporal evaluation is absent.
- Close B-3: connect real reconciler output to warrant evaluation and containment with a genuine end-to-end engine-produced path.
- Close B-4: make the verifier use an externally trusted bundle signer anchor, never a signer key supplied by the bundle.
- Close B-5/B-6/B-7: secure private-key creation/storage, fail closed on missing service keys, and prohibit private seeds in HTTP request bodies.
- Close B-8: define packet replay semantics and a verifier-enforced anti-replay mechanism appropriate to the protocol boundary.
- Close B-9: seal Reconciliation result construction so consumers cannot bypass preconditions.
- Close B-10: place service in CI/workspace coverage and add regression tests proving protocol changes reach service callers.

## Acceptance gate
- No open P0 findings under the central accountability claim.
- All P1 production blockers have code-backed closure evidence.
- Service and standalone verification agree on temporal semantics.
- At least one test crosses reconcile → warrant → containment using engine-produced reconciliation.
- Primary CI command compiles and tests the service tier.

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
