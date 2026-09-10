# Skill 15 — Autonomous Intelligence Stack End-to-End Accountability

## Objective
Integrate AI-stack instrumentation with the existing AIP/Sentinel/Sniffer Dog/NEXORA architecture while preserving strict evidence semantics.

## Canonical architecture
AIP Identity
→ Authority / Delegation
→ Sentinel Authorization
→ ExpectedExecution
→ AIRI
→ Agent Framework
→ Model / Inference Runtime
→ Tool Invocation
→ Host / Container Runtime
→ Independent Observer
→ Action Evidence
→ Reconciliation
→ Warrant
→ Containment
→ NEXORA Proof

## Non-negotiable invariant
The autonomous actor and the component judging the actor must not be the same evidence authority.

## Required test matrix
At minimum cover:
- valid identity + valid authority + matching action
- framework claims action but observer sees nothing
- observer sees action without matching expectation
- parameter substitution
- model substitution
- agent identity substitution
- execution identity substitution
- replay of a valid framework event
- event ordering violation
- worker/process hand-off
- subprocess hand-off
- duplicate event
- dropped event
- observer unavailable
- observer continuity break
- stale ExpectedExecution
- expired authority
- cross-framework event transplantation
- forged adapter event
- malformed provenance commitment

## Result semantics
Default to CANNOT_PROVE.
Do not manufacture success from telemetry completeness.
Maintain existing distinctions such as:
- CANNOT_PROVE
- PHANTOM_CLAIM
- IDENTITY_DIVERGENCE
- SENSOR_INTEGRITY_FAILURE
- CONTINUITY_FAILURE
and only add new result types when the evidence semantics require a new epistemic category.

## NEXORA requirements
Proof packages must include enough inputs for an offline verifier to:
1. authenticate package components;
2. re-derive relevant commitments;
3. reconstruct the applicable reconciliation inputs;
4. recompute the result;
5. compare canonical result digests;
6. reject claimed verdicts not independently derivable.

The verifier must not trust a serialized `Proven`/`Attested` value merely because it is signed by the package author.

## Production boundary
Do not claim production readiness until the known forensic blockers are closed, especially:
- verifier clock semantics
- issuer/grantee binding
- sealed reconciliation result construction
- real engine-produced containment path
- service integration and key handling
- bundle signer trust
- private key storage/regeneration
- private seed handling

## Deliverables
Produce:
- AIRI protocol specification
- Python SDK boundary
- one reference agent-framework adapter
- one model/inference adapter
- one tool gateway adapter
- end-to-end cryptographic binding tests
- offline verification tests
- threat model
- limitations/evidence classification document
- migration/versioning plan
