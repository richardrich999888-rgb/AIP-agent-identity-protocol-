# Production gaps and exit criteria

The requested first milestone is open. This is an engineering increment, not a production support declaration.

| Priority | Gap / current status | Required exit evidence |
|---|---|---|
| P0 | BLOCKED: no BPF capabilities, kernel BTF or approved off-host collector here | Same-run supported events, health/coverage, independent collector signature and offline verification on authorized isolated Linux |
| P0 | BLOCKED: no institutional signing/key-management infrastructure | Existing signed authority chain and ExpectedExecution issued independently of the agent, matched to the actual model-chosen request |
| P0 | NOT_EXECUTED: enterprise admission of new external references | Authenticated tenant-bound API ingest plus API/SDK reads of the very same verified native records |
| P1 | BLOCKED locally: SPIRE Unix socket service | Real JWT-SVID issuance/verification on supported host, rotation/revocation and workload→logical-agent evidence |
| P1 | PARTIALLY_VERIFIED: A2A endpoint/task profile | External organization trust policy, delegated issuer custody, durable distributed replay, TCK compatibility and negative transport/lifecycle coverage |
| P1 | PARTIALLY_VERIFIED: OPA and ContextForge | Bind authenticated policy input/version to native signed authorization and gateway receipt in the same operation |
| P2 | BLOCKED: OpenShell runtime | Genuine sandbox workload, native policy outcomes, sandbox ancestry binding and separate qualified sensor evidence |
| P2 | PARTIALLY_VERIFIED: Microsoft ACS | Authenticated source/signature profile, policy-version provenance and exact native-input→gateway commitment join |
| P3 | NOT_EXECUTED: AGNTCY/NeMo/Cedar/OpenFGA/OTel/CycloneDX | Small justified adapters after reference acceptance; no cloned frameworks |
| P4 | NOT_EXECUTED: clean-host/customer acceptance | Scoped deployment credentials, independent security validation, rotation/backup/failure drills, measured overhead and supported Linux matrix |

The Python library is optional and never loaded by the privileged observer. Install it in a separate venv/service identity. Protect CA/trust-anchor configuration and replay storage; scope remote credentials per audience and resource. Replay reservation is fail-closed and single-host, not a distributed transaction protocol. Explicitly provision revocation feeds, key rotation and clock synchronization before operational use.

Use existing `deploy/pilot/` and `deploy/enterprise/` procedures for customer components; do not expose the evidence MCP reader as an observer-control API. Keep institution authority and collector keys away from the workload and gateway as required by their separate roles. Observe telemetry-drop counters and existing sensor integrity/coverage signals. No new privileged installation procedure is implied by these examples.

CycloneDX mapping is proposed, not standardized AIBOM: use native components/services/dependencies, supported model cards/external references, and namespaced properties for VANIAN claim status/evidence links. Retain DECLARED, DISCOVERED, AUTHENTICATED, INDEPENDENTLY_OBSERVED, VERIFIED and UNKNOWN per claim; validate against an exact upstream schema before exporting. No custom field is represented as an official CycloneDX extension.

No vendor, foundation, banking regulator, UPI/NPCI or government endorsement is asserted. Interoperability is the architectural analogy; no marketplace, token/payment network or central proprietary trust authority is introduced.
