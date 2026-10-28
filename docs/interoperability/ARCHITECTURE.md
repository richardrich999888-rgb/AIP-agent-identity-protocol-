# VANIAN interoperability increment

Status: PARTIALLY_VERIFIED. The first end-to-end milestone is **not complete**.

## Reconciled baseline

On 2026-10-28 GitHub contained draft PRs #6 and #7 and a newer draft PR #8. PR #8 already combines the requested branches. This work starts at its exact merge commit `e3aa195def7524d6ec84d37a934beebe18b6c794` (parents `65b6ff7fdad5ae70546a57216a497399091c7dc7` and `bd15b8e627e5ef67ba259559ed81feb6894cde48`). No draft is merged by this work. Existing RBI evidence remains unchanged.

The new Python package is outside the observer, uses upstream extension points, and emits reference records. It does not mint another AIP identity, evaluate another policy language, or replace ContextForge, the enterprise console, SDKs, evidence MCP server, or native Rust cryptography.

## Authoritative existing models

| Meaning | Existing implementation | Interoperability rule |
|---|---|---|
| Logical identity and delegation | `aip-types::AgentIdentityDocument`, `ScopedToken`, `DelegationToken` | Retain original signed formats; issuer-qualified external claims are references |
| Process binding | `aip-types::ExecutionBinding` | PID, start ticks, boot ID and executable digest; a pathname or framework name is insufficient |
| Expected operation | `aip-authorize::ExpectedExecution` | Existing decision-point signature and authority references; no conversion from an unsigned allow |
| Tool boundary | `aip-airi::SignedToolReceipt` | Verify gateway anchor and actual parameter commitment |
| Observation and custody | `aip-observe::ObservationBatch`, `AttestedBatch`, `SignedSensorHealth` | Existing independently provisioned collector and coverage checks |
| Verdict | `aip-reconcile` expectation/lineage reconciliation | Preserve native verdict and integrity findings; missing evidence stays CannotProve |
| AIBOM | `aip-aibom::EvidenceBundle` | Reuse verified native inputs; no new trust score |
| Institution boundary | Existing `aip-service` enterprise tenant/resource and reader scope | External tenant comes from operator configuration, never a model-controlled claim |

## Implemented flow

ADK BasePlugin records application correlation. The official A2A SDK performs discovery and messaging over pinned HTTPS with client certificates. A deployment-specific signed task credential constrains a request and parent task; it is explicitly not an A2A standard or an AIP execution authorization. The identity bridge checks pinned JWT keys and preserves unresolved logical mappings. OPA remains the evaluator. Microsoft ACS remains the governance controller. The existing ContextForge plugin signs actual gateway requests using Rust.

The reference-only OCSF adapter imports OpenShell records without inventing authentication. OpenShell already has external enforcement; VANIAN's intended addition is corroboration under separately established observer coverage.

The offline Rust composition accepts native signed evidence only, with assessor-supplied keys. It exposes tool-boundary comparison separately from runtime reconciliation and explicitly does not verify an institutional authority chain or external identity mapping.

## Deployment boundary

Institutions retain their IdP, policy engine, gateway, collector, trust anchors and evidence service. No VANIAN-operated central service is required. The initial banking deployment remains observer-only and non-gating. The ADK telemetry hook counts/logs lost events without altering tool outcomes. Upstream governance can still enforce its own configured policy.

Existing enterprise API/SDK routes expose native evidence. This increment does **not** add external-reference ingestion or present these lab records as admitted enterprise evidence. Admission, tenant authorization and source validation remain a production gap. See [PRODUCTION_GAPS.md](PRODUCTION_GAPS.md).
