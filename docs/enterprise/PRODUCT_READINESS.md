# Enterprise product readiness

**Milestone: PARTIAL. Suitable for engineering evaluation of the implemented
interfaces; the complete enterprise/bank deployment acceptance is not met.**

This branch builds on `3a029aec`, preserves RBI `0991fb1`, and incorporates the
concurrent real-agent validation/lint commits through `f025a57`. Its changes
are split into runtime packaging, service/storage, gateway and customer
interface commits. The default branch and other working checkouts were not
modified. See `INVENTORY.md` for exact source/ref evidence and
`VALIDATION_REPORT.md` for executed checks.

## What already worked

The existing Rust authorization/delegation, observer, confidential transport,
collector custody/continuity, reconciliation, lineage, signed gateway receipt,
tenant-scoped service stores and independent verifiers were reused. The RBI
branch had a successful hosted Linux rehearsal at `0991fb1`, run
`40409155305`; that is historical development evidence, not a bank deployment
or a fresh run on the actual presentation machine.

## What this branch implements and validates

- A verifiable runtime archive, restricted configuration/preflight,
  role-separated systemd installation, resource limits and retained-data
  uninstall. Deterministic package tests pass; actual Linux installation and
  sensor qualification remain a separate gate.
- A real native plugin for pinned ContextForge, using Rust receipt signing,
  durable replay reservations and honest post-dispatch uncertainty. Twenty-eight
  actual integration/configuration checks pass, including the official MCP
  client, a genuine local-model LangGraph read and offline receipt verification.
- A Reader role, tenant-scoped read contract, institution-anchored collector
  archive admission/retrieval, real verification and a console using actual API
  records. JSONL persistence failure is no longer acknowledged from RAM, and
  the service refuses an unusable artifact backend at startup.
- Repaired PostgreSQL artifact provisioning, forced tenant RLS/grants and
  concurrent-insertion handling. Source parity, feature compilation and all
  14 explicitly executed restricted-role controls passed against hosted
  PostgreSQL 16.15; institutional database deployment remains unqualified.
- Typed Python/TypeScript read clients and an optional restricted stdio MCP
  evidence server. Real service/client tests prove authorized retrieval and
  cross-tenant refusal for signed verdicts and collector archives.

## What a bank can install today

An approved engineering team can build and review the runtime archive from
source, stage/install its probe and collector roles, configure the existing
service behind its ingress, install the pinned ContextForge integration and
use the customer read interfaces. These are evaluation artifacts and commands,
not a certified release or a qualified OS/container/Kubernetes support matrix.
No real bank credentials, production data, institution-provided signing private
keys or external VANIAN trust service are required by the sample artifacts.
The validation harnesses generate fresh ephemeral test signing keys; those
private keys are not included in the retained public evidence.

The optional Helm chart is disabled by default. Pinned Helm lint/render and
configuration-refusal tests pass, but cluster/runtime use is unqualified. Air-gap
instructions exist, but a complete signed institution/platform-specific
offline dependency bundle has not been built and installed. New runtime
packages are not yet published through the existing Sigstore release workflow.

## Final acceptance gates

| Required outcome | Current status |
| --- | --- |
| Clean supported Linux installation and service startup | `BLOCKED_BY_INFRASTRUCTURE` in this local run; packaging tests are not an install qualification |
| Genuinely separate independently administered collector | `BLOCKED_BY_INFRASTRUCTURE`; local processes/containers do not establish it |
| Genuine AI workload | LangGraph + real local model + actual MCP read executed; current Linux kernel observation of that same run remains blocked |
| Kernel evidence and signed collector archive | Fresh five-act RBI rehearsal passed on disposable hosted Linux in run `40672603812`; this is not the genuine LangGraph gateway run or a qualified bank-host installation |
| Supported MCP gateway tool integration | Passed on exact pinned ContextForge profile; production authentication/TLS/plugin combinations are unvalidated |
| Authorized API/SDK/MCP evidence retrieval | Passed against actual service with real signed collector fixtures and engine verdicts; those fixtures are not the local LangGraph run |
| Offline independent verification | Current gateway checks, historical observer mutation regression and fresh RBI offline checks passed; fresh institutional anchors/deployment still needed |
| Complete same-run authorization/observation/receipt/verdict join | `IMPLEMENTED_BUT_NOT_INTEGRATED` at product/workload level; no substitute unit test is presented as a full-system pass |
| Two additional real delegated/coding frameworks | Launchers/harness preserved from concurrent work; current full Linux executions unvalidated |
| External assessment and institution approval | `BLOCKED_BY_EXTERNAL_APPROVAL` |

## Production blockers and external validation

Require approved Linux compatibility/capability and two-host key-custody tests;
fresh RBI rehearsal on the actual host; complete signed workload
authorization/reconciliation; capacity/loss/restart and backup/restore tests;
bounded collector workers and durable probe outage handling; reviewed workload
enrollment and per-tenant trust policy; institutional TLS/mTLS/IdP/rate limits;
secret/key rotation and real HSM/KMS integration; retention/encrypted backups;
release signing/SBOM/image scanning; and a qualified independent assessment.

Current `/v1/coverage` remains unavailable because no live coverage monitor is
connected. Admitting a historical signed snapshot does not change that. An API
packet signature, gateway `Forwarded`, model recommendation or static dashboard
must never be promoted to proof of authorized execution or a completed banking
transaction.
