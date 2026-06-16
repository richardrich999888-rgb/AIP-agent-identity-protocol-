# 05 — Prototype Plan & Milestones

**Goal:** take AIP from **TRL 4** (lab-validated core) to a **field-trialable
prototype (TRL 6–7)** integrated with one sponsoring Service use case.

Durations are indicative and assume a small team (document 06); they will be
firmed up against the selected Problem Statement and disbursement schedule.
Each milestone has an **objective, deliverable, and acceptance test** so
progress is verifiable, not asserted.

## Phase A — Sponsor alignment & threat model (M0–M1)

- **Objective:** lock the sponsoring use case, integration target, security
  domain, and accreditation requirements.
- **Deliverables:** signed use-case definition; security & data-handling
  plan; interface specification with the sponsor's system.
- **Acceptance:** sponsor sign-off on scope and interface spec.

## Phase B — Hardened verification service & key management (M1–M3)

- **Objective:** replace the reference prototype with an authenticated,
  access-controlled, multi-tenant service; integrate sovereign key
  management/HSM and key rotation.
- **Deliverables:** hardened `aip-service` with authn/authz, audit, and
  rotation; deployment artifacts for the sponsor's environment.
- **Acceptance:** automated security tests pass; no unauthenticated mutating
  endpoint; key rotation demonstrated; load/latency targets met under
  `--release` benchmarks.

## Phase C — Operator / auditor console (M2–M4)

- **Objective:** UI to issue authority, inspect packets, **verify (incl.
  offline)**, visualise the accountability graph, and export evidence
  bundles.
- **Deliverables:** console application; offline-verifier build for
  air-gapped use.
- **Acceptance:** an evaluator with no network access verifies a packet and
  reconstructs its authority chain; every UI check maps 1:1 to an engine
  rule (no UI-side verification logic).

## Phase D — Integration with the sponsor use case (M3–M6)

- **Objective:** instrument the sponsor's chosen agent/workflow so each
  consequential action emits an EvidencePacket; integrate with the sponsor's
  identity/authority roots.
- **Deliverables:** integration adapter/SDK; populated cross-language
  conformance vectors; integration test report.
- **Acceptance:** end-to-end run in the sponsor's representative environment
  produces packets that verify at `AUTHORITY_BOUND` (and
  `COUNTERPARTY_SIGNED` where a counterparty exists).

## Phase E — Security review & accreditation support (M5–M7)

- **Objective:** independent security assessment; support accreditation for
  the target environment.
- **Deliverables:** threat model, third-party/security-cell review response,
  remediation; documentation set.
- **Acceptance:** review findings closed or risk-accepted by the sponsor;
  accreditation pre-requisites met. (Targets: CERT-In empanelled assessment,
  and alignment with applicable MoD cyber guidelines — see document 07.)

## Phase F — Field prototype trial & report (M6–M9)

- **Objective:** demonstrate the prototype in a relevant/operational
  environment.
- **Deliverables:** trial plan, execution, and **field-trial report**
  including tamper-detection and offline-verification demonstrations.
- **Acceptance:** sponsor confirms TRL 6–7 criteria met; go/no-go for
  productisation/induction documented.

## Milestone summary

| Phase | Window | Headline deliverable | TRL after |
|---|---|---|---|
| A | M0–M1 | Use-case + interface spec | 4 |
| B | M1–M3 | Hardened service + KMS | 5 |
| C | M2–M4 | Operator/offline console | 5 |
| D | M3–M6 | Sponsor integration | 6 |
| E | M5–M7 | Security review/accreditation support | 6 |
| F | M6–M9 | Field-trial prototype + report | 6–7 |

`[FILL IN: align windows and fund-disbursement milestones to the selected
iDEX scheme; total programme duration target ~9–12 months.]`

## Risk register (top items)

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Sponsor integration access/clearances delayed | Med | High | Phase A gate; parallelise B/C which need no classified access |
| Accreditation longer than planned | Med | Med | Engage security cell early (Phase A); design to known guidelines |
| Key-management/HSM constraints in target env | Med | Med | Abstract KMS interface; support multiple backends |
| Scope creep beyond accountability (e.g. asked to add detection/autonomy) | Med | Med | Hold the scope boundary in document 03; accountability only |
| Small-team key-person dependency | Med | High | Hire plan in document 06; document and test everything |
