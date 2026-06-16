# 06 — Due-Diligence Data Room

Status: **READY** (exists, code/doc-backed) · **PARTIAL** (started/incomplete)
· **MISSING** (not yet produced). Audiences: A=angels, V=VCs, B=banks,
Au=auditors.

## Technology & code

| Artifact | Status | For | Where / note |
|---|---|---|---|
| Source repository (Rust) | READY | A V B Au | this repo |
| Builds clean | READY | A V | `cargo build --workspace` |
| Test suite (core 214 / svc 37) | READY | A V Au | `cargo test` |
| Reproducible demo (loan example) | READY | A V B Au | `cargo run -p aip-protocol --example loan_approval` |
| Open spec (EvidencePacket + rules) | READY (v0.1-draft) | B Au | `AIP_SPEC.md` |
| Architecture & migration notes | READY | V B | `docs/STRATEGY_*`, `aip-service/MIGRATION_NOTES.md` |
| Threat model | READY (summary) | B Au | `01_EVALUATION_PACKAGE.md` §6 |
| Cross-language conformance vectors | MISSING | B Au | needed before SDKs |
| Standalone signed verifier binary | MISSING | Au | P1 — auditor self-service |
| Audit-export bundle | MISSING | Au | P1 |
| SBOM / dependency inventory | PARTIAL | B | `Cargo.lock` exists; no formal SBOM |
| CI pipeline (build+test gating) | MISSING | A V | no `.github` workflow yet |

## Security & compliance

| Artifact | Status | For | Note |
|---|---|---|---|
| Auth + tenant-isolation design + tests | READY | B Au | `auth.rs`, `vault.rs` |
| Credibility/corrections record | READY | A V B Au | `AUDIT_CORRECTIONS.md` |
| Independent security assessment (CERT-In) | MISSING | B Au | pre-deployment blocker |
| SOC 2 / ISO 27001 | MISSING | B | post-pilot |
| Key-management/HSM design doc | MISSING | B | pre-prod |
| Data retention / DR / BCP plan | MISSING | B | pre-prod |
| Control-framework mapping (SOX/EU AI Act/NIST) | MISSING | Au | needed for audit opinion |
| Pen-test report | MISSING | B | pre-prod |

## Commercial & corporate

| Artifact | Status | For | Note |
|---|---|---|---|
| Pilot evaluation pack (this folder) | READY | B Au | `docs/design_partner/` |
| iDEX submission pack | READY (placeholders) | V | `docs/idex_open_challenge/` |
| Product/strategy narrative | READY | A V | `docs/STRATEGY_TRUST_INFRASTRUCTURE.md` |
| Provisional patents | PARTIAL | A V | `reports_and_patents/` — honest IP position in `04_INNOVATION_AND_IP.md` |
| Cap table / incorporation / financials | MISSING | A V | founder to provide |
| Team CVs / key-person | MISSING | A V | founder to provide |
| Design-partner LOI / pipeline | MISSING | A V B | none yet — the goal of this pack |
| Pricing / commercial model | MISSING | V B | not yet defined |
| References / case studies | MISSING | B | none until first pilot |

## Prioritised MISSING list (do these next, in order)

1. **Standalone signed verifier binary** + **audit-export bundle** — unblocks
   auditor self-service; small build on existing `verify_packet`.
2. **Independent security assessment (CERT-In)** — the universal bank/auditor
   pre-deployment gate.
3. **Durable storage + backup/DR plan** — replace single-file vault; the CRO's
   operational blocker.
4. **Key rotation + KMS/HSM design** — key-compromise story.
5. **Control-framework mapping** (SOX authorization / EU AI Act traceability)
   — lets a Big-4 partner actually opine.
6. **CI pipeline + SBOM** — table-stakes engineering credibility for VCs.
7. **Founder/corporate artifacts** (cap table, team, financials) — investor data room.
8. **First design-partner LOI** — the single most valuable missing item; every
   other artifact exists to obtain it.
