# Production Readiness Checklist

Status: ✅ done · 🟡 partial / pilot-grade · ⬜ not started.
Honest as of the current commit; see `aip-service/MIGRATION_NOTES.md` and
`docs/design_partner/04_PILOT_READINESS.md` for detail.

## Security

| Item | Status | Notes |
|---|---|---|
| Authentication on endpoints | ✅ | API keys (bearer), fail-closed |
| Tenant isolation | ✅ | per-record tenant; cross-tenant reads denied |
| Secrets at rest | ✅ | API secrets stored only as SHA-256 hashes |
| Role separation | 🟡 | machine / admin; finer RBAC later |
| **TLS** | ⬜ | terminate at ingress/proxy; not in-service |
| **Rate limiting** | ⬜ | not implemented |
| **Key rotation** | 🟡 | API keys: edit file + restart; no rotation endpoint |
| **KMS/HSM for signing key** | ⬜ | signing seed is a local file today |
| Dependency scanning | ✅ | `cargo audit` + `cargo deny` in CI |
| Secret scanning | ✅ | gitleaks in security workflow |
| Filesystem vuln scan | ✅ | trivy in security workflow |
| Independent security assessment | ⬜ | CERT-In / pen-test — pre-deployment blocker |
| Memory safety | ✅ | Rust |

## Reliability

| Item | Status | Notes |
|---|---|---|
| Durable storage | 🟡 | append-only JSONL file; single node |
| **Backups** | ⬜ | operator-provided in pilot; no built-in tooling |
| **Disaster recovery / BCP** | ⬜ | not defined |
| High availability | ⬜ | single instance |
| Graceful degradation (non-gating) | ✅ | AIP records; not in the transaction critical path (pilot design) |
| Idempotent writes | ✅ | vault `store` idempotent on packet id |

## Operations

| Item | Status | Notes |
|---|---|---|
| Container image | 🟡 | `deploy/docker/Dockerfile` builds from the single root workspace (fixed 2026-09; it previously referenced a deleted manifest). **Not built or smoke-tested in CI.** |
| Compose topology | 🟡 | `docker-compose.yml` (service + postgres; minio placeholder). Requires `AIP_KEY_PASSPHRASE` (the service refuses an unwrapped key outside `AIP_CUSTODY_POLICY=development`); compose now fails fast if it is unset. **No CI smoke test.** |
| CI (fmt/clippy/test/audit/deny) | ✅ | `.github/workflows/ci.yml` |
| Release pipeline | 🟡 | `.github/workflows/release.yml` ships `aip-service`, `aip-verify`, `nexora-verify` with per-target `SHA256SUMS`. **Checksummed, not signed** — no cosign/sigstore/GPG. |
| **Metrics / monitoring** | ⬜ | structured `tracing` logs only; no metrics/SIEM export |
| Config via env | ✅ | documented in compose + Dockerfile |
| Runbook | ⬜ | not written |

## Compliance

| Item | Status | Notes |
|---|---|---|
| Data residency / on-prem | ✅ | no foreign cloud in trust path; fully offline-deployable |
| PII minimization | ✅ | inputs/payloads referenced by hash; content can stay out of the packet |
| Retention / immutability tooling | ⬜ | append-only by construction; no retention controls yet |
| Control-framework mapping (SOX / EU AI Act / NIST) | ⬜ | not written |
| SOC 2 / ISO 27001 | ⬜ | none |

## Auditability

| Item | Status | Notes |
|---|---|---|
| Independent offline verification | ✅ | `aip-verify`; pure function of packet + trusted keys |
| Tamper detection | ✅ | hash + agent signature; catches hash-recomputing attacker |
| Authority reconstruction | ✅ | `/v1/authority/{id}` + accountability graph |
| Privileged-action audit logging | 🟡 | revoke logs admin key id; broader audit log pending |
| Signed audit-export bundle | ✅ | `GET /v1/evidence/{id}/export` → signed ZIP (manifest + detached Ed25519); `aip-verify <bundle.zip> --trust-bundle-signer <pk>` verifies offline. The embedded report is integrity-level only; the auditor re-runs with their own anchors. |
| Open format / spec | ✅ | `AIP_SPEC.md` (v0.1-draft) |

## The pre-production blocker list (must close before a regulated rollout)

1. TLS + rate limiting at ingress.
2. Independent security assessment (CERT-In) + remediation.
3. Durable, backed-up storage (replace single-file vault) + DR/BCP.
4. KMS/HSM for the signing key + API-key rotation.
5. ~~Signed audit-export bundle + standalone verifier distribution~~ —
   **closed.** `GET /v1/evidence/{id}/export` emits a signed bundle;
   `aip-verify` (packets, bundles) and `nexora-verify` (Ghost verdicts,
   NEXORA proofs) are both built by `release.yml`. Remaining: release
   artifacts are checksummed, not signed (see Operations).
6. Metrics/monitoring + runbook.
7. Control-framework mapping for the target jurisdiction.
