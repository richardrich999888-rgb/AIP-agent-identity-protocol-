# AIP — Technical Audit, TRL Assessment & Production Roadmap

> **⚠ Superseded on the TRL number.** This document's readiness assessment is
> dated 2026-08-23 and has been superseded by
> `docs/ENGINEERING_MATURITY_AND_STRATEGIC_READINESS.md` (2026-09-07), a
> post-validation addendum that assesses maturity **by component** rather than
> as one number: the AIRI/Sniffer Dog software accountability core at **~TRL 5,
> approaching TRL 6**, physical-autonomy profiles at TRL 4, and physical
> autonomous-system accountability at TRL 2–3. Everything else in this document
> stands. Cite the addendum, not this file, for a readiness level.

**Audit date:** 2026-08-23 · **Audited tree:** `main` @ `872dbf3` (+ nightly-CI fix)
**Owner:** K. NAGA SRI GANESH
**Method:** every claim below was re-verified against source, a clean local
build, and the full test suites during this audit. Nothing is carried over
from marketing or patent documents.

---

## 1. Executive summary

AIP is a working, tested, laboratory-validated **accountability infrastructure
for autonomous AI agents**: it issues cryptographic agent identities, enforces
mathematically attenuated delegated authority, and emits **offline-verifiable
tamper-evident evidence** of what an agent did and who authorized it.

- **What is real:** ~15,800 lines of Rust across two workspaces, zero `unsafe`
  code, an adversarial test suite (every tamper scenario must trip a specific
  named verification rule), a multi-tenant authenticated HTTP service with
  JSONL and PostgreSQL storage backends, a signed audit-export bundle format
  with a standalone verifier binary, Docker/compose deployment, and a
  fully green CI/security/release pipeline.
- **What is not real:** AEGIS, CCVL, Dilithium/PQC signing, TEE quote
  verification, quantum/neuromorphic anything. These exist only in
  patent-prose working documents (see `AUDIT_CORRECTIONS.md`).
- **System TRL: 4** (validated in laboratory environment). Component TRL for
  the crypto/evidence core: **4–5**. The credible 12-month path to TRL 7 and
  first revenue is a design-partner pilot on the existing pilot-grade
  service, followed by the hardening milestones in §6.

---

## 2. Exact technology contained in this repository

### 2.1 Core libraries — `aip-standalone/` (Cargo workspace, v0.4.0)

| Crate | LOC | What it implements |
|---|---:|---|
| `aip-types` | 619 | Wire-format data structures for identities, delegations, evidence |
| `aip-crypto` | 309 | Ed25519 (RFC 8032) sign/verify, SHA-256, Base58 `AIP-ID` derivation with checksum, raw-signature helpers for bundle manifests |
| `aip-core` | 5,179 | **Authority layer:** capability scope lattice with MEET (intersection) attenuation; depth-limited, per-hop-signed delegation chains; cascade revocation; nonce/replay protection; hash-chained scope-bound audit log; identity runtime & store; `.well-known` discovery document |
| `aip-protocol` | 2,395 | **Accountability layer:** `EvidencePacket` v1 (`AEP1` canonical length-prefixed encoding — never JSON-hashing); 14-rule verification engine producing a `VerificationReport` and a **derived** trust floor; accountability graph (Human → Delegate → … → Action → Receipt); signed audit-export **bundle** (`build_zip`/`verify_zip`) |
| `aip-cli` | 335 | Local CLI (identity/delegation/evidence operations) |
| `aip-verify` | 208 | Standalone offline verifier binary — verifies a single packet **or** a signed `.zip` audit bundle |
| `banking_demo` | ~400 | End-to-end demonstrator: authority → delegation → action → evidence → tamper detection |
| `aip-test`, `aip-real-tests` | 2,150 | Adversarial, property, stress, edge-case and security test crates |

### 2.2 Service — `aip-service/` (v0.2.0, axum)

4,201 LOC. Binaries: `airon-aip` (HTTP service), `aip-migrate` (JSONL→PostgreSQL migration).

- **Endpoints:** `/health`, `/v1/identity/{issue,verify,public-key,delegate,verify-chain,revoke}`, `/v1/evidence/{generate,verify,:id,:id/export}`, `/v1/authority/:id`, `/.well-known/jwks.json`.
- **Auth:** API-key bearer auth, fail-closed; secrets stored only as SHA-256
  hashes; roles `machine`/`admin`; per-tenant isolation enforced as a storage
  envelope (cross-tenant reads denied).
- **Tokens:** EdDSA (Ed25519) JWTs with strict validation (no leeway,
  algorithm pinned), unique `jti` per token, revocation set.
- **Storage:** `EvidenceStore` trait with two backends — append-only JSONL
  (default) and **PostgreSQL** (`--features postgres`, deadpool pool,
  advisory-locked schema init, `deploy/sql/schema.sql`).

### 2.3 Deployment, CI, supply chain

- `deploy/docker/Dockerfile` — multi-stage, non-root runtime user, ships
  `aip-service` + `aip-migrate` + `aip-verify`; `docker-compose.yml` with
  PostgreSQL; example key file (hashes only, gitleaks-allowlisted).
- `.github/workflows/ci.yml` — fmt, clippy `-D warnings`, tests, cargo-audit,
  cargo-deny, coverage. `security.yml` — nightly cargo-audit, gitleaks,
  trivy (secrets + IaC misconfig). `release.yml` — tag-triggered binaries for
  4 targets (linux x86_64/aarch64, macOS x86_64/aarch64) with `SHA256SUMS`.
- `deny.toml` — license policy (`LicenseRef-Proprietary` for own crates) and
  one justified advisory ignore (RUSTSEC-2026-0097: `rand` unsoundness not
  reachable — AIP uses `OsRng` only).

### 2.4 Specifications & commercial documents

`AIP_SPEC.md` (open packet spec), `docs/AUDIT_EXPORT_SPEC.md`,
`docs/PRODUCTION_READINESS.md`, `docs/BACKUP_AND_RECOVERY.md`,
`docs/STORAGE_PERFORMANCE.md`, investor dossier, 7-document design-partner
pack, 8-document iDEX defence submission pack, `ROADMAP.md`,
`AUDIT_CORRECTIONS.md`.

### 2.5 Explicitly NOT in this repository (despite patent-document prose)

| Claimed in `reports_and_patents/` | Reality |
|---|---|
| AEGIS ("AI containment layer", `aegis/src/lib.rs`) | No such code or directory |
| CCVL three-channel content engine, `resolver.rs`, `audit.rs` | No such code |
| Dilithium-3 / ML-DSA / any post-quantum signing | Not implemented; format only reserves an algorithm byte |
| HELIX / CORTEX / quantum / neuromorphic layers | Fiction |
| TEE enclave-quote verification | Structural checks only |

These are recorded in `AUDIT_CORRECTIONS.md` and must never appear in
customer- or investor-facing claims.

---

## 3. Audit results (verified 2026-08-23)

| Check | `aip-standalone` | `aip-service` |
|---|---|---|
| `cargo fmt --check` | clean | clean |
| `cargo clippy --all-targets -- -D warnings` | clean | clean |
| `cargo test --workspace` | see §3.1 | **38 passed, 0 failed** |
| `unsafe` blocks | **0** | **0** |
| cargo-audit / cargo-deny | green (1 justified ignore) | green |

### 3.1 Test suites

- `aip-standalone`: **223 passed, 0 failed, 3 ignored** across 9 test
  binaries (largest: 109 unit tests in `aip-core`, 67 adversarial tests in
  `aip-real-tests`; the ignored tests are wall-clock throughput gates that
  only run meaningfully under `--release`).
- `aip-service`: 38 passed, 0 failed, 0 ignored (PostgreSQL integration
  tests additionally run under `--features postgres` with a live database).
- The verification suite is adversarial by construction: each tamper
  scenario must flip a **specific named rule**, so silently weakened checks
  fail the build.

### 3.2 CI status

- PR pipeline: green (all checks passed on the PR #2 head).
- Nightly `Security` workflow: was **failing since 2026-07-21** — the
  scheduled gitleaks job scans full git history and flagged the two
  documented sample-key SHA-256 hashes in `deploy/docker/keys.example.json`
  (rule `generic-api-key`) at historical commit `51a04c9`. **Fixed in this
  audit** by adding `.gitleaks.toml` (path allowlist for the example file,
  default ruleset otherwise) and `.gitleaksignore` (fingerprints for the two
  historical findings). Verified locally with gitleaks 8.24.3: full-history
  scan exits 0. *Takes effect on main once this branch is merged.*

### 3.3 Known debt (honest list)

1. **Stale docs:** `docs/idex_open_challenge/02_TECHNOLOGY_AND_TRL.md` still
   calls the service "unauthenticated" (auth + tenants + PG landed later);
   `PRODUCTION_READINESS.md` "Durable storage" row predates the PostgreSQL
   backend.
2. **Patent overclaims** quarantined in `reports_and_patents/` (see §2.5).
3. `[FILL IN]` placeholders in iDEX documents 00/04/06 (entity, budget, CVs)
   — deliberate, only the founder can complete them.
4. No TLS in-process, no rate limiting, no metrics endpoint, no KMS/HSM,
   single-node (full gap list in §5).

---

## 4. Technology Readiness Level (honest assessment)

TRL scale per ISO 16290 / DoD definitions.

| Component | TRL | Evidence & limiting factor |
|---|:-:|---|
| Cryptographic primitives (Ed25519, SHA-256 via audited crates) | 8–9 (inherited) | Standards-based, mature libraries; *our use* of them is validated at lab scale only |
| Identity + AIP-ID binding (`aip-crypto`, `aip-types`) | 5 | Complete, adversarially tested; not yet exercised against a hostile external party |
| Authority layer: delegation, scope MEET, revocation (`aip-core`) | 4–5 | Complete + property/stress tested in lab; no operational deployment |
| Accountability layer: EvidencePacket + 14-rule verifier + bundle (`aip-protocol`, `aip-verify`) | 4–5 | Offline verification round-trips end-to-end incl. tamper cases; no third-party auditor has consumed bundles in production |
| HTTP service (auth, tenants, JSONL/PG storage) | 4 | Pilot-grade; lacks TLS-in-process, rate limiting, HA, metrics |
| Deployment (Docker/compose/release pipeline) | 4 | Builds and runs; never operated in a customer environment |
| Console / SDKs / KMS / TEE / PQC | 0–2 | Concept or reserved-format-hook only |
| **Integrated system** | **4** | *Technology validated in laboratory environment.* The gate to TRL 5–6 is one external pilot in a relevant environment; to TRL 7, a production-representative deployment with a design partner. |

**What would falsify TRL 4?** Nothing currently — the demo, tests, and CI
reproduce it (`cargo test --workspace`, `cargo run -p banking-demo`).
**What blocks TRL 5+?** No external environment has run AIP against real
workloads. That is a deployment/traction gap, not an engineering-quality gap.

---

## 5. Gap analysis to production

**P0 — blockers for any paid production deployment**

| Gap | Current state | Required |
|---|---|---|
| TLS | Terminate at external proxy only; PG connection `NoTls` | rustls in-process option + TLS to PG; documented ingress pattern |
| Rate limiting / quotas | None | Per-key token bucket (tower middleware) + tenant quotas |
| Key rotation | Edit file + restart | Rotation endpoint + overlapping key validity; signing-key rotation runbook |
| KMS/HSM | Signing seed is a local file | KMS-backed seed (age/sops minimum; cloud KMS or HSM for enterprise) |
| Metrics/monitoring | `tracing` logs only | `/metrics` (Prometheus), RED metrics, alert pack, SIEM export |
| Backups/DR | Operator-provided | pg_dump + WAL archiving scripts, restore drill, documented RPO/RTO |
| Independent security assessment | None | External pen-test / CERT-In empanelled review before first paid tenant |

**P1 — needed to sell beyond a hand-held pilot**

- High availability (stateless service replicas + managed PG), retention
  policies, admin/auditor **console** (issue, inspect, verify, visualize —
  the current surface is API-only), Python/TypeScript **SDKs** + OpenAPI
  spec, conformance test-vector suite for third-party verifier
  implementations, finer RBAC, runbook.

**P2 — differentiation / expansion**

- Transparency-log anchoring of packet hashes, PQC signature option (ML-DSA
  behind the reserved algorithm byte), real TEE attestation, agent-framework
  integrations (MCP, LangChain, OpenAI/Anthropic agent SDKs), compliance
  mappings (EU AI Act Art. 12 & 26 logging/oversight, NIST AI RMF, SOX ITGC).

---

## 6. Technical roadmap to a production-ready, monetizable product

Phases are gated by acceptance criteria, not dates alone. Indicative
timeline assumes 1–2 engineers + founder.

### Phase 0 — Hygiene (this week)
- Merge the nightly-CI fix to `main`; confirm scheduled Security run green.
- Refresh the two stale docs (§3.3.1); keep `AUDIT_CORRECTIONS.md` canonical.
- Tag `v0.4.0` to exercise the release pipeline end-to-end.
- **Exit:** all three workflows green on main including the nightly; signed
  binaries downloadable.

### Phase 1 — Pilot hardening (months 0–3) → TRL 5
- TLS: rustls listener option; TLS to PostgreSQL; ingress reference config.
- Rate limiting per API key + body-size and concurrency limits.
- `/metrics` Prometheus endpoint + basic Grafana dashboard + alert rules.
- API-key rotation endpoint (dual-validity window); signing-key rotation
  runbook; secrets via env/file mounts documented for k8s.
- Backup/restore scripts + drill (documented RPO ≤ 24h, RTO ≤ 4h pilot-grade).
- OpenAPI 3.1 spec generated from the router; Python + TypeScript SDKs
  (thin, generated + hand-polished); quickstart of ≤ 15 minutes.
- Recruit **2–3 design partners** (fintech ops, AI-agent platform, internal
  audit teams) running the pilot playbook in `docs/design_partner/`.
- **Exit:** one external organization generating and verifying real evidence
  packets in *their* environment for 30 consecutive days.

### Phase 2 — Productization (months 3–6) → TRL 6
- Auditor/operator **console** (read-heavy web UI: search packets, render
  accountability graph, one-click offline-bundle export & verify).
- HA: stateless replicas behind LB, managed/replicated PostgreSQL, health
  and readiness probes, zero-downtime deploy.
- KMS integration (cloud KMS + PKCS#11 path for HSM); per-tenant signing keys.
- Retention & legal-hold controls on the evidence vault.
- Conformance suite: published test vectors so third parties can implement
  verifiers — this is what makes the *format* a standard and the moat real.
- External penetration test; fix findings; publish security whitepaper.
- SOC 2 Type I control implementation started (logging, access, change mgmt).
- **Exit:** a paying pilot ($ pilot fee) on an SLA; pen-test report clean of
  criticals; a third party has verified a bundle using only the spec.

### Phase 3 — Scale & moat (months 6–12) → TRL 7 + revenue
- Transparency-log anchoring (packet-hash Merkle roots to an append-only log).
- PQC option: ML-DSA-65 signing behind the reserved algorithm identifier,
  hybrid mode for migration (this converts the patent prose into truth).
- Agent-framework integrations: MCP server exposing issue/verify tools,
  LangChain/agent-SDK middleware that auto-emits EvidencePackets.
- Compliance packs: EU AI Act (Art. 12 record-keeping, Art. 26 oversight),
  NIST AI RMF mapping, SOX ITGC evidence exports — sold as content, cheap to
  build on the existing verifier.
- iDEX/defence track in parallel (docs 00–07): grant-funded TRL 6–7 field
  trial on sovereign infrastructure.
- **Exit:** 3+ paying customers, SOC 2 Type I report, one regulated-industry
  reference, defence pilot underway.

### Monetization model

| Stream | What is sold | Why it holds |
|---|---|---|
| **Open core** | Spec + `aip-verify` verifier free forever | Verification must be vendor-neutral or nobody trusts the evidence — this drives adoption, not revenue |
| **Evidence Vault (SaaS or self-hosted enterprise)** | Hosted authenticated service, PG vault, console, retention, HA, support | Per-agent/month + per-packet storage tiers |
| **Compliance packs** | AI-Act/NIST/SOX report generators on the vault | High-margin content on existing engine |
| **Enterprise licence** | Air-gapped deployment, KMS/HSM, priority support, indemnity | Defence/regulated buyers pay for sovereignty (§ iDEX pack) |
| **Grants (non-dilutive)** | iDEX/DRDO TRL-raising milestones | Funds the TRL 6–7 climb without equity |

**Pricing anchor for pilots:** ₹8–15L / $10–20k per design-partner pilot
(6 months, capped agents), converting to annual per-agent licensing.

---

## 7. Top risks

1. **Traction, not tech:** the binding constraint on TRL and revenue is a
   design partner, not engineering. Mitigation: Phase 1 exit criterion is
   external usage, and everything else is subordinated to it.
2. **Credibility debt from patent prose:** any investor or customer who
   greps the repo will find §2.5 claims. Mitigation: `AUDIT_CORRECTIONS.md`
   + this document state reality first; consider moving
   `reports_and_patents/` out of the product repo.
3. **Big-vendor adjacency:** IAM/observability vendors could bundle a
   look-alike. Mitigation: open conformance suite + first-mover evidence
   format (Phase 2) — the moat is the adopted format, not the code.
4. **Single maintainer / bus factor:** one owner today. Mitigation: Phase 1
   hire; everything already reproducible from CI.
