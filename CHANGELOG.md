# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning is [SemVer](https://semver.org/).

## [Unreleased]

### Added
- **Signed audit-export bundle.** `GET /v1/evidence/{id}/export` returns a
  portable `application/zip` (evidence, verification report JSON + Markdown,
  authority graph JSON + DOT, manifest, Ed25519 bundle signature) for offline
  verification by auditors/regulators. New `aip-protocol::bundle`
  (`build_zip`/`verify_zip`), raw Ed25519 helpers in `aip-crypto`, and
  `aip-verify bundle.zip` (PASS/WARNING/FAIL). Spec: `docs/AUDIT_EXPORT_SPEC.md`.
  Tenant-scoped export (cross-tenant → 404); every tamper scenario flips a
  named bundle check (tested in `aip-protocol/tests/bundle.rs` and an
  in-process HTTP test).

### Added (storage)
- **PostgreSQL Evidence Vault backend.** New `EvidenceStore` trait with two
  implementations: `JsonlEvidenceStore` (the original append-only file) and
  `PostgresEvidenceStore` (feature `postgres`) — durable, transactional,
  tenant-isolated. Handlers depend only on the trait; backend chosen at
  runtime via `AIP_STORE_BACKEND` (`jsonl` default | `postgres`) + `DATABASE_URL`.
- Schema: `evidence_packets` (+ tenant/hash/created_at indexes) and
  materialised, tenant-isolated `authority_nodes` / `authority_edges`
  (`deploy/sql/schema.sql`; applied idempotently on startup under an advisory
  lock).
- `aip-migrate` tool: idempotent JSONL → PostgreSQL import preserving each
  record's tenant (requires `--features postgres`).
- `aip-service` converted to lib + bins (`airon-aip`, `aip-migrate`).
- Live-DB integration tests (store/get/all/count, cross-tenant isolation,
  tenant-conflict, authority materialisation) gated by `AIP_TEST_DATABASE_URL`;
  10k-packet benchmark (`pg_benchmark_10k`, `--ignored`).
- `docs/BACKUP_AND_RECOVERY.md`, `docs/STORAGE_PERFORMANCE.md`; docker compose
  now wires PostgreSQL as the primary backend with a healthcheck.

### Changed
- Authority graph is now built from a supplied packet list
  (`AuthorityGraph::from_packets`), making it storage-backend agnostic.

### Added (prior)
- `aip-verify`: standalone offline EvidencePacket verifier CLI for auditors
  (`cargo install --path aip-standalone/aip-verify`). Verifies integrity with
  no configuration; accepts trusted issuer/counterparty keys and a revocation
  list for full authority verification.
- GitHub Actions: `ci.yml` (fmt, clippy `-D warnings`, test, audit, deny,
  best-effort coverage), `security.yml` (cargo-audit, gitleaks, trivy),
  `release.yml` (multi-target binaries → GitHub Release).
- `deny.toml` (cargo-deny) for both workspaces.
- `CONTRIBUTING.md`, `RELEASE_PROCESS.md`, `CHANGELOG.md`,
  `docs/PRODUCTION_READINESS.md`, PR template.
- `deploy/docker/`: production Dockerfile (workspace-aware) and
  `docker-compose.yml` (aip-service + postgres + MinIO object-storage
  placeholder) with documented environment variables.
- `aip-protocol` example `loan_approval` producing a real ₹5 crore
  EvidencePacket, verification report, and authority graph.

### Changed
- Cleaned all clippy `-D warnings` findings across both workspaces; both are
  now `fmt --check` and `clippy -D warnings` clean.

### Security
- (Prior) API-key authentication + tenant isolation on the service; secrets
  stored only as SHA-256 hashes; fail-closed when no keys configured.

## [0.4.0] — accountability layer

### Added
- `aip-protocol`: EvidencePacket v1, 14-rule verification engine,
  accountability graph.
- `aip-service`: `/v1/evidence/{generate,verify}`, `/v1/evidence/{id}`,
  `/v1/authority/{id}`; Evidence Vault (append-only, tenant-scoped); authority
  graph; API-key auth + tenant isolation; wired onto `aip-core`/`aip-protocol`.

### Fixed
- Reputation score integer overflow in `aip-core::calculate_reputation`
  (weighted mean no longer rescaled); bounds now property-tested.
- Broken `aip-standalone` workspace manifest (member paths) — workspace builds.

### Security
- Removed non-reproducing benchmark artifacts; marked experimental modules
  (reputation, hardware attestation, liveness) in rustdoc. See
  `AUDIT_CORRECTIONS.md`.
