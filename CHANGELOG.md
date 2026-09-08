# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning is [SemVer](https://semver.org/).

## [Unreleased]

### Security
- **Observer integrity boundary (observation-integrity finding).** A foreign
  eBPF program on a tracepoint Sniffer Dog samples suppresses that tracepoint's
  perf submission host-wide with no dropped-record accounting, so a live,
  continuity-verified observer can be silently blind — and, before this change,
  still sign `Active` coverage and let a blinded window drive a `PhantomClaim`.
  Fixed, fail-safe and strictly monotone (it can only turn a coverage claim
  into `CannotProve`, never the reverse):
  - New `ObserverState::IntegrityUnknown`, carried inside the signed
    `SensorHealth`, set when the collector detects a foreign tracepoint gate.
  - `PerfTracepoints::foreign_bpf_program_count` (via `PERF_EVENT_IOC_QUERY_BPF`)
    and `ProcessTracer::mechanism_integrity` — the synchronous, fail-closed
    detector.
  - `covered_by_kernel_pushed_source` now requires a gate-independent
    kernel-pushed mechanism (netlink connector / `fanotify` / `AF_PACKET`); a
    lone perf-tracepoint mechanism no longer licenses a non-occurrence claim.
  - Reconciler maps `IntegrityUnknown` to `cannot_prove(ObserverIntegrityUnknown)`.
  - **Wire change:** `OBSERVE_PROTOCOL_VERSION` 8 → 9 (additive state code
    `0x06`; all in-tree records rebuild against v9). `CANNOT_PROVE`,
    `EvidenceCeiling` and the single reconciler authority are unchanged.
  Specs: `docs/OBSERVATION_INTEGRITY_REQUIREMENTS.md`,
  `docs/OBSERVATION_MECHANISM_INDEPENDENCE.md`,
  `docs/OBSERVATION_INTEGRITY_DECISION_RECORD.md`; reproduction in
  `validation/observation_integrity/`.

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
