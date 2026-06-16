# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning is [SemVer](https://semver.org/).

## [Unreleased]

### Added
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
