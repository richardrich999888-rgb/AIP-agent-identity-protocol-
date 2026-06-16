# Release Process

## Environments

```
Development  →  Staging  →  Production
 (feature/*)     (develop)     (main + tag)
```

- **Development:** feature branches; local checks + CI on PRs.
- **Staging:** `develop` branch; full CI green; deploy to a staging host for
  integration/pilot rehearsal.
- **Production:** cut from `main` at a signed tag; binaries from the release
  workflow.

## Required before a production release

All must be true:

- [ ] CI workflow green on `main` (fmt, clippy `-D warnings`, tests both workspaces).
- [ ] Security workflow green (`cargo audit`, gitleaks, trivy — no secrets, no
      CRITICAL/HIGH vulns).
- [ ] `CHANGELOG.md` updated with the release section (date + version).
- [ ] Version bumped (workspace `version` in `aip-standalone/Cargo.toml`;
      `aip-service/Cargo.toml`).
- [ ] `MIGRATION_NOTES.md` updated if behavior/schema changed.
- [ ] Production-readiness items relevant to the deployment reviewed
      (`docs/PRODUCTION_READINESS.md`).

## Cutting a release

```bash
# 1. Ensure develop is green, then open a release PR develop → main.
# 2. After merge, from main:
git checkout main && git pull
git tag -a v0.4.0 -m "v0.4.0"
git push origin v0.4.0
```

Pushing a `v*` tag triggers `.github/workflows/release.yml`, which:

1. Builds `aip-service` and `aip-verify` for linux-amd64, linux-arm64,
   macos-amd64, macos-arm64.
2. Produces per-target tarballs with `SHA256SUMS`.
3. Publishes a GitHub Release with the binaries attached and generated notes.

## Versioning

Semantic versioning. The EvidencePacket wire format is versioned separately by
its `version` field and `AIP_SPEC.md`; a breaking format change requires both a
spec bump and a major release.

## Rollback

Releases are immutable tags + binaries. To roll back, deploy the previous
tag's artifacts. The Evidence Vault is append-only and format-versioned, so
older binaries continue to verify previously stored packets.
