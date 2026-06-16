# Contributing to AIP

## Repository layout

Two independent Cargo workspaces:

- `aip-standalone/` — the strategic core: `aip-types`, `aip-crypto`,
  `aip-core`, `aip-protocol`, plus `aip-cli`, `aip-verify`, `banking_demo`,
  and test crates.
- `aip-service/` — the deployable HTTP service (thin layer over the core).

CI runs `fmt`, `clippy -D warnings`, and `test` against **both**.

## Branch model

```
main         protected; always releasable; tagged releases cut from here
develop      integration branch; CI must be green
feature/*    one branch per change, branched from develop
```

Rules:

- **No direct commits to `main`.** Changes reach `main` only via PR from
  `develop` (or a release PR).
- **All changes go through a Pull Request.** Use the PR template.
- **CI must pass before merge** (fmt, clippy with `-D warnings`, tests,
  `cargo audit`, `cargo deny`). The security workflow must also be green.
- At least one review approval before merge.

## Local checks before opening a PR

Run in each workspace you touched:

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --all
```

`aip-standalone` additionally has release-only perf gates:

```bash
cargo test --all --release
```

## Commit convention

`<type>(<scope>): <subject>`

Types: `feat` · `fix` · `docs` · `test` · `security` · `ci` · `infra` · `refactor`

Examples:

```
feat(evidence): add signed audit export
fix(auth): enforce tenant isolation on get_evidence
security(keys): store API secrets as SHA-256 hashes only
ci(workflows): add cargo-deny gate
docs(readme): document aip-verify usage
refactor(vault): derive authority graph from records
```

## What not to do during a hardening sprint

- Do not introduce new cryptographic primitives, protocols, or product
  features. Operational maturity and existing-primitive productization only.
- Do not commit secrets, private keys, or `*.jsonl` data files
  (`.gitignore` excludes them; the security workflow scans for them).

## Definition of done

- Code compiles, is formatted, clippy-clean (`-D warnings`).
- Tests cover the change; tamper/negative cases included for verification logic.
- Docs and (if behavior/schema changed) `MIGRATION_NOTES.md` and `CHANGELOG.md`
  updated.
