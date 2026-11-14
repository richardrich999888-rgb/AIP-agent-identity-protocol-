# P0-049 iteration 2 — dependency gates

Implementation: `9e3909eea8328d7e81a5887a6e80430237642616`.
Review: [draft PR #21](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/pull/21).

**Release NOT READY.** This bounded iteration addresses the dependency-check
failure identified in iteration 1. It does not complete another teaching/demo
phase or earn rehearsal credit.

## Acceptance criteria

1. Replace the affected bundled SQLite and rustix versions with the upstream
   patched versions; retain exact Cargo.lock checksums and introduce no exemption.
2. Open actual database bytes written by the previous engine. Preserve search,
   tenant/clearance boundaries, quarantine and dependency digests; safely update
   content, FTS entries and versions across a close/reopen.
3. Preserve a failed audit exit through its report-writing pipeline. Prove both
   vulnerability and operational errors fail, and a clean audit still succeeds.
4. Run the affected runtime and consumer tests, formatting, clippy and dependency
   checks. Retain failures, raw outputs and source/CI provenance.

## Reconciled starting state

Started from `7de9ba4d0fb8da83ec294380e719b82ecadee7ca` on
`feature/airon-teach-demo`; the local tree was clean and matched draft PR #21.
Fetched AIP again and refreshed OVERLAY's 24-branch remote inventory. OVERLAY's
approved base remains `eccb66886d1f6b0b751909b6743d7e731e8061fb`; no wow-demo
branch appeared. No divergent branches were merged or unavailable commits reused.

The prior head's scoreboard and contract checks passed; Security failed. Main CI
was still running when inspected. A green `cargo audit (RUSTSEC)` job was not
reliable evidence of an empty advisory report: its unspecified Linux shell ran
`cargo audit ... --json | tee audit.json` without pipeline failure propagation.

## Change and evidence boundary

| Component | Before | After | Reason |
|---|---|---|---|
| rusqlite | Exact 0.32.1 | Exact 0.41.0 | Wrapper supporting patched bundled SQLite |
| libsqlite3-sys | Locked 0.30.1 / SQLite 3.46.0 | Locked 0.39.1 / linked SQLite 3.54.1 | RUSTSEC-2026-0459 |
| rustix | Locked 1.1.5 | Locked 1.1.6 | RUSTSEC-2026-0486 unsoundness warning |
| Security audit shell | Unspecified `bash -e` | Explicit `bash`, with `-eo pipefail` | Preserve failed audit/report-write status |

Rust 1.99.1 was used. rusqlite 0.41.0 declares Rust 1.89 as its dependency minimum;
this is not a claim that the whole workspace was tested on Rust 1.89. The upgrade
also changes the wrapper's hashlink/hashbrown dependencies and adds target-specific
Wasm dependencies to the lockfile; native Linux is the tested target. Historical
baseline inventories remain unchanged. No retrieval, validation, approval,
activation or signing algorithm was edited.

The regression fixture was generated with the old runtime and actual SQLite
3.46.0 before updating dependencies. Its decoded database SHA-256 is
`4f8be7e73bf20fbb17bc6f77dfa4ce5b9aaa2c1807aab5a351cee6fef4fac486`.
Nine tenant/clearance combinations retain their original results and hashes.
The generator, expected outputs and encoded bytes are under
`sovereign/vanian-sovereign/tests/fixtures/sqlite-032/`.

`validation/ci/test_audit_exit.py` executes the actual workflow command with a
temporary Cargo stub. The old shell control maps Cargo exit 1 and 42 to step exit
0. The patched step preserves both failures, retains the JSON report, accepts exit
0 and refuses a failed report write. These are failure-injection controls, not a
substitute for the real dependency scan.

The real cargo-audit 0.23.0 run used the same RustSec database snapshot
`fd6f39814c4d3c359fdbe223d0280dec4933f78f` for both lockfiles, with **no ignored
advisories**: old lockfile exit 1 (one vulnerability and one unsoundness warning),
updated lockfile exit 0 (zero vulnerabilities and zero warnings). The database was
staged beforehand; this check is not evidence of an offline package installation.
Exploit reproduction for malformed WAL files and rustix xattrs is not claimed.

## Reproduction

Local results: **284 tests passed** for vanian-sovereign and syntriass-runtime,
including two new database-upgrade tests and all 19 live namespace sandbox tests.
The other rustix consumers passed **144 tests** (including two doc-tests).
No failures or skips in either invocation. The four audit failure-propagation
tests passed; formatting and clippy with warnings denied passed. These are
separate from iteration 1's Python capability-learning test counts.

Real cargo-deny 0.20.2 also returned exit 0 for advisories, bans, licences and
sources, with `--locked` and the unchanged repository policy. Its raw JSON-lines
diagnostics retain all warnings: one unmatched existing advisory exemption and
68 duplicate/wildcard dependency warnings. No warning suppression was added.
The clean source commit was then rebuilt and the existing bounded recorder rerun
inside the network namespace: motor 14/14, expected transformer rejection 11/12,
corrected transformer 12/12, unchanged capability hashes and zero model calls.
This remains fixture-based C1 evidence, not completed teaching acceptance.

CI inspection found the source commit's workflows queued with no jobs assigned:
[scoreboard](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/43095210388),
[Security](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/43095210411),
[main CI](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/43095210476).
This is an outstanding verification dependency. No inference is made about the
queue's cause, and no remote check is counted as passed for this commit. The
workflow now includes the old-database regression tests; existing global tests
and Trivy checks remain enabled.

From the repository root, with the development toolchain/dependencies staged:

```bash
cargo test --locked -p vanian-sovereign -p syntriass-runtime -- --nocapture
cargo test --locked -p ot-accountability-core -p ot-sentinel -p aip-feed-conformance
cargo fmt --all -- --check
cargo clippy --locked -p vanian-sovereign -p syntriass-runtime --all-targets -- -D warnings
python3 -m unittest discover -s validation/ci -p 'test_audit_exit.py' -v
cargo audit --db /absolute/path/to/advisory-db --no-fetch --json
cargo deny check
```

Audit input is this repository's Cargo.lock. Pin the advisory database to the SHA
above to reproduce the recorded advisory classification; use a fresh database for
current release assessment. Building/installing the auditing tools may download
dependencies. Full offline installer acceptance remains open.

## Primary references

- [SQLite advisory](https://rustsec.org/advisories/RUSTSEC-2026-0459.html).
- [Pinned rustix advisory](https://github.com/RustSec/advisory-db/blob/fd6f39814c4d3c359fdbe223d0280dec4933f78f/crates/rustix/RUSTSEC-2026-0486.md).
- [rusqlite 0.41.0 release](https://github.com/rusqlite/rusqlite/releases/tag/v0.41.0).
- [GitHub shell execution semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idstepsshell).

Raw test, audit, failure-control and CI observations are retained in
`evidence/p0-049-iteration-2/`. They are unsigned engineering evidence. Full release
trust material, authenticated pack installation, C1 session/question linkage,
remaining W3, fresh OVERLAY demos and independent acceptance are still required.
