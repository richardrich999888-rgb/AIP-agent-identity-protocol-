# Iteration 003 — delayed lifecycle binding evidence

Parent commit: `353b2169e48fd000aa079ef6afa94ad0e02afbe7`.
Date: 12 November 2026; command receipts use UTC.
Single selected item: P0-048-B delayed connector-event binding and cache ordering.

## Acceptance and actual results

Require reproducible failures before correction; keep stale events unbound and
retain their originals; prevent stale exits consuming newer bindings; invalidate
an older binding on failed newer measurement; keep positive, concurrent-instance
and loss controls; preserve CANNOT_PROVE and offline signatures; report host
restrictions without weakening checks; publish only to the feature branch.

| Evidence | Result |
|---|---|
| `baseline-lifecycle.*` | New tests over unchanged parent production code: 2 pass, 6 fail |
| `fixed-lifecycle.*` | Same eight regressions pass |
| `scoped-regression-complete.*` | 489 executed passes, nine blocked early returns, one failed BPF test, one ignored timing benchmark; overall exit 101 |
| `baseline-xdp*` | Independently compiled unchanged baseline test reproduces EPERM failure; no repository library is linked |
| `format.*`, `clippy.*` | Workspace formatting and scoped all-target Clippy pass |
| `retained-lifecycle.*` | Eight regressions pass; fresh synthetic signed originals retained |
| `offline-verification/summary.json` | Four checks pass: signature, missing-health refusal, one-byte attack, wrong anchor |

Cargo reports 498 `ok` results; nine are capability-dependent early returns and
are excluded from the 489 executed passes. `blocked-tests.json` names every one,
the actual BPF failure and the explicit release-only timing exclusion. No new
capture-rate, latency, throughput or scalability benchmark is claimed.

The first scoped offline attempt failed because the fresh cache lacked existing
locked dependency `hex 0.4.3`. `scoped-build.*` records its download/build under
`--locked`; the subsequent full run used `--offline`. The first full run stopped
at BPF failure; `scoped-regression-complete.*` uses `--no-fail-fast` to expose all
remaining results. Both failed attempts are retained. An initial direct `cargo
fmt` invocation lacked the toolchain bin directory in PATH and reported no fmt
subcommand; `format-apply.*` and `format.*` record the corrected environment.
An initial metadata collection tried the removed nested Cargo.lock path; collection
was corrected to the unchanged repository-root Cargo.lock before saving its receipt.

## Reproduce

Use Rust 1.99.1 with the component hashes and licences in `toolchain.json` and
the repository-root Cargo.lock. No dependency manifest changed. The restored
toolchain was installed after reading the audit/checkpoint, using the already
recorded pinned official manifest hash. `install_rust.py` is the exact local
restoration script, not a clean-host installer or air-gap bundle.

From the repository root, with the pinned toolchain on PATH:

```sh
cargo test --locked --offline -p aip-observe --test lifecycle_races -- --nocapture
cargo test --locked --offline --no-fail-fast -p aip-observe -p aip-reconcile -p aip-observe-verify -- --nocapture --test-threads=4
cargo fmt --all -- --check
cargo clippy --locked --offline -p aip-observe -p aip-reconcile -p aip-observe-verify --all-targets -- -D warnings
P0_048_LIFECYCLE_RETAIN_DIR=/tmp/p0-048-fresh-lifecycle cargo test --locked --offline -p aip-observe --test lifecycle_races -- --nocapture --test-threads=1
cargo build --locked --offline -p aip-observe-verify
python3 validation/p0_048/verify_lifecycle_archive.py --verifier /path/to/target/debug/aip-observe-verify --originals /tmp/p0-048-fresh-lifecycle --output /tmp/p0-048-fresh-verification
```

Retention and verifier output directories must not exist; originals are never
overwritten. Exact argv, cwd, selected environment, elapsed time, exit codes and
log hashes are in the matching JSON receipts. `run-command.py.txt` records the
local command recorder. `baseline-lifecycle_races.rs.txt` is the original test
source before formatting; its assertions are unchanged in the final test.
`revisions-and-source.json` records all fetched remote heads and source hashes.

`originals/` is explicitly **synthetic event stimulation with real local process
measurement**, not live netlink evidence. Its key is a same-administrator test
anchor. The native CLI's signature success does not imply an execution verdict,
authorization, observation completeness or independent custody. There is no
health file. The labelled mutation is stored separately. No network-isolated
clean host or independent collector infrastructure was used.

## CI and publication boundary

`prior-head-ci.json` records provider results for parent 353b216. Its main
format/Clippy/debug-release, audit, Python SDK, Postgres, RED, RBI and harness
checks passed. Coverage generation and same-run task logs completed, but both
artifact uploads failed after five attempts with an HTML response where JSON
was expected. Those missing uploads are not retained acceptance archives.
Security CI retained the earlier tokenizer-hash Gitleaks and inherited Helm
Trivy findings; none was suppressed. Current-head CI is reported on draft PR
#20 after publication, and pending checks are not passes.

`SHA256SUMS` covers this iteration's source/docs/evidence, excluding itself.
Validate older manifests against their own immutable commits because the live
checkpoint changes each iteration. Never rewrite historical signed evidence.
The lifecycle report and checkpoint identify the remaining work. No merge or
next-item execution is part of this iteration.
