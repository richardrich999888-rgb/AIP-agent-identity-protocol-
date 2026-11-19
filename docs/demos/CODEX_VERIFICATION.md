# Verification of the Codex pull requests (2026-11-19)

Done read-only from this session: separate worktrees and a separate build
directory, nothing pushed, no GitHub comments. Logs:
`scratchpad/codex-verify/*.log` on the machine that ran them. Machine:
4 vCPU, 15 GB RAM, no GPU. This host does not have tracefs mounted, so the
native kernel tests skip here. Those claims rest on the hosted CI logs the
PRs cite, and are marked as such.

## PR #20 — Fix native attribution and classify historical security findings
`codex/p0-048-snifferdog-enterprise-assurance` → `fix/vanian-end-to-end-green`.
**Partially verified: nothing failed. Only claims needing a privileged kernel
or hosted artifacts are unchecked.**

| Claim | Result |
|---|---|
| A stale exec no longer binds to the wrong process instance | **Verified.** Restoring the pre-fix `probe.rs` makes `lifecycle_races` fail 6/8; with the fix, 8/8 pass |
| Repeated socket rows no longer inflate evidence | **Verified.** Pre-fix code fails `repeated_signed_socket_records_count_as_one_fact`; the edge observer gains 6 tests (from 0) |
| `fmt`, `clippy -D warnings`, tests on aip-observe / aip-edge / aip-edge-observer | **Verified:** 339 passed, 0 failed, 1 ignored (an existing throughput benchmark) |
| 17 classification tests, 3 scanner controls | **Verified.** Python 17 + 15 + 3 OK; controls 3/3 (a copied manifest gives 4 new blocking findings; a synthetic secret is caught by both gitleaks and trivy) |
| Scanner exceptions are narrow | **Verified.** Exact-fingerprint `.gitleaksignore` entries. The trivy gate accepts only the 4 known findings, after hash-checking the source file, and fails if one disappears or the scanner errors. Trivy runs with no ignore file |
| Ten native Linux tests must really run | Gate logic **verified**. The runs themselves skip here; hosted run 43582310061 shows `{"status":"PASS","cases":10}` |
| 286 prior evidence files byte-identical | **Verified**, with one nuance: `iteration-004/README.md` is edited by a later commit in the same PR |
| Genuine-agent batch counts, coverage run, Rust 1.100 drift | **Not checked** (hosted artifacts) |

Concerns: CI is pinned to Rust 1.99.1 because a newer Cargo breaks a test
launcher. That is stated, but deferred rather than fixed. The four HIGH Helm
findings remain, classified, and the deployment is explicitly not qualified.

## PR #23 — Reject mixed executable snapshots and retain assurance evidence
`codex/p0-057-independent-agent-assurance` → PR #20's branch.
**Partially verified: every count reproduced. Hosted and ContextForge parts
are unchecked.**

| Claim | Result |
|---|---|
| 455 tests on aip-core / aip-reconcile / aip-mcp-gateway / aip-observe-verify | **Verified: 455 passed**, 0 failed, 0 ignored |
| 102 aip-observe tests, real-exec ones not skipped | **Verified: 102 passed**. Both real-exec tests ran |
| The two race regressions fail before the fix | **Verified two ways.** The PR's own `baseline-reproducer.patch` at `ceb7682` makes both fail. Disabling the final consistency check makes both fail |
| Verifier controls 8 / 6 / 6; sha256 manifests for iterations 001–003 | **Verified** |
| Bounded, read-only journal export | **Verified by reading the code.** Read-only database, hashed identifiers, 1,000-row cap, labelled not-proof |
| 27 ContextForge checks; 10 hosted kernel tests | **Not checked** (need ContextForge and a tracefs host) |

Concerns: the fix narrows the exec race but cannot close it (an exec just
after the final check, or into an identical file). The code says so. The
genuine-agent workflow's missing-receipt failure is still unexplained, and
the PR says that too.

## PR #22 — Scoped native interface for AIRON integration
`codex/p0-056-airon-runtime-interface` → `feature/airon-teach-demo`.
**Partially verified, weak evidence.**

| Claim | Result |
|---|---|
| The 201-test runtime baseline passes | **Verified:** 201 passed; vanian-sovereign library 79/79, `agent_execution` 32, `sqlite_upgrade` 2 |
| "78 of 79 library checks" because of a host ptrace limit | **Not reproduced:** all 79 passed here, so the original failure was host-specific |
| Authorized delete updates the search index | **Checked by hand only.** Delete is limited to the same tenant and clearance; search afterwards returns nothing. **No test added** |
| A lower clearance cannot see or delete; `can_ingest:false` refused; world-readable config refused; unknown fields refused | **Checked by hand** |
| AIRON's 20 integration tests with real Docling | **Not checked** (external repository) |
| Base `93c65bc` | **Out of date:** `feature/airon-teach-demo` is now 5 commits further on (`3cd5846`) |

Concerns:
- The new trust-boundary binary `airon-bridge` and `SqliteCorpus::delete` have **no tests**.
- Its trivy check is red on GitHub and the description doesn't mention it. It is probably the same inherited Helm finding.
- File-permission checks cover only the config and identity files.

## Also found while checking PR #13 (this branch)

`cargo audit · cargo deny` turned red on 2026-11-19 because of two advisories
published after 7 November, both in base-branch dependencies:
- **RUSTSEC-2026-0459:** bundled SQLite in `libsqlite3-sys` 0.30, via `rusqlite` 0.32 in `vanian-sovereign`. Fixed in `rusqlite` 0.41, which needs Rust 1.89.
- **RUSTSEC-2026-0543:** `chrono` is unmaintained; it is used by `airon-aip`.

Not ignored here; the fix belongs to those crates' owners.
