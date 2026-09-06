# Evidence Base — Master Forensic Codebase Audit

**Audit date:** 2026-09-06
**Auditor posture:** forensic, read-only. No product source, test, or configuration file was modified. No commit was created on any product path. No branch was checked out or merged.
**Repository HEAD during audit:** `16493c5` on `claude/aip-security-architecture-audit-zpf9b3`; working tree clean throughout.
**Toolchain:** cargo 1.94.1 / rustc 1.94.1 (2026-03-25).

## Acquisition method

All six branch trees were obtained without altering the working tree:

```
git fetch origin <ref>
git archive <ref> | tar -x -C scratchpad/sixbranch/<alias>
```

No `git checkout`, no `git worktree`, no `git merge`. Every claim below is
anchored to a path of the form `<alias>/<path>:<line>`, where `<alias>`
denotes the extracted tree of that branch.

## Branch aliases

| Alias | Ref | HEAD |
|---|---|---|
| `main` | `main` | `872dbf375838` |
| `prod` | `claude/codebase-production-readiness-wm6idp` | `82da7a6af110` |
| `audit` | `claude/aip-security-architecture-audit-zpf9b3` | `16493c58aed3` |
| `importot` | `import/orbitaltrust-accountability-layer` | `6cc439f19016` |
| `valladder` | `codex/val-ladder-sync` | `ae46a3a2f4e2` |
| `aipv4` | `codex/aip-v4-accountability` | `73bf70cf9e68` |

## Claim discipline

Every claim in these reports carries one of the following labels. Where a
claim is unlabelled it is CODE-PROVEN.

| Label | Meaning |
|---|---|
| **CODE-PROVEN** | Read directly from source at a cited path and line. |
| **EXECUTION-PROVEN** | Demonstrated by running code; the probe and its output are reproduced. |
| **TEST-PROVEN** | Established by a test that actually exercises the property in question. |
| **DOCUMENTED** | Asserted by a document in the repository; not independently verified. |
| **INFERRED** | A conclusion drawn from proven facts; the inference is stated. |
| **UNKNOWN** | Not determinable from the current codebase. |

## Severity scale

| Level | Meaning |
|---|---|
| **P0** | Catastrophic — the system asserts a security property it does not hold. |
| **P1** | Production blocker. |
| **P2** | Material risk; must be tracked and scheduled. |
| **P3** | Non-blocking defect or hazard. |
| **P4** | Informational. |

## Execution evidence collected

All figures produced during this audit on the toolchain above.

| Target | Root | Passed | Failed | Ignored | Suites | Exit |
|---|---|---:|---:|---:|---:|---|
| prod | `aip-standalone` | 787 | 0 | 3 | 78 | 0 |
| main | `aip-standalone` | 143 | 0 | 1 | 6 | 0 |
| audit | `aip-standalone` | 143 | 0 | 1 | 6 | 0 |
| importot | `aip-standalone` | 143 | 0 | 1 | 6 | 0 |
| valladder | `aip-standalone` | 146 | 0 | 0 | 5 | 0 |
| aipv4 | `aip-standalone` | 142 | 0 | 0 | 5 | 0 |
| valladder | `aegis-quantum` | 110 | 0 | 0 | 12 | 0 |
| main | `aip-service` | 38 | 0 | 0 | 3 | 0 |
| prod | `aip-service` | 39 | 0 | 0 | 3 | 0 |

Zero test failures were observed on any branch or root. Zero compiler
warnings were emitted by the prod workspace or the aegis-quantum workspace.

**Roots not exercised by any run above** (each is a separate Cargo root and
is not reached by `cargo test --workspace` in `aip-standalone`):
`importot/orbitaltrust-accountability/rust/{ot-accountability-core,
ot-sentinel,ot-verifier,ot-mcp-gateway}`,
`importot/orbitaltrust-accountability/python-sdk`,
`aipv4/aegis-quantum`, and `aip-service` on all branches except where run above.

## What "0 failed" does and does not establish

It establishes that every assertion the authors wrote holds. It does not
establish that the assertions cover the security properties claimed. Report
03 (Security Invariant Matrix) and Report 04 (Runtime Accountability Trace)
separate these two questions, and in three cases —
the containment path, the aegis-quantum LRU bound, and the aegis-quantum PQC
exchange — the tests pass while the property they appear to cover is untested.
