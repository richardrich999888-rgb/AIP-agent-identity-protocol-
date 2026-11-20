# Repository audit (enterprise WOW loop, item 0.2a)

Collected 21 Nov 2026, 00:2x IST, from `git fetch origin '+refs/heads/*:refs/remotes/origin/*'` (44 branches), the GitHub API (`list_pull_requests`, state=all: 23 PRs; #15 and #18 are issues, not PRs), and `cargo test --locked -p <crate>` in this worktree. Per-branch data: `evidence/audit-branches.json`.

**Not done, so this is 0.2a, not 0.2.** The plan asks to re-use `command-center/docs/REPOSITORY_AUDIT.md` from P0-059. That file is not reachable: the P0-059 commits are not on the remote (0.1). Nothing here restates P0-059 claims.

## Structural facts

- `main` is `872dbf37`. Its latest commit is from 19 Jun 2026 (the merge of PR #2). **No PR has merged since then.** There are 21 open PRs, 15 of them drafts.
- Most work stacks on `feature/syntriass-runtime-v02` (`2883da7b`, latest commit 31 Oct). Seven open PRs target it: #25, #13, #21, #19, #17, #16 and #14.
- Several PRs form long chains, each based on another PR's branch: #4/#5 → `claude/aip-security-architecture-audit-zpf9b3`; #6 → #7/#8, with #7 → #10 and #8 → #9 → #11 → #12 → #20 → #23; and #22 → #21. Merging any of them means merging its chain in order.
- 9 of 44 branches have commits since 13 Nov. The table counts commits ahead of `main` and, of those since 6 Nov, the ones carrying a `Co-Authored-By: Claude` trailer.

| Branch | Head | Last commit | Ahead of main | Claude-trailer commits since 6 Nov, not in main |
|---|---|---|---|---|
| `claude/vanian-enterprise-wow` | `ae68bbcc` | 2026-11-20 | 535 | 53 |
| `fix/aip-service-drop-chrono` | `ba7805da` | 2026-11-20 | 470 | 2 |
| `feature/wow-demos` | `f665cab2` | 2026-11-20 | 509 | 27 |
| `feature/airon-teach-demo` | `beeec631` | 2026-11-19 | 528 | 18 |
| `feature/vanian-ai-visibility-control-plane` | `3150433b` | 2026-11-18 | 4 | 0 |
| `codex/p0-057-independent-agent-assurance` | `d8ea3625` | 2026-11-14 | 429 | 0 |
| `codex/p0-048-snifferdog-enterprise-assurance` | `d2883d7d` | 2026-11-14 | 427 | 0 |
| `anuj-final` | `f9e7b42b` | 2026-11-13 | 388 | 0 |
| `codex/p0-056-airon-runtime-interface` | `f1ba9fc2` | 2026-11-13 | 521 | 15 |
| `anuj-testing` | `7d84df27` | 2026-11-10 | 1 | 0 |
| `fix/aip-edge-distinct-corroboration` | `9b810988` | 2026-11-07 | 468 | 2 |
| `fix/model-resolver-and-setup` | `86f21056` | 2026-11-07 | 468 | 1 |
| `fix/chart-probe-seccomp` | `a0b1045b` | 2026-11-07 | 468 | 2 |
| `fix/ci-userns-sandbox-tests` | `c39fc1f0` | 2026-11-06 | 467 | 0 |
| `integration/snifferdog-complete-enterprise-validation` | `ab161597` | 2026-11-03 | 394 | 0 |
| `testing` | `1f2eb189` | 2026-11-02 | 1 | 0 |
| `codex/open-source-agents-nov1-validation` | `75e75bb0` | 2026-11-02 | 389 | 0 |
| `research/syntriass-generalization-r1-20261031` | `f610ff9b` | 2026-10-31 | 468 | 0 |
| `feature/syntriass-runtime-v02` | `2883da7b` | 2026-10-31 | 466 | 0 |
| `feature/syntriass-intelligence-runtime-v01` | `7bf697b8` | 2026-10-31 | 456 | 0 |

The other 24 branches are older; all are in `evidence/audit-branches.json`. The trailer count is a lower bound on assistant-authored work, because commits without the trailer are not counted.

## Pull requests

| # | State | Head → base | Updated | Title |
|---|---|---|---|---|
| 25 | open | `fix/aip-service-drop-chrono` → `feature/syntriass-runtime-v02` | 2026-11-20 | Base CI repair: drop unmaintained chrono, patch bundled SQLite/rustix, port sibling-binary and namespace fixes |
| 13 | open (draft) | `feature/wow-demos` → `feature/syntriass-runtime-v02` | 2026-11-20 | WIP: wow demos (do not merge) |
| 21 | open (draft) | `feature/airon-teach-demo` → `feature/syntriass-runtime-v02` | 2026-11-19 | WIP: teaching validation, scoped expert approval and signed replay |
| 24 | open (draft) | `feature/vanian-ai-visibility-control-plane` → `main` | 2026-11-18 | Research scaffold: AI activity, agent inventory, provenance and FinOps |
| 23 | open (draft) | `codex/p0-057-independent-agent-assurance` → `codex/p0-048-snifferdog-enterprise-assurance` | 2026-11-14 | P0-057: reject mixed executable snapshots and retain assurance evidence |
| 20 | open (draft) | `codex/p0-048-snifferdog-enterprise-assurance` → `fix/vanian-end-to-end-green` | 2026-11-14 | Fix native attribution and classify historical security findings |
| 22 | open (draft) | `codex/p0-056-airon-runtime-interface` → `feature/airon-teach-demo` | 2026-11-13 | P0-056: scoped native interface for AIRON integration |
| 19 | open | `fix/aip-edge-distinct-corroboration` → `feature/syntriass-runtime-v02` | 2026-11-07 | aip-edge: count one socket as one corroboration |
| 14 | open | `fix/model-resolver-and-setup` → `feature/syntriass-runtime-v02` | 2026-11-07 | Model resolver, dataset setup, pinned Python env |
| 17 | open | `fix/chart-probe-seccomp` → `feature/syntriass-runtime-v02` | 2026-11-07 | Give the probe pod the runtime's default seccomp profile |
| 16 | open | `fix/ci-userns-sandbox-tests` → `feature/syntriass-runtime-v02` | 2026-11-07 | Refuse when the sandbox namespaces cannot be created, and grant them in CI |
| 8 | open (draft) | `integration/snifferdog-complete-enterprise-validation` → `codex/snifferdog-real-agent-swarm-validation` | 2026-11-02 | Observe local Qwen and governance-enabled agents with signed AIP evidence |
| 12 | open (draft) | `fix/vanian-end-to-end-green` → `integration/vanian-enterprise-service-delivery` | 2026-10-29 | Repair combined execution assurance and retain explicit custody limits |
| 11 | open (draft) | `integration/vanian-enterprise-service-delivery` → `feature/vanian-agent-governance-interoperability` | 2026-10-28 | Deliver Linux packages, deployment registry and customer SDK onboarding |
| 9 | open (draft) | `feature/vanian-agent-governance-interoperability` → `integration/snifferdog-complete-enterprise-validation` | 2026-10-28 | Add tested agent interoperability with native authority and gateway correlation |
| 10 | open (draft) | `feature/customer-service-delivery-model` → `feature/snifferdog-enterprise-integration` | 2026-10-28 | Add evidence-first enterprise service onboarding model |
| 6 | open (draft) | `codex/snifferdog-real-agent-swarm-validation` → `claude/skill-25-implementation-xbz0t3` | 2026-10-28 | Add real-agent observation harness and fix startup identity race |
| 7 | open (draft) | `feature/snifferdog-enterprise-integration` → `codex/snifferdog-real-agent-swarm-validation` | 2026-10-28 | Build Sniffer Dog enterprise evaluation integration |
| 5 | open (draft) | `codex/rbi-demo-preflight-2026-10-27` → `claude/aip-security-architecture-audit-zpf9b3` | 2026-10-26 | Fix RBI rehearsal evidence and restore audit-branch CI |
| 4 | open (draft) | `codex/accountability-test-gaps-2026-10-20` → `claude/aip-security-architecture-audit-zpf9b3` | 2026-10-20 | Add accountability regression tests and gateway stdio coverage |
| 3 | open | `import/orbitaltrust-accountability-layer` → `main` | 2026-09-04 | Import: OrbitalTrust accountability layer (side-by-side, not merged) |
| 2 | merged | `claude/codebase-production-readiness-wm6idp` → `main` | 2026-06-19 | Fix CI: clippy 1.96, valid SPDX license, cargo-deny/audit advisory |
| 1 | merged | `claude/codebase-production-readiness-wm6idp` → `main` | 2026-06-16 | Reposition AIP as accountability infrastructure |

## Sentinel, containment and NEXORA (extension asked by the plan)

| Crate | Source lines | Tests run | Last commit | What it says it is (its `Cargo.toml` description) |
|---|---|---|---|---|
| `aip-sentinel-feed` | 1117 | 34 passed / 0 failed / 0 ignored | 2026-10-26 | Renders attested kernel evidence as an out-of-band effect log for an independent reconciler |
| `aip-containment` | 1537 | 31 passed / 0 failed / 0 ignored | 2026-10-27 | Ghost Skill 9: containment boundary, consumes a signed warrant and an execution binding |
| `aip-nexora` | 4180 | 196 passed / 0 failed / 0 ignored | 2026-10-29 | NEXORA commitment layer over verified execution history (Merkle commitment, signatures) |
| `aip-warrant` | 661 | 23 passed / 0 failed / 0 ignored | 2026-09-06 | Ghost Skill 8: warrant engine over authenticated reconciliation results |
| `aip-reconcile` | 5282 | 224 passed / 0 failed / 0 ignored | 2026-10-26 | Ghost Stage 4: ExpectedExecution vs attested observation, CANNOT_PROVE by default |

Total: 508 passed / 0 failed / 0 ignored, from `cargo test --locked -p <crate>` for each of the five crates, each exit 0. These counts show the crates' own tests pass. They do **not** show that the crates are wired into the demo: nothing in `command-center/` (this branch) calls them yet. Capability classes are item 0.3.

## Implications for the loop

- The demo branch is based on `feature/wow-demos`, which is 509 commits ahead of a June `main`. "Do not merge to main" is easy to keep; any eventual merge is a stacked-PR problem, not a single PR.
- Fixes on PR #25 (base CI repair) are prerequisites for green CI on every PR that targets `feature/syntriass-runtime-v02`.
