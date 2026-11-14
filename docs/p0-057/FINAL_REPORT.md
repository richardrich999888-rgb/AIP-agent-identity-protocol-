# P0-057 checkpoint report — programme NOT COMPLETE

Organisation: VANIAN Technologies Pvt. Ltd. Date: 14 November 2026 IST.
Branch: `codex/p0-057-independent-agent-assurance`.
Draft review: [PR #23](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/pull/23).

The audit and first attribution repair are implemented. Enterprise acceptance
remains **NOT READY**. This filename is the requested ongoing programme report;
it is not a declaration that all P0-057 deliverables or acceptance gates pass.

## Iteration 001 — audit and reconcile

**Completed:** remote commit `ceb7682b11311b3f05649c513adcf1b8eecedb94` records
all 40 captured remote branches, 18 open PRs, dependency/license/build/deployment
inventory, ancestry and overlapping changes. Base is P0-048 `61dd730`; default
`main` is `872dbf3`. Existing authority, sensors, gateway, verifier, packaging and
same-run work are preserved. No automatic merge or concurrent-work overwrite.

**Verified:** 12 baseline probe tests pass; initial source tree was clean.
Provider inspection confirms five successful workflows and failed Security at
the original P0-048 base. Those are existing source-specific results.

**Failed / unresolved:** shell push lacked credentials; connected Git-object
publication succeeded with exact tree comparison. Logical-agent/action binding,
cross-branch integration, custody, installation and performance remain open.

**Evidence:** `validation/p0_057/iteration-001`, `BASELINE_AUDIT.md`,
`BRANCH_RECONCILIATION.md`, `INTEGRATION_MATRIX.md`.

## Iteration 002 — executable consistency

**Completed:** source `5be83a87bec680d26510c2be93e66fdfda008b1e`, tree
`fe4a962a670c092e9729817272e9513d87dffd46`. The probe hashes the opened executable,
checks device/inode/size/mtime/ctime, rechecks process start and placement, rejects
sampled changes and invalidates stale cache entries. It no longer accepts the
reproduced cold-cache mixed path/hash or warm-cache stale image after exec.
The wire format, authority/signature/coverage/verdict predicates are unchanged.

**Verified:**

| Check | Executed result |
|---|---|
| Observer library and lifecycle/socket/placement/blind-spot suites | 102 pass, zero failures/ignored |
| Core, reconciliation, gateway and offline verifier suites | 455 pass, zero failures/ignored |
| Separate verification of final local samples | 8 checks pass: originals, one-byte tamper, wrong anchors, missing health |
| Required native Linux qualification, run 43582459564 | 10 actual kernel assertions and 2 archive checks pass at exact source |
| Local replay of hosted originals | 6 checks pass; manifest and nine source-file hashes match; coverage stays absent for unverified/degraded archives |
| Separate replay of genuine same-run signed results | 6 checks pass; both original CannotProve results reproduce exactly, missing receipts preserve uncertainty, wrong anchors reject |
| Formatting and scoped all-target Clippy with warnings denied | pass |
| Real pinned ContextForge + MCP upstream + independent Rust receipt verification | 27 checks pass; 27 signed receipts, 16 upstream invocations |
| Hosted full CI at source `5be83a8` | all six jobs pass, including Rust tests, coverage, RED suite, SDK, PostgreSQL and supply-chain checks |

Focused reruns overlap the suites. No total is presented as a count of live
attacks, AI agents, independently administered hosts or production workloads.

**Failed:** both original exec-race assertions reproduced before the fix; the
first signed-sample build used an incorrect helper namespace; the first broader
offline run lacked a cached locked dependency. Originals remain, followed by
successful corrected runs. No test threshold or assertion was weakened.

**New release blocker:** genuine same-run workflow `43582459576` failed its
recovery scene: the actual tool ran but the archive contains no unique signed
Forwarded receipt for the authorised decision. Only the controlled negative
request's Refused receipt is retained. The earlier observed scene and observer
interruption scene passed their harness assertions, but their reconciliations
remain `CannotProve` (`ActionEvidenceUnavailable` and `WindowNotCovered`).
No agent log or unsigned tool event was substituted for the missing receipt.
The original failure ZIP SHA-256 is
`bc5c9882c37fcd4039bb4f3db082329fffbc74a6624125dccd7660766d678c0a`.

**Evidence:** `validation/p0_057/iteration-002` retains reproduction patch, raw
logs, source/binary hashes, signed originals, public anchors, mutations, provider
receipts and the untouched hosted ZIP. ZIP SHA-256:
`f6859f1235aa10755df8949ceb6b4d055d9d452512a15194f1a7026497d21996`.
See `ATTRIBUTION_RESULTS.md`, `ADVERSARIAL_RESULTS.md` and `REPRODUCE.md`.

## Iteration 003 — retain failure diagnostics

**Completed:** source `5a7d2625a861821e74f979cd0700fbbe6dbe1de1`, tree
`d9c2ada9464fc7e25b34c6637b91a1c61358600f`. The same-run harness exports a bounded,
read-only replay-journal diagnostic after its service processes stop, including
failed trials. It hashes identifiers, exports only fixed state names, and never
exports credentials, private tables, arguments or SQLite files. Diagnostics
remain unsigned and cannot replace receipts or upgrade a verdict.

**Verified:** four actual temporary-SQLite regression tests and 11 existing
same-run control tests pass. Corrupt, missing, symlinked, invalid and oversized
archives fail to an explicit unavailable diagnostic; original bytes are retained.
Fresh hosted run `43583751360` at this exact source passed observed,
interruption and recovery scenes. All three captured a Forwarded journal state;
their verified reconciliations remain CannotProve. The new archive SHA-256 is
`4351d0217fa5f616d46d6a59db34d2f0173d2715fbd6f372b98370225f846942`.
Native qualification, enterprise integration, security, contracts and RBI
workflows also pass at this head; full CI state is recorded in the ledger.

**Failed / unresolved:** the original recovery failure is not repaired by this
diagnostic change. The available original evidence cannot distinguish omitted
pre/post hooks, missing context and another gateway failure. A separate real
gateway run passed all 27 checks, which does not erase the same-run failure.
The subsequent genuine hosted recovery passed without a cause-specific repair;
this is a separate successful attempt, not proof the intermittent gap is fixed.

**Evidence:** `validation/p0_057/iteration-003` and iteration 002's unmodified
same-run failure ZIP, full compressed job log and selected original manifests.
Fresh source-specific workflow state is recorded in the qualification ledger.

## Acceptance limits and next item

This repair does not prove historical event-time identity, concurrent logical
agent ownership, a complete tool effect, universal Shadow AI discovery or an
independent observation trust domain. The graph document maps existing evidence
and specifies missing edges; its complete exporter/launch binding is not built.
Benchmark values are null because the required experiments have not run.
Installation, two-host and demonstration documents are acceptance procedures
with explicit unexecuted status, not completed customer demonstrations.

P0-048 advanced concurrently to `d2883d7` with compiler/security classification.
That branch's Security passes, but live enabled Kubernetes privileges remain
unaccepted. P0-057 adds no scanner suppression. PR synthetic-merge CI and exact
native head qualification are distinct; final provider state is retained in the
evidence checkpoint rather than inferred from earlier runs.

**Next:** reproduce and repair the missing Forwarded receipt with the new
gateway diagnostic, preserving the original failed trial and adding a regression
for the established cause. Then close authority-owned request-to-workload binding
and build the versioned offline graph without inventing absent edges.
Independently administered hosts/keys and external review are mandatory later
gates and cannot be self-approved by this work.
