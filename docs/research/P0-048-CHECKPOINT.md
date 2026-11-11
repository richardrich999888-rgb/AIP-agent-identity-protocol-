# P0-048 checkpoint — iteration 002

Branch: `codex/p0-048-snifferdog-enterprise-assurance`.
Integration base: `fix/vanian-end-to-end-green`,
`4d0ce1e32c8dedde4e3a930abc2becf1f56b864e`.
Parent: `40f2c1bd003e5c40378fb7e91ec89b4de9a03fbf`.
Date: 12 November 2026 (Asia/Kolkata).

Previous checkpoint:
[iteration 001 at its published commit](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/blob/40f2c1bd003e5c40378fb7e91ec89b4de9a03fbf/docs/research/P0-048-CHECKPOINT.md).
All remote heads were fetched again and captured before this item.

## Selected single item and acceptance

**P0-048-B: socket multiplicity correction, including the shared inode join.**

1. Review PR #19 and reproduce the baseline counting failure.
2. Port only the socket fix; preserve signature, identity, coverage and verdict rules.
3. Deduplicate the shared path without breaking existing callers or hiding malformed rows.
4. Keep distinct sockets, state changes, process instances and in-window evidence.
5. Run positive/negative regressions and the same before/after real socket churn.
6. Cross-check live stable sockets through a second kernel interface; retain its limits.
7. Retain fresh signed originals and verify them separately, including tamper refusal.
8. Record blocked tests explicitly, commit/publish on the feature branch, inspect CI,
   update the draft/checkpoint and stop. Do not merge automatically.

## Result

Socket correction implemented and locally verified. The baseline deterministically
counted four copies as four facts and failed one of fourteen existing end-to-end
tests under churn. The patched churn run passed all fourteen. Forty samples of
three stable sockets matched `fstat` ground truth, with no duplicate counts.

The primary scoped suites have 241 distinct executed passes and **four BLOCKED
kernel-capability tests**; reruns overlap. Rust's early-return “ok” results for
those four are not passes. Formatting and scoped Clippy passed. Twenty-three
new regressions cover duplicate, non-collapse and live cross-check properties.

Two complete batch/health archives passed the separate offline signature checker.
The intentionally lost observer emitted no health; it remains CANNOT_PROVE.
Its surviving initial batch signature verifies only that batch. One-byte tampering
and a wrong anchor fail. The first harness attempt wrongly required the absent
outage health file; that failed attempt is preserved and the corrected harness
explicitly tests the missing-health refusal. No evidence was fabricated.

- [Source change and limits](P0-048-SOCKET-CORRECTNESS.md)
- [Commands, failures, scoped results and original evidence](../../validation/p0_048/iteration-002/README.md)
- [Explicit blocked-test ledger](../../validation/p0_048/iteration-002/blocked-tests.json)
- [Original architecture audit](P0-048-ARCHITECTURE-INVENTORY.md)
- [Original dependency audit](P0-048-DEPENDENCY-MATRIX.md)
- [Baseline gap register](P0-048-SECURITY-GAPS.md)

The original audit reports describe the frozen baseline. This iteration changes
G01's socket-multiplicity status and removes the local Rust-toolchain limitation
for the scoped checks, while leaving the other qualification gates open.

## Checklist

| Workstream | Current state |
|---|---|
| A — audit | Completed to the recorded structural and targeted-review scope |
| B — sensor correctness | Socket-multiplicity item complete locally; broader lifecycle, namespaces, concurrent attribution and interruption qualification incomplete |
| C — SPIFFE/SPIRE | Existing adapter qualification and lifecycle/binding guarantees pending |
| D — OTel GenAI | Existing cross-branch telemetry and full GenAI correlation pending |
| E — Tetragon | Optional evaluation on a supported host pending |
| F — policy/gateway | Complete fresh negative matrix pending |
| G — frameworks | Full framework task acceptance pending; historical failures remain |
| H — custody | Scoped fresh signatures/tamper checks complete; independent administration and full custody matrix pending |
| I — air gap | Complete bundle and clean-host/firewall qualification pending |
| J — performance | Bounded churn is not the required performance matrix |
| K — demo | Full retained nine-scene demo acceptance pending |
| L — release | NOT MET: full regression/security CI, clean installation, independent custody and ten full rehearsals remain open |

The local host refuses NETLINK_CONNECTOR and `unshare --pid --fork` (EPERM).
No host restriction was relaxed. Prior-head Security CI reports tokenizer-hash
Gitleaks matches and inherited Helm Trivy findings; neither was suppressed.
CI for the commit containing this checkpoint is reported on draft PR #20 and
is distinct from local checks. Pending jobs are not passes.

## Next single item

Continue B with process/descriptor lifecycle and namespace attribution races,
using independently established synthetic ground truth. A supported disposable
Linux host with the required process-event and namespace facilities is necessary
to close the four blocked live tests. PID/UID/ancestry alone must never identify
a logical agent; ambiguous or missing evidence must remain CANNOT_PROVE.

Stop after this iteration. No automatic merge or next-item execution.
