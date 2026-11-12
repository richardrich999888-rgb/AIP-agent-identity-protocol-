# P0-048 checkpoint — iteration 003

Branch: `codex/p0-048-snifferdog-enterprise-assurance`.
Integration base: `fix/vanian-end-to-end-green`,
`4d0ce1e32c8dedde4e3a930abc2becf1f56b864e`.
Parent: `353b2169e48fd000aa079ef6afa94ad0e02afbe7`.
Date: 12 November 2026 (Asia/Kolkata).

Previous checkpoint:
[iteration 002 at its published commit](https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/blob/353b2169e48fd000aa079ef6afa94ad0e02afbe7/docs/research/P0-048-CHECKPOINT.md).
All remote branches were fetched and current CI reviewed before selecting this item.

## Selected single item and acceptance

**P0-048-B: delayed connector lifecycle-event binding and cache ordering.**

1. Reproduce stale exec/fork/exit binding before changing production source.
2. Refuse event-to-instance bindings that contradict process start time or a
   newer cached event; keep rejected original events unbound.
3. Invalidate old bindings when a newer exec/fork cannot be measured.
4. Preserve positive controls, concurrent-instance separation, loss invalidation,
   signature and coverage checks, and CANNOT_PROVE for insufficient evidence.
5. Retain fresh, visibly synthetic signed regression evidence and separately
   check signatures, one-byte tampering, wrong anchors and missing health.
6. Record failed/blocked checks, commit/publish only on the feature branch,
   inspect CI, update the draft/checkpoint and stop.

## Result

The selected correction is implemented and locally verified: six of eight new
regressions failed on the unchanged parent; all eight pass after the correction.
Only the native probe's binding cache/timestamp checks changed in production.
The public API, protocol, dependency lockfile, verifier and reconciler are unchanged.

The complete scoped observe/reconcile/verifier run reports **489 executed passes,
nine BLOCKED live checks, one failed BPF host check and one explicitly ignored
release-only timing benchmark**. Overall command exit is 101, not a green suite.
The unmodified parent BPF test independently reproduces EPERM before verifier
evaluation. No assertion, security check or host restriction was relaxed.
Formatting and scoped all-target Clippy with denied warnings pass.

Four offline archive checks pass. The exact fresh signed batch contains synthetic
connector stimuli plus real procfs/pidfd process measurements. Signature integrity
is established under the supplied same-administrator test key. Live connector
capture, complete coverage, independent administration and an execution verdict
are not established. Missing health remains missing and is refused.

- [Correction, acceptance and remaining attribution limits](P0-048-LIFECYCLE-CORRECTNESS.md)
- [Commands, failures and original evidence](../../validation/p0_048/iteration-003/README.md)
- [Blocked, failed and ignored test ledger](../../validation/p0_048/iteration-003/blocked-tests.json)
- [Offline check results](../../validation/p0_048/iteration-003/offline-verification/summary.json)
- [Prior socket correction](P0-048-SOCKET-CORRECTNESS.md)
- [Frozen baseline gap register](P0-048-SECURITY-GAPS.md)

## Checklist

| Workstream | Current state |
|---|---|
| A — audit | Completed to the recorded structural and targeted-review scope |
| B — sensor correctness | Socket multiplicity and delayed connector-event/cache corrections complete locally; executable/descriptor consistency, namespaces, concurrent attribution and interruption qualification incomplete |
| C — SPIFFE/SPIRE | Existing adapter qualification and lifecycle/binding guarantees pending |
| D — OTel GenAI | Existing cross-branch telemetry and full GenAI correlation pending |
| E — Tetragon | Optional evaluation on a supported host pending |
| F — policy/gateway | Complete fresh negative matrix pending |
| G — frameworks | Full framework task acceptance pending; historical failures remain |
| H — custody | Fresh scoped socket/lifecycle signatures and tamper checks complete; independent administration and full custody matrix pending |
| I — air gap | Complete bundle and clean-host/firewall qualification pending |
| J — performance | Bounded churn is not the required performance matrix |
| K — demo | Full retained nine-scene demo acceptance pending |
| L — release | NOT MET: full regression/security CI, clean installation, independent custody and ten full rehearsals remain open |

## CI and remaining external dependencies

Parent 353b216's format/Clippy/debug-release, audit, SDK, Postgres, RED, RBI and
harness jobs passed. Coverage generation and same-run task logs completed, but
both artifact uploads failed after five attempts with HTML where JSON was
expected. Missing uploaded archives are not acceptance evidence. The provider
receipt is retained in `iteration-003/prior-head-ci.json`.

Prior Security CI findings remain: two tokenizer SHA-256 strings matched by
Gitleaks and four inherited Helm-render HIGH findings from Trivy. They were not
suppressed. Current publication-head CI is inspected and reported on draft PR
#20; pending checks are not passes. No automatic merge is authorized.

The current host denies connector/fanotify/packet/BPF facilities or lacks tracefs,
as itemized in the ledger. Closing those live checks requires a supported
isolated Linux host. Independently administered custody, clean-machine offline
installation, complete framework task qualification and ten full retained demo
rehearsals remain external or later qualification gates.

## Next single item

Continue B with executable/descriptor measurement consistency across exec and
process exit, retaining explicit namespace and clock limits. PID/UID/ancestry
and a process-lifetime handle cannot alone prove executable image at event time
or which logical in-process agent acted. Actual high-load PID reuse and complete
namespace qualification remain open.

Stop after this iteration. No automatic merge or next-item execution.
