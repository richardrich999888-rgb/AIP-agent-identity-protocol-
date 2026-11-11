# P0-048 checkpoint — iteration 001

Branch: `codex/p0-048-snifferdog-enterprise-assurance`.
Base: `fix/vanian-end-to-end-green`, `4d0ce1e32c8dedde4e3a930abc2becf1f56b864e`.
Date: 12 November 2026 (Asia/Kolkata).

## Selected work item

**P0-048-A: repository architecture/dependency inventory and baseline decision.**

Acceptance criteria:

- Fetch all remote heads and locate the previous P0-048 checkpoint.
- Inspect the six named branches and PRs #8, #9, #11, #12, #16, #17 and #19.
- Inventory native/nested manifests, dependency locks, workflows, containers,
  services, deployment definitions and existing integrations.
- Link critical claims to immutable source or baseline code/test/evidence paths.
- Distinguish source presence, component tests, live task acceptance and
  unresolved external gates; do not mark an unverified dependency mandatory.
- Retain reproducible commands, original failed attempts and scoped results.
- Commit only the audit artifacts on the requested branch, push and inspect CI;
  open a draft against the selected integration baseline, with no main merge.

## Result

Audit deliverables completed with explicit limits. All 37 remote heads were
captured, ten relevant trees inventoried, and no previous P0-048 checkpoint
found. The source baseline is not changed. This is a structural inventory and
targeted critical-path review, not exhaustive source-level security validation.

- [Architecture and branch inventory](P0-048-ARCHITECTURE-INVENTORY.md)
- [Dependency matrix](P0-048-DEPENDENCY-MATRIX.md)
- [19-gap register](P0-048-SECURITY-GAPS.md)
- [Commands, results and provenance](../../validation/p0_048/iteration-001/README.md)

Fresh portable regressions: **43 passed, 0 skipped in the final invocations**.
Earlier invocation import failures remain retained and are not added to this
count. Rust tests/formatting/Clippy and pytest interoperability tests were not
executed locally because the relevant tools are unavailable. Historical CI is
recorded separately. No fresh sensor execution, independently administered
collector test, framework task or clean-host install is claimed.

Commit identity is the commit containing this checkpoint (read with
`git log -1 --format=%H -- docs/research/P0-048-CHECKPOINT.md`). Remote CI for
that commit is separate from the historical baseline and must be read from the
draft PR; pending, skipped or unstarted jobs are not passes.

## Workstream checklist

| Workstream | Status after this iteration |
|---|---|
| A — audit/inventory | Completed to the explicitly stated inventory/review scope; fresh runtime qualification is not part of this completion |
| B — native sensor correctness | NEXT; #19 reviewed, baseline still needs the minimal socket correction and shared-join analysis |
| C — SPIFFE/SPIRE | Pending qualification of existing adapters and missing lifecycle/binding guarantees |
| D — OTel GenAI correlation | Pending reconciliation of existing other-branch controller telemetry and GenAI mapping |
| E — Tetragon comparison | Pending optional evaluation on a supported isolated host |
| F — policy/gateway assurance | Pending complete fresh negative matrix over existing integrations |
| G — real frameworks | Pending; preserve retained failures and scoped LangGraph evidence |
| H — cryptographic custody | Pending; independent collector administration is externally blocked |
| I — offline deployment | Pending complete bundle and actual clean-host/firewall acceptance |
| J — performance | Pending measured independent-ground-truth workload matrix |
| K — customer demo | Pending reuse/reconciliation of the existing demo with full archive retention and authority comparison |
| L — release acceptance | NOT MET; final report/dependencies/threat model/benchmarks/open gaps/demo guide remain release deliverables |

## Next single item and acceptance

P0-048-B: reproduce and fix socket multiplicity on this baseline after
reviewing #19's exact patch. Preserve its per-process-instance and effect-window
logic, evaluate shared `observe_sockets` callers, and distinguish state changes
from independent corroborations. Require deterministic positive/negative tests
and before/after genuine socket churn under an independently checked workload.
Never weaken a threshold or convert insufficient evidence to VERIFIED. A
supported Rust/Linux build and observation host is required for the live gate.
Do not merge divergent runtime/demo/governance branches wholesale as a shortcut.

Stop after this iteration. No automatic merge or next workstream execution.
