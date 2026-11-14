# P0-048-B — delayed lifecycle-event binding

Iteration 003, 12 November 2026. Parent: `353b2169e48fd000aa079ef6afa94ad0e02afbe7`.
This closes one reproducible binding-cache defect group, not the complete sensor,
namespace, logical-agent or enterprise qualification workstream.

## Finding and correction

The connector exec/fork path measured the current holder of a numeric PID without
checking whether that instance existed when the event occurred. The tracepoint
path already applied that check. The connector's exit path also consumed any
cached binding for the PID regardless of event order, and a newer exec whose
measurement failed left the previous binding in the cache.

Six of eight new regressions failed on the unchanged parent production source.
The signed fixture's binding pattern was `[true, true, true, false]` for an old
exec, current exec, stale exit and later exit; it should be
`[false, true, false, true]`. This was a reproduced attribution error. It was not
a demonstrated false VERIFIED execution verdict or a measured live PID-reuse rate.

[The native probe](../../aip-standalone/aip-observe/src/probe.rs) now:

1. Applies the existing clock-anchor/start-tick predicate to connector exec and
   fork measurements, retaining rejected originals with no process binding.
2. Remembers the kernel timestamp alongside the cached process instance.
3. Leaves older or equal-time exec/fork/exit events unbound without replacing or
   consuming the newer binding. Equal timestamps do not establish ordering.
4. Invalidates the old binding before trying a newer exec/fork measurement, so
   a failure cannot leave the earlier image available to a later exit.
5. Preserves loss/fault invalidation, original event timestamps, probe sequencing,
   signatures, coverage rules and the distinction between process and agent.

The public API and serialized protocol did not change. Two existing private cache
fixtures now supply the timestamp field; their loss/consumption assertions remain.
No dependency manifest, lockfile, signature verifier or reconciler was changed.

## Evidence and acceptance

The tests use real local procfs/pidfd measurements and **synthetic connector event
stimuli**. Child workloads really execute, but their injected event records are
not represented as live netlink capture. Same-UID sibling processes remain distinct
instances with `NotEstablished` agent attribution. A killed/reaped child supplies
the real failed-measurement case.

| Check | Observed outcome |
|---|---|
| Eight new regressions on parent production source | 2 passed; 6 failed |
| Same regressions after correction | 8 passed; also passed in the broader run and retained-evidence run |
| Full scoped observe/reconcile/offline-verifier suite | 489 executed passes; 9 blocked early returns; 1 failed BPF host check; 1 explicitly ignored timing benchmark; command exit 101 |
| Existing unbound-execution verdict checks | `xe05`, `xe06` and `t03h` passed, preserving CANNOT_PROVE |
| Workspace formatting and scoped all-target Clippy, warnings denied | Passed |
| Retained original signature, missing-health refusal, one-byte tamper, wrong anchor | Four offline checks passed |

See the [original command logs and reproduction guide](../../validation/p0_048/iteration-003/README.md),
[eight regressions](../../aip-standalone/aip-observe/tests/lifecycle_races.rs),
[blocked/failure ledger](../../validation/p0_048/iteration-003/blocked-tests.json),
and [offline verification result](../../validation/p0_048/iteration-003/offline-verification/summary.json).
Repeated runs overlap and are not added to the distinct-pass total.

The BPF negative test requires a verifier rejection with `EACCES` and an
invalid-packet-access diagnostic. This host refuses `BPF_PROG_LOAD` with `EPERM`
before that evaluation, and supplies no verifier diagnostic. The unmodified
parent test was also compiled independently, with no repository library linked,
and reproduced the same failure. It stays FAIL; the kernel property is blocked.
No test assertion or host restriction was relaxed. XDP was never attached to an
interface. The nine other capability-dependent early returns are not passes.

## What the archive proves

`originals/batches.jsonl` contains the exact fresh signed synthetic-test batch.
`scope-and-anchor.json` contains its explicit scope and public verification key.
Private keys stayed in memory. The separate native CLI verified those bytes and
refused a one-byte derivative and a wrong public key. Asking it to read the
absent health archive failed with exit 2; no health or coverage was fabricated.

The signature establishes integrity under this same-administrator test key.
It does not establish truthful kernel provenance for the injected stimuli,
execution authorization, complete observation, logical-agent attribution,
independent administration or an execution verdict. The verifier ran locally
without runtime downloads; network egress was not independently disabled, so
this is not clean-machine or air-gap deployment acceptance.

## Remaining limits and next item

- Start time is still measured at clock-tick resolution. PID reuse within a tick
  is not ruled out by this predicate. Actual high-load PID reuse is not qualified.
- The cache is not a durable per-PID event history. It retains no timestamp
  tombstone after consumption, loss or failed measurement. This is not general
  replay protection; signed stream continuity and coverage remain separate gates.
- A PIDFD anchors process lifetime, not atomic executable-image identity across
  exec. Sequential stat, executable-path, metadata/hash and namespace reads still
  need a separate race analysis. Repeated exec within one process remains open.
- Missing/stale clock anchors, suspend boundaries, namespace mapping and stale
  PID-indexed agent claims have not been qualified here. Agent claims remain claims.
- Live connector, tracepoint, fanotify, packet and BPF tests require the supported
  disposable host facilities named in the ledger. Independent audit comparison,
  full concurrent-agent load tests and separately administered custody remain open.

The next single item is executable/descriptor measurement consistency across
exec and process exit, with namespace evidence kept explicit. Full B and release
acceptance remain incomplete. The frozen baseline gap register is not rewritten.

## Research basis

The Linux connector assigns `ktime_get_ns()` timestamps to exec/fork/exit events
([pinned source revision](https://github.com/torvalds/linux/blob/24a0b5e196cf70ccff97bc0add6fa7178ad50cc4/drivers/connector/cn_proc.c)).
The [Linux 6.12 clock documentation](https://docs.kernel.org/6.12/core-api/timekeeping.html)
distinguishes monotonic time from boottime across suspend. This is why the existing
clock conversion is retained. The source hash and licence header are recorded in
[upstream-research.json](../../validation/p0_048/iteration-003/upstream-research.json).
No upstream kernel code was integrated or installed.
