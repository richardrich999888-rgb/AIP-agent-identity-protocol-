# P0-048-B — socket multiplicity correction

Iteration 002, 12 November 2026 (Asia/Kolkata). Parent:
`40f2c1bd003e5c40378fb7e91ec89b4de9a03fbf`, on
`codex/p0-048-snifferdog-enterprise-assurance`. Integration base remains
`fix/vanian-end-to-end-green`. This closes the socket-multiplicity work item,
subject to the recorded checks; it does **not** complete all of B or release L.

## Reproduced defect

The baseline counted four copies of one genuinely signed socket observation
as four supporting facts. The new live regression failed with `left: 4,
right: 1`; its absence/self-report companion remained conservative.

The unchanged 14-test edge end-to-end suite also failed under four threads of
loopback socket churn. The replay test compared a two-record run with a
five-record honest run. One test failed, thirteen passed; the load generator
completed 307,193 connections, each with a byte received by its peer. This is
an actual baseline failure, not a result copied from PR #19.

After the patch, the same suite and churn command passed all 14 tests. The
generator completed 341,191 connections. This is one bounded before/after
experiment, not a capture-rate, overhead or scalability benchmark. Durations
and per-thread counts are in the original JSON/logs; different connection
counts are not normalized into an invented performance improvement.

## Smallest integration and shared-path correction

Reviewed PR #19 at `9b8109884455e37a61ca7abef1bb7d78a39a860d`. Applied only the
socket change from `5c899356ccbaf11f3e2a87ec79408960aa312201`; its unrelated
sovereign namespace patch was not imported.

- [Edge observer](../../aip-standalone/aip-edge-observer/src/main.rs) retains
  the reviewed distinct-row guard and reports repeats, including those already
  removed by the shared probe.
- [Shared probe](../../aip-standalone/aip-observe/src/probe.rs) now collapses
  identical socket effects after the inode join. Existing `observe_sockets`
  callers keep their three-field return shape. The diagnostic variant returns
  malformed-row and repeated-row counts separately. The raw parser is unchanged.
- [Effect assessment](../../aip-standalone/aip-edge/src/effect.rs) counts a
  socket once per observed process and effect window, including repeated
  batches. It prefers an in-window representative, preserves distinct sockets
  and process instances, and validates every input before collapsing repeats.
- [Live regression](../../aip-standalone/aip-edge/tests/socket_duplicates.rs)
  uses genuinely signed observations; twenty copies of absence/self-report
  cannot establish an effect. Optional retention refuses to overwrite an archive.
- [Socket cross-check](../../aip-standalone/aip-observe/tests/socket_multiplicity.rs)
  compares forty probe samples of three held sockets with inode values obtained
  through `fstat`, a separate kernel interface. It is still one kernel and
  administrator, and it does not qualify auditd or an independent security domain.

The equality key preserves protocol, both endpoints, state and inode. State
changes remain observations; the edge stance accepts only ESTABLISHED. Different
start ticks or boot IDs are never merged. Non-socket observations are not
collapsed by the effect helper. A lower count is not a relaxed threshold.

## Evidence and acceptance boundaries

[Iteration evidence](../../validation/p0_048/iteration-002/README.md) contains
the exact commands, baseline failures, fixed runs, toolchain pins, signed
archives and verifier results. The audit inventory from iteration 001 remains
a frozen description of its baseline; this report records the source delta.

The three modified production files contain no new signing key, trust-anchor
rule, authority predicate, evidence threshold or reconciliation verdict.
Existing signature, replay, wrong-instance, wrong-boot, coverage-loss and
multi-effect refusals are exercised by the applicable suites. Full-workspace
release acceptance and broader sensor/framework qualification remain open.

## Remaining limits

- Polled socket presence is not a continuous event stream or a proof of the
  connect syscall. Missing short-lived sockets remain missing evidence.
- A pidfd anchors a live process instance; it does not freeze its descriptor
  table or solve close/reuse races. Namespace boundaries and concurrent logical
  agents still require the remaining B qualification work.
- The same-host collector and local verifier use separate keys/processes but
  share administration. Offline signature verification uses the explicitly
  retained synthetic trust anchors, not institution-approved independent custody.
- Fresh test archives do not repair any missing historical demo archives.
  Their signatures are not proof of an uncompromised kernel or complete capture.
- No production enforcement, deployment, main-branch merge, external outreach,
  new framework integration or certification claim is part of this change.

Next single item: test native process/descriptor lifecycle and namespace races
against independently established synthetic ground truth. Keep unavailable
kernel capabilities and ambiguous attribution BLOCKED/CANNOT_PROVE.
