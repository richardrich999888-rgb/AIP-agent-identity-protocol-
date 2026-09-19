# Sniffer Dog 3.0 — specification and status

**Status** IMPLEMENTED IN PART — two tiers shipped with tests; two tiers specified; no hardware exercised
**Date** 2026-09-10
**Baseline** Sniffer Dog 2.0 at `12767ea` (observation + observation integrity)
**Governing decisions** ADR-015 (enforcement boundary), `CYBER_PHYSICAL_SAFETY_STACK.md`

---

## 1. What 3.0 is

Sniffer Dog 2.0 is an observer that knows when it has gone blind. 3.0 keeps
that observer **exactly as it is** and adds two things beside it — never
inside it:

```
                     ┌──────────────────────────────────────────┐
                     │  2.0  OBSERVATION  (unchanged)           │
   workload ───────► │  keyless probe · off-host collector      │──► AttestedBatch
                     │  IntegrityUnknown · gate-independent cov │    SignedSensorHealth
                     └──────────────────────────────────────────┘
                                          │ ObserverState only
                                          ▼
   ┌──────────────────────────┐   ┌──────────────────────────────┐
   │ 3.0  ENFORCEMENT         │   │ 3.0  INTERLOCK               │
   │ aip-enforce              │   │ aip-interlock                │
   │ seccomp user-notify      │   │ signed dead-man heartbeat    │
   │ signed capability epoch  │   │ watchdog state machine       │
   │ ─► EnforcementDecision   │   │ safe-state contract          │
   │    (a claim, not evidence)│  │ ─► relay: permitted / not    │
   └──────────────────────────┘   └──────────────────────────────┘
        ▲ reads nothing from 2.0        ▲ reads ObserverState; writes nothing back
```

The three components are three authorities. 2.0 observes. `aip-enforce`
decides syscalls. `aip-interlock` decides whether an actuator may be
energised. **None of them can write into another**, and each of the two new
crates carries a test that reads its own manifest to keep it that way.

## 1a. Lineage — which "Sniffer Dog" this is built on

There are two things in this repository's history that a reader may call
Sniffer Dog, and 3.0 is built on exactly one of them.

| | `ot-sentinel` | `aip-observe` (Sniffer Dog 2.0) |
|---|---|---|
| where | `import/orbitaltrust-accountability-layer` only (PR #3, one commit `6cc439f`, imported from ASC-space). **Not on `main`, not on the production branch.** | production branch; merged into this branch at `429939a` |
| what it reads | **application-layer JSONL logs** the surrounding system writes — a tool server's access log, an egress proxy's log, an exec audit trail (`sensors.rs`). Zero uses of `perf_event_open`, netlink, tracepoints or procfs | **kernel-pushed sources**: `sched`/`sock` tracepoints via `perf_event_open`, the netlink process connector, `fanotify`, the `AF_PACKET` tap, pidfd-anchored procfs |
| who authors the content | the writing process, from its own program | the kernel, from its own state |
| key | the sentinel signs its own findings on the host | keyless probe on the host; collector signs off-host |
| tests reproducible here | 82 lib unit tests; the 31 `ghost_hunt` scenarios **do not build** (depend on `ot-mcp-gateway` / `ot-pqc`, absent from the import) | full workspace suite, plus sealed live validation runs |
| uses the name "Sniffer Dog" | never — zero occurrences on that branch | yes |

**`ot-sentinel` is the ancestor, not the base.** The production branch
already put it through `OT_SENTINEL_HARVEST_AUDIT.md` (Phases 0–3, with
builds and tests reproduced in a scratch workspace) and harvested what
survived the gates: its response policy became `aip-warrant`; its four-way
continuity audit (Amnesia / RolledBack / Forked / ArchiveTruncated) became
the collector's `ContinuityBreak` taxonomy; its graph resolution was rebuilt
over signed chains. Its **log-tailing sensors were deliberately fenced out
as observation** by `APPLICATION_LOG_SENSOR_DECISION.md` (Gate 5, DECIDED):
an application, database or proxy record is a statement written by a
host-side process about itself — a witness's claim, `Claimed` at best, with
no loss signal the observer can trust — and it may never produce, upgrade
or lower a verdict, never count as coverage. The gateway was rejected as
code (unbuildable, a second evidence model) and kept as deployment design.

So: 3.0 sits on the kernel-observing 2.0, which is the only lineage with an
off-host key and a trustworthy loss signal. Nothing of `ot-sentinel` that
was not already harvested is re-imported here, and in particular its log
sensors are not a 3.0 tier — the decision that excludes them stands.

## 2. Tier status

| tier | crate | what it does | status | evidence |
|---|---|---|---|---|
| Observation | `aip-observe` | kernel-pushed observation; `IntegrityUnknown` on a foreign tracepoint gate | **2.0, shipped** | sealed validation runs, `12767ea` |
| Enforcement | `aip-enforce` | seccomp user-notify supervision under a signed, counter-bound capability epoch; signed `EnforcementDecision` records | **shipped** | 16 pure tests + 5 live tests on kernel 6.18.44 |
| Interlock | `aip-interlock` | signed heartbeat, watchdog state machine, safe-state precondition, signed board measurements | **shipped, host side + state machine; no board firmware, no hardware** | 3 unit + 16 adversarial tests |
| Payload comparison | — | `sk_msg` capture, userspace hashing, `PayloadDivergence` as an `ActionComparison` | **specified only** | `CYBER_PHYSICAL_SAFETY_STACK.md` §2.2 |
| Scope attenuation | — | post-ingest scope may only shrink; reuse `is_scope_subset` | **specified only** | `CYBER_PHYSICAL_SAFETY_STACK.md` §2.4 |

## 3. Enforcement tier — contract

**Mechanism.** Classic-BPF seccomp filter installed in the child with
`no_new_privs`, returning `SECCOMP_RET_USER_NOTIF` for `execve`/`execveat`
and `SECCOMP_RET_ALLOW` otherwise. The listener is duplicated into the
supervisor with `pidfd_getfd` after a two-way handshake, and the child drops
its own copy before it execs — otherwise the child would hold open the file
that gates its own syscall.

**Decision.** Pure: `decide(health, cache, request, now)`. Deny on any of:
enforcer degraded, no epoch, epoch not yet valid, epoch expired, program not
in the epoch's content-hash set, program unhashable. The order is the order
of the enum.

**Epoch.** Signed by an issuer the enforcer anchors, over a domain-separated,
prefix-free encoding. The anchor declares the issuer's root of trust; an epoch
claiming a different root is refused before its signature is checked. The
counter must strictly exceed the highest admitted; a replay evicts nothing.
Only `RootOfTrust::SoftwareKey` has an issuer in this repository.

**Record.** Every decision is signed by the enforcer's own key under
`SYNTRIASS/GHOST/ENFORCEMENT_DECISION/v1`, carrying the process instance the
supervisor measured (`None` when it could not — never a guess).

**The standing table** (ADR-015 §2), pure and tested:

| enforcer claim | observer finding | standing |
|---|---|---|
| denied | no execution observed | `Held` |
| denied | **execution observed** | **`Bypassed`** |
| allowed | execution observed | `Ordinary` |
| allowed | no execution observed | `Unexercised` |
| any | observation unavailable | `CannotEstablish` — silence never confirms a denial held |

This crate defines the finding's *shape* and never produces one; producing
one is observation.

**What the live tests establish** (`aip-enforce/tests/live.rs`, kernel
6.18.44-fc-v24, x86_64):

- an allowed program executes; a disallowed one fails with `EPERM` and the
  shell reports 126;
- with no epoch, even the launch is refused;
- an expired epoch denies a program it names;
- **a supervisor that closes its listener without answering leaves the child
  unable to exec — the kernel returns `ENOSYS`** — fail-closed by the kernel,
  not by this crate;
- every record verifies under the enforcer's anchor and carries the epoch id.

**Stated residuals.** A root adversary detaches the supervisor. The path→file
race between the supervisor's hash and the kernel's own open under `CONTINUE`
is narrowed (hash through `/proc/<pid>/root`, refuse relative paths and
fd-relative `execveat`) but closed only by a read-only mount, which is a
deployment obligation. `connect` gating is in the pure decision and not yet
in the live supervisor.

## 4. Interlock tier — contract

**Heartbeat.** `SYNTRIASS/GHOST/INTERLOCK_HEARTBEAT/v1`: interlock id, sender
id, epoch, strictly increasing counter, counter source (`Software` or
`Atecc608b` — only the former exists here), host condition, sender clock.
Signed by the host; verified by the interlock against its own anchors.
`VerifiedHeartbeat` has no constructor other than verification.

**Condition.** Derived exhaustively from `ObserverState`: `Active` →
`Nominal`; every other state → `Withheld(ObserverNotActive { code })`. A new
observer state is a build failure, not an armed actuator. Enforcement
degradation and operator hold also withhold. A withheld heartbeat is still
signed and sent — a positive "I cannot vouch" beats silence a board cannot
tell from a cut cable.

**Watchdog.** `Disarmed → Armed → Tripped`, with `Tripped` absorbing. Trips
on: silence past `period × (tolerated_misses + 1)`, a counter that does not
increase, an epoch mismatch, or a withheld condition. A clock that goes
backwards counts as the full budget elapsed. Only `operator_reset` leaves
`Tripped`; no heartbeat does.

**Safe state.** `ActuatorProfile.safe_state` is not optional. Arming is
refused when the worst-case trip time exceeds the actuator's declared
stopping budget, when the first heartbeat is not `Nominal`, and when the
watchdog is tripped. **This crate never chooses a safe state.** De-energising
is unsafe for a multirotor in flight and a loaded gripper; the declaration is
the operator's, after their hazard analysis.

**Measurement.** `SYNTRIASS/GHOST/INTERLOCK_MEASUREMENT/v1`, signed by the
*board's* key: current, encoder ticks, or relay contact state, placed against
the last accepted counter. **Not an `ObservationRecord`** — no
`SourceMechanism` exists for it, and `aip-observation` is deliberately not a
dependency. This is exactly one step short of Stage 4 of the physical
validation roadmap, and that step belongs in `aip-observation`.

**What is not here.** Board firmware. A transport. Any hardware. The state
machine is written to compile for a Cortex-M4 later and is tested on the host
now, where the tests cannot be skipped.

## 5. What 3.0 does not claim

- **It does not close B-3.** The software containment path remains
  ACCEPTED/JUSTIFIED and unreachable from engine output. Enforcement is
  prevention before a verdict; the interlock is an out-of-band safety
  function. Neither produces a `Reconciliation`.
- **It does not raise any evidence strength.** An enforcement decision and an
  interlock measurement are claims by their signers.
- **It does not survive root.** Both new tiers say so in their own text.
- **It does not use BPF-LSM, kprobes, fentry or in-kernel hashing**, because
  none exists on the validation kernel and the first cannot consult hardware
  in any case.
- **It has not touched the bench.** No STM32, no ATECC608B, no TPM, no relay,
  no current sensor has been exercised.

## 6. Test evidence

| suite | tests | result | kernel |
|---|---|---|---|
| `aip-interlock` unit | 3 | pass | n/a |
| `aip-interlock/tests/adversarial.rs` | 16 | pass | n/a |
| `aip-enforce/tests/adversarial.rs` | 16 | pass | n/a |
| `aip-enforce/tests/live.rs` | 5 | pass | 6.18.44-fc-v24, x86_64, uid 0 |

The live suite forks real children under a real filter. It needs
`CONFIG_SECCOMP_FILTER` and `pidfd_getfd` over one's own child, both of which
the validation host has and which a hardened CI runner may not.

## 7. Next, in order

1. Board firmware for the watchdog core and a serial/Ethernet transport for
   the heartbeat — then the first physical trip.
2. Current sensing on the board and the `aip-observation` mechanism that
   turns `InterlockMeasurement` into an `ObservationRecord` (roadmap Stage 4).
3. `connect` gating in the live supervisor via `cgroup/connect4`.
4. Payload comparison (`sk_msg` + userspace hashing).
5. The scope-attenuation rule in the reconciler.
6. An `EpochIssuer` backed by an ATECC608B's monotonic counter — the point at
   which `RootOfTrust::Atecc608b` stops being vocabulary.
