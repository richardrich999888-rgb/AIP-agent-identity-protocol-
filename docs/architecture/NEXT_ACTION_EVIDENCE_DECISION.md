# NEXT ACTION EVIDENCE DECISION

Architecture review before any enforcement stage: which action class, after
TCP connection establishment, adds the most independently observable
evidence for the least architectural compromise. Decided from the repository
and this host, not from convenience.

## 1. Problem

Ghost can independently prove exactly one thing an agent does: that an
authorized process instance established a TCP connection to an authorized
endpoint (`ACTION_EVIDENCE.md`, §14). Every other action an agent performs —
running a tool, writing a file, resolving a name, using a credential —
reconciles to `CANNOT_PROVE`, and an agent that never opens a TCP connection
is invisible to the action layer entirely. One class is a proof of
architecture, not a useful evidence surface.

## 2. Current proven boundary

| Layer | Proven | Not proven |
|---|---|---|
| Authorization | DP-signed `ExpectedExecution` with action kind, parameter digest, binding, window | anything about what happened |
| Observation | pidfd-anchored instance facts; kernel-pushed fork/exec/exit (connector); kernel-pushed TCP state transitions (perf tracepoint); polled socket tables; signed coverage, loss, restart | procfs truth under root; anything payload-level |
| Reconciliation | `CANNOT_PROVE` default; `PHANTOM_CLAIM` under recomputed lifecycle coverage; `IDENTITY_DIVERGENCE`; `SENSOR_INTEGRITY_FAILURE`; `CONTINUITY_FAILURE`; `VERIFIED_EXECUTION` for `ghost.net.connect.v1` as `Presence` or `Transition`, `Attested` | `VERIFIED_EXECUTION` for any other kind; `UNATTRIBUTED_EFFECT`; `LINEAGE_VIOLATION` |

## 3. What an action evidence adapter must provide

The Stage 7/7b work fixes the shape. Every evidence class must separate, as
distinct types or fields, never merged:

| Concern | Where it lives | What it is |
|---|---|---|
| **Observation** | `ObservedExecution` | a measurement the probe took (process facts, socket row) |
| **Event** | `KernelLifecycleEvent { kind, mechanism, cpu, kernel_timestamp_ns, probe_seq, bound, attribution, claimed_decision_id }` | a fact the kernel pushed, with its own time and CPU |
| **Action evidence** | derived in `aip-reconcile::action` (`derive_action`, `derive_transitions`) | the reconciler's deterministic interpretation of observations/events as `(action_kind, parameter_digest)`; never authored by the observer (I19) |
| **Process binding** | `bound: Option<ObservedProcess>` | pidfd-anchored `(pid, start_ticks, boot_id, exe_sha256)` at event time, with the start-time rule; `None` is a pid reference, never identity |
| **Temporal placement** | `attested_at_ms` (collector clock, signed), `clock_anchor` (probe claim), `kernel_timestamp_ns` | before / within / after / unanchored; kernel and wall clocks never compared without an anchor |
| **Provenance** | `SourceMechanism` per observation/event, gated by the collector registry, `probe_policy` in health | which mechanism produced the bytes; `Open` = unverified |
| **Coverage** | `attested_coverage`, `covered_by` (signed), recomputed by the reconciler from batches | what interval, by which mechanisms, was continuously observed |
| **Loss** | `dropped_events: Option<u64>` → `Degraded` | `None` = no counter (never "zero"); `Some(n>0)` = counted loss |
| **Correlation / join keys** | `decision_id` (claim), structural `ExecutionBinding` match, `sk` for sockets, `(parent_pid, child_pid)` for spawns | typed; pid alone never joins |
| **Strength** | `EvidenceStrength` enum, fixed by result kind; `ActionEvidenceKind` names the fact | no scalar, no severity, no `trusted = true` |

The interface a new class must implement is therefore: a `SourceMechanism`
variant (kernel-pushed or not, lifecycle-covering or not); a
`KernelLifecycleKind` (or `ObservedEffect`) variant carrying only kernel
fields; a probe ingestion rule stating exactly which task is the actor and
when it is anchored; an authorization vocabulary in `aip-authorize::actions`;
one deterministic derivation in `aip-reconcile::action`; and the temporal,
claim, coverage and provenance predicates already enforced by
`compare_action` and the central guard.

## 4. Candidate action classes

| # | Class | Kernel primitive on this host | Actor binding | Notes |
|---|---|---|---|---|
| 1 | TCP connection establishment | `sock:inet_sock_set_state` via perf | initiation in caller context | **done** |
| 2 | Process execution / subprocess creation | `sched:sched_process_fork` (parent context; `parent_pid`, `child_pid`), `sched:sched_process_exec` (child context; kernel-authored `filename`, `pid`, `old_pid`) via perf; proc connector fork/exec already ingested | fork: parent = actor, anchorable; exec: child anchorable, `/proc/<pid>/exe` hashed | measured live: fork fires under the parent, exec under the child |
| 3 | File creation / modification | `syscalls:sys_enter_openat` exposes `filename` as a **user pointer only** (measured); fanotify (`FAN_REPORT_PIDFD`) would be needed | fanotify: pidfd per event | needs a new mechanism family; no path from tracepoints without eBPF |
| 4 | Privileged operation | no tracepoint for `cap_capable`; audit subsystem | — | no kernel-pushed source in scope |
| 5 | Outbound network connection | = 1 for TCP; UDP has no state machine | — | UDP: existence only, no transition |
| 6 | DNS resolution | payload (I23) | — | out |
| 7 | Subprocess creation | = 2 | | |
| 8 | Credential / token use | application-level | — | out |
| 9 | IPC | unix sockets are outside `inet_sock_set_state`; no tracepoint with peer identity | — | out for now |
| 10 | Other kernel effects (mount, module, ptrace) | connector reports ptrace attach (`Other`); no instance binding of the target | — | later |

## 5. Comparison matrix

Scored against the criteria in the task; ✓ strong, ◐ partial, ✗ absent.

| Criterion | 2 process exec | 3 file write | 5 UDP | 9 IPC | 10 other |
|---|---|---|---|---|---|
| independent kernel evidence | ✓ two static tracepoints, kernel-pushed | ◐ fanotify (kernel), new family | ◐ table only | ✗ | ◐ |
| binds to an execution instance | ✓ actor = fork's parent (process context); child anchored at exec | ✓ via pidfd | ◐ table join | ✗ | ✗ |
| correlates with `ExpectedExecution` | ✓ params = executable content hash (Stage 1 identity rule), kernel `filename` as context | ◐ path is not content; needs a path vocabulary | ◐ | ✗ | ✗ |
| pre- vs post-authorization | ✓ an exec is an instant; anchored kernel time + collector clock, as for TCP | ✓ | ✗ (existence) | — | — |
| detects unauthorized effects | ✓ every child exec of the bound agent is an event; with a DP completeness statement → `UNATTRIBUTED_EFFECT` | ✓ | ✗ | — | — |
| detects phantom claims | ◐ requires lifecycle coverage (connector) as today; sched exec stream adds exec coverage | ◐ | ✗ | — | — |
| exposes action-level evidence | ✓ *what ran* (hash) and *who ran it* (actor instance) | ✓ | ✗ | — | — |
| loss semantics | ✓ `PERF_RECORD_LOST` (same ring code) | ◐ fanotify queue overflow event | none | — | — |
| replay resistance | ✓ claim-tied at the actor's fork event; pid pair + kernel times | ✓ | ✗ | — | — |
| root-host limits | same as TCP: root can stop the ring; content of delivered events is kernel-authored | same | worse | — | — |
| implementation complexity | **low**: reuses the perf tracepoint reader, the anchor, the claim, the guard | high: new mechanism family, mount marks, permission model | low but weak | high | high |
| runs on existing Sniffer Dog | ✓ the mechanism family exists | ✗ new family | ✓ | ✗ | ✗ |

## 6. Security properties of the chosen class

- **Actor attribution is kernel-contexted.** `sched_process_fork` runs in the
  parent's task; the probe anchors `parent_pid` with a pidfd and binds only
  if the parent instance's start tick is not later than the fork's kernel
  time. The actor is therefore `(pid, start, boot, exe_sha256)` of the
  process that forked, not a pid.
- **What ran is content, not path.** The child is anchored at
  `sched_process_exec` and `/proc/<child>/exe` is hashed; the kernel's
  `filename` is recorded as context and never enters the digest (Stage 1
  rule: path-only identity is forbidden).
- **The child instance is the forked child.** Its start tick must lie at or
  after the fork's kernel time and at or before the exec's; a recycled pid
  fails the bound.
- **Two events, one pair.** Fork and exec are paired by `child_pid` with
  exec not earlier than fork; an exec with no anchored fork is an
  unattributed exec (kernel fact, actor `CANNOT_PROVE`); a fork with no exec
  is a spawn without an execution (`ActionTransitionIncomplete`).
- **Temporal placement** reuses the Stage 7b rules: collector clock proves
  *before*; anchor places; no anchor → `Unanchored`.
- **Claims** are attached to the fork event by the actor's registered pid
  and are join keys only.

## 7. Evidence requirements for `VERIFIED_EXECUTION · Transition` (exec)

1. DP-signed `ExpectedExecution` with `action_kind = ghost.process.exec.v1`
   and `parameter_digest = digest({exe_sha256})`.
2. Verified observer chain and health, `Active`, `RegisteredOnly`.
3. A `ProcessSpawn` event (mechanism `SchedTracepoint`) whose **bound parent**
   matches the binding structurally, claimed under this decision and agent.
4. A `ProcessExec` event for that `child_pid`, not earlier in kernel time,
   whose **bound child** carries `exe_sha256` equal to the authorized digest's
   input, with child start tick within `[fork_ts, exec_ts]` (tick tolerance).
5. Placement inside the window (collector clock, then anchor); both carrying
   batches inside attested coverage.
6. Central guard: sealed `Match`, identity `Match`, `action_continuity_verified`,
   strength exactly `Attested`.

## 8. Failure modes → results

| Situation | Result |
|---|---|
| fork seen, parent could not be anchored (exited) | unbound → pid reference → `CANNOT_PROVE / UnboundReferencesOnly` |
| exec seen, child exited before anchoring | exec unbound; spawn incomplete → `ActionTransitionIncomplete` |
| child re-execs before the probe hashes | hash is of the current image at anchor time; documented as with Skill 6.5 `t10` |
| exec of a different binary | digest differs → `ActionEvidenceDoesNotMatch` (kind `Transition`) |
| fork by another instance (same binary, other pid/start) | not a match; claim consistent → `IDENTITY_DIVERGENCE` |
| exec before the decision | `ActionPrecedesAuthorization` (collector clock or anchor) |
| exec after `valid_until` | `ActionEvidenceOutsideWindow` |
| no anchor | `KernelTimeUnanchored` |
| ring loss | `Degraded` → `CANNOT_PROVE` |
| probe restart | `CONTINUITY_FAILURE` |
| unprovisioned mechanism | refused at attestation |
| `Open` policy | `ProvenanceUnverifiedOpenPolicy` |
| any field mutated | `SENSOR_INTEGRITY_FAILURE · Proven` |
| claim names another decision / agent | `ActionEvidenceUnclaimed` / `ClaimInconsistent` |

## 9. CANNOT_PROVE boundaries (unchanged in kind)

Arguments and environment of the executed program (the kernel exposes
`filename` only); what the child did afterwards; the truth of the hashed
image under a root host that swaps `/proc/<pid>/exe` (procfs); exec chains
faster than the probe's anchoring (the hash is of the image present at the
anchor); anything on a host whose root disables or starves the ring; PID
reuse inside one `CLK_TCK` tick; wall-clock placement beyond what the
collector clock decides; non-execution from absence (a phantom still needs
recomputed lifecycle coverage); `Proven` for any content-based fact.

## 10. Recommended next action class

**Process execution — `ghost.process.exec.v1`: an authorized instance
spawning a child that executes an image with a given content hash.**

## 11. Why it is the highest-value next step

An AI agent that does anything on a host runs tools: shells, interpreters,
package managers, `curl`. Every one of those is a fork + exec. This class
makes *what an agent ran* independently observable and matchable to *what it
was authorized to run*, using a kernel source that is already in Sniffer Dog's
family (perf tracepoints), already anchored (pidfd), already timed (boot
clock), already loss-accounted (perf ring). It requires no new mechanism
family, no new trust anchor, no new signed object, and no change to the
reconciler's guard — only a second derivation and a second vocabulary entry.
The file class would be the next most valuable but needs fanotify, a new
mechanism family with its own permission and mount semantics; the remaining
candidates lack a kernel-pushed source with instance binding.

## 12. What it unlocks in reconciliation

`VERIFIED_EXECUTION · Transition` for tool execution; `IDENTITY_DIVERGENCE`
when another instance spawns the authorized tool under the agent's claim;
observed-only exec events as inputs to a future `UNATTRIBUTED_EFFECT` once a
decision point publishes completeness statements; and, with the connector,
actor→child lineage as *attested observation* — the missing input
`EXECUTION_BINDING.md` §11a named for `LINEAGE_VIOLATION`. This stage does
**not** implement lineage violations; it records the attested pair.

## 13. What it still cannot prove

Everything in §9. In particular it does not prove *intent*, does not prove
what the tool did, and does not prove non-execution.

## 14. Required kernel mechanism

`perf_event_open(PERF_TYPE_TRACEPOINT)` on `sched:sched_process_fork` and
`sched:sched_process_exec`, per online CPU, record layouts read from tracefs
(`__data_loc char[]` fields decoded by the offset/length word they carry).
tracefs must be mounted; it was **not** mounted by default in this session's
fresh container and had to be mounted by the operator — a deployment
requirement, recorded. No eBPF.

**Clock (corrected during implementation).** This section originally said
`CLOCK_BOOTTIME`, following Stage 7b's documentation. Implementing the
child-start-tick bound exposed that the Stage 7b samples were not on that
clock: the `use_clockid` flag had been set at the wrong bit, and when set
correctly the tracepoint PMU on this kernel rejects `BOOTTIME`, `REALTIME` and
`TAI` with `EINVAL`, accepting only `CLOCK_MONOTONIC`/`MONOTONIC_RAW`
(measured). Event stamps are therefore `CLOCK_MONOTONIC`; the anchor carries
realtime, boottime, monotonic and `CLK_TCK`, and converts start ticks into
the event clock. `ACTION_EVIDENCE.md` §15.4.

## 14a. Outcome

Implemented as decided: `a5e2cbf` (this document + RED), `1d52f93` (GREEN).
Live on this host: X-P `VERIFIED_EXECUTION · Attested ·
Match(SchedTracepoint, Transition)`; X-A `ActionEvidenceDoesNotMatch` on
content; X-B `AmbiguousObservations` (the bound agent's own exec event is a
genuine match while the other instance's spawn is divergent — ambiguity is
reported, not resolved); X-C `ActionPrecedesAuthorization · BeforeWindow`.
Nothing in §9 became provable; §17 holds.

## 15. Required tests

RED before implementation (live, real processes): an authorized spawn of a
known binary must verify (fails today: `ActionEvidenceUnavailable`); a spawn
of a different binary, a spawn by another instance, and a spawn before the
decision must not verify (pass today for the wrong reason — nothing verifies —
and are pinned). After implementation, fixture-based adversarial tests for:
wrong parent instance (pid / start / boot / exe), unbound parent, unbound
child, child pid recycled (start tick outside `[fork, exec]`), exec of another
binary, exec before / after the window, unanchored, incomplete (fork without
exec), pairing order, other decision / agent / no claim, replay/duplication,
mutation of every field of both events, unprovisioned mechanism, `Open`
policy, loss, restart, and the sched stream not standing in for connector
lifecycle coverage in `PHANTOM_CLAIM`.

## 16. Required documentation

`ACTION_EVIDENCE.md` (second class, §15), `ACTION_EVIDENCE_IMPLEMENTATION_REPORT.md`,
`SNIFFER_DOG.md` (mechanism, event model, deployment: tracefs mount),
`SNIFFER_DOG_IMPLEMENTATION_REPORT.md`, `RECONCILIATION_MODEL.md`,
`RECONCILIATION_IMPLEMENTATION_REPORT.md`, `GAP_MATRIX.md`,
`IMPLEMENTATION_PLAN.md`; this document.

## 17. Explicit non-goals

No containment, warrant, kill, freeze, cgroup, firewall or XDP. No NEXORA. No
PQC claim. No eBPF. No file, DNS, credential or IPC class in this stage. No
argument capture. No generic "AI security engine": one vocabulary entry, one
derivation, one mechanism, and the same `CANNOT_PROVE` default.
