# SNIFFER_DOG — kernel-mediated evidence sources for the Ghost observer

Status: **IMPLEMENTED (procfs poll, pidfd-anchored measurement, netlink
process-event connector, kernel socket tables, provenance gating; since
Stages 7b/7c three static tracepoints — `sock:inet_sock_set_state`,
`sched:sched_process_fork`, `sched:sched_process_exec` — read through
`perf_event_open` rings) / NOT IMPLEMENTED (eBPF, any other tracepoint, XDP,
packet or wire visibility, filesystem and syscall observation, network
transport, durable collector state).**

> The agent-level layer around this observer — identity, profile, lineage,
> capability passport, experience ledger, history, evidence graph, profile API
> — is specified, **DESIGN_ONLY**, in `SNIFFER_DOG_2_0_SPECIFICATION.md`.
> Nothing in that document changes the trust boundary described here.

Stage 6.5 (`aip-standalone/aip-observe`, protocol version 2; version 3 after
the PR3 correction that adds `ObservationBatch.active_mechanisms` and
`SensorHealth.covered_by` — see §6a). Skill 6 remains
the attestation foundation; this stage changes only *where the observed facts
come from* and *how a verifier can tell*. Nothing here authorizes, reconciles,
scores, classifies, or actuates.

---

## 1. The blind spot this closes, and the one it does not

Skill 6 established: an independently keyed collector attests which bytes it
received from a host probe, in what order, with what continuity. Its report
recorded the remaining gap plainly: the *content* of those bytes was a procfs
read taken by a probe on the observed host, and a root-compromised host can
present any procfs it likes. Nine characterization tests
(`tests/blind_spots.rs`, run before any change) pinned the consequences:

| Case | Finding against Skill 6 | Classification |
|---|---|---|
| A/J procfs content | fabricated and real measurements indistinguishable at the collector | PROVEN blind spot; root resistance = DEPLOYMENT ASSUMPTION |
| B start/exit between polls | short-lived process leaves no record | PROVEN blind spot; kernel event source NOT_IMPLEMENTED |
| C reads unanchored | no proof two procfs reads belong to one instance | CANNOT_PROVE |
| D exec replacement | identity changes if both sides are polled; the event itself unseen | PROVEN partial; exec event NOT_IMPLEMENTED |
| E/F network, syscalls | no observation path | NOT_IMPLEMENTED |
| G restart vs execution | outage uncovered (Skill 6 handled); execution across it | CANNOT_PROVE |
| H dropped events | polling has no loss signal | NOT_IMPLEMENTED |
| I ordering/time | collector order only; host clock contextual; no kernel time | NOT_IMPLEMENTED |

What Stage 6.5 changes: B, D, H and I now have a kernel-generated source; C
has a kernel-bound instance anchor; E has a socket-level (not packet-level)
source; every observation states its provenance inside the signed bytes; and a
host-side party can no longer *label* its report as kernel-sourced.

What Stage 6.5 does **not** change: a root attacker on the observed host still
controls what the kernel *shows* the probe through procfs, can kill or starve
the probe, and can race it. The kernel-pushed events narrow the lie — their
existence, order, CPU and monotonic timestamp are the kernel's — but the
identity behind an event is still established from procfs. See §8.

## 2. What this environment can observe (measured, not assumed)

Probed on the build host before design (Linux 6.18, Firecracker microVM):

| Capability | Result | Used? |
|---|---|---|
| root, `CAP_NET_ADMIN`, `CAP_BPF`, `CAP_PERFMON` | present | — |
| initial PID and network namespace | yes (`/proc/1/ns/pid == /proc/self/ns/pid`) | required by connector |
| `pidfd_open` | works | **yes** |
| netlink process-event connector (`CONFIG_PROC_EVENTS=y`) | delivers FORK/EXEC/EXIT with pid, tgid, cpu, `timestamp_ns`; `ENOBUFS` on overflow | **yes** |
| `/proc/net/{tcp,udp}` (no v6 tables on this host) | readable | **yes** |
| `bpf()` syscall | reachable (EINVAL on garbage, not EPERM) | **no** — NOT_IMPLEMENTED |
| tracefs `/sys/kernel/tracing` | mounted | **no** — NOT_IMPLEMENTED |
| `perf_event_open` | reachable | **no** — NOT_IMPLEMENTED |
| XDP / driver hooks | not investigated; nothing here needs the wire | **no** — NOT_IMPLEMENTED |

The choice of the connector over eBPF is deliberate for this slice: it is
kernel-generated, needs no BPF loader crate or program compilation, exposes an
explicit loss signal, and is implementable with `libc` alone (already in the
lockfile). eBPF/tracepoints remain the path to syscall and file effects and to
exec arguments, and are recorded as future work, not as a capability.

## 3. Architecture

```text
 OBSERVED HOST (attacker reach)                     OFF-HOST COLLECTOR
 ────────────────────────────────────────────       ───────────────────────────────────
 ProcfsProbe   run_id, per-run seq, loss counter    CollectorSigner   key · ledger · registry
   sources:                                           · ProbePolicy Open | RegisteredOnly
   · ProcfsPoll        /proc read                     · registry: probe_id → mechanisms it
   · PidFdAnchored     /proc read inside pidfd           may claim   (refuses others)
   · ProcConnector     kernel FORK/EXEC/EXIT          · tracks probe run_id (restart),
                        + cpu + kernel ts               seq range (gap/replay), loss
   · ProcNetTable      /proc/net/* ⋈ /proc/<pid>/fd    · continuity ledger (Skill 6)
   │                                                  · signs AttestedBatch, SensorHealth
   ▼                                                  ▼
 ObservationBatch  unsigned; no signature field ──▶ AttestedBatch  signed; head computed
```

## 4. Event model (protocol version 2)

| Structure | Domain | New in 6.5 |
|---|---|---|
| `ObservedExecution` | `SYNTRIASS/GHOST/OBSERVED_EXECUTION/v1` | `mechanism: SourceMechanism` (signed); `ObservedEffect::SocketObserved` |
| `KernelLifecycleEvent` | `SYNTRIASS/GHOST/KERNEL_EVENT/v1` | new: kind (Fork/Exec/Exit/Other), `cpu`, `kernel_timestamp_ns`, `probe_seq`, `bound: Option<ObservedProcess>`, attribution, claimed decision id |
| `ObservationBatch` | `SYNTRIASS/GHOST/OBSERVATION_BATCH/v1` | `probe_run_id`, `probe_seq_first/last`, `dropped_events: Option<u64>`, `kernel_events`; v3: `active_mechanisms` |
| `SensorHealth` | `SYNTRIASS/GHOST/OBSERVER_HEALTH/v1` | `probe_policy`; v3: `covered_by` |
| `AttestedBatch` | `SYNTRIASS/GHOST/OBSERVER_HEAD/v1` | v4: `attested_at_ms` — the collector's own clock, signed |

**Protocol version 4 (Stage 7b).** `KernelLifecycleKind::SocketState`
(protocol, local, remote, `old_state`, `new_state`, kernel socket identity
`sk`, `current_pid`) delivered by the `sock:inet_sock_set_state` tracepoint
through `perf_event_open`; `ObservationBatch.clock_anchor` (a probe sample of
the host realtime and boot clocks, so kernel timestamps can be placed on the
wall clock — a probe claim); `AttestedBatch.attested_at_ms` (the collector's
clock at signing, inside the signed preimage). `SourceMechanism::
SockStateTracepoint`. Version 3 records are refused like earlier versions.

**Protocol version 5 (Stage 7c).** `KernelLifecycleKind::ProcessSpawn`
(`parent_pid`, `child_pid`, both `comm`s) and `ProcessExec` (`pid`, `old_pid`,
the kernel's `filename`) delivered by the `sched:sched_process_fork` and
`sched:sched_process_exec` tracepoints through the same perf plumbing;
`SourceMechanism::SchedTracepoint`; `BootClockAnchor` gains `monotonic_ns`
and `clk_tck` so the probe's process start ticks can be placed on the event
clock (§6b). Version 4 records are refused like earlier versions.

Every new field is inside the canonical encoding (single encoder,
`aip_types::canonical`; length-prefixed strings; explicit codes for enums;
presence byte for options; counts for vectors). Version 1 records are refused
by the collector and by every verifier — the Stage 3 format existed only on
this branch and was never released.

### `SourceMechanism` — provenance, signed and gated

| Mechanism | Kernel-pushed? | Instance-anchored? | Root can forge content? | Loss signal |
|---|---|---|---|---|
| `ProcfsPoll` | no | no | yes | none |
| `PidFdAnchored` | binding is kernel state; facts are procfs | **yes** | yes | n/a |
| `ProcConnector` | **yes** | only if a pidfd anchor succeeded (`bound`) | existence/order/cpu/time: no (user space cannot inject into the kernel's netlink source); identity: yes | **`ENOBUFS`** |
| `ProcNetTable` | no (polled kernel table) | taken under a pidfd anchor | yes | none |
| `SockStateTracepoint` | **yes** (static tracepoint via the perf ring) | only for `CLOSE → SYN_SENT` — the `connect()` call runs in the caller's context — and only if a `PidFdAnchored` measurement of `current_pid` succeeded and its start tick is not later than the event's kernel time | existence/order/time/endpoints: no (kernel-authored, user space cannot inject); identity: yes (procfs); root can disable or starve the ring | **`PERF_RECORD_LOST`** (counted per ring) |
| `SchedTracepoint` | **yes** (two static tracepoints via the perf ring) | fork: the parent (the event fires in the parent's context) if a `PidFdAnchored` measurement of `parent_pid` succeeded under the start-tick rule; exec: the new image's task if anchored likewise. The child of a fork is bound at its exec, not at the fork | existence/order/time/pids/kernel filename: no; identity and image content: yes (procfs); root can disable or starve the ring | **`PERF_RECORD_LOST`** (counted per ring) |

### `SockStateTracepoint` — what the kernel says about a connection

`perf_event_open(PERF_TYPE_TRACEPOINT, sock:inet_sock_set_state)` on every
online CPU, sample type `TID | TIME | CPU | RAW`, `use_clockid` with
`CLOCK_MONOTONIC` (Stage 7c correction: the tracepoint PMU on this kernel
rejects `BOOTTIME`, `REALTIME` and `TAI` with `EINVAL`, and Stage 7b's flag
had been set at the wrong bit — see `ACTION_EVIDENCE.md` §15.4), one 8-page
ring per CPU. The record layout is read from
tracefs (`events/sock/inet_sock_set_state/format`) at open time, never
assumed. Measured on this host's 6.18 kernel:

- `CLOSE → SYN_SENT` fires in the connecting task's context — `current_pid`
  is the caller; the local port is **not yet assigned** (`sport = 0`).
- `SYN_SENT → ESTABLISHED` carries the full 4-tuple but runs in softirq
  context; its `current_pid` names nobody in general.
- The two are linked by `sk`, the kernel socket identity, for the socket's
  lifetime. `subject_pid()` therefore returns `Some` only for the initiation.

Loss: a ring overflow is reported as `PERF_RECORD_LOST` with a count; the
probe folds it into `dropped_events` and the collector degrades the window
(`Degraded`), exactly as for connector `ENOBUFS`. A record that fails to
decode is counted as lost, never guessed.

Privilege: tracefs mounted and either `perf_event_paranoid ≤ -1` or
`CAP_PERFMON`/`CAP_SYS_ADMIN`. Absent either, `SockStateTracer::open` is
`Unavailable` and the mechanism does not exist for that host. No eBPF, no
XDP, no packet capture is involved or claimed.

### `SchedTracepoint` — what the kernel says about a process (Stage 7c)

`perf_event_open(PERF_TYPE_TRACEPOINT)` on `sched:sched_process_fork` and
`sched:sched_process_exec`, same sample type, clock, ring and layout
discipline as above (`aip-observe/src/perf.rs` is shared; `sched.rs` decodes
the two records, including the `__data_loc char[]` fields by the
offset/length word they carry). Measured on this host before implementation:

- `sched_process_fork` fires in the **parent's** task context with
  `parent_pid`, `child_pid`, `parent_comm`, `child_comm` — the spawning task
  is attributable at the event. `subject_pid()` is the parent;
  `spawned_child_pid()` is the child.
- `sched_process_exec` fires in the **new image's** context with `pid`,
  `old_pid` and the kernel-resolved `filename`. The content of the image is
  **not** in the event; the probe hashes `/proc/<pid>/exe` under a pidfd
  anchor, and only that hash enters action evidence. `filename` is context.
- Instance binding for both uses the start-tick rule: the process's
  `/proc/<pid>/stat` start ticks, converted to the event clock through the
  batch's anchor, must not exceed the event's kernel timestamp.

Loss, privilege and the absence of eBPF/XDP are exactly as for
`SockStateTracepoint`. The sched stream **does not** provide process-lifecycle
coverage for `PHANTOM_CLAIM` (`covers_process_lifecycle` is `ProcConnector`
only): it reports forks and execs that happened, it says nothing about exits
and the reconciler does not let it stand in for the connector.

**Deployment requirement.** tracefs must be mounted (`mount -t tracefs nodev
/sys/kernel/tracing`). It was **not** mounted by default in this session's
fresh container; without it every tracepoint mechanism is `Unavailable` and
the observer is polling-only, which the signed `active_mechanisms` makes
visible.

### `KernelLifecycleEvent.bound`

`Some(process)` only when the probe anchored the subject with a pidfd while
it was alive. `None` means: the kernel reported a pid doing something at a
kernel time; **which instance and which binary is `CANNOT_PROVE`**. No method
converts a bare pid into an identity (`subject_identity_digest() == None`,
`matches_process_of() == false`). After the source reports loss the probe
forgets every exec-time binding, because the pid may since have been recycled
(`kernel_exit_after_loss_is_not_attributed_to_an_earlier_exec`).

## 5. Independence boundary — what stops the agent manufacturing observation

Structural, in order of strength:

1. **No key on the host.** Unchanged from Skill 6: `ProcfsProbe` has no key
   field or signing method; `ObservationBatch` has no signature field.
2. **No chain position on the host.** Sequence and `prev_head` are assigned by
   the collector; the probe's own `run_id`/`seq` are claims the collector
   checks, never trusts.
3. **No self-declared provenance.** `SourceMechanism` is signed, and under
   `ProbePolicy::RegisteredOnly` the collector refuses a batch from an
   unregistered probe id (`UnregisteredProbe`) or one claiming a mechanism the
   operator did not provision for that probe (`MechanismNotProvisioned`).
   Registering any probe switches the collector to `RegisteredOnly`.
4. **Open policy is loud, not hidden.** A collector that accepts any probe
   records `probe_policy: Open` in every signed health record; a verifier can
   refuse to treat such evidence as kernel-sourced.

What remains a **deployment assumption**: that a batch reaching the collector
under a registered `probe_id` actually came from that probe. This crate has
no transport, hence no transport authentication. Registration bounds what a
genuine probe may claim; it cannot, without an authenticated channel, stop an
impostor from *using* a registered id. That channel is the obligation.

## 6. Continuity, gaps and loss

Three independent signals, all visible at the collector, none inferred:

| Signal | Source | Effect |
|---|---|---|
| chain gap / replay / rollback / fork | Skill 6 ledger | `Degraded` / refused / refused / `Quarantined` |
| probe restart | `probe_run_id` changed | `note_probe_restart()` → `Recovering`; coverage dropped; no back-fill |
| **collector restart** (harvest from PR #3 `ot-sentinel/state.rs`) | `CollectorSigner::resume(snapshot, id, keys, archive)` audits the carried `(sequence, head)` against the archive of the collector's own signed health records | `None` → chain continues at the next sequence but continuity stays `Unverified` until a contiguous batch; `Amnesia` / `RolledBack` → the archive head is adopted so no second chain starts under the same key; `Forked` → `Quarantined`; `ArchiveTruncated` → state kept, reported; foreign state refused; forged or other-observer archive records ignored (each is verified under the collector's key) |
| probe sequence discontinuity | `probe_seq_first ≠ last+1` within a run | `ProbeStreamFault::SequenceDiscontinuity` → `Degraded` |
| kernel event loss | `dropped_events: Some(n>0)` (from `ENOBUFS`) | `ProbeStreamFault::EventsLost` → `Degraded` |
| polling mechanism | `dropped_events: None` | "no loss" is `CANNOT_PROVE`, not zero |

Degradation is sticky for the ledger epoch, matching Skill 6's rule that a
recorded gap is never erased by later contiguity. `SensorHealth.continuity` is
reported alongside `state`, so "degraded *and* unverified" loses no
information. Coverage is only extended on a contiguous, fault-free batch and
never widens over silence, loss, or a restart.

## 6b. Kernel time and wall time (Stage 7b)

Kernel timestamps are `CLOCK_MONOTONIC` nanoseconds (the event clock; Stage
7c corrected the Stage 7b text, which said `CLOCK_BOOTTIME` — the flag had
not been applied and the PMU rejects that clock); authorizations are Unix
milliseconds from the decision point's clock. They are different clock
domains and are never compared directly. Two anchors exist:

1. **`AttestedBatch.attested_at_ms`** — the collector's clock when it signed
   the batch, off-host and inside the signature. An event in the batch cannot
   have happened after this moment. Comparing it with the decision point's
   `issued_at` compares two off-host clocks with no host input: this is how
   a transition can be shown to **predate** a decision.
2. **`ObservationBatch.clock_anchor`** — the probe's back-to-back sample of
   `CLOCK_REALTIME`, `CLOCK_BOOTTIME` and `CLOCK_MONOTONIC`, plus `CLK_TCK`
   (protocol v5). Kernel-authored values, but the
   host clock is attacker-controllable under §8, so a placement derived from
   it is a probe claim, `Attested` at most, and used only where the collector
   clock cannot decide. Without it, kernel time is **unanchored** and the
   reconciler says so rather than guessing.

The probe's instance binding for a `connect()` initiation, a fork's parent
or an exec's task compares two kernel clocks through the anchor:
`/proc/<pid>/stat` start ticks are on the boot clock and are converted to the
event clock by the anchor's boot−monotonic offset (`BootClockAnchor::
start_ticks_to_ns`); the result must not exceed the event's kernel
timestamp, or the pid was recycled after the event. Resolution is one tick
(10 ms); pid reuse inside one tick is not excluded by time alone. The two
clocks coincide on a host that has not suspended; because a suspend between
anchor and event shifts the offset, the probe re-anchors every batch.

## 6a. Per-mechanism coverage (PR3 A-3, protocol v3)

A window can only support a statement about what did **not** happen if a
source that would have seen it was live for the whole window. Before PR3 the
signed health said *that* a window was covered, not *by what*; a verifier
would have had to infer connector coverage from whether kernel events
happened to be present — inference from content, the I8 failure.

Now: the probe declares its live sources (`ProcfsProbe::declare_source`) and
every batch carries `active_mechanisms` = declared ∪ actually used
(canonically ordered, inside the signed bytes, bounded by the collector's
registry). The collector keeps the **intersection** over the contiguous
coverage epoch and publishes it as `SensorHealth.covered_by`; it resets with
the epoch (gap, loss, restart, new epoch). The reconciler's precondition for
`PHANTOM_CLAIM` is `SignedSensorHealth::covered_by_kernel_pushed_source()`:
verified health, `Active`, window inside `attested_coverage`, and a
kernel-pushed mechanism in `covered_by`. The declaration is a probe claim in
the same trust class as every other probe claim (§5).

## 7. Process identity

Unchanged Stage 1 rule, now with kernel help:

- identity = `(pid, pid_start_time_ticks, boot_id)` + executable content hash;
  `exe_path` is context; PID alone is never identity.
- `PidFdAnchored` proves the reads belong to one instance that was alive when
  they completed (`InstanceEnded` otherwise) — closing blind spot C.
- `AnchoredMeasurement::wait_exit` is a kernel statement that *this instance*
  ended, immune to PID reuse.
- A kernel `Exit` is attributed to an instance only via an earlier bound
  `Exec` in the same run with no intervening loss.
- Reboot changes `boot_id`; kernel timestamps are ns-since-boot and are not
  comparable across boot ids — the reconciler must refuse such comparisons.

## 8. Threat model and what root can still do

Attacker may: hold root on the observed host; spawn/kill/inspect processes;
modify files, config, the host clock; kill, restart, starve or race the probe;
exhaust buffers; reorder host-local state; erase or roll back local state;
partition the host.

| Attack | Result now |
|---|---|
| feed the probe a fabricated procfs view | **still possible** for `ProcfsPoll`/`PidFdAnchored` content and for the `bound` identity of a kernel event; the collector attests receipt (A4 in the Skill 6 report stands) |
| inject a fake kernel event from user space | not via the connector (kernel is the netlink source); via a rogue probe only if the collector is `Open` or the rogue can use a registered id over an unauthenticated transport |
| relabel a polled report as kernel-sourced | refused under `RegisteredOnly` |
| kill/restart the probe | `run_id` changes → `Recovering`; outage never covered |
| starve the connector | `ENOBUFS` → `EventsLost` → `Degraded`; exec-time bindings dropped |
| replay a probe batch | sequence discontinuity → `Degraded` |
| roll back / restore host state | irrelevant to chain position; probe seq/run visible |
| alter host clock | affects `host_wall_clock_ms` and the probe's `clock_anchor`; kernel `timestamp_ns`, collector sequence and `attested_at_ms` untouched — a placement that rests on the anchor is a claim, one that rests on `attested_at_ms` is not |
| disable, filter or starve the perf ring | `Unavailable` at open (mechanism absent from `active_mechanisms`/`covered_by`), or `PERF_RECORD_LOST` → `Degraded`; silence is never coverage |
| steal the collector key | forges history until the key version is revoked (`t17`) — unresolved risk, NEXORA's domain |

## 9. Network observation model

Implemented: **socket-level** association — rows of the kernel TCP/UDP tables
whose inode appears in the instance's `/proc/<pid>/fd`, taken under a pidfd
anchor; gives protocol, local/remote address and port, kernel socket state,
inode. And, since Stage 7b, **socket state transitions** pushed by the kernel
(`SockStateTracepoint`): the `connect()` initiation bound to the calling
instance and the handshake completion of the same socket, with kernel
timestamps — connection *creation* as an event. (Stage 7c adds process
creation and image execution the same way — `SchedTracepoint`, §4 — which is
process observation, not network observation.) Neither gives: packets,
bytes, payload, DNS names, TLS state, or anything on the wire. There is no
XDP, no AF_PACKET, no conntrack read. Per I23 both are metadata and can never
be promoted to payload evidence.

## 10. Relationship to Skill 7 (reconciliation)

The reconciler receives, per subject: `AttestedBatch`es (observations with
provenance, kernel events with optional bound identity), `SignedSensorHealth`
(state, continuity, probe policy, coverage), plus `ExpectedExecution` and the
agent's `EvidencePacket` from earlier stages. Rules this stage makes possible
and the reconciler must honour:

- join on `decision_id` and **process identity** (`identity_bytes`), never pid;
- an unbound kernel event contributes existence/order/time, not identity;
- `ObservationAvailability::Unavailable` ⇒ `CANNOT_PROVE` for the window;
- `probe_policy: Open` ⇒ provenance claims are unverified;
- `PHANTOM_CLAIM` requires `Covered` **and** `Active` **and** a kernel-pushed
  source over the exact window — a polled source alone cannot support it.

## 11. NOT_IMPLEMENTED (explicit)

eBPF programs, raw tracepoints, any tracepoint other than
`sock:inet_sock_set_state`, `sched:sched_process_fork` and
`sched:sched_process_exec`, XDP, packet or wire capture, filesystem and
syscall observation, exec argument and environment capture, UDP "connection"
events, cgroup/namespace context in the event model, network transport and
its authentication, durable storage of the collector snapshot and archive
(the collector exposes `snapshot()` / `resume()` and audits continuity, but
writing them to disk is the operator's), key lifecycle beyond
version/revoke, hardware or TEE attestation, any performance measurement.
(Three static tracepoints read through the perf ring **are** implemented —
Stages 7b and 7c; that is the whole of the tracing surface.)
