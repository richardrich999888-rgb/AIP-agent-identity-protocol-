# SNIFFER DOG IMPLEMENTATION REPORT

Stage 6.5 — Observer evidence hardening. Companion to `SNIFFER_DOG.md`
(architecture) and `OBSERVER_IMPLEMENTATION_REPORT.md` (Skill 6).

**Status: PASS** against the stage's gate conditions, with the limitations in
§16–§18 recorded as limitations. Nothing in this stage claims root or kernel
compromise is solved, packet or wire visibility, zero loss, or any
performance figure.

## 1. Objective

Move the observer from "cryptographically attested observation of what the
collector reports" toward "independently sourced, kernel-mediated evidence of
what happened", without letting the observer become an authority. Concretely:
add kernel-generated event and identity sources beside procfs polling, make
every observation state its provenance inside the signed bytes, make restarts,
gaps and losses visible at the collector, and make it impossible for a
host-side party to label its own report as kernel-sourced.

## 2. Existing observation blind spots (reproduced first)

Commit `48da218` — nine characterization tests in
`aip-observe/tests/blind_spots.rs`, run against the unchanged Skill 6 code:

| Case | Test | Finding | Classification |
|---|---|---|---|
| A/J procfs content, root | `a_fabricated_measurement_is_indistinguishable_from_a_real_one_at_the_collector` | fabricated and real measurements both attest and verify; no kernel provenance on a polled observation | PROVEN blind spot; root resistance DEPLOYMENT ASSUMPTION |
| B start/exit between polls | `b_a_short_lived_process_is_invisible_to_polling` | `/bin/true` ran; polling finds nothing; no event source | PROVEN; kernel source NOT_IMPLEMENTED |
| C unanchored reads | `c_polling_after_exit_yields_no_instance_linkage` | no proof two reads belong to one instance | CANNOT_PROVE |
| D exec replacement | `d_exec_between_polls_changes_identity_but_the_event_is_unseen` | Stage 1 identity differs if both sides polled; the exec event unseen | PROVEN partial; event NOT_IMPLEMENTED |
| E open socket | `e_open_socket_is_invisible_to_the_polling_observation` | no socket facts in a polled observation | NOT_IMPLEMENTED |
| F syscalls/effects | `f_no_syscall_or_effect_observation_path_exists` | only presence/absence expressible | NOT_IMPLEMENTED |
| G restart vs continuity | `g_restart_leaves_the_outage_uncovered_and_says_nothing_about_execution` | outage uncovered (Skill 6); execution across it unknown | PROVEN handled / CANNOT_PROVE |
| H dropped events | `h_polling_exposes_no_loss_counter` | no loss signal | NOT_IMPLEMENTED |
| I ordering/time | `i_observation_time_is_host_supplied_and_carries_no_kernel_timestamp` | host clock sealed verbatim; no kernel time | NOT_IMPLEMENTED |

All nine still pass after the change (they describe the polling mechanism,
which survives as one provenance). One binding was made `mut` because
`batch()` now drains pending kernel events; no assertion changed.

## 3. Threat model

Root on the observed host who can inspect/spawn/kill processes, modify files
and configuration, alter the host clock, kill/restart/starve/race the probe,
exhaust buffers, reorder or erase or roll back host-local state, and
partition the host from the collector. The collector, its key and its
registry are assumed outside the attacker's reach (unchanged from Skill 6,
A1). The kernel of the observed host is **not** assumed honest to the probe
for procfs *content*; it **is** assumed to be the sole author of netlink
connector messages (user space cannot inject into the kernel's netlink
source).

## 4. Observation-source architecture

See `SNIFFER_DOG.md` §3. Host side: `ProcfsProbe` with four sources, a random
`run_id` per start, a per-run sequence counter, an optional loss counter, a
pid→claim registry and a pid→bound-instance cache. Collector side:
`CollectorSigner` with the Skill 6 ledger plus a probe registry, probe-stream
tracking (run id, sequence range, loss) and sticky degradation.

## 5. Kernel instrumentation used

| Mechanism | Syscall / file | Why |
|---|---|---|
| `pidfd_open` + `poll` | `SYS_pidfd_open`, `poll(2)` | kernel handle bound to a process instance; exit notification immune to PID reuse |
| netlink process-event connector | `socket(AF_NETLINK, NETLINK_CONNECTOR)`, `CN_IDX_PROC`, `PROC_CN_MCAST_LISTEN` | kernel-pushed FORK/EXEC/EXIT with pid, tgid, cpu, `timestamp_ns`; `ENOBUFS` on overflow |
| kernel socket tables | `/proc/net/{tcp,tcp6,udp,udp6}`, `/proc/<pid>/fd` | socket↔process association |

Not used, explicitly: `bpf()`, tracefs, `perf_event_open`, XDP, AF_PACKET,
conntrack, fanotify/inotify, audit. All were confirmed *available* on the
build host (§"What this environment can observe" in `SNIFFER_DOG.md`); none
was needed for this slice's properties, and adding an eBPF loader would have
meant new dependencies and program compilation for no property this stage
was authorized to claim. Only `libc` was added (already in the lockfile).

## 6. Event model

`SNIFFER_DOG.md` §4. Protocol version 1→2; every new field is inside the
canonical encoding; domain tags: `SYNTRIASS/GHOST/KERNEL_EVENT/v1` added; all
tags pairwise-distinct (tested).

## 7. Trust boundary

Unchanged from Skill 6 for signing (collector key off-host; probe has none).
Added: the probe registry and policy live at the collector; `probe_policy` is
in every signed health record. The transport between probe and collector
remains NOT_IMPLEMENTED and is the deployment obligation that makes
registration binding (§18).

## 8. Independence boundary

"What prevents the observed agent from manufacturing its own observation?"

| Vector | Structural answer |
|---|---|
| sign an observation | no key on the host; agent-signed batches fail `SignatureInvalid`; a tricked anchor fails `ObserverKeyIsAgentKey` (`t02`) |
| choose a chain position | assigned by the collector (`t13`) |
| declare kernel provenance | refused under `RegisteredOnly` as `MechanismNotProvisioned` / `UnregisteredProbe` (`t01`) |
| inject a fake kernel event | not through the connector; only through a rogue probe under `Open` policy or an impersonated registered id over an unauthenticated transport — the former is visible in signed health (`t01b`), the latter is §18 |
| forge procfs content to its own probe | **still possible** (§16) |

## 9. Continuity model

Skill 6 chain ledger unchanged. Added: probe `run_id` change → automatic
`note_probe_restart()` (Recovering, coverage dropped, no back-fill); probe
sequence discontinuity within a run → `ProbeStreamFault::SequenceDiscontinuity`
→ `Degraded`; degradation sticky for the ledger epoch; `state()` reports
`Degraded` over `Unverified` while `continuity` is reported separately.
Collector restart → fresh epoch, `ContinuityUnverified`, `prev_head` zero
(`t13`).

## 10. Loss / gap model

| Signal | Meaning |
|---|---|
| `dropped_events: None` | polling: no loss counter exists; zero loss is CANNOT_PROVE |
| `dropped_events: Some(0)` | a loss-capable source reported no loss since the last batch |
| `dropped_events: Some(n>0)` | the kernel reported `ENOBUFS` `n` times → `EventsLost` → `Degraded`, coverage `None`, exec-time bindings forgotten |
| probe seq skip / repeat / reverse | `SequenceDiscontinuity` → `Degraded` |
| `probe_seq_first > probe_seq_last` | `MalformedBatch`, refused |

Live: `t15` starves a 1-byte receive buffer, bursts 400 processes and
observes `ENOBUFS` → `Degraded` → `ObservationAvailability::Unavailable
{ ObserverDegraded }`.

## 11. Process identity model

Stage 1 rule preserved: `(pid, start ticks, boot id)` + exe content hash; path
is context. New: `PidFdAnchored` proves one-instance reads; `wait_exit` is a
kernel statement about that instance; `KernelLifecycleEvent.bound` is `Some`
only after a successful anchor; a bare pid yields no identity and matches no
binding (`t08`, unit tests). Exit attribution requires a bound exec in the
same run with no intervening loss.

## 12. Network observation model

Socket-level only. Live `t11`: a listening TCP socket bound by the test
process is found in the kernel table, joined by inode to the process, and
attested as `SocketObserved { Tcp, 127.0.0.1:<port>, LISTEN, inode }` with no
payload, packet, wire or authorization field. Connection creation as an event,
packet capture, and wire visibility are NOT_IMPLEMENTED. IPv6 tables were
absent on the build host; the parser handles them (unit test).

## 13. Adversarial tests

`aip-observe/tests/sniffer_dog.rs` (22) mapped to the brief's twenty cases:

| # | Case | Test | Distinct failure class |
|---|---|---|---|
| 1 | fake kernel event injection | `t01_…`, `t01b_…` | provenance (`MechanismNotProvisioned`, `UnregisteredProbe`); Open visible |
| 2 | re-signed forgery | `t02_…` | integrity (`SignatureInvalid`), provenance (`ObserverKeyIsAgentKey`) |
| 3 | reuse of old observation | `t03_…` | continuity (`SequenceDiscontinuity`) |
| 4/5 | rollback, gap | `t04_t05_…` | continuity; `MalformedBatch` |
| 6/7 | duplication, reordering | `t06_t07_…` | integrity (`PayloadHashMismatch`) |
| 8 | PID reuse | `t08_…` | identity (unbound event matches nothing) |
| 9 | start/exit race | `t09_live_…` | kernel sees what polling cannot; identity honestly absent |
| 10 | executable replacement | `t10_live_…` | two kernel `Exec` events for one pid; anchored hash = new binary; pidfd exit |
| 11 | network without expectation | `t11_…` | socket-level, no authorization field |
| 12 | expected without observed | `t12_…` | availability only; no phantom |
| 13 | collector restart | `t13_…` | continuity (`ContinuityUnverified`, epoch reset) |
| 14 | host reboot | `t14_…` | identity (boot id) |
| 15 | event loss | `t15_live_…`, `t15b_…` | continuity (`EventsLost` → `Degraded`) |
| 16 | key substitution | `t16_…` | integrity |
| 17 | key compromise boundary | `t17_…` | forgery succeeds until revocation — boundary, not defence |
| 18 | malformed kernel input | `t18_…` + `linux::tests` | no panic; `Other` never interpreted |
| 19 | malformed identifiers | `t19_…` + `linux::tests` | no panic; rows skipped and counted |
| 20 | canonical collisions | `t20_…` + `observed::tests` | injective |
| — | every new field mutation | `every_new_attested_field_mutation_is_detected` (17 fields) | integrity |
| — | classes distinct, no authorization class | `failure_classes_are_distinct_and_no_authorization_class_exists` | — |

Unit tests added: `linux::tests` (3: connector parser incl. 9 malformed
shapes, socket tables v4/v6/garbage, socket link), `observed::tests` (+3:
mechanism codes, kind collisions/unbound identity, v4/v6 endpoint),
`probe::tests` (+3: run/seq/loss, exit-after-loss unbound, exit attribution).

Live tests self-skip with a loud message where the connector cannot be
opened; on the build host none skipped.

## 14. Before / after results

| Suite | Before 6.5 (`de4f450`) | After RED (`48da218`) | After (`this stage`) |
|---|---|---|---|
| aip-observe | 42 | 51 (+9 blind spots) | **82** (25 unit + 26 Skill 6 + 9 blind spots + 22 Sniffer Dog) |
| aip-authorize / aip-core / aip-crypto / aip-types / aip-protocol / aip-test / aip-real-tests | 35 / 140 / 8 / 5 / 46 (1 ign) / 13 / 67 (2 ign) | unchanged | unchanged |
| **aip-standalone total** | 356 / 0 / 3 | 365 / 0 / 3 | **396 / 0 / 3** |
| aip-service | 39 / 0 | 39 / 0 | **39 / 0** |

`cargo clippy --workspace --all-targets -- -D warnings` and
`cargo fmt --all -- --check`: clean in both workspaces. Skills 3–6 tests
unmodified and passing (Skill 6's 26 adversarial tests run unchanged against
protocol v2).

## 15. What is PROVEN

- A short-lived process invisible to polling is reported by the kernel with
  exec and exit events carrying kernel cpu and timestamp (`t09`, live).
- A binary replacement in place is delivered as a second kernel exec for the
  same pid; the anchored measurement afterwards hashes the new binary; the
  pidfd reports that instance's exit (`t10`, live).
- Kernel event loss is signalled (`ENOBUFS`), counted, sealed, and degrades
  coverage rather than being silent (`t15`, live; `t15b`).
- A registered probe cannot claim a mechanism it was not provisioned for; an
  unregistered probe is refused; the regime is in signed health (`t01`).
- The agent cannot sign, cannot choose a chain position, cannot relabel
  provenance, and an anchor that is the agent's key is refused (`t02`).
- Replay, rollback, gap, duplication and reordering of probe output are each
  detected as distinct classes (`t03`–`t07`).
- A bare pid never yields an identity; PID reuse and reboot break the match
  (`t08`, `t14`).
- Collector restart cannot silently continue the chain (`t13`).
- A socket owned by a measured instance is observable at socket level with no
  authorization content (`t11`).
- Malformed kernel datagrams and table rows never panic and are never
  interpreted (`t18`, `t19`, unit tests).
- All new fields are injectively encoded and their mutation is detected.

## 16. What remains CANNOT_PROVE

- **The truth of procfs content** on a root-compromised host: `ProcfsPoll`,
  `PidFdAnchored`, `ProcNetTable` content and the `bound` identity of a
  kernel event all come from procfs. The collector attests receipt and order.
- The identity behind an **unbound** kernel event (`bound: None`).
- Anything about a process between polls when only polled sources are
  available for the window.
- That no event was lost when `dropped_events` is `None`.
- Execution continuity across an observer restart or a collector restart.
- That a batch under a registered `probe_id` actually came from that probe
  (no transport authentication).
- Comparability of kernel timestamps across boot ids.
- Anything an `Open`-policy collector labels as kernel-sourced.

## 17. NOT_IMPLEMENTED

eBPF programs; tracepoints / raw tracepoints; perf ring buffers; XDP or any
driver hook; packet or wire capture; filesystem, syscall and exec-argument
observation; connection-creation events (sockets are polled); cgroup and
namespace context in the event model; probe→collector transport and its
authentication; collector persistence; key lifecycle beyond version and
revocation; hardware/TEE attestation; any performance measurement.

## 18. Deployment assumptions

1. The collector process, its key and its registry are outside the observed
   host's reach.
2. The probe→collector channel authenticates the probe; without it, probe
   registration bounds what a genuine probe may claim but cannot stop an
   impostor using a registered id.
3. Production collectors run `RegisteredOnly`; `Open` evidence is treated as
   unverified provenance.
4. The connector requires `CAP_NET_ADMIN` in the initial network namespace;
   where absent, `ProcConnector::open` is `Unavailable` and the kernel-pushed
   properties simply do not exist for that host.
5. The connector's receive buffer is sized for the host's event rate; loss is
   visible either way.

## 19. Performance measurements

**None taken.** No throughput, latency, overhead, loss-rate or NIC figures
are claimed. Hardware-level validation: NOT_PROVEN. A future plan would need a
dedicated host, a defined event rate, connector buffer sizing, and measurement
of `EventsLost` frequency under load — none of which this stage did.

## 20. Prohibited claims

Do not claim: root compromise or kernel compromise is solved; eBPF, kernel
tracing or XDP observation; packet, byte, payload or wire visibility;
zero-loss or continuous observation beyond an attested, fault-free,
contiguous chain; that an observation is true rather than received; that a
bare pid identifies a process; that a `SocketObserved` effect is a connection
event; any TRL, throughput, latency or overhead figure; that an action was
authorized, malicious, or did not happen; any reconciliation result class.

## 21. Security invariants affected

| Invariant | Effect |
|---|---|
| I2, I4 | strengthened: pidfd-anchored instance reads; kernel exit bound to instance; bare pid never identity |
| I5, I10 | preserved: no key on host; provenance cannot be self-declared under `RegisteredOnly` |
| I8 | preserved and tested: no observation → availability statement, never a claim about execution |
| I9 | extended: probe restart, sequence discontinuity and kernel loss are explicit degraded states |
| I14 | every new field length-prefixed / coded / presence-tagged; collision tests |
| I15 | a kernel event stream is a source, not a protocol claim; no Merkle, no anchoring |
| I19, I22 | preserved: no authorization concept exists in the crate; `ExpectedExecution` never read |
| I23 | `SocketObserved` is metadata by type; no payload variant exists |

## 22. Relationship to Skill 7 reconciliation

Inputs the reconciler now has per subject and window: attested observations
with provenance; kernel lifecycle events with kernel time and optional bound
identity; signed health with state, continuity, probe policy and coverage;
plus `ExpectedExecution` and the agent's `EvidencePacket`. Rules this stage
makes possible and the reconciler must honour: join on `decision_id` and
process identity, never pid; an unbound kernel event contributes existence,
order and time only; `Unavailable` ⇒ `CANNOT_PROVE`; `Open` policy ⇒
provenance unverified; `PHANTOM_CLAIM` needs `Covered` + `Active` + a
kernel-pushed source over the exact window — polling alone can never support
it.

## 23. Stage 7b addendum — kernel-pushed socket state transitions

Commits: RED `ed9c75b`, implementation (see git log), docs. Protocol version
3 → 4.

### 23.1 Why

`ACTION_EVIDENCE.md` §7 recorded: *the table shows existence at the sample,
not creation*. A connection opened before an authorization and still open
inside its window satisfied the presence class (live test T-A produced
`VERIFIED_EXECUTION`), and a connection made and closed between two polls
was unprovable (T-C produced `CANNOT_PROVE`). Both were reproduced live
against `ab05544` before any production change.

### 23.2 What was audited on the host

`/sys/kernel/tracing` is mounted; `events/sock/inet_sock_set_state` exists
with id 1427 and a readable `format`; `perf_event_open(PERF_TYPE_TRACEPOINT)`
succeeds on all four CPUs as root (`perf_event_paranoid = 2`, capabilities
present); `unprivileged_bpf_disabled = 2`. A live connect traced through a
tracefs instance showed `CLOSE → SYN_SENT` in the connecting task's context
with `sport = 0`, `SYN_SENT → ESTABLISHED` with the full tuple, and the
server side's `LISTEN → SYN_RECV → ESTABLISHED` in softirq context under the
client's pid — the reason `current_pid` is trusted only for the initiation.

### 23.3 Kernel instrumentation used

`aip-observe/src/sockstate.rs`: `SockStateTracer::open()` reads the
tracepoint id and record layout from tracefs, opens one `perf_event_open`
per online CPU (`sample_type = TID | TIME | CPU | RAW`, `sample_period = 1`,
`use_clockid = 1`, `clockid = CLOCK_BOOTTIME`, `wakeup_events = 1`,
`PERF_FLAG_FD_CLOEXEC`), maps a header page plus eight data pages per fd,
enables with `PERF_EVENT_IOC_ENABLE`, and reads `PERF_RECORD_SAMPLE` /
`PERF_RECORD_LOST` from the rings, delivering samples in kernel-time order.
`parse_sock_state_record` decodes a raw record by the parsed layout; non-TCP
protocols, unknown families, out-of-range states and short records are
`Malformed`, never guessed. `boot_clock_anchor()` samples
`CLOCK_REALTIME`/`CLOCK_BOOTTIME` back-to-back. The `perf_event_attr` layout
is declared explicitly (ABI size 128) rather than taken from a binding.

No eBPF program, loader, map or verifier interaction exists. No XDP. No
packet capture.

### 23.4 Event model additions (v4)

- `SourceMechanism::SockStateTracepoint` — kernel-pushed; does **not** cover
  process lifecycle (`covers_process_lifecycle() == false`), so it cannot
  stand in for the connector in a `PHANTOM_CLAIM`.
- `KernelLifecycleKind::SocketState { protocol, local, remote, old_state,
  new_state, sk, current_pid }`; `subject_pid()` is `Some(current_pid)` only
  for `CLOSE → SYN_SENT`; `is_connect_initiation()`,
  `is_connect_established()`; `tcp_state` constants.
- `ProcfsProbe::ingest_socket_event` — anchors the initiation's
  `current_pid` with a pidfd and binds only if
  `instance_started_no_later_than(process, event_ns)`; every other
  transition is recorded unbound. `declare_clock_anchor`.
- `ObservationBatch.clock_anchor: Option<BootClockAnchor>` (signed).
- `AttestedBatch.attested_at_ms` (signed); `ObserverAttestor::attest_at`.

### 23.5 What is PROVEN (additions)

- The kernel reported a TCP socket transitioning `CLOSE → SYN_SENT` and the
  same socket (`sk`) transitioning `SYN_SENT → ESTABLISHED`, at kernel times,
  on the recorded CPUs (live: T-C, T-P; fixture: `tp01`).
- The initiation was made by an instance the probe anchored **and** whose
  start tick is not later than the event's kernel time (`tp11`; live).
- A transition attested before a decision was issued predates it, by two
  off-host clocks (`tp03`; live T-A: `attested_at_ms < issued_at`).
- Ring loss is counted and degrades the window (`tp17`); a restart is a
  continuity failure (`tp18`); every signed field of a socket event, the
  bound instance, the clock anchor and the attestation clock are
  mutation-detected at `Proven` (`tp14`).
- An unprovisioned probe cannot label events `SockStateTracepoint` (`tp15`);
  `Open` policy yields unverified provenance (`tp16`).

### 23.6 What remains CANNOT_PROVE (additions)

- The wall-clock placement of a kernel timestamp **beyond** what the
  collector's clock decides: the boot-clock anchor is the host's clock, a
  claim, `Attested` at most; without it kernel time is unanchored.
- PID reuse within one `CLK_TCK` tick (10 ms) of the event: the start-time
  rule cannot exclude it; the pidfd anchor and executable hash narrow it.
- Which process performed a transition other than the initiation
  (`current_pid` in softirq context names nobody).
- Anything on a host whose root disables the tracepoint, filters the perf
  event or starves the ring: the mechanism is then absent or `Degraded`, and
  silence is never coverage — but the *content* of what was delivered is
  kernel-authored and not host-forgeable, unlike procfs.
- UDP, SCTP, MPTCP; anything about bytes or payload.

### 23.7 NOT_IMPLEMENTED (revised)

eBPF; raw tracepoints; any tracepoint other than `sock:inet_sock_set_state`;
XDP; packet or wire capture; filesystem, syscall and exec-argument
observation; cgroup/namespace context; transport authentication; collector
persistence; key lifecycle beyond version/revoke; hardware/TEE attestation;
performance measurement.

### 23.8 Deployment and privilege

tracefs mounted at `/sys/kernel/tracing` (or `/sys/kernel/debug/tracing`);
`perf_event_paranoid ≤ -1` or `CAP_PERFMON`/`CAP_SYS_ADMIN` for the probe;
the collector's clock is the temporal authority and must be off-host; the
probe's `clock_anchor` is the host's clock and is treated as such.
