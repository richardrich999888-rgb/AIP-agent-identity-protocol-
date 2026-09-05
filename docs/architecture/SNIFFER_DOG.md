# SNIFFER_DOG — kernel-mediated evidence sources for the Ghost observer

Status: **IMPLEMENTED (procfs poll, pidfd-anchored measurement, netlink
process-event connector, kernel socket tables, provenance gating) /
NOT IMPLEMENTED (eBPF, tracepoints, perf ring buffers, XDP, packet or wire
visibility, filesystem and syscall observation, network transport, durable
collector state).**

Stage 6.5 (`aip-standalone/aip-observe`, protocol version 2). Skill 6 remains
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
| `ObservationBatch` | `SYNTRIASS/GHOST/OBSERVATION_BATCH/v1` | `probe_run_id`, `probe_seq_first/last`, `dropped_events: Option<u64>`, `kernel_events` |
| `SensorHealth` | `SYNTRIASS/GHOST/OBSERVER_HEALTH/v1` | `probe_policy` |
| `AttestedBatch` | `SYNTRIASS/GHOST/OBSERVER_HEAD/v1` | unchanged |

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
| probe sequence discontinuity | `probe_seq_first ≠ last+1` within a run | `ProbeStreamFault::SequenceDiscontinuity` → `Degraded` |
| kernel event loss | `dropped_events: Some(n>0)` (from `ENOBUFS`) | `ProbeStreamFault::EventsLost` → `Degraded` |
| polling mechanism | `dropped_events: None` | "no loss" is `CANNOT_PROVE`, not zero |

Degradation is sticky for the ledger epoch, matching Skill 6's rule that a
recorded gap is never erased by later contiguity. `SensorHealth.continuity` is
reported alongside `state`, so "degraded *and* unverified" loses no
information. Coverage is only extended on a contiguous, fault-free batch and
never widens over silence, loss, or a restart.

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
| alter host clock | affects `host_wall_clock_ms` only; kernel `timestamp_ns` and collector sequence untouched |
| steal the collector key | forges history until the key version is revoked (`t17`) — unresolved risk, NEXORA's domain |

## 9. Network observation model

Implemented: **socket-level** association — rows of the kernel TCP/UDP tables
whose inode appears in the instance's `/proc/<pid>/fd`, taken under a pidfd
anchor; gives protocol, local/remote address and port, kernel socket state,
inode. It does **not** give: packets, bytes, timing, payload, DNS names, TLS
state, or anything on the wire. There is no XDP, no AF_PACKET, no conntrack
read. Per I23 the variant is metadata and can never be promoted to payload
evidence. Connection *creation* as an event is NOT_IMPLEMENTED (polling only).

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

eBPF programs, tracepoints/raw tracepoints, perf ring buffers, XDP, packet or
wire capture, filesystem and syscall observation, exec argument capture,
cgroup/namespace context in the event model, network transport and its
authentication, collector persistence, key lifecycle beyond version/revoke,
hardware or TEE attestation, any performance measurement.
