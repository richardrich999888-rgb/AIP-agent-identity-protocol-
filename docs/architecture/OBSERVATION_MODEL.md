# OBSERVATION_MODEL

> **Completion mandate, final state.** Gates 1–11 are complete;
> `SNIFFER_DOG_COMPLETE_IMPLEMENTATION_REPORT.md` is the single record of
> what exists, what was measured, what may be claimed and what may not.
> Final status: **VALIDATED RUNTIME**, scoped there — the evidence
> machinery, not a shipped product.

> **Status note (post Stages 3–7c, Skill 8, PR #3 harvest).** §1 below is the
> Stage 0 discovery and reads "MISSING" for runtime observation; that was
> true at `377d5fc`. The observer now exists — `aip-observe` with a
> probe/collector split, kernel-pushed sources, provenance gating, loss
> accounting and restart-continuity audit — and is described in
> `SNIFFER_DOG.md`, `OBSERVER_IMPLEMENTATION_REPORT.md` and
> `SNIFFER_DOG_IMPLEMENTATION_REPORT.md`. The semantics in §3–§4 are the
> ones implemented. Statements of absence in §1 are kept for traceability.
> §5 (Gate 2 of the completion mandate) records the wire-level mechanism
> evaluation and the decision taken: an `AF_PACKET` header tap.


> **Status (PR3).** §1–§2 are the discovery record at `377d5fc`. Since then:
> Stage 1 added `ExecutionBinding` (`EXECUTION_BINDING.md`), Stage 2 the
> `ExpectedExecution` producer (`DECISION_POINT.md`), Stage 3 / 6.5 the
> observer (`OBSERVER_IMPLEMENTATION_REPORT.md`, `SNIFFER_DOG.md`). The
> `ObservedExecution` sketch in §4 was superseded by `aip_observe::{ObservedExecution,
> KernelLifecycleEvent}`, which carry **no** `action_kind`/`parameter_digest`
> — see `RECONCILIATION_MODEL.md` "Context match". §3's three states are
> realised as `ObservationAvailability::{Covered, Unavailable{reason}}`;
> `OBSERVATION_UNAVAILABLE` is an availability *state*, whose reconciliation
> result is `CANNOT_PROVE`.

## 1. Current state — verified by exhaustive search

`RUNTIME_OBSERVATION = MISSING`

Search over all production Rust (`aip-standalone/`, `aip-service/`) at
`377d5fc`, counting files with any match:

| Term | Files |
|---|---:|
| `ebpf`, `XDP`, `perf_event`, `ring_buffer`, `procfs`, `netlink` | **0** |
| `Sentinel`, `Ghost`, `nexora` | **0** |
| `observed_execution`, `ExpectedExecution`, `reconcile`, `Reconciliation` | **0** |
| `cgroup` | 1 — `aip-core/src/runtime.rs:127-129`, reading `/proc/1/cgroup` for a container-ID *string* |

Per category:

| Category | Status | Evidence |
|---|---|---|
| PROCESS OBSERVATION | **MISSING** | only `std::process::id()` at `runtime.rs:40`; no exec/fork/exit hook |
| NETWORK OBSERVATION | **MISSING** | no socket, netlink, or packet path |
| FILESYSTEM OBSERVATION | **MISSING** | — |
| WORKLOAD OBSERVATION | **MISSING** | — |
| RESOURCE OBSERVATION | **MISSING** | — |
| SENSOR ATTESTATION | **MISSING** | no observer, therefore no attestation |

`aip-core/src/runtime.rs` is **environment fingerprinting, not observation**:

| Field | Provenance | Line |
|---|---|---|
| `agent_id` | **self-reported** — unvalidated `&str` argument | `:38 → :64` |
| `pid` | OS-observed, but **never compared at verification** | `:40`; excluded at `:76,84-93` |
| `exe_hash` | `sha256(current_exe().to_string_lossy())` — **hashes the path string, not the binary** | `:41-44`, doc `:20` |
| `hostname` | `$HOSTNAME` env var first, `/etc/hostname` third; `gethostname(2)` never called | `:108-117` |
| `container_id` | `$CONTAINER_ID` env var short-circuits and is returned verbatim | `:121-142` |
| process start time | **NOT PRESENT** | — |

`verify_runtime_binding` (`:78-95`) computes
`is_same_environment = hostname_match && exe_match`; `container_match` is
computed at `:87` and deliberately excluded at `:93`; `runtime_hash` is never
recomputed. The result never enters an `EvidencePacket` — `RuntimeBinding` is
computed and only `println!`'d (`aip-cli/src/main.rs:127,137`).

Per **I16**, and per the skill's §10 rule that logs are not observation:
nothing here constitutes independent runtime observation.

## 2. Expected execution

`EXPECTED_EXECUTION_PRODUCER = MISSING`

Candidate producers examined:

| Candidate | Verdict |
|---|---|
| AIP authorization | **no decision point exists** in production |
| Capability invocation | `is_scope_subset` / `scope_intersection` are pure predicates with no invocation site that gates execution |
| Policy decision | no policy engine |
| Tool invocation | no tool/MCP surface in production (0 files) |
| Gateway decision | no gateway in production |
| `POST /v1/evidence/generate` | **records, does not decide.** `generate_packet` (`aip-service/src/evidence.rs:220-300`) seals caller-supplied decision, actions, root token, delegation chain **and the caller's own private key**, verifying none of it |

The nearest thing to an expected-execution record is the `DecisionRecord`
inside a sealed packet — but it is produced *after* the fact by the acting
party, with no adjudication. It is a **claim**, not an authorization.

## 3. Required semantics (design, not implemented)

Ghost must distinguish three states that the current codebase cannot express:

| State | Meaning | Never means |
|---|---|---|
| `OBSERVED` | a sensor with attested continuity over the window recorded a matching effect | — |
| `NOT_OBSERVED` | a sensor with **attested coverage of that window** recorded no such effect | "the execution did not occur", unless coverage is proven |
| `OBSERVATION_UNAVAILABLE` | no sensor, degraded sensor, coverage gap, or unverified continuity | anything about whether execution occurred |

Per **I8** and **I9**, `OBSERVATION_UNAVAILABLE` must be a first-class value in
the type system, not `Option::None` and not a boolean false. A reconciliation
result derived from an unavailable observation must be `CANNOT_PROVE`, never
`PHANTOM_CLAIM`.

## 4. Minimum future interface

Defined, not implemented. Two producers must exist before reconciliation is
meaningful:

```rust
/// Emitted by an authorization decision point BEFORE execution.
/// Must be produced by a party the agent does not control.
struct ExpectedExecution {
    decision_id: [u8; 16],        // reuse aip-protocol's join key
    authority_ref: AuthorityRef,  // root jti + chain jtis
    agent_id: String,             // AIP-ID
    action_kind: ScopeAction,
    parameter_digest: [u8; 32],   // canonical digest of adjudicated params
    binding: ExecutionBinding,    // see EXECUTION_BINDING.md
    authorized_at: u64,
    valid_until: u64,             // MUST be signature-covered — see I6, I21
    decision_sig: Signature,      // by the decision point, NOT the agent
}

/// Emitted by an independent observer.
struct ObservedExecution {
    observation_id: [u8; 16],
    binding: ExecutionBinding,
    effect: ObservedEffect,       // process spawn | egress | file | syscall
    observed_at_ns: u64,          // monotonic + wall, both
    coverage: CoverageWindow,     // what the sensor can vouch for
    observer_sig: Signature,      // see OBSERVER_ATTESTATION.md
}
```

**Trust assumption to state explicitly (§13, I23):** a kernel network sensor
sees 5-tuples, byte counts and timing. It does **not** see TLS-encrypted
application payloads. Therefore `parameter_digest` equality can only be
established by cooperation from the agent runtime or an in-path proxy that
terminates TLS. Any design that compares parameters must declare which of those
two it assumes, and `ObservedEffect` must keep `NetworkMetadata` and
`ApplicationPayload` as distinct variants so metadata can never be silently
promoted to payload evidence.

## 5. Wire-level observation — mechanism evaluation and decision (Gate 2)

The completion mandate asks for "real network/wire observation" and for the
candidate mechanisms to be evaluated against the actual repository and host
before one is chosen. This section is that record. Commits: RED `36b026c`,
GREEN `57849bd`.

### 5.1 What this host permits (measured, not assumed)

Kernel `6.18.44`, root with a full capability set, `bpf(BPF_MAP_CREATE)`
succeeds, `CONFIG_BPF_SYSCALL/JIT/CGROUP_BPF/NET_CLS_BPF/XDP_SOCKETS/
DEBUG_INFO_BTF=y`, `AF_PACKET` raw and datagram sockets open, tracefs
mounted with `sock`, `tcp`, `net`, `skb`, `xdp` and 714 `syscalls`
tracepoints, `perf_event_paranoid = 2` (irrelevant under
`CAP_SYS_ADMIN`). No `tc`, `bpftool` or `ip` binaries; `clang` present.
Interfaces: `lo`, `eth0`, two idle `ifb` devices. A header-only capture on
`lo` with `SO_TIMESTAMPNS` and `PACKET_STATISTICS` was run by hand before
any code was written: fourteen frames of one loopback connection, each
delivered twice (`PACKET_OUTGOING` then `PACKET_HOST`), kernel realtime
stamps, zero drops.

### 5.2 Candidates

| Mechanism | What it yields | Process attribution | Independent of the observed host's root? | Cost here | Verdict |
|---|---|---|---|---|---|
| Static tracepoints via `perf_event_open` (`sock:inet_sock_set_state`, `sched:*`) | socket-layer state changes, process lifecycle, kernel monotonic stamps | yes for syscall-driven transitions, through the pidfd anchor | no — same kernel, same root | already implemented (Stages 7b/7c) | **kept** as the attribution source |
| `sock:sock_send_length` / `sock_recv_length` tracepoints | per-socket byte counts in the caller's context, linked by `sk` | yes | no | small; same perf machinery | **implemented in Gate 3** as `SockSendTracepoint` / `ghost.net.send.v1` (`ACTION_EVIDENCE.md` §16) |
| `net:net_dev_queue` / `net_dev_xmit` / `netif_receive_skb` tracepoints | per-skb device name and length | none (`skbaddr` only; no socket link without eBPF) | no | small | rejected: neither attribution nor headers |
| kprobes (`tcp_connect`, `tcp_sendmsg`, …) | arbitrary kernel state | yes, with eBPF to read `sk` | no | eBPF loader + bytecode + BTF-dependent offsets | rejected for this gate: stronger *reach*, not stronger *evidence*; a duplicate of what the tracepoints already give |
| eBPF `cgroup/connect4`, `sockops`, `sk_msg` | in-kernel attribution by cgroup and socket cookie; payload visibility with `sk_msg` | yes | no | `aya` (crates.io reachable) or a hand-rolled loader; bytecode compiled with `clang -target bpf` at build time | rejected for this gate: same trust root as the tracepoints; `sk_msg` payload access is forbidden by I23; the loader is a large new surface that adds no independence |
| TC (`cls_bpf`) | per-packet ingress/egress with eBPF | none without extra maps | no | eBPF loader, `tc` absent here | rejected: superset of AF_PACKET's evidence at eBPF's cost, on the same host |
| XDP | earliest inbound packet hook, drop capability | none | no | eBPF loader, driver support, `ifb`/`lo` do not support native XDP; generic XDP only | **Gate 10**: detect NIC/driver, dry-run first; a *response* mechanism, not an evidence one |
| `AF_PACKET` (`SOCK_DGRAM`, `ETH_P_ALL`, `SO_TIMESTAMPNS`, `PACKET_STATISTICS`) | a copy of every frame at the device layer with direction, interface, kernel realtime capture stamp and a kernel drop counter | **none** (the device layer has no task context) | **yes when placed on a mirror port or TAP host** — the same code produces the same evidence there; on the observed host itself, no | `libc` only; `CAP_NET_RAW` | **chosen** |

### 5.3 Decision

    DECISION:       AF_PACKET header tap (`aip_observe::wiretap::WireTap`),
                    `SourceMechanism::WireTapAfPacket`, event kind
                    `KernelLifecycleKind::WireSegment`.
    THREAT:         the socket-state tracepoint is the only kernel path by
                    which a connection is seen; a host that can suppress or
                    starve the perf ring leaves the verifier with nothing
                    but silence, and a verifier has no second path to
                    compare against.
    ASSUMPTION:     the kernel's device layer copies frames faithfully to a
                    packet socket the probe opens; when the tap runs on a
                    mirror host, that host's kernel is outside the observed
                    host's root.
    MECHANISM:      headers only — IP addresses, TCP ports, flags, seq/ack,
                    payload length, frame length, direction, interface,
                    kernel realtime stamp. Nothing after the TCP header is
                    copied, hashed or kept. Loss from `tp_drops`, truncated
                    or unstamped frames.
    IMPLEMENTATION: `aip-observe/src/wiretap.rs`; the probe ingests segments
                    unbound and unattributed; the collector's registry gates
                    the mechanism; the reconciler's `corroborate_wire` joins a
                    verified socket transition to exactly one SYN / SYN-ACK
                    pair on its tuple inside a one-second window around the
                    kernel transition, placed through the batch clock anchor.
    TEST:           `aip-observe/tests/wiretap.rs` wt01–wt10 (wt10 live);
                    `aip-reconcile/tests/wire_corroboration.rs` wc01–wc15;
                    `ghost-demo/tests/live_wire.rs` w_p / w_n (live).
    LIMITATION:     on the observed host the tap is root-forgeable and root-
                    stoppable like every other source, so a corroborated
                    verdict stays `Attested`; a tap on a mirror host needs its
                    own collector chain, and cross-observer reconciliation is
                    not implemented (`MixedObservers` is refused), so
                    "independent" placement is a deployment the code permits
                    and the verifier cannot yet exploit; the tap does not
                    know which interface a connection used, so `NotObserved`
                    may mean "not on the tapped path" and is never a
                    contradiction; TLS and everything above TCP remain
                    invisible (I23); IPv6 extension headers are not walked;
                    non-TCP traffic is out of scope.
    DEPENDENCIES:   Stage 7b transition evidence; batch clock anchor.
    STATUS:         IMPLEMENTED, live-demonstrated on this host.

### 5.4 What the wire adds to the three states

`OBSERVED / NOT_OBSERVED / OBSERVATION_UNAVAILABLE` of §3 are unchanged for
the verdict. For the *wire question* they appear as
`Reconciliation.wire: WireCorroboration` — `Corroborated`, `NotObserved`
(tap live and clean, no complete handshake placed in the window),
`Unavailable` (no live clean tap over the window), `Ambiguous{handshakes}`
(two distinct SYNs on the tuple), `NotEvaluated` (no transition verdict to
corroborate). None of these raises strength above `Attested` and none lowers
a verdict; wire segments alone attribute nothing and verify nothing. See
`RECONCILIATION_MODEL.md` "The wire question".

## 6. Filesystem observation — mechanism evaluation and decision (Gate 4)

Commits: RED `4a5f716`, GREEN `2f1ba9b`. Class: `ghost.fs.write.v1`
(`ACTION_EVIDENCE.md` §17).

### 6.1 What this host permits (measured)

714 `syscalls:*` tracepoints under tracefs; `CONFIG_FANOTIFY=y`,
`CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y`, `CONFIG_INOTIFY_USER=y`,
`CONFIG_AUDITSYSCALL=y` with no audit daemon; root filesystem ext4 on
`/dev/vda` reporting **fsid 0**. `fanotify_init(FAN_REPORT_PIDFD)` and
`fanotify_mark(FAN_MARK_MOUNT)` succeed; `fanotify_mark(FAN_MARK_FILESYSTEM)`
with `FAN_REPORT_DFID_NAME` fails with `ENODEV` (zero fsid). Measured before
any code: a shell's `echo > file` on the root mount produced one event with
mask `MODIFY|CLOSE_WRITE`, an fd whose `/proc/self/fd` link was the file's
path, its inode, and a pidfd whose `fdinfo` named the shell's pid; a writer
that had exited before the read came back with `FAN_NOPIDFD`.

### 6.2 Candidates

| Mechanism | What it yields | Process attribution | Object identity | Cost here | Verdict |
|---|---|---|---|---|---|
| `syscalls:sys_enter_openat` / `write` / `unlinkat` … via `perf_event_open` | pid, flags, mode, return values | the caller (syscall context) | **none without eBPF**: `filename` is a user-space pointer in the record, not the string | already-implemented perf plumbing | rejected: no path, no object |
| kprobes / eBPF (`bpf_probe_read_user_str`, LSM `file_open` with `d_path`) | path at entry, inode | the caller | path or inode | eBPF loader + bytecode; same host root | rejected for this gate: reach, not independence; loader cost (Gate 2 §5.2) |
| `inotify` | mask, name | **none** | watch descriptor | small | rejected: cannot attribute |
| audit (`CONFIG_AUDITSYSCALL`) | syscall records with pid, cwd, path | the caller | path | daemon absent; a second pipeline with its own loss semantics | rejected here |
| **`fanotify`** notification class, `FAN_REPORT_PIDFD`, mount mark | per `FAN_CLOSE_WRITE`/`FAN_MODIFY`: an open fd to the object and a pidfd the kernel created from the event's own `struct pid` | **the kernel binds the instance itself**; `FAN_NOPIDFD` when it has gone | kernel-resolved path + `(dev, ino)` through the fd; file handles (`FAN_REPORT_FID`) refused here | `libc` only; `CAP_SYS_ADMIN` | **chosen** |

### 6.3 Decision

    DECISION:       fanotify mount watch (`aip_observe::fanotify::FanotifyWatch`),
                    `SourceMechanism::Fanotify`, event kind
                    `KernelLifecycleKind::FileEvent`; one class, ghost.fs.write.v1.
    THREAT:         an agent's file effects are invisible to the action layer;
                    a pid-number anchor taken after the fact can bind a
                    recycled pid inside one clock tick.
    ASSUMPTION:     the kernel's fanotify queue and pidfd creation are faithful;
                    the marked mount is the one the agent writes on.
    MECHANISM:      FAN_CLOSE_WRITE on a marked mount; the object descriptor
                    resolved to the kernel's current path and (dev, ino) then
                    closed; the pidfd owned and used to measure the instance
                    (alive before and after); FAN_Q_OVERFLOW counted as loss;
                    nothing read from the file.
    IMPLEMENTATION: `aip-observe/src/fanotify.rs`, `ProcfsProbe::ingest_file_event`,
                    `PidFd::from_raw`; `aip-authorize` fs_write_action /
                    fs_write_parameters; `aip-reconcile` FileWrite /
                    derive_file_writes / TransitionEvidence::File /
                    FilePathUnresolved.
    TEST:           `aip-observe/tests/fanotify.rs` fa01–fa07 (fa05/fa06 live);
                    `aip-reconcile/tests/file_evidence.rs` fw01–fw15;
                    `ghost-demo/tests/live_file.rs` f_p / f_a / f_n (live).
    LIMITATION:     the path is a name resolved at read time in the probe's
                    mount namespace (renames, bind mounts, namespaces);
                    file-handle identity is refused on this host; events
                    carry no kernel timestamp (placement rests on read
                    cadence plus the clock anchor); creates / deletes /
                    renames need FID reporting; content is never observed;
                    the measurement content (start tick, image hash) is
                    procfs — `Attested`, never `Proven`; root can remove the
                    mark or starve the queue (then Degraded, never silent).
    DEPENDENCIES:   pidfd anchoring (Skill 6.5), transition evidence path.
    STATUS:         IMPLEMENTED, live-demonstrated on this host.

### 6.4 The five states, as the mandate names them

| Gate 4 state | §3 state | Record |
|---|---|---|
| OBSERVED | `OBSERVED` | `VERIFIED_EXECUTION · Attested` |
| NOT OBSERVED | `NOT_OBSERVED` for the *action*, with the instance observed | `CANNOT_PROVE · ActionEvidenceUnavailable` — fanotify is not lifecycle coverage, so never `PHANTOM_CLAIM` |
| AMBIGUOUS | — | `CANNOT_PROVE · AmbiguousObservations` |
| LOSS | `OBSERVATION_UNAVAILABLE` (degraded) | `CANNOT_PROVE · ObserverDegraded` |
| UNAVAILABLE | `OBSERVATION_UNAVAILABLE` | `NoObserverEvidence`, a refused batch, or `ProvenanceUnverifiedOpenPolicy` |

## 7. XDP — mechanism evaluation and decision (Gate 10)

The mandate requires XDP to be evaluated against the actual host, detecting
the NIC and driver and dry-running before anything is claimed. This section
records what was measured and what was decided. **No library code in this
repository loads a BPF program**; the evaluation lives in
`aip-observe/tests/gate10_xdp_evaluation.rs`.

### 7.1 What this host is

| Fact | Value | How |
|---|---|---|
| Kernel | 6.18.44 | `uname -r` |
| `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_JIT_ALWAYS_ON`, `CONFIG_XDP_SOCKETS`, `CONFIG_DEBUG_INFO_BTF` | all `y` | `/proc/config.gz` |
| Interfaces | `eth0`, `ifb0`, `ifb1`, `lo` | `/sys/class/net` |
| `eth0` driver | `virtio_net` (PCI `1af4:1041`, `virtio-pci`) | `/sys/class/net/eth0/device/driver` |
| BTF | `/sys/kernel/btf/vmlinux` present, 4.7 MB | filesystem |
| Unprivileged BPF | disabled (`unprivileged_bpf_disabled = 2`) | `/proc/sys/kernel` |

`virtio_net` implements native XDP; a generic (SKB-mode) attach is available
on any driver. Nothing here was assumed from the driver name — the dry run
below is what establishes capability.

### 7.2 The dry run, and what it measured

A 27-instruction XDP program was hand-assembled: bounds-check the frame
against `data_end`, match `ETH_P_IP`, IPv4 with `ihl = 5`, protocol TCP,
test the SYN flag, increment a counter in a `BPF_MAP_TYPE_ARRAY`, and return
`XDP_PASS` on every path. It was loaded with `bpf(BPF_PROG_LOAD)` — so the
in-kernel verifier, not a document, is the judge — and executed with
`BPF_PROG_TEST_RUN`.

| Measurement | Result |
|---|---|
| Verifier | accepted the guarded program |
| Verdict on a TCP SYN | `XDP_PASS`, counter 0 → 1 |
| TCP ACK, UDP datagram, 20-byte truncated frame | `XDP_PASS`, counter unchanged — the parser discriminates and the short frame takes the guard |
| 1 000 runs | counter 1 → 1 001; kernel-reported ~10 ns per run |
| The same program with the `data_end` guard removed | refused: `EACCES`, log `invalid access to packet, off=12 size=2, R2(id=0,off=12,r=0)` |

The ~10 ns figure is the kernel's own `BPF_PROG_TEST_RUN` duration for this
program on this host under no load. It is **not** a throughput, line-rate or
overhead figure for anything, and nothing in this repository measures those.

Nothing was attached to any interface. `BPF_PROG_TEST_RUN` executes the
program against a supplied buffer; no real frame passes through it, so no
packet could be delayed or dropped. The only route off this host is `eth0`,
and attaching to it with no out-of-band path is precisely the irreversible
act "dry-run first" exists to prevent.

### 7.3 The decision

    DECISION:       XDP is CAPABLE on this host and is NOT ADOPTED into the
                    observation model.

    THREAT:         A host-side party fabricates or suppresses the evidence
                    that a connection existed on the wire.

    ASSUMPTION:     The device-layer question is already answered. Gate 2's
                    AF_PACKET tap observes TCP/IP headers below the socket
                    layer with kernel timestamps (SO_TIMESTAMPNS) and
                    accounted loss (PACKET_STATISTICS), and the reconciler
                    consumes it as WireCorroboration.

    MECHANISM:      XDP would run a program in the driver's receive path,
                    before an skb exists.

    IMPLEMENTATION: None. The evaluation is a test, not a capability.

    TEST:           x10a (load, execute, discriminate, count, measure),
                    x10b (the verifier refuses an unbounded read).

    LIMITATION:     What XDP would add over the existing tap is earlier
                    placement and better behaviour under load — neither of
                    which changes a verdict, because XDP has no socket or
                    process context and therefore cannot attribute a frame
                    to an execution instance any better than the tap can.
                    What it would cost is a program in the kernel data path,
                    inside the TCB, for every packet. Its one genuinely new
                    capability is XDP_DROP, which is network isolation — an
                    actuation Gate 9 deliberately did not build.

    DEPENDENCIES:   None taken on.

    STATUS:         EVALUATED, NOT ADOPTED. Reopen if a requirement appears
                    that the tap provably cannot meet — sustained loss the
                    tap cannot absorb, or a decision to build network
                    isolation as a containment action, which would be its
                    own gate under Skill 9's rules.

## 8. Hardware validation (Gate 11)

    STATUS:         NOT PERFORMED — the hardware is not available.

The mandate permits hardware validation on a Dell R630 with an Intel X710
"if available", and requires empirical results only. This host is a virtual
machine: the CPU reports the `hypervisor` flag, DMI identity is masked
(`/sys/class/dmi/id/*` unreadable), and the only network device is
`virtio-pci 1af4:1041` bound to `virtio_net`. There is no X710, no R630, and
no physical NIC of any kind to measure.

Consequently **no throughput, line-rate, latency, overhead, packet-loss or
TRL figure for physical hardware appears anywhere in this repository**, and
none may be quoted. Every performance-shaped number recorded at any gate is
named with the interface that produced it and the conditions under which it
was taken, on this virtual host.
