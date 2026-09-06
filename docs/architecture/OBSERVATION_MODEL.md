# OBSERVATION_MODEL

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
