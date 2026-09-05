# OBSERVATION_MODEL

> **Status note (post Stages 3–7c, Skill 8, PR #3 harvest).** §1 below is the
> Stage 0 discovery and reads "MISSING" for runtime observation; that was
> true at `377d5fc`. The observer now exists — `aip-observe` with a
> probe/collector split, kernel-pushed sources, provenance gating, loss
> accounting and restart-continuity audit — and is described in
> `SNIFFER_DOG.md`, `OBSERVER_IMPLEMENTATION_REPORT.md` and
> `SNIFFER_DOG_IMPLEMENTATION_REPORT.md`. The semantics in §3–§4 are the
> ones implemented. Statements of absence in §1 are kept for traceability.


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
