# EXECUTION_BINDING

## 1. Current state

`EXECUTION_BINDING = MISSING`. Zero occurrences of `ExecutionBinding` in
production code.

The nearest existing type is `aip_core::runtime::RuntimeBinding`
(`aip-standalone/aip-core/src/runtime.rs:10-26`). It is **not** a suitable
foundation and must not be extended in place:

| Requirement | `RuntimeBinding` today |
|---|---|
| Binds agent identity to a process | No — `agent_id` is an unvalidated `&str` argument (`:38`) with no proof of key possession |
| Survives PID reuse | No — no process start time anywhere in the crate (verified: 0 matches for `start_time`/`starttime`) |
| Measures the executable | No — `sha256` of `current_exe().to_string_lossy()`, the **path string** (`:41-44`) |
| Resists environment forgery | No — `hostname` reads `$HOSTNAME` first (`:108-117`); `container_id` returns `$CONTAINER_ID` verbatim (`:121-142`) |
| Signed | No — no signature field on the struct |
| Reaches evidence | No — `EvidencePacket` has no runtime field; result is only printed (`aip-cli/src/main.rs:127,137`) |
| Verified meaningfully | No — `pid` excluded from the verdict (`:76,84-93`); `container_match` computed then discarded (`:87` vs `:93`) |

Violates **I2**, **I4**, **I10**.

## 2. Why PID alone fails — the concrete case

`std::process::id()` returns a `u32` that the kernel reuses. Between the
authorization decision and the observation, the original process may exit and
an unrelated process may inherit the same PID. With no start time, no
observation can distinguish them, and attribution silently transfers to the
wrong workload (**I4**).

The minimal fix is a **process instance key**, not a PID:

```
ProcessInstance = (pid, pid_start_time_ticks, boot_id)
```

`pid_start_time_ticks` is field 22 of `/proc/<pid>/stat`; `boot_id` is
`/proc/sys/kernel/random/boot_id`. The triple is unique for the lifetime of a
boot and is what makes a PID meaningful. Neither is read anywhere today.

## 3. Proposed `ExecutionBinding` — design only, do not implement yet

Every field carries a security purpose; nothing is included because it sounds
useful.

```rust
struct ExecutionBinding {
    // ── identity: who ────────────────────────────────────────────────
    agent_id: String,          // AIP-ID; ties to derive_aip_id
    key_proof: Signature,      // agent proves key possession over the
                               // binding challenge — closes the
                               // "unvalidated &str" hole in runtime.rs:38

    // ── process instance: which process, unambiguously ───────────────
    pid: u32,
    pid_start_time_ticks: u64, // defeats PID reuse (I4)
    boot_id: [u8; 16],         // defeats reuse across reboots

    // ── workload: what code ──────────────────────────────────────────
    exe_content_sha256: [u8; 32], // the BINARY, not the path (contrast :41-44)
    exe_path: String,             // context only; never an identity claim

    // ── containment context: where ───────────────────────────────────
    cgroup_id: u64,            // kernel cgroup v2 id, not a /proc string
    mnt_ns: u64,
    pid_ns: u64,
    net_ns: u64,               // required to interpret any network observation

    // ── liveness window: when this binding is meaningful ─────────────
    bound_at_ns: u64,
    valid_until_ns: u64,       // MUST be signature-covered (I6, I21)
}
```

### Field justification

| Field | Threat it addresses |
|---|---|
| `key_proof` | agent claiming an identity it does not hold the key for |
| `pid_start_time_ticks`, `boot_id` | PID reuse transferring attribution (**I4**) |
| `exe_content_sha256` | a different binary at the same path — the exact weakness of `runtime.rs:41-44` |
| `cgroup_id`, `*_ns` | container/namespace escape and mis-scoped observation |
| `valid_until_ns` | an unbounded binding outliving the process (**I21**) |

### Lifecycle events the binding must handle

| Event | Required behaviour |
|---|---|
| process restart | new `ProcessInstance` ⇒ new binding; old binding expires, is not transferred |
| container restart | `cgroup_id` and namespace ids change ⇒ new binding |
| PID reuse | `pid_start_time_ticks` differs ⇒ **binding does not match**; attribution must fail closed |
| namespace / cgroup change | binding invalidated; re-bind required |
| runtime replacement (exec) | `exe_content_sha256` changes ⇒ new binding |
| credential change / rotation | `key_proof` re-established; prior bindings expire |

### Who signs it

The binding is **co-asserted**: the agent proves key possession, but the
process facts must be attested by the observer, which the agent does not
control (**I10**). A binding signed only by the agent is worth exactly as much
as `RuntimeBinding` is today — nothing. See `OBSERVER_ATTESTATION.md`.

## 4. Integration point in existing code

`ExecutionBinding` must reach signed evidence. The extension point is
`EvidencePacket` (`aip-standalone/aip-protocol/src/evidence_packet.rs:210-246`),
which currently has **no runtime field**.

Adding one is a **wire-format change**: `canonical_bytes` (`:251-334`) must
encode it with the length-prefixed helpers in `canonical.rs`, and
`PACKET_VERSION` must be bumped (`aip-protocol-change-guard` §3). Batch it with
the `expires_at` fix (P0-1) so there is one version break, not two.
