# EXECUTION_BINDING

Status: **IMPLEMENTED (self-reported binding + packet integration) /
NOT IMPLEMENTED (independent attestation of the binding — Stage 3).**

Implemented under Skill 4 (`syntriass-execution-binding`); see
`EXECUTION_BINDING_IMPLEMENTATION_REPORT.md` for the change-by-change record.
Sections 1–2 preserve the discovery findings that motivated the design.

---

## 1. Threat

An authorization decision, an agent's evidence, and a later observation each
refer to "the process". If "the process" is named by a PID, the kernel's PID
recycling lets an unrelated process inherit the attribution of a finished one
(**I4**). If the executable is named by its path, a different binary at the
same path inherits the identity of the intended one (**I2**). If identity is
self-declared (`agent_id: &str`), anyone can claim it.

Concrete case: between the authorization decision and the observation, the
original process exits and another process receives the same PID. With no
start time, no observation can distinguish them and attribution silently
transfers to the wrong workload.

### 1.1 What existed before (discovery, unchanged)

`aip_core::runtime::RuntimeBinding` (`aip-standalone/aip-core/src/runtime.rs`)
is **not** a suitable foundation and was not extended; it is now marked
`NOT_PRODUCTION_CAPABILITY` in its module doc and retained only for the CLI
display path.

| Requirement | `RuntimeBinding` |
|---|---|
| Binds agent identity to a process | No — `agent_id` is an unvalidated `&str` argument |
| Survives PID reuse | No — no process start time anywhere |
| Measures the executable | No — `sha256` of `current_exe().to_string_lossy()`, the **path string** |
| Resists environment forgery | No — `hostname` reads `$HOSTNAME`; `container_id` returns `$CONTAINER_ID` verbatim |
| Signed | No |
| Reaches evidence | No — `EvidencePacket` had no runtime field |
| Verified meaningfully | No — `pid` excluded from the verdict |

## 2. Assumptions

| # | Assumption | Basis |
|---|---|---|
| A1 | Linux procfs is available to the collecting process: `/proc/<pid>/stat`, `/proc/<pid>/exe`, `/proc/sys/kernel/random/boot_id`. | Verified in the build container (kernel 6.18). Other platforms return `BindingError::UnsupportedPlatform`. |
| A2 | Field 22 of `/proc/<pid>/stat` (`starttime`, clock ticks since boot) is constant for a process's lifetime and differs between two processes that hold the same PID within one boot. | `proc(5)`. Two processes can receive the same PID and the same `starttime` only if the kernel recycles a PID within one clock tick (10 ms at `CLK_TCK=100`) — this residual is recorded in §7. |
| A3 | `boot_id` is a random UUID regenerated at every boot and constant during a boot. | Kernel behaviour. |
| A4 | SHA-256 is collision-resistant, so equal `exe_content_sha256` implies equal executable contents. | Standard hash assumption; nothing stronger is claimed. |
| A5 | The collecting process is honest **or** an independent observer later attests the same facts. | This is exactly the boundary this stage does *not* close (§9, §11). |

## 3. Mechanism

```text
ProcessInstance  = (pid: u32, pid_start_time_ticks: u64, boot_id: [u8;16])
ExecutionBinding = (version, agent_id, ProcessInstance, exe_content_sha256, exe_path, bound_at_ms)

identity_bytes   = "GHOST/ExecutionIdentity/v1" ‖ version ‖ agent_id ‖ pid ‖ start ‖ boot_id ‖ exe_content_sha256
canonical_bytes  = "GHOST/ExecutionBinding/v1"  ‖ version ‖ agent_id ‖ pid ‖ start ‖ boot_id ‖ exe_content_sha256 ‖ exe_path ‖ bound_at_ms

same_execution(a, b)  ⇔  identity_bytes(a) == identity_bytes(b)
```

- Process identity is the full tuple. Equality is derived over all three
  fields; `same_execution` compares identity bytes, so a future change that
  compares PIDs alone fails the permanent guard test
  `pid_equality_never_implies_same_execution`.
- Executable identity is the SHA-256 of the **contents** of `/proc/<pid>/exe`
  (the mapped binary, hashed through the procfs link so a replaced or unlinked
  on-disk file cannot change what is measured). `exe_path` is carried as
  context and is **excluded** from `identity_bytes`.
- All variable-length fields are length-prefixed by the shared encoder
  (`aip_types::canonical`); both encodings start with a domain tag; the two
  tags differ so a binding digest can never be confused with an identity
  digest, nor with any AIP token, packet, or Ghost object.

### 3.1 Field justification

| Field | Purpose | In identity? | Signed as packet content? |
|---|---|---|---|
| `version` | encoding/semantics version | yes | yes |
| `agent_id` | who the binding is about; must equal the packet agent (R15) | yes | yes |
| `process.pid` | kernel handle — meaningless alone | yes (with the other two) | yes |
| `process.pid_start_time_ticks` | defeats PID reuse within a boot (I4) | yes | yes |
| `process.boot_id` | defeats reuse across boots (I4) | yes | yes |
| `exe_content_sha256` | detects binary replacement at the same path (I2) | yes | yes |
| `exe_path` | human/operator context; deliberately **not** identity | no | yes |
| `bound_at_ms` | when the self-report was taken; metadata, **not** an authorization window (I21) | no | yes |

Fields from the earlier proposal that were **not** adopted, and why:

| Proposed field | Decision | Reason |
|---|---|---|
| `key_proof: Signature` | not added | Inside an `EvidencePacket` the agent's packet signature already proves key possession over the binding (R4). A standalone binding signature would be a second self-attestation and risks being mistaken for observer attestation. `ExpectedExecution` (Stage 2) and `ObservedExecution` (Stage 3) will each sign the binding with **their own** authority. |
| `valid_until_ns` | not added | Skill 4 §18: temporal validity belongs to the authorization layer (tokens, R10). Duplicating expiry here would create a second expiry semantics. |
| `cgroup_id`, `mnt_ns`, `pid_ns`, `net_ns` | deferred | Containment context is needed to *interpret* observations (Stage 3) and to scope containment (Stage 8); it does not change process-instance identity. Add when the observer defines what it can attest. |

## 4. Implementation

| Component | Location |
|---|---|
| `ProcessInstance`, `ExecutionBinding`, `canonical_bytes`, `identity_bytes`, `same_execution`, domain tags, `EXECUTION_BINDING_VERSION = 1` | `aip-standalone/aip-types/src/lib.rs` (section "GHOST STAGE 1") |
| Collector `collect_self_binding` / `collect_binding_for_pid` (Linux), parsers `parse_proc_stat_start_time`, `parse_boot_id`, `hash_file_contents`, digests `binding_digest`, `execution_identity_digest`, `BindingError` | `aip-standalone/aip-core/src/execution_binding.rs` |
| `EvidencePacket.execution_binding: Option<ExecutionBinding>` (`#[serde(default)]`), canonical encoding (presence byte + nested length-prefixed bytes, between receipt binding and claimed trust floor), builder `.execution_binding(..)` | `aip-standalone/aip-protocol/src/evidence_packet.rs` |
| Rule R15 `EXECUTION_BINDING` | `aip-standalone/aip-protocol/src/verification.rs` (`check_execution_binding`), `verification_report.rs` |

### 4.1 Sources and units

| Fact | Source | Units / format | Failure |
|---|---|---|---|
| `pid_start_time_ticks` | `/proc/<pid>/stat`, field 22, parsed from the **last** `)` so a hostile `comm` cannot shift fields | clock ticks since boot (`CLK_TCK`, 100/s here); `0` rejected | `BindingError::Unavailable{field:"pid_start_time_ticks"}` |
| `boot_id` | `/proc/sys/kernel/random/boot_id` | textual UUID → 16 bytes; all-zero rejected | `BindingError::Unavailable{field:"boot_id"}` |
| `exe_content_sha256` | contents of `/proc/<pid>/exe`, streamed | 32 bytes | `BindingError::Unavailable{field:"exe_content_sha256"}` |
| `exe_path` | `readlink(/proc/<pid>/exe)` | lossy UTF-8 string | `BindingError::Unavailable{field:"exe_path"}` |

No wall-clock creation time is used for process identity; `bound_at_ms` is
metadata only.

## 5. Test evidence

`aip-standalone/aip-core/src/execution_binding.rs` (12 tests):

| Skill 4 test | Test | Property |
|---|---|---|
| A — PID reuse | `same_pid_different_start_time_is_a_different_instance` | tuple inequality, `same_execution == false`, identity digests differ |
| B — reboot | `same_pid_same_start_different_boot_is_a_different_instance` | as above with differing `boot_id` |
| §14 guard | `pid_equality_never_implies_same_execution` | for every single-field variant with equal PID, `same_execution` is false |
| C — executable replacement | `same_path_different_contents_yields_different_executable_identity` | same path, contents A then B → digests differ and equal `sha256(contents)`; path hash would have been identical |
| D — path mutation | `exe_path_does_not_participate_in_identity_but_is_signed_content` | identity equal, canonical bytes differ |
| E — injectivity | `canonical_encoding_is_injective_over_variable_fields`, `domain_tags_lead_both_encodings_and_differ` | `("ab","c")` ≠ `("a","bc")`, every field change changes bytes, tags differ |
| parser robustness | `parse_stat_handles_comm_with_spaces_and_parens`, `parse_stat_rejects_malformed_input_without_panicking`, `parse_boot_id_roundtrip_and_rejections` | hostile `comm`, short/garbage/zero inputs → `Err`, never panic |
| live collection (Linux) | `collect_self_binding_reads_real_process_instance`, `collect_for_nonexistent_pid_fails_explicitly` | real pid/start/boot/exe hash; nonexistent PID → explicit error |

`aip-standalone/aip-protocol/tests/evidence_packet.rs` (9 tests):

| Skill 4 test | Test | Property |
|---|---|---|
| F — signed mutation | `test_binding_field_mutations_detected_by_hash` | each of 8 fields mutated after sealing → R3 fails, `tampered` |
| G — transplant | `test_binding_transplant_detected_by_hash_and_signature` | different binding → R3; hash recomputed without key → R4 |
| presence | `test_binding_presence_is_part_of_canonical_bytes`, `test_json_without_binding_key_parses_as_none` | absence ≠ presence; legacy JSON parses as `None` and then fails R3 honestly |
| R15 | `test_binding_for_other_agent_rejected_even_when_resealed`, `test_degenerate_binding_fields_rejected`, `test_packet_without_binding_verifies_and_reports_absence`, `test_execution_binding_rule_passes_but_is_flagged_self_reported` | agent mismatch / zero fields rejected; absence reported; passing detail says "NOT independently observed"; floor unchanged |
| H — self-report limit | `test_resealed_self_binding_swap_verifies_documenting_self_report_limit` | the agent **can** re-seal with a different well-formed self-binding and the packet verifies — pinned as the documented boundary that only an observer can close |

## 6. Failure semantics

- Any unreadable or unparsable source → `Err(BindingError)`. No field is
  defaulted, zeroed, or substituted (no hostname, path hash, or wall clock in
  place of a missing fact).
- Non-Linux targets → `Err(BindingError::UnsupportedPlatform)`.
- A packet **without** a binding verifies; R15 records "no execution binding
  present; process-instance attribution unavailable". The reconciler must
  treat that as `CANNOT_PROVE` for attribution (I3).
- A packet **with** a degenerate binding (pid 0, start 0, zero boot id, zero
  exe hash, wrong version) fails R15 — a binding may be absent, never empty.
- R15 never sets `tampered`: an inconsistent binding under a valid signature is
  producer inconsistency, not post-signing modification.

## 7. Limitations

1. **Self-report.** Every binding produced today is collected by the agent
   about itself. It is a correlation key, not evidence that the process
   exists or ran. A root-compromised host can present arbitrary procfs
   content. Test H pins this.
2. **Sub-tick PID recycling.** Two processes receiving the same PID within one
   clock tick of the same boot would share `(pid, start, boot)`. This is a
   kernel-level residual; the observer stage may add `pid_ns`/`cgroup_id` and
   spawn ordering to narrow it, but it cannot be eliminated by the agent.
3. **Executable ≠ behaviour.** `exe_content_sha256` identifies the binary
   image, not loaded libraries, interpreters' scripts, JIT code, or
   `ptrace`-injected code. A Python agent is identified as the Python
   interpreter.
4. **Linux only.** No Windows/macOS process-instance source is implemented;
   the API returns an explicit error rather than a weaker binding.
5. **No namespace/cgroup context yet.** Observations from a different PID
   namespace cannot yet be scoped; see §3.1 deferred fields.
6. **PACKET_VERSION.** The binding was added inside the unreleased v2
   canonical layout rather than as v3, per IMPLEMENTATION_PLAN §1.2 ("one bump
   covers Stages 0 + 1"). Any v2 packet sealed between commits `830c1e5` and
   this change (none exist outside this branch's test runs) would fail R3.

## 8. Platform assumptions

Linux procfs semantics as in `proc(5)`: `starttime` is field 22 in clock
ticks since boot; `comm` is parenthesised and may contain spaces and
parentheses; `/proc/<pid>/exe` is a magic link to the mapped executable;
`boot_id` is a UUID. `CLK_TCK` is not stored because ticks are compared, not
converted.

## 9. Trust boundary

```text
agent process ──reads own /proc──▶ ExecutionBinding (self-report)
        │
        └─ signs packet (R4) ──▶ EvidencePacket.execution_binding
                                   │
                                   ▼
                          verifier: R3/R4 (integrity), R15 (consistency)
                                   │
                                   ▼   NOT provided by this stage
                          observer attests the same (pid,start,boot,exe)
```

The verifier can prove: the agent signed *this* binding, the binding is
well-formed and names the packet agent. The verifier cannot prove: that the
binding is true. Passing R15 is explicitly labelled "NOT independently
observed" in the report detail.

## 10. Relationship to `decision_id`

`DecisionRecord.decision_id` remains the primary correlation key. The binding
is complementary: reconciliation joins on `decision_id` **and**
`execution_identity_digest`. A binding never replaces or derives a decision
id, and a decision id never implies a process instance.

## 11. Relationship to the future observer

Stage 3's `ObservedExecution` embeds an `ExecutionBinding` collected by the
observer (outside the agent's trust boundary) and signed with the observer's
key. Reconciliation compares `identity_bytes` of the expected/self-reported
binding with the observed one:

- equal → identity match (one input to `VERIFIED_EXECUTION`, never sufficient
  alone);
- unequal, both attested → `IDENTITY_DIVERGENCE`;
- observer binding absent → `CANNOT_PROVE`.

The parsers in `aip_core::execution_binding` are pure and reusable by an
observer; the collector itself is not an observer.

## 11a. Parent/child relationships and lifetime semantics (investigated; design only)

Investigated under the Stage 1 authorization; **not implemented**, for the
reasons below. Nothing here is a capability.

**Parent/child.** `/proc/<pid>/stat` field 4 (`ppid`) is available to the
agent, and the parent's own `ProcessInstance` could be read from
`/proc/<ppid>/stat`. It was deliberately **not** added to the binding:

- `ppid` is not stable: when the parent exits the child is re-parented to
  PID 1 or a subreaper, so a self-read `ppid` describes a moment, not a
  lineage.
- Lineage is exactly the fact that `LINEAGE_VIOLATION` (RECONCILIATION_MODEL)
  requires to be *independently attested*; a self-reported parent would
  invite the reconciler to treat an agent claim as ancestry evidence (I5).
- The observer (Stage 3) sees `fork`/`exec` events as they happen and can
  record `(parent ProcessInstance → child ProcessInstance)` with its own
  signature. That is the correct home for lineage.

Until then the reconciler's answer to any lineage question is `CANNOT_PROVE`.

**Start.** A process instance begins at `exec` of the measured binary; its
`ProcessInstance` tuple is fixed from that point. A later `exec` in the same
PID changes `exe_content_sha256` and therefore yields a *different* execution
identity even though `(pid, start, boot)` is unchanged — this is intended:
identity is "this process instance running this binary".

**Termination.** A binding carries no termination fact and cannot: the agent
cannot report its own exit. After exit the PID may be recycled; the recycled
process has a different `pid_start_time_ticks` and so a different identity
(Test A). Whether an action fell inside the *authorization* window is R10's
question (tokens); whether it fell inside the *process lifetime* is a question
only an observer with coverage over that window can answer (I8, I9).
`bound_at_ms` records when the self-report was taken and nothing else.

**Attribution rule for downstream stages.** Given a packet binding `B_pkt`
and an observer binding `B_obs`:

| Condition | Attribution |
|---|---|
| `B_obs` absent | `CANNOT_PROVE` |
| `identity_bytes(B_pkt) == identity_bytes(B_obs)`, observer coverage attested | identity match (input to `VERIFIED_EXECUTION`) |
| identities differ, both attested | `IDENTITY_DIVERGENCE` |
| equal PID only | **never** attribution (guard test) |

## 12. Self-reported binding is not independent observation

Stated once more because it is the invariant most likely to be eroded by
convenience: a binding collected by `collect_self_binding`, carried in an
`EvidencePacket`, and passing R15 is the **agent's claim** about which process
it is. It satisfies I2 and I4 as an *identifier* (not PID-only, not path-only,
survives PID reuse) but does not satisfy I5 or I10. Nothing in this stage may
be described as observation, attestation, or proof of execution.
