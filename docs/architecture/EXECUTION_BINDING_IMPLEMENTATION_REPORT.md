# EXECUTION BINDING IMPLEMENTATION REPORT

Skill 4 (`syntriass-execution-binding`) / Orchestrator Stage 1.

## Status

**PASS** — under the completion criteria of Skill 4 §28, with the limitations
in §"Known limitations" below. Nothing in this stage claims independent
observation.

## Baseline

- Predecessor gate: Skill 3 PASS, `docs/architecture/AIP_CORRECTNESS_REPORT.md`
  at commit `f78a599`.
- Start of Stage 1: HEAD `a4d9670` (Skill 10 file), working tree clean.
- Test baseline at start: aip-standalone 254 passed / 0 failed / 3 ignored;
  aip-service 38 passed.
- Hard-stop checklist (Skill 4 §2): all clear. `EXECUTION_BINDING.md` §3's
  earlier field proposal differed from Skill 4 §18 on `valid_until_ns`; the
  proposal was explicitly marked "design only", and the deviation is recorded
  in `EXECUTION_BINDING.md` §3.1 rather than silently resolved.

## Existing weakness demonstrated first (Skill 4 §13)

Before the new type was relied upon, the weakness of the pre-existing
`RuntimeBinding` was pinned by three characterization tests in
`aip-standalone/aip-core/src/runtime.rs`. They **pass against the unchanged
`RuntimeBinding`**, which is the point: each asserts a property an execution
binding must *not* have.

| Test | Demonstrated weakness | Result against current `RuntimeBinding` |
|---|---|---|
| `weakness_runtime_binding_ignores_pid_entirely` | PID rewritten by +1,000,000 → `is_same_environment == true` (PID reuse invisible, I4) | passes = weakness confirmed |
| `weakness_runtime_binding_hashes_path_not_contents` | `exe_hash == sha256(path string)` and `!= sha256(binary contents)` (same-path replacement invisible, I2) | passes = weakness confirmed |
| `weakness_runtime_binding_has_no_instance_identity` | no `start_time`/`boot_id` field exists; two instances differ only by an agent-set wall clock | passes = weakness confirmed |

If a future change "fixes" `RuntimeBinding` in place these tests fail and
redirect the author to `execution_binding`, which asserts the opposite
properties (`same_pid_different_start_time_is_a_different_instance`,
`same_path_different_contents_yields_different_executable_identity`).
`RuntimeBinding` itself is unchanged and marked `NOT_PRODUCTION_CAPABILITY`.

## Scope items investigated but not implemented

| Item | Finding | Where recorded |
|---|---|---|
| Parent/child relationships | `ppid` is self-read and unstable under re-parenting; lineage must be observer-attested (`LINEAGE_VIOLATION` precondition). Not added to the binding. | `EXECUTION_BINDING.md` §11a |
| Start / termination semantics | Instance begins at `exec`; a later `exec` changes identity via the exe hash; termination cannot be self-reported; lifetime coverage is an observer question (I8/I9). `bound_at_ms` is collection time only. | `EXECUTION_BINDING.md` §11a |
| Attribution rule | Observer binding absent → `CANNOT_PROVE`; identity match requires equal `identity_bytes` **and** attested coverage; equal PID never attributes. | `EXECUTION_BINDING.md` §11a |
| cgroup / namespace ids | Needed to scope observations, not to identify an instance; deferred to Stage 3. | `EXECUTION_BINDING.md` §3.1 |

## Files inspected

`docs/architecture/{SECURITY_INVARIANTS, EXECUTION_BINDING, IMPLEMENTATION_PLAN,
OBSERVATION_MODEL, RECONCILIATION_MODEL, TARGET_ARCHITECTURE, GAP_MATRIX,
AIP_CORRECTNESS_REPORT}.md`;
`aip-standalone/aip-core/src/runtime.rs` (the prior `RuntimeBinding`);
`aip-standalone/aip-protocol/src/{evidence_packet, verification,
verification_report}.rs`; `aip-standalone/aip-types/src/{lib, canonical}.rs`;
`aip-standalone/aip-protocol/tests/evidence_packet.rs`; every `EvidencePacket
{` literal in both workspaces (only the builder constructs one); the live
procfs of the build container (`/proc/self/stat` field 22 = 433843,
`boot_id` present, `CLK_TCK` = 100, kernel 6.18).

## Files changed

| File | Change |
|---|---|
| `aip-standalone/aip-types/src/lib.rs` | **new section** "GHOST STAGE 1": `ProcessInstance`, `ExecutionBinding`, `EXECUTION_BINDING_DOMAIN`, `EXECUTION_IDENTITY_DOMAIN`, `EXECUTION_BINDING_VERSION`, `canonical_bytes`, `identity_bytes`, `same_execution` |
| `aip-standalone/aip-core/src/execution_binding.rs` | **new** — Linux procfs collector, parsers, streaming exe hash, digests, `BindingError`; 12 tests |
| `aip-standalone/aip-core/src/lib.rs` | `pub mod execution_binding` |
| `aip-standalone/aip-core/src/runtime.rs` | module doc: `NOT_PRODUCTION_CAPABILITY`, superseded (no production code change); 3 characterization tests of the existing weakness |
| `aip-standalone/aip-protocol/src/evidence_packet.rs` | `execution_binding: Option<ExecutionBinding>` (`#[serde(default)]`); canonical encoding; builder method; `PACKET_VERSION` doc updated to state v2 covers Stages 0 + 1 |
| `aip-standalone/aip-protocol/src/verification.rs` | R15 `check_execution_binding` |
| `aip-standalone/aip-protocol/src/verification_report.rs` | `rules::EXECUTION_BINDING` |
| `aip-standalone/aip-protocol/tests/evidence_packet.rs` | fixture gains a synthetic binding (`build_fixture_opts(.., with_binding)`); 9 tests |
| `docs/architecture/EXECUTION_BINDING.md` | rewritten to the 12-item structure required by Skill 4 §23 |
| `docs/architecture/EXECUTION_BINDING_IMPLEMENTATION_REPORT.md` | this report |

## Exact data model

```rust
pub const EXECUTION_BINDING_DOMAIN:  &str = "GHOST/ExecutionBinding/v1";
pub const EXECUTION_IDENTITY_DOMAIN: &str = "GHOST/ExecutionIdentity/v1";
pub const EXECUTION_BINDING_VERSION: u16  = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessInstance {
    pub pid: u32,
    pub pid_start_time_ticks: u64,   // /proc/<pid>/stat field 22, clock ticks since boot
    pub boot_id: [u8; 16],           // /proc/sys/kernel/random/boot_id
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionBinding {
    pub version: u16,
    pub agent_id: String,
    pub process: ProcessInstance,
    pub exe_content_sha256: [u8; 32], // SHA-256 of /proc/<pid>/exe CONTENTS
    pub exe_path: String,             // context only; not identity
    pub bound_at_ms: u64,             // metadata; not an authorization window
}
```

Equality semantics: `ProcessInstance` derives `PartialEq` over all three
fields. `ExecutionBinding::same_execution` compares `identity_bytes`
(version, agent, pid, start, boot, exe hash). Derived `PartialEq` on
`ExecutionBinding` compares every field including path and time and is used
only for round-trip tests.

## Canonical encoding

Both encodings use `aip_types::canonical` (the single encoder introduced in
Skill 3): `put_domain` (length-prefixed tag) → `put_u16(version)` →
`put_str(agent_id)` → `put_u32(pid)` → `put_u64(start)` → raw 16-byte
`boot_id` → raw 32-byte `exe_content_sha256` → [canonical only:
`put_str(exe_path)` → `put_u64(bound_at_ms)`]. Fixed-width fields are raw
because their width is fixed; every variable-length field is length-prefixed;
the two tags differ. Injectivity tests: `("ab","c")` vs `("a","bc")` across
`agent_id`/`exe_path`, empty-string shifts, and single-field perturbation of
every field.

Inside an `EvidencePacket` the binding is encoded as `0x01 ‖
put_bytes(canonical_bytes)` (or `0x00` when absent) between the receipt
binding and the claimed trust floor.

## Signature coverage

- **Inside a packet:** the agent's packet signature (R4) covers the binding
  through the canonical bytes; R3 catches any mutation. This proves the agent
  signed this binding — i.e. key possession over the claim — and nothing more.
- **Standalone:** no separate binding signature was introduced (see
  `EXECUTION_BINDING.md` §3.1). The decision point (Stage 2) and the observer
  (Stage 3) will each sign bindings under their own domain and key, which is
  what makes them meaningful; a second self-signature here would add no
  security and could be mistaken for attestation.
- The binding creates no authority (Skill 4 §10): R15 does not participate in
  the trust-floor derivation.

## Packet integration

- Field is `Option` with `#[serde(default)]`: packets/JSON without it parse
  as `None`.
- Wire format: added inside v2. Rationale: IMPLEMENTATION_PLAN §1.2 specified
  one bump covering Stages 0 + 1; v2 was created in this branch by Skill 3 and
  has not been released or persisted anywhere (verified: no fixtures, no
  stored artefacts). The `PACKET_VERSION` doc now states the v2 layout
  explicitly. Test `test_binding_presence_is_part_of_canonical_bytes` proves
  presence/absence are distinct bytes; `test_json_without_binding_key_parses_as_none`
  proves a stripped legacy JSON fails R3 rather than silently verifying.
- Verification: new rule **R15 `EXECUTION_BINDING`**, recorded after R13 and
  before the trust-floor derivation. All 14 existing rules and their order are
  unchanged; R15 does not short-circuit anything and does not set `tampered`.
- The service (`aip-service`) builds packets through the builder and is
  unaffected (binding `None` → R15 passes with "absent" detail); 38/38 tests
  pass.

## Tests added

| Location | Count | Names |
|---|---|---|
| `aip-core/src/runtime.rs` | 3 | `weakness_runtime_binding_ignores_pid_entirely`, `weakness_runtime_binding_hashes_path_not_contents`, `weakness_runtime_binding_has_no_instance_identity` (characterization of the pre-existing weakness) |
| `aip-core/src/execution_binding.rs` | 12 | `same_pid_different_start_time_is_a_different_instance`, `same_pid_same_start_different_boot_is_a_different_instance`, `pid_equality_never_implies_same_execution`, `same_path_different_contents_yields_different_executable_identity`, `exe_path_does_not_participate_in_identity_but_is_signed_content`, `canonical_encoding_is_injective_over_variable_fields`, `domain_tags_lead_both_encodings_and_differ`, `parse_stat_handles_comm_with_spaces_and_parens`, `parse_stat_rejects_malformed_input_without_panicking`, `parse_boot_id_roundtrip_and_rejections`, `collect_self_binding_reads_real_process_instance` (linux), `collect_for_nonexistent_pid_fails_explicitly` (linux) |
| `aip-protocol/tests/evidence_packet.rs` | 9 | `test_execution_binding_rule_passes_but_is_flagged_self_reported`, `test_packet_without_binding_verifies_and_reports_absence`, `test_binding_field_mutations_detected_by_hash`, `test_binding_transplant_detected_by_hash_and_signature`, `test_binding_presence_is_part_of_canonical_bytes`, `test_json_without_binding_key_parses_as_none`, `test_binding_for_other_agent_rejected_even_when_resealed`, `test_degenerate_binding_fields_rejected`, `test_resealed_self_binding_swap_verifies_documenting_self_report_limit` |

Mapping to Skill 4 §13: A, B, C, D, E, F, G implemented as listed; H is
implemented as the explicit self-report-limit test (a re-sealed swap **is**
accepted by the packet alone, by design, and the test pins that so no later
stage can claim otherwise). §14 permanent guard:
`pid_equality_never_implies_same_execution`.

## Tests intentionally not added

- A live PID-reuse test (spawn, exit, spawn until the kernel recycles a PID)
  — non-deterministic and slow; the property is proven on the data model,
  which is where a regression would occur.
- A cross-reboot test — cannot run in CI; the `boot_id` property is tested on
  parsed data.
- A test that the packet detects a *false* self-binding — impossible by
  construction (see Test H); this is the Stage 3 observer's job.
- Windows/macOS collectors — not implemented, so nothing to test beyond the
  `UnsupportedPlatform` branch, which is `cfg`-gated out on Linux.

## Test results

| Suite | Before Stage 1 | After |
|---|---|---|
| aip-core | 125 | **140** (+12 execution_binding, +3 runtime characterization) |
| aip-protocol tests/evidence_packet.rs | 26 | **35** (+9) |
| aip-crypto / aip-types / aip-protocol unit / bundle / aip-test / aip-real-tests | 8 / 5 / 4 / 6 (1 ign) / 13 / 67 (2 ign) | unchanged |
| **aip-standalone total** | 254 / 0 / 3 | **278 / 0 / 3** |
| aip-service | 38 | **38** |

`cargo clippy --workspace --all-targets -- -D warnings` and
`cargo fmt --all -- --check`: clean in both workspaces.

## Threat coverage

| Threat | Mechanism | Test | Status |
|---|---|---|---|
| PID reuse within a boot transfers attribution (I4) | `pid_start_time_ticks` in identity | A, §14 guard | covered (identifier level) |
| PID reuse across reboot (I4) | `boot_id` in identity | B | covered |
| Binary replaced at same path (I2) | content hash via `/proc/<pid>/exe` | C, live test | covered |
| Path spelling used as identity (I2) | `exe_path` excluded from `identity_bytes` | D | covered |
| Encoding collision / type confusion (I14) | length prefixes + two domain tags | E | covered |
| Post-sealing binding mutation / transplant | R3/R4 over canonical bytes | F, G | covered |
| Binding for another agent, or empty binding, presented as valid | R15 | resealed-other-agent, degenerate | covered |
| Absence silently equal to presence | presence byte | presence, legacy-JSON | covered |
| Missing facts fabricated | `BindingError`, no defaults | parser rejections, nonexistent PID | covered |
| **Agent lies about its own binding** | — | H (documents acceptance) | **NOT covered — Stage 3** |
| Network 4-tuple / hostname / process name as identity | not representable in the type; documented prohibition | — | excluded by design |

## Known limitations

See `EXECUTION_BINDING.md` §7. In one line each: self-report only; sub-tick
PID recycling residual; binary image ≠ behaviour (interpreters, injected
code); Linux only; no namespace/cgroup context yet; binding added inside
unreleased v2 rather than a v3 bump.

## Remaining dependencies

- **Stage 2 — Decision Point** (`syntriass-decision-point`): `ExpectedExecution`
  must embed an `ExecutionBinding` and be signed by a party the agent does not
  control. It consumes `identity_bytes` as the join key; it must not re-derive
  identity from PID.
- **Stage 3 — Observer**: closes the self-report gap by collecting and signing
  a binding from outside the agent's trust boundary. May reuse
  `parse_proc_stat_start_time`, `parse_boot_id`, `hash_file_contents`.
- **Stage 4 — Reconciliation**: joins on `decision_id` +
  `execution_identity_digest`; absent observer binding → `CANNOT_PROVE`.

## Gate decision

Skill 4 completion criteria (§28) are met as evidenced above. The repository
is **ready for SKILL 5 — DECISION POINT**, subject to explicit authorization.
Skill 5 must consume `ExecutionBinding` / `identity_bytes` as-is and must not
re-derive identity from PID, path, or network identifiers.

## Security claims that remain prohibited after this stage

Do not claim, on the basis of this stage: process attribution, independent
observation, that an execution occurred, that the executable is trusted, that
PIDs are unique, or that the binding is tamper-*proof*. The correct statement
is: *the process-instance identity includes PID plus start-time and boot
context, so PID reuse is not treated as the same execution under the
documented platform assumptions; executable identity is derived from
executable contents and therefore detects content replacement under the
SHA-256 assumption; the binding is agent-signed content and, until an
independent observer attests it, a self-report.*
