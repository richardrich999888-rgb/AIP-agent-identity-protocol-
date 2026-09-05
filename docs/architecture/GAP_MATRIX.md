# GAP_MATRIX

Discovered at commit `377d5fc`. Priorities per skill §21:
**P0** security correctness · **P1** architectural dependency ·
**P2** production hardening · **P3** performance · **P4** research.

Status updates (rows marked **CLOSED** / **PARTIAL** below keep their
original discovery text for traceability):

- Stage 0 (Skill 3) closed at `830c1e5`…`f78a599` — see
  `AIP_CORRECTNESS_REPORT.md`.
- Stage 1 (Skill 4) closed at `4ff1f5c` — see
  `EXECUTION_BINDING_IMPLEMENTATION_REPORT.md`.
- Stage 2 (Skill 5) — library decision point `aip-authorize`; see
  `DECISION_POINT_IMPLEMENTATION_REPORT.md`.
- Stage 3 (Skill 6) — observer/collector split `aip-observe`; see
  `OBSERVER_IMPLEMENTATION_REPORT.md`.
- Stage 6.5 (Sniffer Dog) — kernel-mediated sources and provenance gating in
  `aip-observe` (protocol v2); see `SNIFFER_DOG.md` and
  `SNIFFER_DOG_IMPLEMENTATION_REPORT.md`.
- PR3 corrective review — see `PR3_GAP_REVIEW.md`; three MUST-FIX items
  closed (section D below); reconciliation readiness decided.

## D. PR3 corrective review (pre-reconciliation)

| Component | Found | Fix | Pri |
|---|---|---|---|
| `wellknown::verify_delegation_with_jwks` — **CLOSED** | verified the signature envelope only; a hop with rewritten `expires_at`/scope/grantee still verified (the Skill 3 attack through a public verifier) | recomputes the hop payload via `delegation::verify_delegation_token_signature`, shared with `verify_delegation_chain` | **P0** |
| `verify_ed25519` algorithm label — **CLOSED** | accepted any `Signature.algorithm`; an Ed25519 signature labelled `MlDsa65`/`Hybrid` verified (**I7**) | refuses non-Ed25519 labels with `EvolutionRequired` | **P0** |
| Per-mechanism coverage in signed health — **CLOSED** (observer protocol v3) | health stated *that* a window was covered, not *by which source*; `PHANTOM_CLAIM` would have required inferring kernel coverage from event presence (**I8**) | `ObservationBatch.active_mechanisms` (declared ∪ used, registry-bounded), `SensorHealth.covered_by` (intersection over the epoch), `covered_by_kernel_pushed_source()` | **P0** |
| Cross-crate domain-tag audit | no single test saw all 16 tags | `aip-test/src/domain_audit.rs` | — |
| Identity digests not byte-comparable across crates | `ExecutionBinding::identity_bytes` ≠ `ObservedProcess::identity_bytes` by design | documented: compare structurally via `matches_process_of` | E |
| `[u8;16]` identifiers indistinguishable by type | `decision_id`, `batch_id`, `probe_run_id`, `jti`, … | Skill 7 must introduce newtypes at its boundary | D |

## A. AIP correctness (must precede any Ghost work)

| Component | Current state | Target state | Gap | Dependency | Pri |
|---|---|---|---|---|---|
| Token/delegation expiry integrity — **CLOSED `830c1e5`** | `expires_at` absent from both signing payloads (`capability.rs:208`, `delegation.rs:369`); read by R10 (`verification.rs:495,497`) | expiry covered by issuer signature | agent extends its own authority window; all 14 rules pass, `tampered=false` | none — fix pattern already exists at `aip-core/src/lib.rs:135-142` | **P0** |
| `aip-core` canonical encoding — **CLOSED `830c1e5`** (encoder relocated to `aip_types::canonical`) | non-injective; unprefixed string concat (`delegation.rs:381-382`) | length-prefixed via `aip-protocol/src/canonical.rs` | one signature valid for two distinct tokens (**I14**) | batch with expiry fix (one wire break) | **P0** |
| Domain separation — **PARTIAL `830c1e5`** (all `aip-core` payloads tagged; packet/action/receipt payloads deferred to next wire bump) | absent in every signed preimage (`aip-crypto:151-162`) | type tag per signed object | new Ghost types confusable with packets/tokens | canonical encoder | **P0** |
| Authorization decision point — **PARTIAL (Stage 2)**: `aip-authorize::DecisionPoint` implemented as a library authority boundary with its own key and configured issuer anchors; deployment as a separate process and `/v1/evidence/generate` integration remain open | **does not exist**; `/v1/evidence/generate` seals caller assertions using a caller-supplied private key (`evidence.rs:130,220-300`) | adjudicating decision point emitting signed `ExpectedExecution` | agent is sole authority for its own execution (**I1**) | expiry + encoder fixes | **P0** |
| Service verify trust anchors — **PARTIAL `f78a599`** (documented as calculator; type-level separation pending decision point) | caller supplies `trusted_issuers` (`evidence.rs:161,307-309`) | documented as calculator; never an authority | self-authorization loop if consumed as a decision (**I19**) | doc + type-level separation | **P0** |
| Packet replay | no seen-set; same packet verifies forever | explicit replay oracle in `VerificationContext` | replayed evidence indistinguishable | none | **P1** |
| Absolute expiry — **DECIDED `f78a599`: no wall clock** (R10 semantics are explicit and offline relative to signed timestamps; see `AIP_CORRECTNESS_REPORT.md` "Verification-time semantics") | R10 never consults a clock; `is_token_expired` uncalled | optional `ctx.verification_time` | expired-years-ago token verifies | expiry fix | **P1** |
| `aip-service` duplicate authority engine | unsigned tokens, no attenuation at issuance, no expiry check, different `Action` enum (`aip-service/src/{delegation,capability}.rs`) | deleted; route through `aip-core` | two security models; log write ⇒ privilege escalation (**I18**) | — | **P1** |
| Private keys at rest — **PARTIAL `228b02e`** (custom `Debug` redacts; `Serialize` kept for `store.rs`; plaintext at rest remains) | plaintext JSON, `Debug`+`Serialize` on `KeyPair` (`aip-types:25-30`, `store.rs:149-151`) | `serde(skip)`, custom `Debug`, 0600, zeroize | key disclosure | — | **P1** |
| `validate_aip_id` panic — **CLOSED `14da5a8`** | byte-index slice on `&str` (`aip-crypto:81-82`), reachable from JSON | char-boundary safe | authenticated request abort | — | **P1** |

## B. Ghost prerequisites

| Component | Current state | Target state | Gap | Dependency | Pri |
|---|---|---|---|---|---|
| `ExpectedExecution` — **CLOSED (Stage 2)**: `aip-authorize::ExpectedExecution`, domain `GHOST/ExpectedExecution/v1`, signed `issued_at`/`valid_until`, embeds `ExecutionBinding`, offline-verifiable against `DecisionPointTrustAnchors` | **MISSING** (0 occurrences) | signed pre-execution authorization record | no "expected" side of reconciliation | decision point (P0) | **P0** |
| `ExecutionBinding` — **CLOSED `4ff1f5c`** as a self-reported, agent-signed binding in `EvidencePacket` (R15); independent attestation of it remains the Observer's gap | **MISSING**; `RuntimeBinding` is self-reported, unwired, path-hashed | agent ↔ process-instance binding in signed evidence | cannot attribute execution to an agent (**I2**) | canonical encoder, packet version bump | **P0** |
| Process instance identity — **CLOSED `4ff1f5c`** | `pid` only (`runtime.rs:40`); no start time, no boot id | `(pid, pid_start_time, boot_id)` | PID reuse transfers attribution (**I4**) | ExecutionBinding | **P0** |
| Executable identity — **CLOSED `4ff1f5c`** (contents of `/proc/<pid>/exe`) | `sha256(path_string)` (`runtime.rs:41-44`) | `sha256(binary contents)` | different binary, same path, same hash | ExecutionBinding | **P0** |
| Observer — **PARTIAL (Stage 3 → 6.5)**: keyless host probe with four provenance-tagged sources — procfs poll, pidfd-anchored instance reads, kernel netlink process-event connector (fork/exec/exit with kernel time; `ENOBUFS` loss surfaced), kernel socket tables (socket-level only). Still no eBPF/tracepoint/perf/XDP path; procfs *content* remains root-forgeable; polled sources still miss what happens between polls | **MISSING** (0 files: ebpf/XDP/perf_event/procfs/netlink) | independent runtime observer | no observation of any kind | binding + attestation | **P1** |
| `ObserverAttestation` — **CLOSED (Stage 3)**: anchor decided as *remote collector*; key held by `CollectorSigner`, structurally unreachable from host-side types; deployment as a separate process remains an operator obligation | **MISSING** | trust root not held by observed agent | observation would be a second self-report (**I10**) | anchor decision (open) | **P0** for design, **P1** to build |
| Sensor health / continuity — **CLOSED (Stage 3 → 6.5)**: five signed states, collector-side ledger with replay/fork/rollback/gap/head-mismatch faults; 6.5 adds probe run-id (restart), per-run sequence discontinuity and counted kernel event loss as explicit `Degraded` causes, and `probe_policy` in signed health; coverage never back-fills an outage, a loss, or a restart | **MISSING** | 5 explicit states, signed | silence indistinguishable from coverage (**I9**) | observer | **P1** |
| Reconciler | **MISSING** (0 occurrences) | join on `decision_id` + binding | no comparison exists | both producers | **P1** |
| `OBSERVATION_UNAVAILABLE` semantics — **PARTIAL (Stage 3)**: `ObservationAvailability::Unavailable{reason}` is a first-class type with seven typed reasons; the `CANNOT_PROVE` default belongs to the reconciler (Stage 4) | **MISSING** | first-class type, `CANNOT_PROVE` default | risk of inferring non-execution from silence (**I8**) | reconciler | **P0** for design |
| Warrant engine | **MISSING** | severity ⊥ strength; `Proven` gate | containment on suspicion (**I12**, **I13**) | reconciler | **P1** |
| Containment | **MISSING** (correctly) | proof-gated, advisory default | — | warrant engine | **P2** |

## C. Commitment / NEXORA

| Component | Current state | Target state | Gap | Dependency | Pri |
|---|---|---|---|---|---|
| Merkle primitives | `merkle_leaf/internal/empty` correct, domain-separated | reused as-is | none | — | — |
| Merkle **protocol** | **MISSING** — helpers called only from a test | tree, root over real set, inclusion proof | no commitment exists (**I15**) | verified executions | **P2** |
| Production commitment roots | all `merkle_empty()` (`aip-core/src/lib.rs:62,63,647`) | populated | roots are the empty hash | Merkle protocol | **P2** |
| Chain head anchoring | **MISSING** | signed, externally anchorable head | truncation undetectable | commitment log | **P2** |
| Audit chain | in-memory, unsigned, **no caller** (`scoped_audit.rs:154-156`) | signed, persisted, head-anchored — or deleted | dead code claiming a security property | decision: promote or remove | **P1** |
| NEXORA | **MISSING** from production; unmerged on PR #3 | portable commitment boundary | — | all of the above | **P2** |

## D. Out-of-tree

| Component | State | Disposition |
|---|---|---|
| `ot-sentinel` / NEXORA (PR #3) | **UNMERGED**, tree absent from HEAD | design input only (**I17**). Its two-axis warrant and sensor-attestation designs are worth harvesting |
| `aegis-quantum` XDP (`codex/val-ladder-sync`) | **UNMERGED**, 29 ahead / 22 behind, tree absent | design input only. Observes inbound packets on a bare 4-tuple with **no process identity** — cannot attribute, so cannot feed reconciliation unmodified |
| `aip-core::simulation` | shipped in `aip-cli` despite "not for production" doc (`lib.rs:11-14`) | feature-gate | **P2** |

## E. Test coverage gaps blocking confidence

| Missing test | Why it matters | Pri |
|---|---|---|
| mutate `expires_at`, re-seal, assert rejection | the P0 defect is currently unprovable by the suite | **P0** |
| canonical encoder injectivity / collision vectors | `canonical.rs` has **zero** tests | **P0** |
| PID-reuse attribution refusal | **I4** | **P0** (with binding) |
| `OBSERVATION_UNAVAILABLE` never yields `PHANTOM_CLAIM` | **I8** | **P0** (with reconciler) |
| suspicion cannot reach containment | **I12/I13** | **P1** |
| service: cross-tenant HTTP 401/403, revoked-JTI rejection | single auth guard has zero coverage | **P1** |
