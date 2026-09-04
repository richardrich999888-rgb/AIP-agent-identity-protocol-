# GAP_MATRIX

Commit `377d5fc`. Priorities per skill §21:
**P0** security correctness · **P1** architectural dependency ·
**P2** production hardening · **P3** performance · **P4** research.

## A. AIP correctness (must precede any Ghost work)

| Component | Current state | Target state | Gap | Dependency | Pri |
|---|---|---|---|---|---|
| Token/delegation expiry integrity | `expires_at` absent from both signing payloads (`capability.rs:208`, `delegation.rs:369`); read by R10 (`verification.rs:495,497`) | expiry covered by issuer signature | agent extends its own authority window; all 14 rules pass, `tampered=false` | none — fix pattern already exists at `aip-core/src/lib.rs:135-142` | **P0** |
| `aip-core` canonical encoding | non-injective; unprefixed string concat (`delegation.rs:381-382`) | length-prefixed via `aip-protocol/src/canonical.rs` | one signature valid for two distinct tokens (**I14**) | batch with expiry fix (one wire break) | **P0** |
| Domain separation | absent in every signed preimage (`aip-crypto:151-162`) | type tag per signed object | new Ghost types confusable with packets/tokens | canonical encoder | **P0** |
| Authorization decision point | **does not exist**; `/v1/evidence/generate` seals caller assertions using a caller-supplied private key (`evidence.rs:130,220-300`) | adjudicating decision point emitting signed `ExpectedExecution` | agent is sole authority for its own execution (**I1**) | expiry + encoder fixes | **P0** |
| Service verify trust anchors | caller supplies `trusted_issuers` (`evidence.rs:161,307-309`) | documented as calculator; never an authority | self-authorization loop if consumed as a decision (**I19**) | doc + type-level separation | **P0** |
| Packet replay | no seen-set; same packet verifies forever | explicit replay oracle in `VerificationContext` | replayed evidence indistinguishable | none | **P1** |
| Absolute expiry | R10 never consults a clock; `is_token_expired` uncalled | optional `ctx.verification_time` | expired-years-ago token verifies | expiry fix | **P1** |
| `aip-service` duplicate authority engine | unsigned tokens, no attenuation at issuance, no expiry check, different `Action` enum (`aip-service/src/{delegation,capability}.rs`) | deleted; route through `aip-core` | two security models; log write ⇒ privilege escalation (**I18**) | — | **P1** |
| Private keys at rest | plaintext JSON, `Debug`+`Serialize` on `KeyPair` (`aip-types:25-30`, `store.rs:149-151`) | `serde(skip)`, custom `Debug`, 0600, zeroize | key disclosure | — | **P1** |
| `validate_aip_id` panic | byte-index slice on `&str` (`aip-crypto:81-82`), reachable from JSON | char-boundary safe | authenticated request abort | — | **P1** |

## B. Ghost prerequisites

| Component | Current state | Target state | Gap | Dependency | Pri |
|---|---|---|---|---|---|
| `ExpectedExecution` | **MISSING** (0 occurrences) | signed pre-execution authorization record | no "expected" side of reconciliation | decision point (P0) | **P0** |
| `ExecutionBinding` | **MISSING**; `RuntimeBinding` is self-reported, unwired, path-hashed | agent ↔ process-instance binding in signed evidence | cannot attribute execution to an agent (**I2**) | canonical encoder, packet version bump | **P0** |
| Process instance identity | `pid` only (`runtime.rs:40`); no start time, no boot id | `(pid, pid_start_time, boot_id)` | PID reuse transfers attribution (**I4**) | ExecutionBinding | **P0** |
| Executable identity | `sha256(path_string)` (`runtime.rs:41-44`) | `sha256(binary contents)` | different binary, same path, same hash | ExecutionBinding | **P0** |
| Observer | **MISSING** (0 files: ebpf/XDP/perf_event/procfs/netlink) | independent runtime observer | no observation of any kind | binding + attestation | **P1** |
| `ObserverAttestation` | **MISSING** | trust root not held by observed agent | observation would be a second self-report (**I10**) | anchor decision (open) | **P0** for design, **P1** to build |
| Sensor health / continuity | **MISSING** | 5 explicit states, signed | silence indistinguishable from coverage (**I9**) | observer | **P1** |
| Reconciler | **MISSING** (0 occurrences) | join on `decision_id` + binding | no comparison exists | both producers | **P1** |
| `OBSERVATION_UNAVAILABLE` semantics | **MISSING** | first-class type, `CANNOT_PROVE` default | risk of inferring non-execution from silence (**I8**) | reconciler | **P0** for design |
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
