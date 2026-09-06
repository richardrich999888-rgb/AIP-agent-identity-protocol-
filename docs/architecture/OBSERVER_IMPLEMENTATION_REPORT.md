# OBSERVER IMPLEMENTATION REPORT

Skill 6 (`syntriass-observer-attestation`) / Orchestrator Stage 3.

## 1. Implementation status

**PASS** under Skill 6 §27, with the coverage and TCB limitations in §13
recorded as limitations rather than resolved. Nothing here claims kernel-level
sensing, root resistance, or that any observation is true.

| Requirement (§27) | Status |
|---|---|
| observer architecture exists | yes — `aip-observe`, probe/collector split |
| independent trust root exists | yes — key held by `CollectorSigner`, structurally unreachable from the host-side types |
| `ObservedExecution` is signed | yes — inside an attested batch |
| signature verification implemented | yes — `verify_attested_batch`, `verify_signed_health` |
| domain separation | yes — five new tags, pairwise-distinct test |
| `ExecutionBinding` incorporated | yes — `ObservedProcess::matches_process_of` against a Stage 1 binding |
| continuity explicit | yes — `ObserverLedger`, six fault kinds |
| degradation explicit | yes — five `ObserverState` values |
| replay addressed | yes — ledger sequence + head; a valid signature is never freshness |
| key identity/version represented | yes — `key_version` in every preimage; anchors keyed on `(observer_id, key_version)` |
| observation availability explicit | yes — `ObservationAvailability` with typed reasons |
| adversarial tests pass | yes — 42 tests |
| no authorization logic in the observer | yes — tested structurally |
| no containment logic | yes — no actuation of any kind exists |
| no NEXORA | yes |

Baseline: HEAD `01a119f` (Skill 5 PASS), working tree clean.
Predecessors treated as evidence only for what they state; every limitation
they list is preserved and re-stated in §13.

## 2. Architecture

```text
   OBSERVED HOST (attacker reach)              OFF-HOST COLLECTOR
   ─────────────────────────────────           ────────────────────────────────
   ProcfsProbe                                 CollectorSigner
     · reads /proc/<pid>/stat, exe               · holds the Ed25519 key
     · NO key, NO signing method                 · assigns sequence, prev_head
     · NO chain state                            · ObserverLedger enforces
     │                                             continuity
     │  ObservationBatch (unsigned,               · derives ObserverState
     │  no signature field)                       · signs AttestedBatch + health
     └──────────── transport ──────────────────▶  │
                                                  ▼
                                          AttestedBatch, SignedSensorHealth
                                                  │
                                                  ▼  offline
                                   verify_attested_batch(&anchors)
```

Files: `aip-standalone/aip-observe/src/{lib,observed,probe,attest,continuity,health}.rs`,
`tests/adversarial.rs`.

**What the split buys.** The probe is inside the attacker's reach and holds
nothing worth stealing. It cannot sign, cannot choose its position in the
chain, and cannot decide what coverage will be attested. The consequences of
each host-side attack are therefore bounded:

| Host-side attack | Consequence |
|---|---|
| kill the probe | sequence stops; collector's next health shows the gap; coverage does not extend |
| erase host state | nothing to erase that matters — sequence and head live at the collector |
| restore stale host state | `Rollback` or `HeadMismatch` at the collector, never silent resumption |
| replay a batch | `Replay` — refused; the signature verifying is not freshness |
| forge observations | possible, and attested as *received*; see §5 A4 |
| forge an attestation | not possible without the collector key |
| partition the network | health goes stale → `HealthStale` → `OBSERVATION_UNAVAILABLE` |

## 3. Trust root

**Decision: remote collector.** `OBSERVER_ATTESTATION.md` §3 listed five
candidate anchors, selected none, and recommended the remote collector for the
first slice; Skill 6 §5 prescribes it; this stage was explicitly authorized on
that basis. The deferred product decision is therefore now made and recorded.
The other candidates (TPM 2.0, TEE, hardware-backed local key) remain open for
a later slice and are **not** implemented — no quote verification, no PCR
policy, and no use of `evaluate_hardware_trust`, which remains the
structural-check-only function it always was.

The key lives in `CollectorSigner`. It enters through the constructor, is
redacted in `Debug`, and no type reachable from the observed host has a key
field. `verify_attested_batch_independent_of_agent` additionally refuses an
anchor whose key equals the observed agent's public key, so an operator who
mis-anchors cannot silently turn a self-report into evidence (I10).

**Deployment limitation.** The split is enforced in the type system, not by a
running daemon: there is no network transport, no collector binary, and no
provisioning. In this slice the collector is a library object that an operator
constructs in a separate process. The property "the agent cannot reach the
key" is structurally true of the code and is a deployment obligation in
practice.

## 4. Threat model

The attacker may, on the observed host: hold root; inspect, spawn and kill
processes; modify files and configuration; alter the host clock; kill or
restart the probe; exhaust buffers; reorder locally available events; erase or
roll back local state; and partition the host from the collector. All of these
are exercised as tests except buffer exhaustion, which has no buffer in this
slice (batches are caller-assembled).

## 5. Assumptions

| # | Assumption | If it fails |
|---|---|---|
| A1 | The collector's key is held off the observed host and its process is not compromised. | The whole layer collapses to a second self-report; this is the load-bearing assumption. |
| A2 | The collector's own clock is honest for `emitted_at_ms` and the AIP signature envelope timestamp. | Freshness judgements shift; ordering does not, because ordering comes from the sequence. |
| A3 | The verifier's anchors name the intended observer keys. | Same class of operator error as issuer anchors in `verify_packet`. |
| A4 | **The kernel of the observed host reports truthfully to the probe.** | A root-compromised host can feed the probe fabricated procfs content. The collector then attests *that it received those bytes*, which is true and is all it claims. Nothing in this slice detects it. |
| A5 | Ed25519 and SHA-256 hold. | Standard. |

**What root compromise defeats and does not defeat.** It defeats the *content*
of observations: A4 means a root attacker can make the probe report a process
that does not exist, or hide one that does. It does not defeat the
*attestation*: the attacker cannot sign, cannot rewrite history already at the
collector, and cannot make an outage look like coverage. The honest summary is
that this slice raises observation from "the agent says so" to "an
independently keyed party recorded receiving this, in this order, with these
gaps" — a real gain against a non-root agent and against post-hoc tampering,
and **no gain against root on the content axis**. Closing A4 requires kernel
instrumentation (eBPF/LSM) that Skill 6 does not authorize here.

## 6. Key lifecycle

| Phase | Status |
|---|---|
| Generation | operator-supplied Ed25519 key pair to `CollectorSigner::new` |
| Key version | `u32`, inside every signed preimage |
| Rotation | `rotate_key(new_version, ..)`; verifiers anchor both versions so history stays verifiable — tested |
| Revocation | `ObserverTrustAnchors::revoke(observer_id, version)` — tested |
| Provisioning / distribution of anchors | **NOT IMPLEMENTED** |
| Storage / custody at the collector | **NOT IMPLEMENTED** — in-memory `Vec<u8>`, `Debug` redacted |
| Expiry | **NOT IMPLEMENTED** — no key validity window |
| Key loss / compromise recovery | **NOT IMPLEMENTED** — an operator re-provisions a new `observer_id` or version |
| Collector restart | **NOT IMPLEMENTED as persistence** — the ledger is in memory, so a collector restart loses the chain and the next batch is `NewEpochUnverified`, i.e. `CONTINUITY_UNVERIFIED`, never a silent resumption |

The protocol carries key identity and version, as Skill 6 §16 requires, so the
unimplemented phases can be added without a wire break.

## 7. Continuity model

Continuity binds previous sequence, previous head, current sequence, observer
identity, key version and protocol version — all inside the signed preimage.
The ledger lives at the collector, which is the point: a state file the
attacker can roll back proves nothing about itself.

```text
head(n)  = SHA-256( domain ‖ version ‖ observer_id ‖ key_version
                    ‖ sequence ‖ prev_head ‖ batch_bytes )
prev_head(n) = head(n-1)
```

| Offer | Ledger result |
|---|---|
| next sequence, matching head | `Continuous` → `Verified` |
| skipped sequence, matching head | `AdmittedWithGap` → `GapObserved` (never erased by later contiguity — tested) |
| first batch of a run | `NewEpochUnverified` → `Unverified`; a first batch links to nothing this collector witnessed |
| same sequence, same head | `Replay` — refused |
| same sequence, **different** head | `Fork` — arithmetic proof of integrity failure → permanent quarantine |
| lower sequence | `Rollback` |
| `prev_head` ≠ recorded head | `HeadMismatch` |

`note_probe_restart()` moves the observer to `Recovering` and drops attested
coverage. The first contiguous batch afterwards starts a **fresh** coverage
epoch and does not back-fill the outage — tested.

## 8. Failure semantics

Every listed failure becomes an explicit state or a typed error; none becomes
a statement about the workload.

| Failure | Representation |
|---|---|
| probe killed / restarted | `ObserverState::Recovering`, coverage dropped |
| telemetry drop / sequence gap | `Degraded`, `GapObserved` |
| state rollback | `ContinuityFault::Rollback` / `HeadMismatch` |
| sequence discontinuity | `Gap`, coverage not extended |
| collector unavailable / partition | health goes stale → `UnavailableReason::HealthStale` |
| signature failure | `VerifyError::SignatureInvalid` |
| untrusted or revoked key | `VerifyError::UntrustedObserverKey` — distinct from crypto failure |
| observer key is the agent's key | `VerifyError::ObserverKeyIsAgentKey` |
| malformed procfs | `ProbeError::Unavailable` / `ProcessNotVisible`; never a panic, never a substituted weaker identifier |
| unsupported protocol version | `VerifyError::UnsupportedVersion`, `AttestError::UnsupportedVersion` |
| integrity failure proven | `ObserverState::Quarantined`; the signer refuses to attest again |

## 9. Signed structures

| Structure | Contents | Signed by |
|---|---|---|
| `ObservedExecution` | version, probe_id, `ObservedProcess`, `AgentAttribution`, `ObservedEffect`, optional claimed decision id, host wall clock, probe monotonic position | (inside a batch) |
| `ObservationBatch` | version, probe_id, batch_id, claimed window, observations | **unsigned by construction** |
| `AttestedBatch` | version, observer_id, key_version, sequence, prev_head, batch | collector |
| `SensorHealth` | version, observer_id, key_version, state, continuity, sequence, head, last batch id, attested coverage, emitted_at | collector |

`ObservedProcess` holds only what the observer measured: process instance
(pid, start ticks, boot id) and executable content hash, plus the path as
context. `identity_bytes` excludes the path.

`AgentAttribution` has exactly two variants — `NotEstablished` and
`Claimed { agent_id, claim_source }`. The observer reads the kernel; it cannot
establish an AIP-ID, because that requires proof of key possession, which is
an authority question. There is no `Verified` variant and there must never be.

The chain head is **computed** from the preimage, never carried as a field, so
there is no supplied hash a verifier could be tricked into trusting
(Skill 6 §8).

## 10. Domain separation

`SYNTRIASS/GHOST/OBSERVED_EXECUTION/v1`, `/OBSERVATION_BATCH/v1`,
`/OBSERVED_PROCESS/v1`, `/OBSERVER_HEAD/v1`, `/OBSERVER_HEALTH/v1` — all
length-prefixed and first in their preimage, using the single canonical
encoder from Stage 0 (`aip_types::canonical`); no second encoder was created.
Pairwise distinctness against the Stage 0/1 tags is tested, and a health
signature transplanted onto a batch (and the reverse) is rejected.

## 11. Test inventory

42 tests: 16 unit (`observed`, `health`, `continuity`, `probe`) and 26
adversarial (`tests/adversarial.rs`).

| Skill 6 §21 item | Test |
|---|---|
| 1 observer signature mutation | `signature_mutation_and_signer_mismatch_are_distinct` |
| 2 observed payload mutation | `every_attested_field_mutation_is_detected` (19 fields incl. dropped and duplicated observations) |
| 3 observer identity mutation | same, `identity_scoped` branch |
| 4 sequence rollback | `sequence_rollback_is_refused_and_a_fork_quarantines` |
| 5 sequence replay | `replayed_attestation_is_not_a_new_observation` |
| 6 continuity gap | `a_sequence_gap_degrades_coverage_and_does_not_backfill` |
| 7 observer restart | `observer_restart_is_not_continuous_coverage` |
| 8 stale state restoration | `stale_state_restoration_cannot_reconstruct_continuity` |
| 9 collector partition | `collector_partition_produces_unavailability_not_a_verdict` |
| 10 key unavailable to agent | `the_observed_agent_cannot_forge_an_accepted_attestation`, `the_probe_holds_no_key_and_cannot_produce_a_signature` |
| 11 no authorization injectable | `no_authorization_concept_exists_in_an_observation`, `an_injected_decision_id_confers_nothing` |
| 12 PID reuse | `pid_reuse_cannot_transfer_an_observation`, `matching_a_process_never_matches_an_agent_identity` |
| 13 absence ≠ PHANTOM_CLAIM | `absence_of_observation_never_becomes_a_claim_about_execution` |
| 14 domain confusion | `domain_tags_are_distinct_and_lead_every_preimage`, `a_health_signature_cannot_be_replayed_as_a_batch_attestation` |
| 15 canonical encoding mutation | `observation_encoding_is_injective_across_adjacent_strings`, `sha256_of_preimage_is_the_head_and_is_never_carried` |
| 16 key-version mismatch | `key_version_mismatch_and_rotation_and_revocation` |

Skill 6 §22 property tests: input ≠ signature control
(`the_observed_agent_cannot_forge_an_accepted_attestation`); absence ≠
non-execution (`absence_of_observation_never_becomes_a_claim_about_execution`);
attestation ≠ authorization (`no_authorization_concept_exists_in_an_observation`);
restart ≠ continuous coverage (`observer_restart_is_not_continuous_coverage`).

Also: `health_field_mutation_is_detected`, `unsupported_protocol_version_is_refused`,
`collector_constructor_rejects_bad_material`, `malformed_procfs_input_never_panics`,
`a_quarantined_ledger_refuses_all_later_batches`,
`attested_batch_verifies_offline_and_chains` (JSON round-trip),
`probe_measures_a_real_process_and_matches_stage_one_binding` (a live procfs
measurement that agrees with Stage 1's self-collector for the same process).

## 12. Adversarial test results

| Suite | Before Stage 3 | After |
|---|---|---|
| aip-observe (new) | — | **42** |
| aip-authorize / aip-core / aip-crypto / aip-types / aip-protocol / aip-test / aip-real-tests | 35 / 140 / 8 / 5 / 46 (1 ign) / 13 / 67 (2 ign) | unchanged |
| **aip-standalone total** | 314 / 0 / 3 | **356 / 0 / 3** |
| aip-service | 39 / 0 | **39 / 0** |

Skills 3–5 tests are unmodified and passing, including the two Skill 5
characterization tests that pin the self-authorization loop and the three
Skill 4 tests that pin the `RuntimeBinding` weakness.
`cargo clippy --workspace --all-targets -- -D warnings` and
`cargo fmt --all -- --check` clean in both workspaces.

## 13. Known limitations

1. **A4 is the big one.** Against root on the observed host, procfs content is
   attacker-controlled. The collector attests receipt and order, not truth.
2. **Polling, not eventing.** A process that starts and exits between
   measurements is never seen. Coverage of an interval means "the collector
   attested a contiguous chain across it", not "every event in it was
   captured". No eBPF, LSM, netlink, or perf_event path exists.
3. **No network, filesystem or syscall observation.** `ObservedEffect` has two
   process-lifecycle variants only. Adding a network variant must keep
   metadata and application payload distinct (I23).
4. **No transport or daemon.** Library only; no collector binary, no
   authenticated channel, no batching policy.
5. **Collector ledger is in memory.** A collector restart yields
   `CONTINUITY_UNVERIFIED` rather than false continuity — honest, but it means
   long-run continuity needs durable collector state, which is not built.
6. **Agent attribution is a claim.** The observer cannot bind a process to an
   AIP-ID. Reconciliation must treat the linkage accordingly.
7. **Host wall clock is contextual only.** Ordering comes from the collector
   sequence. There is no trusted time source (I21).
8. **Key lifecycle largely NOT IMPLEMENTED** (§6).
9. **`ObservedProcess::matches_process_of` is a process-identity predicate,
   not a reconciliation verdict.** It is offered so Stage 4 does not re-derive
   the rule; it emits no result class.

## 14. Unresolved risks

- **Collector compromise** is now a single point of failure: whoever holds the
  key can forge history wholesale. No threshold signing, no external
  anchoring, no cross-collector agreement exists. Anchoring the head externally
  is NEXORA's problem (Stage 9) and is deliberately not solved here.
- **A4 plus polling** means an attacker who controls the host can produce a
  clean, fully-attested, continuous chain that describes a fiction. The
  attestation is honest about what it covers; a reader who mistakes "attested"
  for "true" will be wrong. This must be stated wherever observations are
  surfaced.
- **Anchor distribution** is unsolved; a verifier that accepts anchors from an
  untrusted channel inherits the Stage 0 caller-supplied-anchor hazard.
- **Coverage semantics are conservative but coarse.** Coverage is a single
  window per observer; per-subject or per-namespace coverage is not modelled.

## CANNOT_PROVE cases

| Situation | What the observer can say | What remains unprovable here |
|---|---|---|
| Batch verifies | the trusted observer signed these bytes at this position | that the observations are true (A4) |
| Observation present, `Active`, window covered | the observer recorded this process fact and can vouch for the interval | that the action was authorized, or that the agent behind it is the claimed one |
| No observation in a covered window | nothing was recorded in what the observer saw | **not** that nothing executed (I8) |
| Any non-`Active` state | the observer cannot vouch for the window | anything about execution — `OBSERVATION_UNAVAILABLE` |
| Health stale / partition | coverage cannot be established | non-execution, and any verdict |
| `AgentAttribution::Claimed` | the claim was made and is sealed | that the claim is true |
| `NotEstablished` | a process was measured, unattributed | which agent, if any, it belongs to |
| Fork proven | the observer's integrity failed | anything about the workload |
| Process no longer present | the observer's next measurement did not find the instance | when or why it ended, or what it did |

## Prohibited security claims after this stage

Do not claim: kernel-level or eBPF observation; network visibility of any
kind; that an observation proves an action occurred; that an unobserved window
proves non-execution; continuous observation beyond an attested contiguous
chain; root resistance on the content axis; hardware or TEE attestation;
tamper-proof observation; trusted time; process attribution to an AIP
identity; any reconciliation result class; warrants; containment; NEXORA
commitments; post-quantum security.

Correct statement: *an independently keyed collector, whose key the observed
agent cannot reach, attests which observation bytes it received from a
host-side probe, in what order, and over which intervals its own continuity
was verified; the truth of those observations depends on the observed host's
kernel, and coverage gaps are reported explicitly as OBSERVATION_UNAVAILABLE
rather than inferred away.*

## Gate decision

Skill 6 §27 is satisfied. Ready for **SKILL 7 — RECONCILIATION**, subject to
explicit authorization. Reconciliation must consume `AttestedBatch` +
`SignedSensorHealth` + `ExpectedExecution` + `EvidencePacket`, join on
`decision_id` and process identity, default to `CANNOT_PROVE`, and must not
emit `PHANTOM_CLAIM` without attested coverage of the exact window.

## Gate 2 note — the device-layer tap

`aip-observe/src/wiretap.rs` (GREEN `57849bd`) adds a seventh mechanism,
`SourceMechanism::WireTapAfPacket`: an `AF_PACKET` `SOCK_DGRAM` socket on
one device or all, `SO_TIMESTAMPNS` for the kernel's realtime capture stamp,
`PACKET_STATISTICS.tp_drops` (plus truncated and unstamped frames) as the
loss counter, `CAP_NET_RAW` as the only privilege. `parse_wire_frame` keeps
TCP/IP headers only and refuses everything else; the event kind
`KernelLifecycleKind::WireSegment` has no pid, is never bound and is never
attributed, whatever claims the probe holds. The probe still holds no key;
the registry still decides which probe may claim the mechanism. Evaluation
and decision: `OBSERVATION_MODEL.md` §5. Tests: `tests/wiretap.rs`.
