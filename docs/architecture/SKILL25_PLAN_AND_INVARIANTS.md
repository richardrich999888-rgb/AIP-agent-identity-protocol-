# Skill 25 — Plan and Invariant Matrix

**Specification** `.claude/skills/25-industrial-critical-edge-accountability-profile/SKILL.md`
**Baseline** `12767ea`
**Branch** `claude/skill-25-implementation-xbz0t3`
**Related** ADR-008, ADR-009, `INDUSTRIAL_CRITICAL_EDGE_PROFILE.md`,
`docs/audit/SKILL25_EVIDENCE_REPORT.md`

---

## 1. Specification, restated

The authoritative specification is the file named above. It is the only Skill 25
document in the repository and is byte-identical on
`claude/codebase-production-readiness-wm6idp` and
`claude/autonomous-accountability-skills-16-30`. There is no second Skill 25 to
reconcile.

It requires five objects, protocol adapters, a coverage model, override
semantics and four adversarial scenarios; it names three non-negotiable rules;
and its acceptance gate has two clauses.

## 2. Implementation map

| requirement | file / symbol | existing implementation | gap Skill 25 closed | test | mutation | deliverable |
|---|---|---|---|---|---|---|
| `IndustrialCommand` | `command.rs::IndustrialCommand` | `ScopeAction::Custom` + `ActionParameters` (Skill 18) | no industrial action vocabulary; no point-address commitment | `command::tests` (13), `adversarial::a10/a14/a19` | M9 | 18 commands under `ics.`, device+space+point+value+unit committed |
| `ControlLoopExecution` | `controlloop.rs::ControlLoopExecution` | `SystemExecution`, `ExpectedExecution.parameter_digest` | no control-loop commitment; no command freshness | `controlloop::tests` (13), `adversarial::a2/a3/a4` | M6 | committed document + `CommandFreshness` |
| `ProtocolInteraction` | `protocol.rs::ProtocolInteraction` | none | no representation of an industrial exchange; nothing stopping a response code being read as evidence | `protocol::tests` (8), `adversarial::a1/a12/a20` | M1, M9 | 9 protocols, 3 adapters, ceiling from mechanism only |
| `SafetyBoundary` | `safety.rs::SafetyBoundary` | none | safety configuration was not a commitment | `safety::tests` (10), `adversarial::a11/a21` | M7 | signed document, own key + discriminant |
| `PhysicalProcessEffect` | `process.rs::PhysicalProcessEffect` | `ObservationClass::PhysicalEffect` (declared, unimplemented) | no per-claim statement of what a plant claim needs | `process::tests` (7), `adversarial::a22` | M12 | 8 claims, 9 measurements, all unestablishable |
| edge protocol adapters, none trusted | `protocol.rs::ProtocolAdapter` + 3 impls | none | — | `protocol::tests`, `no_second_architecture::no_protocol_is_marked_trusted...` | M9 | trait with no ceiling and no trust surface |
| coverage for compute / network / process state | `coverage.rs` | `ObservationProfile` (Skill 20), `SignedSensorHealth` (Skill 20 + `12767ea`) | classes were not grouped into the domains a plant reasons about | `coverage::tests` (9), `adversarial::a5/a6/a8/a9/a13`, `integration::the_live_run_projects...` | M4, M11 | `CoverageDomain`, `class_domain` total, non-occurrence gate |
| operator / manual override in lineage | `operator.rs` | `AuthorityContext`, `Completeness` | no override vocabulary; nothing stopping "an operator did it" closing a divergence | `operator::tests` (7), `adversarial::a16/a17/a18` | M5 | 7 kinds, attribution rule, `excuses_divergence() == false` |
| replay scenario | — | `Scenario::ReplayedObservation` (Skill 22) | profile-level replay semantics | `adversarial::a1/a2`, `integration::a_replayed_observation...` | M1, M6 | protocol-level + commitment-level + live |
| stale-command scenario | `controlloop.rs::admit_at` | none | — | `adversarial::a3/a4` | M6 | refusal, not a weak finding |
| sensor-gap scenario | `coverage.rs` | `Completeness` (Skill 20) | — | `adversarial::a5/a6` | M4 | `NotObservable` vs `NotObserved` |
| observer-outage scenario | — | `Scenario::ObserverLost` (Skill 22) | profile-level degradation | `adversarial::a7/a8`, `integration::observer_loss...` | M4 | degrade, never accuse |
| containment warrant-controlled and fail-safe | `containment.rs` | `aip-warrant`, `aip-containment` | nothing said compute containment is not process containment | `containment::tests` (5), `adversarial::a23`, `integration::containment_of_an_industrial...` | M10 | 2 scopes, both warranted, neither safe |

## 3. Invariant matrix

Each invariant names where it is enforced, the test that pins it, and the
mutation that proves the test is load-bearing. **A mutation column entry means
the mutation was applied, the crate compiled, and the named test failed.**

| # | invariant | enforced at | pinned by | mutation |
|---|---|---|---|---|
| I1 | A protocol interaction never establishes a physical process change, for any protocol, response or authentication state | `protocol.rs::establishes_process_change` | `no_protocol_interaction_establishes_a_process_change`, `a20` | M1 |
| I2 | An interaction's ceiling is a function of the observation mechanism and of nothing about the protocol | `protocol.rs::evidence_ceiling` | `the_ceiling_is_a_function_of_observation_and_not_of_protocol`, `a12` | M1 |
| I3 | An adapter may only lower an authentication claim | `protocol.rs::ProtocolAdapter::interaction` | `an_adapter_cannot_claim_authentication_a_protocol_does_not_define` | M9 |
| I4 | Only a negotiated cryptographic session distinguishes a replay | `protocol.rs::replay_distinguishable` | `only_a_negotiated_cryptographic_session_distinguishes_a_replay`, `a1` | — |
| I5 | Agreement never raises a ceiling, for any count | `corroborate.rs::ceiling_after_agreement` | `agreement_never_raises_the_ceiling`, `all_three_verticals_refuse_to_raise_a_ceiling_on_agreement` | M2 |
| I6 | A conflict is reported, never resolved | `corroborate.rs::classify`, `is_resolvable` | `a_two_out_of_three_vote_is_still_a_conflict` | — |
| I7 | A state claim may only echo or weaken | `state.rs::LoopState::assertable` | `assertable_never_strengthens_or_substitutes`, `all_three_state_models_may_only_echo_or_weaken` | M3 |
| I8 | The physical evidence tier is unreachable | `state.rs::ProcessEvidence::is_reachable` | `every_plant_state_is_unreachable`, `all_three_verticals_agree_the_physical_tier_is_unreachable` | M3 |
| I9 | A command outside its window is refused, not weakened | `controlloop.rs::admit_at` | `a_stale_command_is_refused_rather_than_weakened`, `a3`, `a4` | M6 |
| I10 | A safety-boundary commitment never establishes enforcement | `safety.rs::enforcement_establishable` | `a_boundary_commitment_never_establishes_enforcement`, `a21` | M7 |
| I11 | The boundary commitment and the control-loop commitment are distinct | `safety.rs` / `controlloop.rs` parameter keys + discriminants | `a11`, `the_three_domain_tags_and_parameter_keys_are_distinct` | — |
| I12 | An unmechanised source is capped at `Corroborative`, independent or not | `sensing.rs::ceiling` | `every_unmechanised_source_is_capped_at_corroborative`, `an_independent_source_with_no_mechanism_is_also_capped` | M8 |
| I13 | No source claims the physical-effect class | `sensing.rs::observation_class` | `no_source_claims_the_physical_effect_class` | — |
| I14 | No plant claim is establishable from any measurement | `process.rs::establishable_from_measurement` | `no_process_claim_is_establishable_from_measurement_in_this_build`, `a22` | M12 |
| I15 | An override never excuses a divergence | `operator.rs::excuses_divergence` | `no_override_ever_excuses_a_divergence`, `a17` | M5 |
| I16 | An unattributed override is never authority | `operator.rs::accepted_as_authority` | `an_unattributed_override_is_refused_as_authority`, `a16` | — |
| I17 | The process-state domain never supports a non-occurrence claim | `coverage.rs::can_support_non_occurrence` | `process_state_is_never_observable...`, `a13` | M11 |
| I18 | Non-occurrence requires an observer whose signed health vouches — so `IntegrityUnknown` cannot license it | `coverage.rs::non_occurrence_admissible` | `an_observer_with_unknown_integrity_cannot_support_a_non_occurrence_claim`, `a8`, `a9` | M4 |
| I19 | A lone perf-tracepoint mechanism does not make a domain gate-independent | `coverage.rs::from_sources` | `a_gate_able_mechanism_alone_does_not_make_a_domain_gate_independent`, `a6` | — |
| I20 | The projection into `ObservationProfile` cannot raise a ceiling | `coverage.rs::observation_profile` | `the_projection_cannot_raise_a_ceiling` | — |
| I21 | Compute containment never restores a safe process state | `containment.rs::restores_process_safe_state` | `containment_never_establishes_a_safe_process_state`, `a23` | M10 |
| I22 | Every containment scope requires a warrant | `containment.rs::requires_warrant` | `every_scope_requires_a_warrant`, `containment_of_an_industrial_execution_stays_on_the_existing_warrant_path` | — |
| I23 | The verifier distinguishes command execution from process confirmation | `profile.rs::execution_versus_confirmation` | `the_acceptance_gate_distinction_holds_for_every_deployment`, `a_live_edge_node_establishes_its_execution_and_nothing_about_a_plant` | — |
| I24 | The profile forks no core type, mints no identifier, holds no key, builds no observation record, adds no proof tree, defines no reconciler or verifier | crate structure | `no_second_architecture.rs` (12 tests) | — |
| I25 | The three verticals answer the shared questions identically | three crates | `cross_vertical.rs` (12 tests) | M2, M3, M8 |

## 4. Frozen architecture — what Skill 25 did not touch

No file outside `aip-standalone/aip-industrial/` was modified except the
workspace member list and `Cargo.lock`. In particular: the identity, authority
and delegation model; `SystemExecution`; `ExpectedExecution`; `RuntimeAction`;
`PlatformBinding`; `ObservationProfile`; `ObservationRecord`; `EvidenceCeiling`;
`EffectAssessment`; the reconciler; NEXORA; AIRI; the Sniffer Dog observation
semantics; the observation-integrity mitigation from `12767ea`; and the Skill 24
robotics profile — including its own `cross_vertical.rs`, left as it shipped
(ADR-009).

## 5. What was deliberately not built

- **No shared profile kit.** ADR-009 records why, on evidence the third
  vertical produced.
- **No `SourceMechanism` variant** for a transmitter, meter or actuator
  feedback. ADR-003's schema-fork argument, third application.
- **No payload parser.** A payload read off the subject's own network is the
  subject's account of the payload.
- **No signed encoder in `aip-types`.** `ProcessLimit` bit-casts through the
  existing `put_u64`; the shared canonical vocabulary is unchanged.
- **No second reconciler, verifier, evidence hierarchy, identity framework,
  proof tree, custody system or containment path.**
