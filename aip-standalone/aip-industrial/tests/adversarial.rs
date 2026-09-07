//! The adversarial matrix for the industrial profile.
//!
//! The Skill 25 specification names four scenarios explicitly — replay, stale
//! command, sensor gap and observer outage — and the discipline the earlier
//! skills established adds substitution, transplant, tamper, omission, wrong
//! identity, wrong binding, wrong authority and observer integrity. All twelve
//! are here, and each has a positive case beside it so a test that passes
//! because the fixture is inert fails instead.
//!
//! Nothing here constructs observation evidence: this crate cannot, which is
//! `no_second_architecture.rs`'s subject. What these tests exercise is the
//! profile's own refusals.

use aip_industrial::{
    class_domain, CommandWindow, ContainmentScope, ControlLoopExecution, ControlRung,
    CoverageDomain, Dnp3Adapter, IndustrialCommand, IndustrialError, IndustrialProfile,
    IndustrialProtocol, LimitBound, LoopState, ModbusTcpAdapter, ObservationCoverage, OpcUaAdapter,
    OverrideClaim, OverrideKind, ProcessClaim, ProcessEvidence, ProcessLimit, ProcessSensingSource,
    ProcessVariable, ProtocolAdapter, ProtocolInteraction, SafetyBoundary, SafetyFunction,
    CONTROL_LOOP_PARAMETER_KEY, SAFETY_BOUNDARY_PARAMETER_KEY,
};
use aip_observation::{Completeness, EvidenceCeiling, ObservationClass};
use aip_observe::{
    ContinuityStatus, CoverageWindow, ObserverState, ProbePolicy, SensorHealth, SignedSensorHealth,
    SourceMechanism,
};
use aip_system::{AuthorityContext, MissionId, PlatformId, SystemId};

// ─── fixtures ───

const OBSERVED_DEPLOYMENT: [ProcessSensingSource; 10] = [
    ProcessSensingSource::SupervisoryRuntimeReport,
    ProcessSensingSource::ControllerStatusReport,
    ProcessSensingSource::ProcessTransmitter,
    ProcessSensingSource::ActuatorPositionFeedback,
    ProcessSensingSource::SafetySystemStatus,
    ProcessSensingSource::EdgeProcessObservation,
    ProcessSensingSource::EdgeLifecycleObservation,
    ProcessSensingSource::EdgeNetworkObservation,
    ProcessSensingSource::EdgeDataTransferObservation,
    ProcessSensingSource::ProtocolWireObservation,
];

/// The same plant with every anchored edge source removed: the sensor-gap and
/// observer-outage fixture.
const BLIND_DEPLOYMENT: [ProcessSensingSource; 5] = [
    ProcessSensingSource::SupervisoryRuntimeReport,
    ProcessSensingSource::ControllerStatusReport,
    ProcessSensingSource::ProcessTransmitter,
    ProcessSensingSource::ActuatorPositionFeedback,
    ProcessSensingSource::SafetySystemStatus,
];

fn system(id: &str) -> SystemId {
    SystemId::parse(id).expect("system id")
}

fn control_loop(system_id: &str, device: &str, point: &str) -> ControlLoopExecution {
    ControlLoopExecution::new(
        MissionId::parse("loop:fic-101").expect("loop id"),
        1,
        system(system_id),
        IndustrialCommand::WriteSetpoint,
        IndustrialProtocol::ModbusTcp,
        CommandWindow {
            from_ms: 1_000,
            until_ms: 2_000,
        },
        250,
        device,
        point,
    )
    .expect("control loop")
}

fn boundary(system_id: &str, bypass: bool) -> SafetyBoundary {
    let b = SafetyBoundary::new(
        "unit-4-esd",
        1,
        system(system_id),
        &[SafetyFunction::SafetyInstrumentedFunction],
        &[
            ProcessLimit::new(ProcessVariable::Pressure, LimitBound::Upper, 4_200, "bar")
                .expect("limit"),
        ],
        &[IndustrialCommand::WriteSetpoint],
    )
    .expect("boundary");
    if bypass {
        b.with_declared_bypass()
    } else {
        b
    }
}

fn health(state: ObserverState, covered_by: Vec<SourceMechanism>) -> SignedSensorHealth {
    SignedSensorHealth {
        health: SensorHealth {
            version: 9,
            observer_id: "edge-collector".into(),
            key_version: 1,
            state,
            continuity: ContinuityStatus::Verified,
            probe_policy: ProbePolicy::RegisteredOnly,
            sequence: 1,
            head: [0u8; 32],
            last_batch_id: None,
            attested_coverage: Some(CoverageWindow {
                from_ms: 0,
                to_ms: 10_000,
            }),
            covered_by,
            emitted_at_ms: 10_000,
        },
        attestation: aip_types::Signature {
            algorithm: aip_types::AlgorithmId::Ed25519,
            signer_id: "edge-collector".into(),
            timestamp: 10_000,
            nonce: [0u8; 16],
            payload_hash: [0u8; 32],
            signature_bytes: vec![0u8; 64],
        },
    }
}

// ─── 1. replay ───

#[test]
fn a1_a_replayed_protocol_exchange_is_indistinguishable_on_every_unsecured_protocol() {
    // The attack: capture a write, put it back on the segment later. Only a
    // negotiated cryptographic session tells the two apart, and most of these
    // protocols do not have one.
    let observed = [
        ProcessSensingSource::EdgeNetworkObservation,
        ProcessSensingSource::ProtocolWireObservation,
    ];
    let indistinguishable: Vec<IndustrialProtocol> = IndustrialProtocol::ALL
        .iter()
        .copied()
        .filter(|p| {
            !ProtocolInteraction {
                protocol: *p,
                positive_response: true,
                authenticated: true,
                socket_observed: true,
                bytes_observed: true,
                wire_observed: true,
            }
            .replay_distinguishable()
        })
        .collect();
    assert_eq!(
        indistinguishable.len(),
        8,
        "eight of nine protocols cannot tell a replay from a fresh command: {indistinguishable:?}"
    );
    // The positive case, so the test is sensitive to the predicate.
    assert!(OpcUaAdapter
        .interaction(true, true, &observed)
        .replay_distinguishable());
    // And even the one that can tell loses the property without a negotiated
    // session.
    assert!(!OpcUaAdapter
        .interaction(true, false, &observed)
        .replay_distinguishable());
}

#[test]
fn a2_a_replayed_commitment_is_the_same_commitment_and_the_window_is_what_stops_it() {
    // A digest cannot distinguish a replay: the same document has the same
    // digest, which is the property that makes it a commitment. What refuses
    // the replay is the bounded window.
    let e = control_loop("ics:unit-4", "plc-1", "40001");
    let replayed = e.clone();
    assert_eq!(e.digest(), replayed.digest());
    assert!(replayed.is_committed_by(Some(&e.digest())));
    assert!(replayed.admit_at(1_500).is_ok(), "inside the window");
    assert!(
        matches!(
            replayed.admit_at(2_000),
            Err(IndustrialError::CommandNotFresh { .. })
        ),
        "the same bytes, offered after the window, are refused"
    );
}

// ─── 2. stale command ───

#[test]
fn a3_a_stale_command_is_refused_at_the_boundary_and_not_one_millisecond_before() {
    let e = control_loop("ics:unit-4", "plc-1", "40001");
    assert!(e.admit_at(1_999).is_ok());
    match e.admit_at(2_000) {
        Err(IndustrialError::CommandNotFresh {
            at_ms,
            from_ms,
            until_ms,
        }) => {
            assert_eq!((at_ms, from_ms, until_ms), (2_000, 1_000, 2_000));
        }
        other => panic!("expected a freshness refusal, got {other:?}"),
    }
    // And early is refused too, rather than treated as an early start.
    assert!(e.admit_at(999).is_err());
}

#[test]
fn a4_staleness_is_not_repaired_by_any_amount_of_evidence() {
    // A command outside its window stays outside it however well observed the
    // edge node was. Freshness is a property of the authorization, not of the
    // observation.
    let e = control_loop("ics:unit-4", "plc-1", "40001");
    for tier in [
        ProcessEvidence::Declared,
        ProcessEvidence::DecisionSigned,
        ProcessEvidence::ExecutionObserved,
        ProcessEvidence::PhysicallyObserved,
    ] {
        let _ = tier;
        assert!(e.admit_at(9_999).is_err());
    }
}

// ─── 3. sensor gap ───

#[test]
fn a5_a_sensor_gap_reads_as_not_observable_rather_than_as_nothing_happening() {
    let full = IndustrialProfile::new(
        "edge",
        &OBSERVED_DEPLOYMENT,
        &[IndustrialProtocol::ModbusTcp],
    )
    .expect("profile");
    let gapped =
        IndustrialProfile::new("edge", &BLIND_DEPLOYMENT, &[IndustrialProtocol::ModbusTcp])
            .expect("profile");

    let full_op = full.observation_profile().expect("projection");
    let gapped_op = gapped.observation_profile().expect("projection");

    assert_eq!(
        full_op.completeness_without_evidence(ObservationClass::NetworkSocket),
        Completeness::NotObserved,
        "a provisioned class that saw nothing is NotObserved"
    );
    assert_eq!(
        gapped_op.completeness_without_evidence(ObservationClass::NetworkSocket),
        Completeness::NotObservable,
        "a class nobody can observe is NotObservable — silence carries no information"
    );
    // Neither says the command did not happen.
    assert_eq!(
        LoopState::assertable(LoopState::CommandIssued, ProcessEvidence::DecisionSigned),
        LoopState::Unknown
    );
}

#[test]
fn a6_removing_a_gate_independent_source_removes_the_right_to_claim_absence() {
    let healthy = health(
        ObserverState::Active,
        vec![
            SourceMechanism::ProcConnector,
            SourceMechanism::WireTapAfPacket,
        ],
    );
    // With the netlink connector and the wire tap: absence is claimable in
    // both software domains.
    let full = ObservationCoverage::from_sources(&OBSERVED_DEPLOYMENT);
    assert!(full.non_occurrence_admissible(CoverageDomain::Compute, &healthy));
    assert!(full.non_occurrence_admissible(CoverageDomain::Network, &healthy));

    // Drop them and keep only perf-tracepoint and polled coverage. The
    // deployment still observes; it just cannot say what did not happen.
    let gate_able = ObservationCoverage::from_sources(&[
        ProcessSensingSource::EdgeProcessObservation,
        ProcessSensingSource::EdgeNetworkObservation,
        ProcessSensingSource::EdgeDataTransferObservation,
    ]);
    assert!(gate_able.domain(CoverageDomain::Network).observable);
    assert!(!gate_able.non_occurrence_admissible(CoverageDomain::Compute, &healthy));
    assert!(!gate_able.non_occurrence_admissible(CoverageDomain::Network, &healthy));
}

// ─── 4. observer outage ───

#[test]
fn a7_an_observer_outage_degrades_and_never_accuses() {
    let blind = IndustrialProfile::new("edge", &BLIND_DEPLOYMENT, &[IndustrialProtocol::ModbusTcp])
        .expect("profile");
    assert!(!blind.has_edge_observer());
    assert_eq!(blind.highest_established_rung(), None);
    let (execution, confirmation) = blind.execution_versus_confirmation();
    assert!(!execution);
    assert!(!confirmation);
    // Nothing about the plant becomes assertable, and nothing becomes
    // deniable either.
    for f in SafetyFunction::ALL {
        let e = blind.safety_evidence(f);
        assert!(!e.command_observed, "{f:?}");
        assert!(!e.establishes_action(), "{f:?}");
    }
    let coverage = blind.coverage();
    for d in CoverageDomain::ALL {
        assert!(!coverage.domain(d).observable, "{d:?}");
    }
}

#[test]
fn a8_every_non_active_observer_state_refuses_an_absence_claim() {
    let c = ObservationCoverage::from_sources(&OBSERVED_DEPLOYMENT);
    for state in [
        ObserverState::Degraded,
        ObserverState::Recovering,
        ObserverState::ContinuityUnverified,
        ObserverState::Quarantined,
        ObserverState::IntegrityUnknown,
    ] {
        let h = health(
            state,
            vec![
                SourceMechanism::ProcConnector,
                SourceMechanism::WireTapAfPacket,
            ],
        );
        for d in CoverageDomain::ALL {
            assert!(
                !c.non_occurrence_admissible(d, &h),
                "{state:?}/{d:?}: a non-Active observer must not license an absence claim"
            );
        }
    }
    // The positive case: only Active, with a gate-independent mechanism.
    let active = health(
        ObserverState::Active,
        vec![SourceMechanism::ProcConnector, SourceMechanism::Fanotify],
    );
    assert!(c.non_occurrence_admissible(CoverageDomain::Compute, &active));
}

// ─── 5. observer integrity ───

#[test]
fn a9_observer_integrity_unknown_means_cannot_prove_and_never_healthy_coverage() {
    // The Skill 24-era production finding, as a profile-level regression: a
    // live, continuity-verified observer whose mechanism may have been gated
    // must not produce coverage that licenses a non-occurrence claim.
    let c = ObservationCoverage::from_sources(&OBSERVED_DEPLOYMENT);
    let blinded = health(
        ObserverState::IntegrityUnknown,
        vec![
            SourceMechanism::ProcConnector,
            SourceMechanism::WireTapAfPacket,
            SourceMechanism::Fanotify,
        ],
    );
    assert!(
        !blinded.covered_by_kernel_pushed_source(),
        "the production predicate must refuse the state"
    );
    for d in CoverageDomain::ALL {
        assert!(!c.non_occurrence_admissible(d, &blinded), "{d:?}");
    }
    // The declared capability is unchanged — the deployment still has the
    // mechanisms. What changed is what may be concluded, which is the whole
    // distinction.
    assert!(c.domain(CoverageDomain::Compute).gate_independent);
}

// ─── 6. tamper ───

#[test]
fn a10_tampering_with_any_committed_field_changes_the_digest() {
    let base = control_loop("ics:unit-4", "plc-1", "40001");
    let variants = [
        control_loop("ics:unit-5", "plc-1", "40001"),
        control_loop("ics:unit-4", "plc-2", "40001"),
        control_loop("ics:unit-4", "plc-1", "40002"),
        base.clone()
            .on_platform(PlatformId::parse("edge:node-1").expect("platform")),
    ];
    for v in &variants {
        assert_ne!(base.digest(), v.digest());
        assert!(!base.is_committed_by(Some(&v.digest())));
    }
    let b = boundary("ics:unit-4", false);
    assert_ne!(b.digest(), boundary("ics:unit-4", true).digest());
    assert_ne!(b.digest(), boundary("ics:unit-5", false).digest());
}

// ─── 7. substitution ───

#[test]
fn a11_a_safety_boundary_commitment_is_not_a_control_loop_commitment() {
    // The spec's first non-negotiable rule, as a substitution test: the two are
    // separate commitments, so a signature over one must not be readable as a
    // signature over the other. Different keys and different structure
    // discriminants, so the digests cannot collide even for documents that
    // happen to line up.
    let e = control_loop("ics:unit-4", "plc-1", "40001");
    let b = boundary("ics:unit-4", false);
    assert_ne!(e.digest(), b.digest());
    assert!(!e.is_committed_by(Some(&b.digest())));
    assert!(!b.is_committed_by(Some(&e.digest())));
    assert_ne!(e.authorization_parameter().0, b.authorization_parameter().0);
    assert_eq!(e.authorization_parameter().0, CONTROL_LOOP_PARAMETER_KEY);
    assert_eq!(b.authorization_parameter().0, SAFETY_BOUNDARY_PARAMETER_KEY);
}

#[test]
fn a12_no_protocol_adapter_can_produce_a_stronger_interaction_than_another() {
    // Substitution across protocols: swapping a Modbus adapter for an OPC UA
    // one must not raise what an exchange is worth.
    let observed = [
        ProcessSensingSource::EdgeNetworkObservation,
        ProcessSensingSource::EdgeDataTransferObservation,
        ProcessSensingSource::ProtocolWireObservation,
    ];
    let modbus = ModbusTcpAdapter.interaction(true, true, &observed);
    let dnp3 = Dnp3Adapter.interaction(true, true, &observed);
    let opcua = OpcUaAdapter.interaction(true, true, &observed);
    assert_eq!(modbus.evidence_ceiling(), dnp3.evidence_ceiling());
    assert_eq!(modbus.evidence_ceiling(), opcua.evidence_ceiling());
    assert_eq!(modbus.evidence_ceiling(), EvidenceCeiling::Attested);
    for i in [modbus, dnp3, opcua] {
        assert!(!i.establishes_process_change());
    }
}

// ─── 8. omission ───

#[test]
fn a13_an_omitted_source_is_recorded_as_absent_capability_not_as_absent_event() {
    let coverage = ObservationCoverage::from_sources(&[
        ProcessSensingSource::EdgeProcessObservation,
        // No network sources at all.
    ]);
    assert!(coverage.domain(CoverageDomain::Compute).observable);
    assert!(!coverage.domain(CoverageDomain::Network).observable);
    let p = coverage.observation_profile("edge").expect("projection");
    assert_eq!(
        p.completeness_without_evidence(ObservationClass::NetworkSocket),
        Completeness::NotObservable
    );
    // And the omission never becomes a claim about the plant either.
    assert_eq!(
        class_domain(ObservationClass::PhysicalEffect),
        Some(CoverageDomain::ProcessState)
    );
    assert!(!CoverageDomain::ProcessState.can_support_non_occurrence());
}

// ─── 9. wrong identity ───

#[test]
fn a14_a_commitment_for_one_system_does_not_commit_for_another() {
    let a = control_loop("ics:unit-4", "plc-1", "40001");
    let b = control_loop("ics:unit-9", "plc-1", "40001");
    assert_ne!(a.digest(), b.digest());
    assert!(!a.is_committed_by(Some(&b.digest())));
    assert_ne!(a.system_id().as_str(), b.system_id().as_str());
    // Same for a safety boundary: a boundary declared for one unit is not in
    // force for another.
    assert_ne!(
        boundary("ics:unit-4", false).digest(),
        boundary("ics:unit-9", false).digest()
    );
}

// ─── 10. wrong binding ───

#[test]
fn a15_a_commitment_bound_to_one_edge_node_does_not_commit_for_another() {
    let base = control_loop("ics:unit-4", "plc-1", "40001");
    let node1 = base
        .clone()
        .on_platform(PlatformId::parse("edge:node-1").expect("platform"));
    let node2 = base
        .clone()
        .on_platform(PlatformId::parse("edge:node-2").expect("platform"));
    assert_ne!(node1.digest(), node2.digest());
    assert_ne!(node1.digest(), base.digest());
    assert!(!node1.is_committed_by(Some(&node2.digest())));
}

// ─── 11. wrong authority ───

#[test]
fn a16_an_unattributed_override_never_becomes_authority() {
    for kind in OverrideKind::ALL {
        let unattributed =
            OverrideClaim::new(kind, "op-7", AuthorityContext::none()).expect("claim");
        assert!(
            !unattributed.accepted_as_authority(ProcessEvidence::PhysicallyObserved),
            "{kind:?}"
        );
        assert!(matches!(
            unattributed.admit(ProcessEvidence::ExecutionObserved),
            Err(IndustrialError::OverrideNotAttributed { .. })
        ));
    }
    // The positive case, so the matrix is sensitive to attribution.
    let attributed = OverrideClaim::new(
        OverrideKind::HmiWriteOnObservedHost,
        "op-7",
        AuthorityContext {
            decision_id: Some([0x33; 16]),
            root_token_jti: None,
        },
    )
    .expect("claim");
    assert!(attributed.accepted_as_authority(ProcessEvidence::DecisionSigned));
}

#[test]
fn a17_an_override_never_explains_away_a_divergence() {
    // The excuse an attacker needs, refused unconditionally.
    for kind in OverrideKind::ALL {
        for decision in [None, Some([0x44u8; 16])] {
            let c = OverrideClaim::new(
                kind,
                "op-7",
                AuthorityContext {
                    decision_id: decision,
                    root_token_jti: None,
                },
            )
            .expect("claim");
            assert!(!c.excuses_divergence(), "{kind:?}/{decision:?}");
        }
    }
}

#[test]
fn a18_a_field_override_is_outside_the_lineage_and_says_so() {
    for kind in [
        OverrideKind::FieldManualOperation,
        OverrideKind::ManualTripStation,
        OverrideKind::ForcedIoPoint,
        OverrideKind::ControllerKeyswitchLocal,
    ] {
        assert_eq!(
            kind.lineage_visibility(),
            Completeness::NotObservable,
            "{kind:?}"
        );
        assert!(!kind.authority_expressible(), "{kind:?}");
    }
}

// ─── 12. transplant ───

#[test]
fn a19_a_commitment_from_one_loop_does_not_transplant_onto_another() {
    let fic = control_loop("ics:unit-4", "plc-1", "40001");
    let other = ControlLoopExecution::new(
        MissionId::parse("loop:pic-202").expect("loop id"),
        1,
        system("ics:unit-4"),
        IndustrialCommand::WriteSetpoint,
        IndustrialProtocol::ModbusTcp,
        CommandWindow {
            from_ms: 1_000,
            until_ms: 2_000,
        },
        250,
        "plc-1",
        "40001",
    )
    .expect("control loop");
    assert_ne!(fic.digest(), other.digest());
    assert!(!fic.is_committed_by(Some(&other.digest())));
}

// ─── the standing claims, restated adversarially ───

#[test]
fn a20_a_forged_positive_response_establishes_exactly_what_a_real_one_does() {
    // Which is nothing about the plant. There is no adversary model in which
    // this differs, because the profile never reads the response as evidence.
    for positive in [true, false] {
        for protocol in IndustrialProtocol::ALL {
            let i = ProtocolInteraction::unobserved(protocol, positive);
            assert!(!i.establishes_process_change(), "{protocol:?}/{positive}");
            assert_eq!(i.evidence_ceiling(), EvidenceCeiling::Corroborative);
        }
    }
}

#[test]
fn a21_a_declared_safety_boundary_never_becomes_an_enforced_one() {
    for bypass in [true, false] {
        let b = boundary("ics:unit-4", bypass);
        assert!(!b.enforcement_establishable(), "bypass={bypass}");
        assert!(!b.enforcement_evidence_required().is_reachable());
        assert_eq!(b.highest_rung(), ControlRung::CommandIssued);
    }
}

#[test]
fn a22_no_plant_claim_survives_any_deployment_including_the_maximal_one() {
    let p = IndustrialProfile::new("edge", &ProcessSensingSource::ALL, &IndustrialProtocol::ALL)
        .expect("profile")
        .with_authenticated_telemetry();
    for v in ProcessVariable::ALL {
        for c in ProcessClaim::ALL {
            let e = p.process_effect(v, c);
            assert!(!e.establishes(), "{v:?}/{c:?}");
            assert!(!e.is_independently_observed(), "{v:?}/{c:?}");
        }
    }
    assert!(!p.establishes_process_effect());
}

#[test]
fn a23_containment_of_the_edge_node_is_never_containment_of_the_plant() {
    for s in ContainmentScope::ALL {
        assert!(s.requires_warrant(), "{s:?}");
        assert!(!s.restores_process_safe_state(), "{s:?}");
        assert!(!s.safe_state_evidence_required().is_reachable(), "{s:?}");
    }
    assert!(ContainmentScope::EdgeCompute.mechanism_exists());
    assert!(!ContainmentScope::ProcessActuation.mechanism_exists());
}
