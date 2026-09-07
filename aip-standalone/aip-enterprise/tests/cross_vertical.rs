//! Five verticals, and the line between what generalises and what does not.
//!
//! # Why this file replaces the three-way guard
//!
//! ADR-007 installed a two-way consistency guard in `aip-robotics`. ADR-009
//! widened it to three in `aip-industrial`, deferred the shared profile-kit
//! extraction again, and moved its trigger to *the first non-embodied
//! vertical*. **This is that vertical**, and this file is what the trigger
//! produced.
//!
//! The result, recorded in ADR-011: **three rules generalise across all five,
//! and a fourth property that the earlier guards happened to share does not.**
//!
//! | property | UAS | robotics | industrial | space | enterprise |
//! |---|---|---|---|---|---|
//! | agreement never raises a ceiling | ✓ | ✓ | ✓ | ✓ | ✓ |
//! | a state claim may only echo or weaken | ✓ | ✓ | ✓ | ✓ | ✓ |
//! | independence without a mechanism establishes nothing | ✓ | ✓ | ✓ | ✓ | ✓ |
//! | **the top evidence tier is unreachable** | ✓ | ✓ | ✓ | ✓ | **✗** |
//!
//! The last row is the finding. Enterprise's local effects *are* observable —
//! a file write is `Fanotify` — so its top tier is reachable. That property was
//! never universal; it was embodiment-specific, and four embodied verticals in
//! a row made it look otherwise.
//!
//! So this file has two sections. The universal rules are asserted over all
//! five. The embodiment-specific property is asserted over the four embodied
//! ones **and explicitly denied for the fifth**, so that a future edit which
//! quietly made enterprise's tier unreachable — or made an embodied vertical's
//! reachable — fails here.

use aip_observation::EvidenceCeiling;

// ═══ Section 1 — the three universal rules, across five verticals ═══

#[test]
fn all_five_verticals_refuse_to_raise_a_ceiling_on_agreement() {
    for n in 1..=8usize {
        let uas = aip_uas::SensorAgreement {
            quantity: aip_uas::NavigationQuantity::Position,
            agreeing: vec![aip_uas::TelemetrySource::GnssReceiverOnboard; n],
            disagreeing: vec![],
        };
        let robot = aip_robotics::SensorAgreement {
            agreeing: vec![aip_robotics::SensingSource::EncoderOnboard; n],
            disagreeing: vec![],
        };
        let ics = aip_industrial::InstrumentAgreement {
            agreeing: vec![aip_industrial::ProcessSensingSource::ProcessTransmitter; n],
            disagreeing: vec![],
        };
        let space = aip_space::SourceAgreement {
            agreeing: vec![aip_space::SpaceSensingSource::HousekeepingTelemetry; n],
            disagreeing: vec![],
        };
        let ent = aip_enterprise::SourceAgreement {
            agreeing: vec![aip_enterprise::EnterpriseSource::AgentSelfReport; n],
            disagreeing: vec![],
        };
        for base in [
            EvidenceCeiling::Corroborative,
            EvidenceCeiling::Attested,
            EvidenceCeiling::Proven,
        ] {
            assert_eq!(uas.ceiling_after_agreement(base), base, "uas {n} {base:?}");
            assert_eq!(
                robot.ceiling_after_agreement(base),
                base,
                "robotics {n} {base:?}"
            );
            assert_eq!(
                ics.ceiling_after_agreement(base),
                base,
                "industrial {n} {base:?}"
            );
            assert_eq!(
                space.ceiling_after_agreement(base),
                base,
                "space {n} {base:?}"
            );
            assert_eq!(
                ent.ceiling_after_agreement(base),
                base,
                "enterprise {n} {base:?}"
            );
        }
    }
}

#[test]
fn all_five_verticals_report_a_conflict_rather_than_resolving_it() {
    let uas = aip_uas::SensorAgreement {
        quantity: aip_uas::NavigationQuantity::Altitude,
        agreeing: vec![
            aip_uas::TelemetrySource::GnssReceiverOnboard,
            aip_uas::TelemetrySource::ImuOnboard,
        ],
        disagreeing: vec![aip_uas::TelemetrySource::BarometerOnboard],
    };
    let robot = aip_robotics::SensorAgreement {
        agreeing: vec![
            aip_robotics::SensingSource::EncoderOnboard,
            aip_robotics::SensingSource::OdometryOnboard,
        ],
        disagreeing: vec![aip_robotics::SensingSource::LidarOnboard],
    };
    let ics = aip_industrial::InstrumentAgreement {
        agreeing: vec![
            aip_industrial::ProcessSensingSource::ProcessTransmitter,
            aip_industrial::ProcessSensingSource::HistorianArchive,
        ],
        disagreeing: vec![aip_industrial::ProcessSensingSource::IndependentPlantSensor],
    };
    let space = aip_space::SourceAgreement {
        agreeing: vec![
            aip_space::SpaceSensingSource::HousekeepingTelemetry,
            aip_space::SpaceSensingSource::AttitudeSolutionOnboard,
        ],
        disagreeing: vec![aip_space::SpaceSensingSource::GroundRadiometricTracking],
    };
    let ent = aip_enterprise::SourceAgreement {
        agreeing: vec![
            aip_enterprise::EnterpriseSource::AgentSelfReport,
            aip_enterprise::EnterpriseSource::FrameworkTrace,
        ],
        disagreeing: vec![aip_enterprise::EnterpriseSource::HostSocketObservation],
    };

    assert!(!uas.is_resolvable() && !uas.classify().establishes());
    assert!(!robot.is_resolvable() && !robot.classify().establishes());
    assert!(!ics.is_resolvable() && !ics.classify().establishes());
    assert!(!space.is_resolvable() && !space.classify().establishes());
    assert!(!ent.is_resolvable() && !ent.classify().establishes());
}

#[test]
fn no_vertical_lets_corroboration_establish_anything() {
    assert!(!aip_uas::Agreement::Corroborated {
        agreeing: 9,
        independent: 9
    }
    .establishes());
    assert!(!aip_robotics::Agreement::Corroborated {
        agreeing: 9,
        independent: 9
    }
    .establishes());
    assert!(!aip_industrial::Agreement::Corroborated {
        agreeing: 9,
        independent: 9
    }
    .establishes());
    assert!(!aip_space::Agreement::Corroborated {
        agreeing: 9,
        independent: 9
    }
    .establishes());
    assert!(!aip_enterprise::Agreement::Corroborated {
        agreeing: 9,
        independent: 9
    }
    .establishes());
}

#[test]
fn all_five_state_models_may_only_echo_or_weaken() {
    for claimed in aip_uas::MissionState::ALL {
        for tier in [
            aip_uas::StateEvidence::Declared,
            aip_uas::StateEvidence::DecisionSigned,
            aip_uas::StateEvidence::ExecutionObserved,
            aip_uas::StateEvidence::PhysicallyObserved,
        ] {
            let out = aip_uas::MissionState::assertable(claimed, tier);
            assert!(out == claimed || out == aip_uas::MissionState::Unknown);
        }
    }
    for claimed in aip_robotics::TaskState::ALL {
        for tier in [
            aip_robotics::TaskEvidence::Declared,
            aip_robotics::TaskEvidence::DecisionSigned,
            aip_robotics::TaskEvidence::ExecutionObserved,
            aip_robotics::TaskEvidence::PhysicallyObserved,
        ] {
            let out = aip_robotics::TaskState::assertable(claimed, tier);
            assert!(out == claimed || out == aip_robotics::TaskState::Unknown);
        }
    }
    for claimed in aip_industrial::LoopState::ALL {
        for tier in [
            aip_industrial::ProcessEvidence::Declared,
            aip_industrial::ProcessEvidence::DecisionSigned,
            aip_industrial::ProcessEvidence::ExecutionObserved,
            aip_industrial::ProcessEvidence::PhysicallyObserved,
        ] {
            let out = aip_industrial::LoopState::assertable(claimed, tier);
            assert!(out == claimed || out == aip_industrial::LoopState::Unknown);
        }
    }
    for claimed in aip_space::MissionState::ALL {
        for tier in [
            aip_space::SpaceEvidence::Declared,
            aip_space::SpaceEvidence::DecisionSigned,
            aip_space::SpaceEvidence::ExecutionObserved,
            aip_space::SpaceEvidence::PhysicallyObserved,
        ] {
            let out = aip_space::MissionState::assertable(claimed, tier);
            assert!(out == claimed || out == aip_space::MissionState::Unknown);
        }
    }
    for claimed in aip_enterprise::WorkloadState::ALL {
        for tier in [
            aip_enterprise::EnterpriseEvidence::Declared,
            aip_enterprise::EnterpriseEvidence::DecisionSigned,
            aip_enterprise::EnterpriseEvidence::ExecutionObserved,
            aip_enterprise::EnterpriseEvidence::LocalEffectObserved,
        ] {
            let out = aip_enterprise::WorkloadState::assertable(claimed, tier);
            assert!(
                out == claimed || out == aip_enterprise::WorkloadState::Unknown,
                "enterprise: {claimed:?}/{tier:?} -> {out:?}"
            );
        }
    }
}

#[test]
fn all_five_verticals_agree_that_independence_without_a_mechanism_establishes_nothing() {
    // The rule that had to be re-derived for a protocol exchange in Skill 25
    // and for a cloud audit log here. Five different nouns, one answer.
    let uas = aip_uas::NavigationEvidence::from_sources(
        aip_uas::NavigationQuantity::Position,
        &[aip_uas::TelemetrySource::GroundStationTrack],
        false,
    );
    let robot = aip_robotics::NavigationEvidence::from_sources(
        aip_robotics::PoseQuantity::Position,
        &[aip_robotics::SensingSource::ExternalTracking],
        false,
    );
    let ics = aip_industrial::PhysicalProcessEffect::from_sources(
        aip_industrial::ProcessVariable::Pressure,
        aip_industrial::ProcessClaim::ProcessVariableIsValue,
        &[aip_industrial::ProcessSensingSource::IndependentPlantSensor],
    );
    assert!(!uas.establishes());
    assert!(!robot.establishes());
    assert!(!ics.establishes());
    assert_eq!(uas.ceiling(), EvidenceCeiling::Corroborative);
    assert_eq!(robot.ceiling(), EvidenceCeiling::Corroborative);
    assert_eq!(ics.ceiling(), EvidenceCeiling::Corroborative);

    // Space: ground radiometric tracking is outside the vehicle and unmechanised.
    let s = aip_space::SpaceSensingSource::GroundRadiometricTracking;
    assert!(s.is_independent());
    assert!(!s.can_produce_observation_record());
    assert_eq!(s.ceiling(), EvidenceCeiling::Corroborative);

    // Enterprise: a cloud audit log is written by the provider, and still has
    // no mechanism here.
    let e = aip_enterprise::EnterpriseSource::CloudAuditLog;
    assert!(e.is_independent());
    assert!(!e.can_produce_observation_record());
    assert_eq!(e.ceiling(), EvidenceCeiling::Corroborative);
    let effect = aip_enterprise::EnterpriseEffect::from_sources(
        aip_enterprise::EnterpriseResource::CloudExecution,
        &[aip_enterprise::EnterpriseSource::CloudAuditLog],
    );
    assert!(!effect.has_anchored_observation());
    assert!(!effect.establishes_occurrence());
}

// ═══ Section 2 — the property that is NOT universal ═══

#[test]
fn the_four_embodied_verticals_have_an_unreachable_top_tier_and_enterprise_does_not() {
    // This is ADR-011's finding, as an executable assertion. If a future edit
    // makes enterprise's tier unreachable, or an embodied vertical's reachable,
    // this fails — which is the point of stating it rather than assuming it.
    assert!(!aip_uas::StateEvidence::PhysicallyObserved.is_reachable());
    assert!(!aip_robotics::TaskEvidence::PhysicallyObserved.is_reachable());
    assert!(!aip_industrial::ProcessEvidence::PhysicallyObserved.is_reachable());
    assert!(!aip_space::SpaceEvidence::PhysicallyObserved.is_reachable());

    assert!(
        aip_enterprise::EnterpriseEvidence::LocalEffectObserved.is_reachable(),
        "a file write is Fanotify; the enterprise top tier is reachable and saying otherwise \
         would be a lie the other four verticals made look like a rule"
    );
    // And the thing enterprise still cannot reach is the *remote* effect.
    assert!(!aip_enterprise::EnterpriseEvidence::remote_effect_reachable());
    for s in [
        aip_enterprise::WorkloadState::RemoteEffectApplied,
        aip_enterprise::WorkloadState::Completed,
    ] {
        assert!(!s.reachable_in_this_build(), "{s:?}");
    }
}

#[test]
fn the_four_embodied_verticals_cannot_complete_and_enterprise_cannot_complete_either() {
    // Different reasons, same answer, and the difference matters: the embodied
    // four cannot see a body, and enterprise cannot see another host.
    assert_eq!(
        aip_uas::MissionState::assertable(
            aip_uas::MissionState::Completed,
            aip_uas::StateEvidence::PhysicallyObserved
        ),
        aip_uas::MissionState::Unknown
    );
    assert_eq!(
        aip_robotics::TaskState::assertable(
            aip_robotics::TaskState::Completed,
            aip_robotics::TaskEvidence::PhysicallyObserved
        ),
        aip_robotics::TaskState::Unknown
    );
    assert_eq!(
        aip_industrial::LoopState::assertable(
            aip_industrial::LoopState::ShutdownComplete,
            aip_industrial::ProcessEvidence::PhysicallyObserved
        ),
        aip_industrial::LoopState::Unknown
    );
    assert_eq!(
        aip_space::MissionState::assertable(
            aip_space::MissionState::Completed,
            aip_space::SpaceEvidence::PhysicallyObserved
        ),
        aip_space::MissionState::Unknown
    );
    assert_eq!(
        aip_enterprise::WorkloadState::assertable(
            aip_enterprise::WorkloadState::Completed,
            aip_enterprise::EnterpriseEvidence::LocalEffectObserved
        ),
        aip_enterprise::WorkloadState::Unknown
    );
}

// ═══ Section 3 — structural compatibility: one core, five ids ═══

#[test]
fn the_five_verticals_occupy_one_profile_slot_under_five_ids() {
    let refs = [
        aip_uas::UasProfile::new("o", &[aip_uas::TelemetrySource::ImuOnboard])
            .unwrap()
            .profile_ref()
            .unwrap(),
        aip_robotics::RoboticsProfile::new("o", &[aip_robotics::SensingSource::ImuOnboard])
            .unwrap()
            .profile_ref()
            .unwrap(),
        aip_industrial::IndustrialProfile::new(
            "o",
            &[aip_industrial::ProcessSensingSource::ProcessTransmitter],
            &[aip_industrial::IndustrialProtocol::ModbusTcp],
        )
        .unwrap()
        .profile_ref()
        .unwrap(),
        aip_space::SpaceExecutionProfile::new(
            "o",
            &[aip_space::SpaceSensingSource::HousekeepingTelemetry],
            &[aip_space::AutonomyMode::SafeMode],
            1,
        )
        .unwrap()
        .profile_ref()
        .unwrap(),
        aip_enterprise::EnterpriseProfile::new(
            "o",
            &[aip_enterprise::EnterpriseSource::AgentSelfReport],
            &[aip_enterprise::EnterpriseResource::Agent],
        )
        .unwrap()
        .profile_ref()
        .unwrap(),
    ];
    for r in &refs {
        assert_eq!(
            r.kind,
            aip_system::ProfileKind::Environment,
            "every vertical is one deployment class in one slot"
        );
    }
    for (i, a) in refs.iter().enumerate() {
        for (j, b) in refs.iter().enumerate() {
            if i != j {
                assert_ne!(a.id(), b.id(), "ids must distinguish the verticals");
                assert_ne!(a.digest, b.digest, "documents must not collide");
            }
        }
    }
}

#[test]
fn the_five_domain_tags_and_every_parameter_key_are_distinct() {
    let domains = [
        aip_robotics::ROBOTICS_PROFILE_DOMAIN,
        aip_industrial::INDUSTRIAL_PROFILE_DOMAIN,
        aip_space::SPACE_PROFILE_DOMAIN,
        aip_enterprise::ENTERPRISE_PROFILE_DOMAIN,
    ];
    for (i, a) in domains.iter().enumerate() {
        for (j, b) in domains.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
            }
        }
    }
    let keys = [
        aip_uas::MISSION_PARAMETER_KEY,
        aip_robotics::TASK_PARAMETER_KEY,
        aip_industrial::CONTROL_LOOP_PARAMETER_KEY,
        aip_industrial::SAFETY_BOUNDARY_PARAMETER_KEY,
        aip_space::MODE_TRANSITION_PARAMETER_KEY,
        aip_enterprise::WORKLOAD_BINDING_PARAMETER_KEY,
    ];
    for (i, a) in keys.iter().enumerate() {
        for (j, b) in keys.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "two commitments must not share a parameter key");
            }
        }
    }
}

#[test]
fn no_vertical_declares_the_verdict_engine_as_a_runtime_dependency() {
    // The Skill 27 acceptance gate — "no enterprise-specific branch of
    // reconciliation exists" — has three legs, and each is asserted where it
    // can actually be checked:
    //
    //   1. no vertical *names* verdict vocabulary  → each crate's
    //      `no_second_architecture.rs`, over its own source;
    //   2. no vertical can *reach* the engine at runtime → the manifests, where
    //      `aip-reconcile` is a dev-dependency of every profile crate and a
    //      runtime dependency of none, enforced by Cargo;
    //   3. an enterprise workload reconciles through the *same* engine →
    //      `tests/integration.rs`, against a real execution.
    //
    // This test pins leg 2 by reading the manifests, because a manifest edit is
    // exactly how leg 2 would be lost.
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("aip-standalone")
        .to_path_buf();
    for crate_name in [
        "aip-uas",
        "aip-robotics",
        "aip-industrial",
        "aip-space",
        "aip-enterprise",
    ] {
        let manifest = std::fs::read_to_string(root.join(crate_name).join("Cargo.toml"))
            .unwrap_or_else(|e| panic!("{crate_name}: {e}"));
        // Comments are stripped first: these manifests explain at length that
        // `aip-reconcile` is deliberately dev-only, and a substring search
        // over the prose would report the opposite of what it says.
        let code: String = manifest
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n");
        let (runtime, dev) = code
            .split_once("[dev-dependencies]")
            .expect("every profile crate has a dev-dependencies section");
        assert!(
            !runtime.contains("aip-reconcile"),
            "{crate_name} declares aip-reconcile as a runtime dependency: a profile that can \
             reach the verdict engine at runtime is a profile that could eventually produce a \
             verdict"
        );
        assert!(
            dev.contains("aip-reconcile"),
            "{crate_name} does not exercise the shared engine in tests at all"
        );
        assert!(
            !runtime.contains("aip-nexora"),
            "{crate_name} declares aip-nexora as a runtime dependency"
        );
    }
}

#[test]
fn every_vertical_keeps_the_proof_tree_at_nine_leaf_kinds() {
    assert_eq!(
        aip_nexora::LeafKind::ALL.len(),
        9,
        "no vertical may add a leaf kind; a per-vertical proof tree is a second proof tree"
    );
}
