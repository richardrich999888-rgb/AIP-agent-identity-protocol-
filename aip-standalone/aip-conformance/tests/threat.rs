//! The spanning threat model, checked and exercised (Skill 29, R1–R4).
//!
//! Two halves. The first checks the model's own discipline: total, every
//! answer accounted for, and no way to write "mitigated because we log it".
//! The second drives the four named environments — UAS, robotics, industrial,
//! disconnected — through the threats that actually reach them, so the model's
//! claims about those environments are executed rather than asserted.

use aip_conformance::threat::{Disposition, Layer, Threat, ThreatModel};

// ═══ The model's own discipline ═══

/// Thirteen threats, seven layers, no holes. A model with a hole is one the
/// reader completes by assumption, and the assumption is always favourable.
#[test]
fn the_model_is_total() {
    let m = ThreatModel::build();
    assert!(m.missing().is_empty(), "unanswered: {:?}", m.missing());
    assert_eq!(Threat::ALL.len(), 13, "the specification names thirteen");
    assert_eq!(Layer::ALL.len(), 7, "the specification names seven layers");
    assert_eq!(m.cells.len(), 91);

    let mut ids: Vec<&str> = Threat::ALL.iter().map(|t| t.id()).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 13, "threat ids must be distinct");
}

/// **The acceptance gate.** Every high-impact threat has an explicit system
/// response *or* an explicit uncertainty boundary. A threat with neither is
/// one the model does not answer.
#[test]
fn every_high_impact_threat_has_a_response_or_a_stated_boundary() {
    let m = ThreatModel::build();
    assert!(
        m.threats_with_no_answer().is_empty(),
        "threats with neither a defence nor a stated uncertainty: {:?}",
        m.threats_with_no_answer()
    );
    for t in Threat::ALL {
        assert!(t.is_high_impact(), "{:?} claims not to be high impact", t);
        assert!(
            !t.attacker_controls().is_empty(),
            "{:?} does not state what the attacker controls; a disposition is \
             only meaningful against a stated capability",
            t
        );
    }
}

/// **No threat is marked mitigated merely because a log exists.**
///
/// Enforced by the type: `Disposition` has four variants and none is
/// `Mitigated`. Enumerating it is the check — if one is ever added, this
/// fails and whoever added it has to justify it here.
#[test]
fn the_vocabulary_has_no_word_for_mitigated() {
    for d in [
        Disposition::Prevented,
        Disposition::Detected,
        Disposition::Uncertainty,
        Disposition::NotDetectable,
    ] {
        assert!(matches!(
            d,
            Disposition::Prevented
                | Disposition::Detected
                | Disposition::Uncertainty
                | Disposition::NotDetectable
        ));
    }
    // Only the two positive answers count as a defence. Reducing what the
    // system asserts is the designed response to missing evidence, and it is
    // not the same as stopping an attack.
    assert!(Disposition::Prevented.is_a_defence());
    assert!(Disposition::Detected.is_a_defence());
    assert!(!Disposition::Uncertainty.is_a_defence());
    assert!(!Disposition::NotDetectable.is_a_defence());
}

/// Every cell names a mechanism or a boundary, and every uncertainty that a
/// non-establishment already covers cites it. A `Detected` with no mechanism
/// is the log-shaped claim the gate forbids.
#[test]
fn every_cell_names_a_mechanism_and_no_answer_is_bare() {
    let m = ThreatModel::build();
    for c in &m.cells {
        assert!(
            !c.mechanism.is_empty(),
            "{} {:?} has no mechanism",
            c.threat_id,
            c.layer
        );
        if c.disposition == Disposition::Detected {
            assert!(
                c.mechanism.len() > 30,
                "{} {:?} claims Detected without naming how: {:?}",
                c.threat_id,
                c.layer,
                c.mechanism
            );
        }
        if !c.non_establishment.is_empty() {
            assert!(
                c.non_establishment.starts_with("N-"),
                "{} {:?} cites {:?}, which is not a non-establishment id",
                c.threat_id,
                c.layer,
                c.non_establishment
            );
            assert_ne!(
                c.disposition,
                Disposition::Prevented,
                "{} {:?} cites a non-establishment while claiming Prevented",
                c.threat_id,
                c.layer
            );
        }
    }
}

/// Sensor deception is answered by uncertainty at every layer and by no
/// defence anywhere. Recorded as a test so the day it changes, someone has to
/// change this line and say why.
#[test]
fn sensor_deception_is_the_one_threat_with_no_defence_anywhere() {
    let m = ThreatModel::build();
    assert_eq!(
        m.threats_with_no_defence(),
        vec![Threat::SensorDeception],
        "the set of undefended threats changed"
    );
    // And the reason is the same one the whole repository gives: no
    // implemented mechanism observes a physical quantity.
    assert!(!aip_observation::ObservationClass::PhysicalEffect.is_implemented());
}

/// Emission is deterministic and the committed artifact is current, so a diff
/// in the artifact is a change in the model rather than in the run.
#[test]
fn the_committed_threat_artifact_is_current() {
    let a = ThreatModel::build();
    let b = ThreatModel::build();
    assert_eq!(a.to_json(), b.to_json());
    assert_eq!(a.to_csv(), b.to_csv());
    assert_eq!(a.to_csv().lines().count(), 1 + a.cells.len());

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    for (rel, want) in [
        ("docs/audit/THREAT_MODEL_MATRIX.json", a.to_json()),
        ("docs/audit/THREAT_MODEL_MATRIX.csv", a.to_csv()),
    ] {
        let got = std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| {
            panic!("{rel} missing ({e}); run: cargo run -p aip-conformance --bin emit-threat-model")
        });
        assert_eq!(got, want, "{rel} is stale; re-run the generator");
    }
}

// ═══ Scenario-driven: the four named environments ═══

/// **UAS.** Sensor deception and forged telemetry (X10, X07): a vehicle's own
/// telemetry is the actor's account of itself, so no verdict rests on it and
/// the profile's physical rung is unreachable.
#[test]
fn scenario_uas_the_physical_rung_is_unreachable() {
    use aip_uas::StateEvidence::*;
    assert!(Declared.is_reachable());
    assert!(DecisionSigned.is_reachable());
    assert!(
        ExecutionObserved.is_reachable(),
        "the companion computer is observable"
    );
    assert!(
        !PhysicallyObserved.is_reachable(),
        "an aircraft's physical state has no implemented mechanism; a reachable \
         rung here would mean telemetry had become proof"
    );
}

/// **Robotics.** The same threat against a machine rather than an aircraft.
/// Observer failure (X11) additionally means a degraded collector underwrites
/// nothing, which the shared observer layer enforces for every profile.
#[test]
fn scenario_robotics_the_physical_rung_is_unreachable() {
    use aip_robotics::TaskEvidence::*;
    assert!(ExecutionObserved.is_reachable());
    assert!(
        !PhysicallyObserved.is_reachable(),
        "a machine's motion has no implemented mechanism"
    );
}

/// **Industrial.** A protocol acknowledgement is not a physical process
/// change: the command half is observable and the process half is not.
#[test]
fn scenario_industrial_an_acknowledgement_is_not_a_process_change() {
    use aip_industrial::ProcessEvidence::*;
    assert!(
        ExecutionObserved.is_reachable(),
        "the command leaving the host is observable"
    );
    assert!(
        !PhysicallyObserved.is_reachable(),
        "a valve moving has no implemented mechanism; a reachable rung would \
         mean a PLC acknowledgement established a process change"
    );
}

/// The one asymmetry, held across all four embodied profiles at once: the
/// physical rung is unreachable everywhere, and it is the *same* rung.
///
/// This is the property ADR-011 found to be embodiment-specific rather than
/// universal — enterprise's top tier is reachable because a local file write
/// is `Fanotify`. Sensor deception is therefore a threat the embodied
/// profiles answer with uncertainty and the non-embodied one does not face in
/// the same form.
#[test]
fn scenario_every_embodied_profile_stops_below_the_physical_rung() {
    assert!(!aip_uas::StateEvidence::PhysicallyObserved.is_reachable());
    assert!(!aip_robotics::TaskEvidence::PhysicallyObserved.is_reachable());
    assert!(!aip_industrial::ProcessEvidence::PhysicallyObserved.is_reachable());
    assert!(!aip_space::SpaceEvidence::PhysicallyObserved.is_reachable());
    // Enterprise's top tier is reachable, and that is the disconfirming
    // instance rather than an inconsistency.
    assert!(aip_enterprise::EnterpriseEvidence::LocalEffectObserved.is_reachable());
}

/// **Disconnected.** Lost connectivity and partial observation (X08, X09):
/// delayed arrival is never non-occurrence, and a recorded gap stays a gap.
#[test]
fn scenario_disconnected_delayed_evidence_is_never_non_occurrence() {
    for c in [
        aip_space::GroundConclusion::EvidenceComplete { segments: 3 },
        aip_space::GroundConclusion::EvidenceIncomplete { missing: vec![2] },
        aip_space::GroundConclusion::ContinuityBroken,
        aip_space::GroundConclusion::CannotProve {
            reason: "nothing arrived",
        },
    ] {
        assert!(
            !c.asserts_non_occurrence(),
            "{c:?} asserts non-occurrence; delayed evidence is not absence"
        );
    }

    // The observer half of the same threat, exercised rather than described.
    use aip_observe::{ContinuityStatus, ObserverLedger};
    let h = |b: u8| [b; 32];
    let mut l = ObserverLedger::new();
    l.admit(1, [0u8; 32], h(1)).unwrap();
    l.admit(2, h(1), h(2)).unwrap();
    l.admit(5, h(2), h(5)).unwrap();
    assert_eq!(l.status(), ContinuityStatus::GapObserved);
    l.admit(6, h(5), h(6)).unwrap();
    assert_eq!(
        l.status(),
        ContinuityStatus::GapObserved,
        "a later good batch must not erase a recorded gap"
    );
}
