//! Deterministic offline re-derivation of a checked-in collector trace.
//!
//! The trace in `../../traces/ROBOTICS-PHYSICAL-OBSERVATION-001-synthetic-seed1`
//! was produced by a real OpenCV/AprilTag detector over a synthetically rendered
//! scene. These tests re-derive the admission verdicts from the stored bytes
//! alone, with no camera, no detector and no clock.
//!
//! What this establishes: the classification is reproducible from the artefact.
//! What it does not establish: anything physical. The scene was rendered.

use std::path::PathBuf;

use vanian_external_adapter::{
    admit, Admission, AdmissionLedger, AdmissionPolicy, ExternalObservation, ObserverPosture,
    ProvenanceClass, RefusalReason,
};

fn trace_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../traces/ROBOTICS-PHYSICAL-OBSERVATION-001-synthetic-seed1")
}

fn load() -> Vec<ExternalObservation> {
    let text = std::fs::read_to_string(trace_dir().join("observations.json"))
        .expect("the checked-in trace must be readable");
    let values: Vec<serde_json::Value> = serde_json::from_str(&text).expect("valid json");
    values
        .into_iter()
        .filter_map(|v| serde_json::from_value(v).ok())
        .collect()
}

fn admit_all(observations: &[ExternalObservation], posture: ObserverPosture) -> Vec<Admission> {
    let mut ledger = AdmissionLedger::new();
    observations
        .iter()
        .map(|o| {
            admit(
                o,
                posture,
                o.timestamp_ms,
                AdmissionPolicy {
                    freshness_bound_ms: 30_000,
                },
                &mut ledger,
            )
        })
        .collect()
}

#[test]
fn the_checked_in_trace_loads_and_its_raw_layer_is_intact() {
    let obs = load();
    assert_eq!(obs.len(), 3, "two poses and one displacement");
    for o in &obs {
        assert!(
            o.raw_integrity_holds(),
            "{}: the stored raw bytes no longer hash to their capture digest",
            o.source
        );
    }
}

#[test]
fn the_real_detector_measured_the_displacement_the_scene_was_rendered_with() {
    // The scene put the tag at x=200 px and then x=600 px. The detector, which
    // was not told that, reported 400 px. This is a fact about OpenCV, not
    // about any robot.
    let obs = load();
    let displacement = obs
        .iter()
        .find(|o| o.event_type == vanian_external_adapter::EventType::Displacement)
        .expect("a displacement record");
    let px = displacement.payload["displacement_px"].as_f64().unwrap();
    assert!(
        (px - 400.0).abs() < 1.0,
        "expected ~400 px of rendered displacement, detector said {px}"
    );
}

#[test]
fn every_synthetic_record_is_refused_as_a_physical_claim() {
    // The run's actual result, re-derived. A rendered scene is not an
    // observation of any world, and the adapter says so per record.
    let obs = load();
    for (o, a) in obs.iter().zip(admit_all(&obs, ObserverPosture::Present)) {
        assert_eq!(o.provenance_class, ProvenanceClass::SimulatorGroundTruth);
        assert_eq!(
            a,
            Admission::Refused {
                reason: RefusalReason::SimulatorGroundTruthOfferedAsPhysical
            },
            "{}",
            o.source
        );
        assert!(!a.supports_physical_effect());
    }
}

#[test]
fn the_observer_posture_changes_the_refusal_and_never_the_conclusion() {
    let obs = load();
    for posture in [
        ObserverPosture::Unavailable,
        ObserverPosture::IntegrityUnknown,
        ObserverPosture::PresentAndSilent,
    ] {
        for a in admit_all(&obs, posture) {
            assert!(!a.is_admitted(), "{posture:?}");
            assert!(!a.supports_physical_effect(), "{posture:?}");
        }
    }
}

#[test]
fn the_counterfactual_anchored_camera_reaches_corroboration_and_stops() {
    // A counterfactual, labelled as one: the same measured geometry, relabelled
    // as if it had come from a real camera behind an anchored collector.
    //
    // It is here to show what the pivotal experiment would produce if the
    // hardware existed — CORROBORATION, and not a physical-effect claim,
    // because no SourceMechanism carries an optical observation. Nobody should
    // read this test as evidence that a camera was used. None was.
    let mut obs = load();
    for o in &mut obs {
        o.provenance_class = ProvenanceClass::ExternalSensorAnchored;
    }
    let verdicts = admit_all(&obs, ObserverPosture::Present);
    for (o, a) in obs.iter().zip(&verdicts) {
        assert_eq!(
            *a,
            Admission::AdmittedAsCorroboration {
                ceiling: aip_observation::EvidenceCeiling::Corroborative
            },
            "{}",
            o.source
        );
        assert!(
            !a.supports_physical_effect(),
            "an anchored external camera still does not reach a physical-effect claim"
        );
        assert!(!matches!(a, Admission::EligibleForObservationRecord { .. }));
    }
}

#[test]
fn replaying_the_same_trace_twice_through_one_ledger_refuses_the_second_pass() {
    let obs = load();
    let mut ledger = AdmissionLedger::new();
    let policy = AdmissionPolicy {
        freshness_bound_ms: 30_000,
    };
    // Relabel so the records are admissible at all, then offer each twice.
    let mut anchored = obs.clone();
    for o in &mut anchored {
        o.provenance_class = ProvenanceClass::ExternalSensorAnchored;
    }
    for o in &anchored {
        assert!(admit(
            o,
            ObserverPosture::Present,
            o.timestamp_ms,
            policy,
            &mut ledger
        )
        .is_admitted());
    }
    for o in &anchored {
        assert!(matches!(
            admit(
                o,
                ObserverPosture::Present,
                o.timestamp_ms,
                policy,
                &mut ledger
            ),
            Admission::Refused {
                reason: RefusalReason::Replay { .. }
            }
        ));
    }
    assert_eq!(ledger.len(), anchored.len());
}

#[test]
fn the_manifest_records_that_no_physical_claim_is_supported() {
    let text = std::fs::read_to_string(trace_dir().join("manifest.json")).expect("manifest");
    let m: serde_json::Value = serde_json::from_str(&text).expect("valid json");
    assert_eq!(m["physical_claim_supported"], serde_json::json!(false));
    assert_eq!(m["calibration_performed"], serde_json::json!(false));
    assert_eq!(m["marker_attachment_verified"], serde_json::json!(false));
    assert_eq!(m["source_mode"], serde_json::json!("synthetic"));
}
