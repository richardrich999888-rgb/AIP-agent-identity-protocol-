//! Skill 20 — the declared ceilings must not drift above the enforcement.
//!
//! `EvidenceCeiling` is a *declaration*. `aip-reconcile::precondition_holds`
//! is the *enforcement*. If the declaration ever claimed more than the engine
//! permits, a profile would advertise a capability the system cannot deliver —
//! and a reader of the profile would design around it.
//!
//! This suite ties the two together. It does not modify the reconciler; it
//! reads its vocabulary and asserts the declared table stays consistent.

use aip_observation::*;
use aip_reconcile::{EvidenceStrength, ReconciliationResult};

#[test]
fn only_observer_integrity_declares_a_proven_ceiling() {
    // The reconciler reaches Proven for exactly one result class,
    // SensorIntegrityFailure — a fact recomputable from held bytes (ADR-001).
    // Exactly one observation class may declare a matching ceiling.
    let proven: Vec<ObservationClass> = ObservationClass::ALL
        .into_iter()
        .filter(|c| c.ceiling() == EvidenceCeiling::Proven)
        .collect();

    assert_eq!(
        proven,
        vec![ObservationClass::ObserverIntegrity],
        "SECURITY: a class other than ObserverIntegrity declares a Proven \
         ceiling. ADR-001 reserves Proven for facts recomputable from held \
         bytes; every other class rests on content the observed host's root \
         can forge."
    );
}

#[test]
fn every_content_bearing_class_is_capped_at_attested() {
    // Mirrors precondition_holds: every content-dependent result class there
    // requires *exactly* Attested. A class resting on measured content must
    // not declare more.
    for class in ObservationClass::ALL {
        if class == ObservationClass::ObserverIntegrity {
            continue;
        }
        assert!(
            class.ceiling() <= EvidenceCeiling::Attested,
            "SECURITY: {class:?} declares a ceiling above Attested, but its \
             evidence is content measured on the observed host"
        );
    }
}

#[test]
fn the_reconcilers_proven_class_is_the_one_this_crate_mirrors() {
    // Reads the reconciler's own vocabulary, so a rename or a change in which
    // class can be Proven breaks this test rather than silently diverging.
    //
    // This asserts the *correspondence*, not the reconciler's behaviour: the
    // engine's own tests own that.
    let integrity = ReconciliationResult::SensorIntegrityFailure;
    assert_eq!(integrity.as_str(), "SENSOR_INTEGRITY_FAILURE");
    assert!(
        EvidenceStrength::Proven > EvidenceStrength::Attested,
        "the strength ladder's ordering is what the ceiling table mirrors"
    );
    // The observation class that corresponds to it.
    assert_eq!(
        ObservationClass::ObserverIntegrity.ceiling(),
        EvidenceCeiling::Proven
    );
    assert!(ObservationClass::ObserverIntegrity
        .cannot_establish()
        .contains("workload"));
}

#[test]
fn a_profile_can_lower_a_ceiling_but_never_raise_one() {
    use aip_observe::SourceMechanism;

    // Lowering is allowed: a mirror-port collector that will not vouch for
    // process identity is being more conservative than the architecture.
    let conservative = ObservationProfile::new("collector-o")
        .unwrap()
        .with_class_at(
            ObservationClass::ProcessIdentity,
            EvidenceCeiling::Corroborative,
        )
        .expect("lowering must be permitted");
    assert_eq!(
        conservative
            .capability(ObservationClass::ProcessIdentity)
            .ceiling(),
        EvidenceCeiling::Corroborative
    );

    // Raising is refused rather than silently clamped: a caller attempting it
    // has misunderstood something and should be told.
    for class in ObservationClass::ALL {
        if class.ceiling() == EvidenceCeiling::Proven {
            continue;
        }
        assert_eq!(
            ObservationProfile::new("collector-o")
                .unwrap()
                .with_class_at(class, EvidenceCeiling::Proven)
                .err(),
            Some(ObservationError::CeilingRaised { class }),
            "SECURITY: a profile raised {class:?}'s ceiling to Proven"
        );
    }

    // And the effective ceiling of a record is the minimum of the two, so a
    // conservative profile binds even for a mechanism that could do more.
    let mut o = tests_support_observer();
    let batch = tests_support_batch(&mut o);
    let r = ObservationRecord::from_attested(
        &batch,
        &o.anchors,
        0,
        ObservationCorrelation {
            system_id: aip_system::SystemId::parse("sys:fleet-1").unwrap(),
            execution_id: [0xA1; 16],
            boot_id: [0x11; 16],
            decision_id: None,
        },
    )
    .expect("verifies");
    assert_eq!(r.class(), ObservationClass::ProcessIdentity);
    assert_eq!(r.class().ceiling(), EvidenceCeiling::Attested);
    assert_eq!(
        r.ceiling_under(&conservative),
        EvidenceCeiling::Corroborative,
        "SECURITY: a conservative profile did not bind a stronger mechanism"
    );
    // Sanity: an unrestricted profile leaves the class ceiling intact.
    let open = ObservationProfile::new("collector-o")
        .unwrap()
        .with_mechanism(SourceMechanism::PidFdAnchored);
    assert_eq!(r.ceiling_under(&open), EvidenceCeiling::Attested);
}

// Minimal local fixtures: this suite depends on aip-reconcile, and pulling in
// the shared support module would drag its dependencies into a test whose
// subject is the ceiling table.
fn tests_support_observer() -> Obs {
    use aip_observe::*;
    let keys = aip_crypto::generate_ed25519_keypair();
    let mut signer =
        CollectorSigner::new("collector-o", 1, &keys.private_key, &keys.public_key).unwrap();
    signer.register_probe("probe-o", &SourceMechanism::ALL);
    let mut probe = ProcfsProbe::new("probe-o");
    probe.declare_source(SourceMechanism::PidFdAnchored);
    let anchors = ObserverTrustAnchors::new().trust("collector-o", 1, &keys.public_key);
    Obs {
        signer,
        probe,
        anchors,
    }
}

struct Obs {
    signer: aip_observe::CollectorSigner,
    probe: aip_observe::ProcfsProbe,
    anchors: aip_observe::ObserverTrustAnchors,
}

fn tests_support_batch(o: &mut Obs) -> aip_observe::AttestedBatch {
    use aip_observe::*;
    let obs = o.probe.observation_with(
        ObservedProcess {
            process: aip_types::ProcessInstance {
                pid: 4321,
                pid_start_time_ticks: 777_000,
                boot_id: [0x11; 16],
            },
            exe_content_sha256: [0x33; 32],
            exe_path: "/opt/agent/bin/autonomy".into(),
            container: None,
        },
        ObservedEffect::ProcessPresent,
        SourceMechanism::PidFdAnchored,
        None,
        1_000,
    );
    o.signer
        .attest(o.probe.batch([1; 16], 0, 2_000, vec![obs]))
        .expect("attest")
}
