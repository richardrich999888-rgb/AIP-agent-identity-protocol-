//! Skill 20 — the 25 failure classes.
//!
//! # What these tests establish, precisely
//!
//! An `ObservationRecord` is unsigned in itself, like every Skill 17-19
//! record. What is established is twofold:
//!
//! 1. **It cannot be constructed at all** without a batch that verifies
//!    against the verifier's own anchors. That is a hard boundary, not a
//!    convention — a compromised agent has no function to call.
//! 2. Once built, every identity it carries is inside its canonical preimage,
//!    so a substitution changes the digest and cannot be silent.
//!
//! Prevention of forgery is the observer's signature, checked here at
//! construction. Prevention of relabelling is the encoding.

use aip_observation::*;
use aip_observe::{ObserverTrustAnchors, SourceMechanism};

mod support;
use support::*;

// ═══ 1-4. The subject cannot manufacture, replay or relabel ═══

#[test]
fn f01_a_subject_cannot_fabricate_an_observation() {
    // The core architectural principle. There is no constructor taking an
    // AIRI event, a self-reported ExecutionBinding, or raw bytes — the only
    // one takes an AttestedBatch plus the verifier's anchors. This is
    // enforced by the type system and cannot be asserted at runtime; what is
    // asserted is the consequence: a batch the verifier does not anchor
    // produces nothing.
    let mut o = observer();
    let batch = batch_on(&mut o, BOOT_P, SourceMechanism::PidFdAnchored, 1);

    // A "subject" holding the batch but not the verifier's trust.
    let subject_anchors = ObserverTrustAnchors::new();
    let forged = ObservationRecord::from_attested(
        &batch,
        &subject_anchors,
        0,
        correlation(BOOT_P, EXEC_A, "sys:fleet-1"),
    );
    assert!(
        matches!(forged, Err(ObservationError::ObserverNotTrusted { .. })),
        "SECURITY: an observation was produced without the verifier's anchors"
    );

    // The same batch under the anchors that do trust it works — so the
    // refusal is about trust, not a broken fixture.
    assert!(ObservationRecord::from_attested(
        &batch,
        &o.anchors,
        0,
        correlation(BOOT_P, EXEC_A, "sys:fleet-1")
    )
    .is_ok());
}

#[test]
fn f02_f18_a_replayed_observation_cannot_serve_another_execution() {
    // A genuine, correctly signed observation, re-presented as evidence about
    // a different execution. The correlation is inside the preimage, so the
    // relabelled record has a different digest — and `describes` refuses it
    // for the execution it does not name.
    let a = record_on(BOOT_P, SourceMechanism::PidFdAnchored);

    let mut o = observer();
    let batch = batch_on(&mut o, BOOT_P, SourceMechanism::PidFdAnchored, 1);
    let b = ObservationRecord::from_attested(
        &batch,
        &o.anchors,
        0,
        correlation(BOOT_P, EXEC_B, "sys:fleet-1"),
    )
    .expect("verifies");

    assert_ne!(
        a.digest(),
        b.digest(),
        "SECURITY: the same observation relabelled onto another execution kept \
         its digest"
    );
    assert!(a.describes(&system("sys:fleet-1"), &EXEC_A));
    assert!(
        !a.describes(&system("sys:fleet-1"), &EXEC_B),
        "SECURITY: an observation served as evidence for an execution it does \
         not describe"
    );
}

#[test]
fn f03_f17_changing_the_system_identity_changes_the_record() {
    let a = record_on(BOOT_P, SourceMechanism::PidFdAnchored);
    let mut o = observer();
    let batch = batch_on(&mut o, BOOT_P, SourceMechanism::PidFdAnchored, 1);
    let other_system = ObservationRecord::from_attested(
        &batch,
        &o.anchors,
        0,
        correlation(BOOT_P, EXEC_A, "sys:fleet-2"),
    )
    .expect("verifies");

    assert_ne!(a.digest(), other_system.digest());
    assert!(
        !other_system.describes(&system("sys:fleet-1"), &EXEC_A),
        "SECURITY: an observation about another system was accepted"
    );
}

#[test]
fn f04_f16_a_record_may_not_claim_a_host_the_observer_did_not_measure() {
    // The relabelling attack that would otherwise survive: the batch verifies,
    // the observation is real, and the correlation names a *different* boot.
    // The observation would be genuine and the platform binding a fiction.
    let mut o = observer();
    let batch = batch_on(&mut o, BOOT_P, SourceMechanism::PidFdAnchored, 1);

    let lied = ObservationRecord::from_attested(
        &batch,
        &o.anchors,
        0,
        correlation(BOOT_Q, EXEC_A, "sys:fleet-1"),
    );
    assert!(
        matches!(lied, Err(ObservationError::Malformed { .. })),
        "SECURITY: a record claimed a host-boot the observer never measured"
    );
}

// ═══ 5-8. Observer authority ═══

#[test]
fn f06_f07_an_unregistered_observer_or_wrong_key_version_is_refused() {
    let mut o = observer_named("collector-o", 1);
    let batch = batch_on(&mut o, BOOT_P, SourceMechanism::PidFdAnchored, 1);

    // Right observer id, wrong key version.
    let wrong_version = ObserverTrustAnchors::new().trust("collector-o", 2, &o.keys.public_key);
    assert!(
        ObservationRecord::from_attested(
            &batch,
            &wrong_version,
            0,
            correlation(BOOT_P, EXEC_A, "sys:fleet-1")
        )
        .is_err(),
        "SECURITY: a batch verified under a key version the verifier did not anchor"
    );

    // Unregistered observer entirely.
    let stranger = ObserverTrustAnchors::new().trust(
        "collector-other",
        1,
        &aip_crypto::generate_ed25519_keypair().public_key,
    );
    assert!(ObservationRecord::from_attested(
        &batch,
        &stranger,
        0,
        correlation(BOOT_P, EXEC_A, "sys:fleet-1")
    )
    .is_err());
}

#[test]
fn f08_an_invalid_signature_is_refused() {
    let mut o = observer();
    let mut batch = batch_on(&mut o, BOOT_P, SourceMechanism::PidFdAnchored, 1);
    // Alter a signed field after attestation.
    batch.attested_at_ms += 1;
    assert!(
        ObservationRecord::from_attested(
            &batch,
            &o.anchors,
            0,
            correlation(BOOT_P, EXEC_A, "sys:fleet-1")
        )
        .is_err(),
        "SECURITY: a batch altered after signing produced an observation"
    );
}

#[test]
fn f05_the_collector_clock_is_carried_so_staleness_is_visible() {
    // An observer signing stale data cannot hide when it signed: the
    // collector's own clock is inside the signed batch and is carried into the
    // record, so a verifier can bound when the collector had the batch. The
    // record does not judge staleness — that is the verifier's window.
    let r = record_on(BOOT_P, SourceMechanism::PidFdAnchored);
    assert!(r.attested_at_ms() > 0);
    // And it is committed, so it cannot be adjusted after the fact.
    let bytes = r.canonical_bytes();
    assert!(bytes
        .windows(8)
        .any(|w| w == r.attested_at_ms().to_le_bytes()));
}

// ═══ 9-12. Duplication, ordering, absence ═══

#[test]
fn f09_f10_chain_position_distinguishes_duplicate_and_reordered_batches() {
    // The collector assigns sequence off-host; the host cannot choose it. Two
    // observations from different chain positions are different records even
    // when they observe identical facts.
    let mut o = observer();
    let b1 = batch_on(&mut o, BOOT_P, SourceMechanism::PidFdAnchored, 1);
    let b2 = batch_on(&mut o, BOOT_P, SourceMechanism::PidFdAnchored, 2);
    let c = correlation(BOOT_P, EXEC_A, "sys:fleet-1");

    let r1 = ObservationRecord::from_attested(&b1, &o.anchors, 0, c.clone()).unwrap();
    let r2 = ObservationRecord::from_attested(&b2, &o.anchors, 0, c).unwrap();

    assert_ne!(r1.sequence(), r2.sequence());
    assert_ne!(
        r1.digest(),
        r2.digest(),
        "SECURITY: two chain positions produced the same record digest"
    );
}

#[test]
fn f11_f12_missing_and_partial_observation_are_not_proof_of_absence() {
    // The failure this whole module exists to prevent. Three distinct states,
    // and none of them says the event did not happen.
    let profile = ObservationProfile::new("collector-o")
        .unwrap()
        .with_mechanism(SourceMechanism::PidFdAnchored);

    // Observable, nothing recorded.
    assert_eq!(
        profile.completeness_without_evidence(ObservationClass::ProcessIdentity),
        Completeness::NotObserved
    );
    // Not observable at all here.
    assert_eq!(
        profile.completeness_without_evidence(ObservationClass::PhysicalEffect),
        Completeness::NotObservable
    );
    // Neither asserts an observation...
    for c in [Completeness::NotObserved, Completeness::NotObservable] {
        assert!(
            !c.asserts_observation(),
            "SECURITY: an absence state asserted an observation"
        );
    }
    // ...and the two are distinct, so a blind spot is never summed with a
    // clean look.
    assert_ne!(Completeness::NotObserved, Completeness::NotObservable);
}

// ═══ 13-15. Observer, collector and reboot ═══

#[test]
fn f13_f14_an_undeclared_class_is_not_observable_not_merely_quiet() {
    // Observer or collector unavailable for a class reduces to the same
    // question: can this deployment observe it at all? An empty profile
    // observes nothing, and says so — it does not default to optimism.
    let empty = ObservationProfile::new("collector-o").unwrap();
    for class in ObservationClass::ALL {
        let cap = empty.capability(class);
        assert!(
            !cap.is_observable(),
            "SECURITY: an empty profile claimed to observe {class:?}"
        );
        assert_eq!(
            cap.ceiling(),
            EvidenceCeiling::Corroborative,
            "an undeclared class must default to the lowest ceiling, never an \
             optimistic one"
        );
        assert_eq!(
            empty.completeness_without_evidence(class),
            Completeness::NotObservable
        );
    }
}

#[test]
fn f15_an_observation_after_reboot_describes_a_different_host_boot() {
    // A reboot produces a new boot id, so a record from before it does not
    // describe the host after it. That is correct fail-closed behaviour, and
    // it is why durable hardware identity needs ADR-002.
    let before = record_on(BOOT_P, SourceMechanism::PidFdAnchored);
    let after = record_on(BOOT_Q, SourceMechanism::PidFdAnchored);

    assert!(before.measured_on(&BOOT_P));
    assert!(
        !before.measured_on(&BOOT_Q),
        "SECURITY: a pre-reboot observation described the post-reboot host"
    );
    assert_ne!(before.digest(), after.digest());
}

// ═══ 19-20. Request, execution and effect stay distinct ═══

#[test]
fn f19_f20_no_observation_class_establishes_an_external_effect() {
    // Skill 18's boundary, preserved. Every class states what it cannot
    // establish, and no class's ceiling is a licence to claim an effect.
    for class in ObservationClass::ALL {
        let cannot = class.cannot_establish();
        assert!(!cannot.is_empty(), "{class:?} must state what it cannot do");
    }
    // The classes closest to "an effect happened" say so explicitly.
    assert!(ObservationClass::NetworkWire
        .cannot_establish()
        .contains("remote effect"));
    assert!(ObservationClass::DataTransfer
        .cannot_establish()
        .contains("arrived"));
    assert!(ObservationClass::FilesystemEffect
        .cannot_establish()
        .contains("correct"));
    // And a wire frame cannot even carry a positive finding alone.
    assert_eq!(
        ObservationClass::NetworkWire.ceiling(),
        EvidenceCeiling::Corroborative,
        "SECURITY: a wire frame, which is never bound to a process, was given \
         a ceiling that could carry a positive finding"
    );
}

// ═══ 21-22. Self-report and attestation substitution ═══

#[test]
fn f21_self_report_cannot_be_substituted_for_observer_evidence() {
    // Structural. There is no constructor accepting an AiriEvent, a
    // self-collected ExecutionBinding, or a bare boot id — the type system
    // enforces it, and `tests/guards.rs` asserts no such constructor is added
    // later. What is asserted here is that the record carries the observer's
    // own identity and chain position, which a self-report has no way to
    // supply.
    let r = record_on(BOOT_P, SourceMechanism::PidFdAnchored);
    assert_eq!(r.observer_id(), OBSERVER_ID);
    assert!(r.key_version() > 0);
    // The record names an observer; a self-report names the subject. The two
    // vocabularies do not overlap.
    let json = serde_json::to_string(&r).unwrap();
    assert!(!json.contains("airi"), "no self-report material: {json}");
}

#[test]
fn f22_no_class_accepts_attestation_shaped_material() {
    // ADR-002 stays PROPOSED, and an observer relaying a TPM quote is relaying
    // an attestation — the trust-anchor question is unchanged by which process
    // carries the bytes. No mechanism maps to a class that would accept one,
    // and PhysicalEffect, the class such material would target, has no
    // mechanism at all.
    for m in SourceMechanism::ALL {
        assert_ne!(
            class_of(m),
            ObservationClass::PhysicalEffect,
            "SECURITY: mechanism {m:?} maps to PhysicalEffect. ADR-003 forbids \
             this without an ADR revising it, and ADR-002 remains PROPOSED."
        );
    }
    assert!(
        !ObservationClass::PhysicalEffect.is_implemented(),
        "SECURITY: PhysicalEffect became implemented"
    );
}

// ═══ 23-25. Unsupported claims, malformed input, serialization ═══

#[test]
fn f23_an_authenticated_observer_cannot_exceed_its_class_ceiling() {
    // A correctly anchored observer is still bounded by what its mechanism can
    // establish. Authentication is not correctness.
    let wire = record_on(BOOT_P, SourceMechanism::WireTapAfPacket);
    let profile = ObservationProfile::new("collector-o")
        .unwrap()
        .with_mechanism(SourceMechanism::WireTapAfPacket);

    assert_eq!(
        wire.ceiling_under(&profile),
        EvidenceCeiling::Corroborative,
        "SECURITY: a wiretap observation from a trusted observer was allowed a \
         ceiling above what the mechanism can establish"
    );
    // And a profile cannot lift it.
    assert_eq!(
        ObservationProfile::new("collector-o")
            .unwrap()
            .with_class_at(ObservationClass::NetworkWire, EvidenceCeiling::Proven)
            .err(),
        Some(ObservationError::CeilingRaised {
            class: ObservationClass::NetworkWire
        })
    );
}

#[test]
fn f24_f25_malformed_input_and_round_trips() {
    // Malformed: an index past the end of the batch.
    let mut o = observer();
    let batch = batch_on(&mut o, BOOT_P, SourceMechanism::PidFdAnchored, 1);
    assert!(matches!(
        ObservationRecord::from_attested(
            &batch,
            &o.anchors,
            99,
            correlation(BOOT_P, EXEC_A, "sys:fleet-1")
        ),
        Err(ObservationError::Malformed { .. })
    ));
    // An empty observer id in a profile.
    assert!(ObservationProfile::new("").is_err());
    assert!(ObservationProfile::new(&"x".repeat(129)).is_err());
    assert!(ObservationProfile::new(&"x".repeat(128)).is_ok());

    // Serialization is stable, and there is deliberately no way back.
    //
    // This assertion used to be a JSON round trip, and the round trip *was*
    // the bypass: `Deserialize` constructed a record with no batch and no
    // anchors, which is precisely what claim 1 at the top of this file says is
    // impossible. Writing a record out is still supported; reading one back is
    // not, so the only path to a record remains `from_attested`.
    let r = record_on(BOOT_P, SourceMechanism::PidFdAnchored);
    let json = serde_json::to_string(&r).expect("a record serializes");
    assert!(json.contains("observer_id"), "{json}");
    // Determinism on one record. Two separately built records are not equal —
    // the collector stamps a live clock into each — so encoding one twice is
    // the property that actually holds.
    assert_eq!(r.canonical_bytes(), r.clone().canonical_bytes());
    r.check_version().expect("version accepted");

    // Unknown versions refused, never guessed.
    let mut bad = r.clone();
    for found in [0u16, 2, u16::MAX] {
        bad.version = found;
        assert_eq!(
            bad.check_version(),
            Err(ObservationError::UnsupportedVersion {
                found,
                supported: OBSERVATION_RECORD_VERSION
            })
        );
    }
}

#[test]
fn f25b_every_distinct_context_encodes_distinctly() {
    // Pairwise inequality is not enough: two substitutions landing on one
    // encoding would be a collision even if each differed from the baseline.
    let mut all: Vec<Vec<u8>> = Vec::new();
    for boot in [BOOT_P, BOOT_Q] {
        for m in [
            SourceMechanism::PidFdAnchored,
            SourceMechanism::WireTapAfPacket,
            SourceMechanism::Fanotify,
        ] {
            all.push(record_on(boot, m).canonical_bytes());
        }
    }
    let mut o = observer();
    let batch = batch_on(&mut o, BOOT_P, SourceMechanism::PidFdAnchored, 1);
    for (exec, sys) in [
        (EXEC_B, "sys:fleet-1"),
        (EXEC_A, "sys:fleet-2"),
        (EXEC_B, "sys:fleet-2"),
    ] {
        all.push(
            ObservationRecord::from_attested(&batch, &o.anchors, 0, correlation(BOOT_P, exec, sys))
                .unwrap()
                .canonical_bytes(),
        );
    }
    let n = all.len();
    all.sort();
    all.dedup();
    assert_eq!(
        n,
        all.len(),
        "SECURITY: two distinct contexts encoded identically"
    );
}

/// Claim 1 at the top of this file, enforced rather than asserted in prose.
///
/// A record must be obtainable only from a batch that verifies against the
/// verifier's anchors. `#[derive(Deserialize)]` was a second path — one a
/// compromised agent with a JSON writer could call — and it is gone.
///
/// The guard reads the source because this is a compile-time property: a
/// runtime test cannot demonstrate the absence of a trait implementation, and
/// re-adding the derive would compile cleanly and make every consumer of
/// `describes`, `measured_on` and `ceiling_under` silently accept forgeries.
#[test]
fn a_record_cannot_be_deserialized_into_existence() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/record.rs"),
    )
    .unwrap();
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    let derive = code
        .split("pub struct ObservationRecord {")
        .next()
        .unwrap()
        .lines()
        .rfind(|l| l.trim_start().starts_with("#[derive"))
        .unwrap_or("");
    assert!(
        derive.contains("Serialize"),
        "a record must still be writable: {derive}"
    );
    assert!(
        !derive.contains("Deserialize"),
        "SECURITY: ObservationRecord derives Deserialize, which constructs one \
         with no batch and no anchors, defeating from_attested: {derive}"
    );
    assert!(
        !code.contains("impl<'de> Deserialize<'de> for ObservationRecord"),
        "SECURITY: a hand-written Deserialize is the same bypass"
    );
}
