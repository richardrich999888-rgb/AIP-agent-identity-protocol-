//! Skill 10 Gate 2 — cryptographic binding, RED.
//!
//! Gate 1 made a package that cannot omit a dependency quietly. This gate
//! makes one whose components cannot be **swapped**. A proof for execution
//! A must not survive having identity B, authority C, expectation D,
//! observer E, lineage F, reconciliation G, a warrant for another record or
//! a commitment to other bytes pushed into it.
//!
//! Two independent defences, and every test below exercises at least one:
//!
//! 1. **Agreement.** The components must agree with each other by digest,
//!    id, sequence and head — checked by [`NexoraProof::binding_faults`]
//!    with no signature verification at all, so a transplant is visible
//!    even in an unsealed package a verifier has not yet anchored.
//! 2. **The envelope.** When an assembler sealed the package, the seal is
//!    over every byte, so any transplant breaks it.
//!
//! Neither defence is allowed to be the only one: agreement without the
//! seal still catches a swap, and the seal without agreement still catches
//! a swap.

mod common;

use aip_nexora::proof::*;
use aip_nexora::{LeafKind, NexoraTrustAnchors};
use aip_observe::ObserverAttestor;

/// Two independent scenarios: A is the package under test, B is where a
/// transplanted component comes from.
fn two() -> (common::Scenario, common::Scenario) {
    (common::verified_execution(), common::verified_execution())
}

fn package(s: &common::Scenario) -> NexoraProof {
    NexoraProof::builder(s.a.agent_id.clone(), s.reconciliation.clone())
        .issued_at(s.at + 1)
        .authority(s.a.root.clone(), s.a.chain.clone())
        .expectation(s.a.ee.clone())
        .observer(s.evidence.batches.clone(), s.evidence.health.clone())
        .parameters(DeclaredParameters {
            verification_time_ms: s.at,
            health_max_age_ms: common::HEALTH_MAX_AGE,
            window_tolerance_ms: 0,
            agent_key_supplied: true,
        })
        .build()
}

// ═══ A well-formed package has no faults ═══

#[test]
fn b01_a_package_whose_components_come_from_one_execution_binds() {
    let s = common::verified_execution();
    let p = package(&s);
    assert!(
        p.structural_faults().is_empty(),
        "{:?}",
        p.structural_faults()
    );
    assert!(p.binding_faults().is_empty(), "{:?}", p.binding_faults());
    assert!(p.faults().is_empty(), "faults() is the union");
}

// ═══ Identity substitution ═══

#[test]
fn b02_another_agents_identity_document_does_not_bind() {
    let (a, b) = two();
    let mut p = package(&a);
    // B's identity document, on A's package.
    let doc = aip_core::create_identity(common::provenance("stranger"), None)
        .unwrap()
        .0;
    p.subject.identity = Some(doc);
    assert!(
        p.binding_faults()
            .iter()
            .any(|f| matches!(f, BindingFault::IdentityIsNotTheSubject { .. })),
        "{:?}",
        p.binding_faults()
    );
    let _ = b;
}

// ═══ Authority substitution ═══

#[test]
fn b03_an_authority_the_expectation_was_not_issued_under_does_not_bind() {
    let (a, b) = two();
    let mut p = package(&a);
    // B's root token and chain, on A's expectation.
    p.authority = Some(AuthorityEvidence {
        root: b.a.root.clone(),
        chain: b.a.chain.clone(),
    });
    assert!(
        p.binding_faults()
            .iter()
            .any(|f| matches!(f, BindingFault::AuthorityNotTheExpectations)),
        "{:?}",
        p.binding_faults()
    );

    // A truncated chain is equally a different authority.
    let mut p = package(&a);
    p.authority = Some(AuthorityEvidence {
        root: a.a.root.clone(),
        chain: vec![],
    });
    assert!(p
        .binding_faults()
        .iter()
        .any(|f| matches!(f, BindingFault::AuthorityNotTheExpectations)));
}

// ═══ Execution / expectation substitution ═══

#[test]
fn b04_another_executions_expectation_does_not_bind() {
    let (a, b) = two();
    let mut p = package(&a);
    p.expectation = Some(b.a.ee.clone());
    let faults = p.faults();
    assert!(
        faults.iter().any(|f| matches!(
            f,
            ProofFault::Structural(StructuralFault::ExpectationDecisionMismatch)
        )),
        "{faults:?}"
    );
}

// ═══ Observer substitution ═══

#[test]
fn b05_another_observers_records_do_not_bind() {
    let (a, b) = two();
    let mut p = package(&a);
    // B's batches and health, on A's claim. The observer id is shared,
    // but its keys and batch heads differ. Sequence counters and millisecond
    // timestamps can coincide; neither is a cryptographic identity.
    p.observer = Some(ObserverBundle {
        batches: b.evidence.batches.clone(),
        health: b.evidence.health.clone(),
    });
    let faults = p.binding_faults();
    assert!(
        faults
            .iter()
            .any(|f| matches!(f, BindingFault::CitedBatchHeadMismatch { .. })),
        "{faults:?}"
    );

    // Dropping a cited batch entirely.
    let mut p = package(&a);
    p.observer = Some(ObserverBundle {
        batches: vec![a.evidence.batches[0].clone()],
        health: a.evidence.health.clone(),
    });
    assert!(
        p.binding_faults()
            .iter()
            .any(|f| matches!(f, BindingFault::CitedBatchNotCarried { .. })),
        "{:?}",
        p.binding_faults()
    );

    // A health record with explicitly different cited metadata. Two fast
    // release scenarios can otherwise share both sequence and millisecond.
    let other_health =
        b.o.signer
            .health(
                a.evidence
                    .health
                    .health
                    .emitted_at_ms
                    .checked_add(1)
                    .unwrap(),
            )
            .unwrap();
    assert_ne!(
        other_health.health.emitted_at_ms,
        a.evidence.health.health.emitted_at_ms
    );
    let mut p = package(&a);
    p.observer = Some(ObserverBundle {
        batches: a.evidence.batches.clone(),
        health: other_health,
    });
    assert!(
        p.binding_faults()
            .iter()
            .any(|f| matches!(f, BindingFault::CitedHealthNotCarried { .. })),
        "{:?}",
        p.binding_faults()
    );
}

// ═══ Continuity substitution ═══

#[test]
fn b06_a_continuity_report_from_another_observer_does_not_bind() {
    let s = common::verified_execution();
    let mut p = package(&s);
    let report = common::continuity_report_of("someone-else");
    p.continuity = Some(report);
    assert!(
        p.binding_faults()
            .iter()
            .any(|f| matches!(f, BindingFault::ContinuityForAnotherObserver { .. })),
        "{:?}",
        p.binding_faults()
    );
    // The carried observer's own report binds.
    let mut ok = package(&s);
    ok.continuity = Some(common::continuity_report_of(common::OBSERVER_ID));
    assert!(ok.binding_faults().is_empty(), "{:?}", ok.binding_faults());
}

// ═══ Lineage substitution ═══

#[test]
fn b07_lineage_that_names_the_subject_as_its_own_parent_does_not_bind() {
    let s = common::verified_execution();
    let mut p = package(&s);
    p.lineage = Some(LineageEvidence {
        // The subject's own expectation offered as a *peer* — self-lineage.
        peer_expectations: vec![s.a.ee.clone()],
        identity: None,
        revoked_jtis: vec![],
    });
    assert!(
        p.binding_faults()
            .iter()
            .any(|f| matches!(f, BindingFault::LineagePeerIsTheSubject { .. })),
        "{:?}",
        p.binding_faults()
    );
}

// ═══ Reconciliation substitution ═══

#[test]
fn b08_another_executions_verdict_does_not_bind() {
    let (a, b) = two();
    let mut p = package(&a);
    // B's record, on A's evidence.
    p.claim = b.reconciliation.clone();
    let faults = p.faults();
    assert!(
        faults.iter().any(|f| matches!(
            f,
            ProofFault::Structural(StructuralFault::ExpectationDecisionMismatch)
        )) || faults.iter().any(|f| matches!(
            f,
            ProofFault::Binding(BindingFault::CitedBatchHeadMismatch { .. })
        )),
        "{faults:?}"
    );
}

// ═══ Warrant substitution ═══

#[test]
fn b09_a_warrant_for_another_record_or_another_subject_does_not_bind() {
    let (a, b) = two();
    let mut p = package(&a);
    p.warrant = Some(common::warrant_for(&b.reconciliation, Some(&b.a.agent_id)));
    let faults = p.binding_faults();
    assert!(
        faults
            .iter()
            .any(|f| matches!(f, BindingFault::WarrantForAnotherRecord)),
        "{faults:?}"
    );

    // Right record, wrong subject.
    let mut p = package(&a);
    p.warrant = Some(common::warrant_for(&a.reconciliation, Some("aip1other")));
    assert!(
        p.binding_faults()
            .iter()
            .any(|f| matches!(f, BindingFault::WarrantForAnotherSubject { .. })),
        "{:?}",
        p.binding_faults()
    );

    // The warrant that actually rests on this record binds.
    let mut ok = package(&a);
    ok.warrant = Some(common::warrant_for(&a.reconciliation, Some(&a.a.agent_id)));
    assert!(ok.binding_faults().is_empty(), "{:?}", ok.binding_faults());
}

// ═══ Commitment substitution ═══

#[test]
fn b10_a_commitment_to_other_bytes_does_not_bind() {
    let (a, b) = two();
    // A commitment to B's record, carried by A's package.
    let (proof_object, _anchors) = common::commit(&b.reconciliation);
    let mut p = package(&a);
    p.commitment = Some(proof_object);
    assert!(
        p.binding_faults()
            .iter()
            .any(|f| matches!(f, BindingFault::CommitmentIsNotOfTheClaim)),
        "{:?}",
        p.binding_faults()
    );

    // A commitment of the right bytes under the wrong leaf kind.
    let (mut wrong_kind, _) = common::commit(&a.reconciliation);
    wrong_kind.kind = LeafKind::Warrant;
    let mut p = package(&a);
    p.commitment = Some(wrong_kind);
    assert!(p
        .binding_faults()
        .iter()
        .any(|f| matches!(f, BindingFault::CommitmentIsNotOfTheClaim)));

    // The commitment of this claim binds.
    let (right, _) = common::commit(&a.reconciliation);
    let mut ok = package(&a);
    ok.commitment = Some(right);
    assert!(ok.binding_faults().is_empty(), "{:?}", ok.binding_faults());
}

// ═══ Algorithm confusion ═══

#[test]
fn b11_a_signature_declaring_an_algorithm_nobody_implements_is_a_fault() {
    let s = common::verified_execution();
    let mut p = package(&s);
    // The expectation's signature relabelled as post-quantum. Nothing in
    // this repository implements ML-DSA; a package must say so rather than
    // check the bytes as Ed25519 anyway.
    p.expectation.as_mut().unwrap().decision_sig.algorithm = aip_types::AlgorithmId::MlDsa65;
    let faults = p.binding_faults();
    assert!(
        faults
            .iter()
            .any(|f| matches!(f, BindingFault::UnsupportedAlgorithm { .. })),
        "{faults:?}"
    );
    // And the relabelling moves the bytes, so a seal over them breaks too.
    let kp = aip_crypto::generate_ed25519_keypair();
    let asm = ProofAssembler::new("asm", 1, &kp.private_key, &kp.public_key).unwrap();
    let sealed = asm.seal(package(&s)).unwrap();
    let mut tampered = sealed.clone();
    tampered
        .expectation
        .as_mut()
        .unwrap()
        .decision_sig
        .algorithm = aip_types::AlgorithmId::MlDsa65;
    let anchors = NexoraTrustAnchors::new().trust("asm", 1, &kp.public_key);
    assert!(verify_envelope(&sealed, &anchors).is_ok());
    assert!(verify_envelope(&tampered, &anchors).is_err());
}

// ═══ The seal catches every transplant, independently of agreement ═══

#[test]
fn b12_a_seal_is_broken_by_every_component_substitution() {
    let (a, b) = two();
    let kp = aip_crypto::generate_ed25519_keypair();
    let asm = ProofAssembler::new("asm", 1, &kp.private_key, &kp.public_key).unwrap();
    let anchors = NexoraTrustAnchors::new().trust("asm", 1, &kp.public_key);
    let sealed = asm.seal_at(package(&a), 1_700_000_000_000).unwrap();
    assert!(verify_envelope(&sealed, &anchors).is_ok());

    type Swap = Box<dyn Fn(&mut NexoraProof)>;
    let swaps: Vec<(&str, Swap)> = vec![
        (
            "subject",
            Box::new(|p: &mut NexoraProof| p.subject.agent_id = "aip1other".into()),
        ),
        ("authority", {
            let root = b.a.root.clone();
            let chain = b.a.chain.clone();
            Box::new(move |p: &mut NexoraProof| {
                p.authority = Some(AuthorityEvidence {
                    root: root.clone(),
                    chain: chain.clone(),
                })
            })
        }),
        ("expectation", {
            let ee = b.a.ee.clone();
            Box::new(move |p: &mut NexoraProof| p.expectation = Some(ee.clone()))
        }),
        ("observer", {
            let batches = b.evidence.batches.clone();
            let health = b.evidence.health.clone();
            Box::new(move |p: &mut NexoraProof| {
                p.observer = Some(ObserverBundle {
                    batches: batches.clone(),
                    health: health.clone(),
                })
            })
        }),
        ("claim", {
            let r = b.reconciliation.clone();
            Box::new(move |p: &mut NexoraProof| p.claim = r.clone())
        }),
        (
            "parameters",
            Box::new(|p: &mut NexoraProof| p.parameters.window_tolerance_ms += 1),
        ),
        (
            "issued_at",
            Box::new(|p: &mut NexoraProof| p.issued_at_ms += 1),
        ),
        (
            "sealed_at",
            Box::new(|p: &mut NexoraProof| {
                p.envelope.as_mut().unwrap().sealed_at_ms += 1;
            }),
        ),
    ];
    for (name, swap) in swaps {
        let mut t = sealed.clone();
        swap(&mut t);
        assert!(
            verify_envelope(&t, &anchors).is_err(),
            "the seal survived a {name} substitution"
        );
    }
}

#[test]
fn b13_coincident_health_metadata_does_not_bypass_signature_or_envelope_verification() {
    let (a, b) = two();
    let collision =
        b.o.signer
            .health(a.evidence.health.health.emitted_at_ms)
            .unwrap();
    assert_eq!(collision.health.sequence, a.evidence.health.health.sequence);
    assert_eq!(
        collision.health.emitted_at_ms,
        a.evidence.health.health.emitted_at_ms
    );
    assert_ne!(a.o.public_key, b.o.public_key);
    assert!(aip_observe::verify_signed_health(&collision, &b.o.anchors).is_ok());
    assert!(aip_observe::verify_signed_health(&collision, &a.o.anchors).is_err());

    let kp = aip_crypto::generate_ed25519_keypair();
    let assembler = ProofAssembler::new("asm", 1, &kp.private_key, &kp.public_key).unwrap();
    let anchors = NexoraTrustAnchors::new().trust("asm", 1, &kp.public_key);
    let sealed = assembler.seal(package(&a)).unwrap();
    assert!(verify_envelope(&sealed, &anchors).is_ok());
    let mut transplanted = sealed.clone();
    transplanted.observer.as_mut().unwrap().health = collision;
    // Structural sequence/time agreement cannot authenticate another key's
    // record. Existing health signatures and the sealed bytes still refuse it.
    assert!(transplanted.binding_faults().is_empty());
    assert!(verify_envelope(&transplanted, &anchors).is_err());
}
