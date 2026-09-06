//! Skill 10 Gates 3–5 — the offline verifier, RED.
//!
//! One suite because the three gates are one act: a party with no network,
//! no services, no database and no relationship to the original collector
//! takes a package and a set of trust anchors it chose itself, and decides
//! what the package establishes.
//!
//! - **Gate 3, commitment.** The package's inclusion proof is checked
//!   against the head it names, and the head against the verifier's NEXORA
//!   anchors. (The tree, its proofs and their adversarial cases —
//!   modified, omitted, inserted, reordered and duplicated leaves, wrong
//!   root, wrong sibling, wrong direction, transplantation, cross-domain,
//!   rollback and fork — are already pinned by `merkle.rs` m01–m16 and
//!   `nexora.rs` x01–x15 and are not duplicated here. What this suite adds
//!   is that a *proof* whose commitment does not commit its own claim is
//!   refused.)
//! - **Gate 4, offline.** Every component is verified under the anchors the
//!   verifier supplied, and a component the package does not carry is
//!   `Absent` rather than assumed.
//! - **Gate 5, faithfulness.** The verifier does not trust the claim. It
//!   re-runs this repository's reconciler over the package's own inputs and
//!   refuses any package whose claimed record is not the one that comes
//!   out. `CANNOT_PROVE` re-derives as `CANNOT_PROVE`; `Attested` never
//!   becomes `Proven`, because nothing here writes either.

mod common;

use aip_nexora::proof::*;
use aip_nexora::verify::*;
use aip_reconcile::{EvidenceStrength, ReconciliationResult};

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

/// The anchors an independent verifier would provision for this scenario.
fn anchors(s: &common::Scenario) -> VerifierAnchors {
    VerifierAnchors {
        decision_point: s.a.dp_anchors.clone(),
        observer: s.o.anchors.clone(),
        warrant: aip_warrant::WarrantTrustAnchors::new(),
        nexora: aip_nexora::NexoraTrustAnchors::new(),
        issuers: s.a.issuer_keys.clone(),
        agent_public_key: Some(s.a.agent_kp.public_key.clone()),
    }
}

// ═══ Gate 4 — what a complete, honest package establishes ═══

#[test]
fn v01_a_complete_package_verifies_offline_against_supplied_anchors() {
    let s = common::verified_execution();
    let v = verify_nexora_proof(&package(&s), &anchors(&s));
    assert_eq!(v.verdict, ProofVerdict::Valid, "{v:#?}");
    assert_eq!(v.proof_id, package(&s).proof_id());
    assert_eq!(v.subject, ComponentVerdict::Verified);
    assert_eq!(v.authority, ComponentVerdict::Verified);
    assert_eq!(v.expectation, ComponentVerdict::Verified);
    assert_eq!(v.observer, ComponentVerdict::Verified);
    assert_eq!(v.continuity, ComponentVerdict::Absent);
    assert_eq!(v.lineage, ComponentVerdict::Absent);
    assert_eq!(v.warrant, ComponentVerdict::Absent);
    assert_eq!(v.commitment, ComponentVerdict::Absent);
    assert_eq!(v.envelope, ComponentVerdict::Absent);
    // The result is the re-derived one, and it equals the claim.
    assert_eq!(v.result, Some(ReconciliationResult::VerifiedExecution));
    assert_eq!(v.strength, Some(EvidenceStrength::Attested));
    assert_eq!(
        v.rederived.as_ref().unwrap().digest(),
        s.reconciliation.digest()
    );
    assert_eq!(v.independence, Independence::Checked);
}

#[test]
fn v02_verification_reads_no_clock_no_network_and_no_state() {
    // Determinism is the observable proxy: the same package and anchors
    // give byte-identical verdicts however many times, and in any order.
    let s = common::verified_execution();
    let p = package(&s);
    let a = anchors(&s);
    let first = verify_nexora_proof(&p, &a);
    for _ in 0..3 {
        let again = verify_nexora_proof(&p, &a);
        assert_eq!(again, first, "verification is a pure function");
    }
}

#[test]
fn v03_an_unanchored_authority_is_unverifiable_not_assumed() {
    let s = common::verified_execution();
    // The verifier trusts no decision point.
    let mut a = anchors(&s);
    a.decision_point = aip_authorize::DecisionPointTrustAnchors::new();
    let v = verify_nexora_proof(&package(&s), &a);
    assert!(
        matches!(v.expectation, ComponentVerdict::Unverifiable(_)),
        "{v:#?}"
    );
    assert_ne!(v.verdict, ProofVerdict::Valid);

    // The verifier trusts no observer.
    let mut a = anchors(&s);
    a.observer = aip_observe::ObserverTrustAnchors::new();
    let v = verify_nexora_proof(&package(&s), &a);
    assert!(matches!(v.observer, ComponentVerdict::Unverifiable(_)));
    assert_ne!(v.verdict, ProofVerdict::Valid);

    // The verifier holds no issuer keys: the authority cannot be checked.
    let mut a = anchors(&s);
    a.issuers = std::collections::HashMap::new();
    let v = verify_nexora_proof(&package(&s), &a);
    assert!(matches!(v.authority, ComponentVerdict::Unverifiable(_)));
    assert_ne!(v.verdict, ProofVerdict::Valid);
}

#[test]
fn v04_the_observer_key_may_not_be_the_agents_own() {
    let s = common::verified_execution();
    let mut a = anchors(&s);
    // The verifier is told the agent's key *is* the observer's key: the
    // observation is then a second self-report, not independent evidence.
    a.agent_public_key = Some(s.o.public_key.clone());
    let v = verify_nexora_proof(&package(&s), &a);
    assert_ne!(v.verdict, ProofVerdict::Valid, "{v:#?}");
    assert!(matches!(v.observer, ComponentVerdict::Unverifiable(_)));
}

// ═══ Gate 5 — the claim is re-derived, never believed ═══

#[test]
fn v05_a_claim_that_does_not_come_out_of_the_evidence_is_refused() {
    let s = common::verified_execution();
    let other = common::verified_execution();
    let mut p = package(&s);
    // Somebody else's verdict, on this evidence.
    p.claim = other.reconciliation.clone();
    let v = verify_nexora_proof(&p, &anchors(&s));
    assert!(
        matches!(v.verdict, ProofVerdict::Invalid(_)),
        "a substituted claim must not verify: {v:#?}"
    );
}

#[test]
fn v06_every_single_field_mutation_of_the_claim_is_refused() {
    let s = common::verified_execution();
    let a = anchors(&s);
    let base = package(&s);
    assert_eq!(verify_nexora_proof(&base, &a).verdict, ProofVerdict::Valid);

    type Mutate = Box<dyn Fn(&mut NexoraProof)>;
    let mutations: Vec<(&str, Mutate)> = vec![
        (
            "result",
            Box::new(|p: &mut NexoraProof| p.claim.result = ReconciliationResult::PhantomClaim),
        ),
        (
            "strength raised to Proven",
            Box::new(|p: &mut NexoraProof| p.claim.strength = EvidenceStrength::Proven),
        ),
        (
            "reason",
            Box::new(|p: &mut NexoraProof| {
                p.claim.reason = aip_reconcile::ReasonCode::NoObserverEvidence
            }),
        ),
        (
            "verification time",
            Box::new(|p: &mut NexoraProof| p.claim.verification_time_ms += 1),
        ),
        (
            "an evidence reference dropped",
            Box::new(|p: &mut NexoraProof| {
                p.claim.evidence.pop();
            }),
        ),
        (
            "replay flag",
            Box::new(|p: &mut NexoraProof| p.claim.replay_detected = true),
        ),
    ];
    for (name, m) in mutations {
        let mut p = base.clone();
        m(&mut p);
        let v = verify_nexora_proof(&p, &a);
        assert!(
            matches!(v.verdict, ProofVerdict::Invalid(_)),
            "mutating the {name} produced a valid proof: {v:#?}"
        );
    }
}

#[test]
fn v07_mutating_the_evidence_changes_what_comes_out_and_the_proof_fails() {
    let s = common::verified_execution();
    let a = anchors(&s);

    // A batch altered after the collector signed it.
    let mut p = package(&s);
    p.observer.as_mut().unwrap().batches[1].batch.claimed_to_ms += 1;
    let v = verify_nexora_proof(&p, &a);
    assert!(matches!(v.verdict, ProofVerdict::Invalid(_)), "{v:#?}");

    // The expectation's binding altered: another process instance.
    let mut p = package(&s);
    p.expectation
        .as_mut()
        .unwrap()
        .execution_binding
        .process
        .pid += 1;
    assert!(matches!(
        verify_nexora_proof(&p, &a).verdict,
        ProofVerdict::Invalid(_)
    ));

    // Evidence removed entirely: the claim is no longer derivable.
    let mut p = package(&s);
    p.observer = None;
    let v = verify_nexora_proof(&p, &a);
    assert!(matches!(v.verdict, ProofVerdict::Invalid(_)), "{v:#?}");
}

#[test]
fn v08_a_cannot_prove_package_verifies_as_cannot_prove_and_is_never_upgraded() {
    let s = common::cannot_prove();
    // The honest package for a CANNOT_PROVE: the expectation, no observer.
    let p = NexoraProof::builder(s.a.agent_id.clone(), s.reconciliation.clone())
        .issued_at(s.at + 1)
        .authority(s.a.root.clone(), s.a.chain.clone())
        .expectation(s.a.ee.clone())
        .parameters(DeclaredParameters {
            verification_time_ms: s.at,
            health_max_age_ms: common::HEALTH_MAX_AGE,
            window_tolerance_ms: 0,
            agent_key_supplied: true,
        })
        .build();
    let v = verify_nexora_proof(&p, &anchors(&s));
    assert_eq!(v.verdict, ProofVerdict::Valid, "{v:#?}");
    assert_eq!(v.result, Some(ReconciliationResult::CannotProve));
    assert_ne!(v.strength, Some(EvidenceStrength::Proven));
    // And the verifier says the observation was not available, rather than
    // saying nothing.
    assert_eq!(v.coverage.observation, ObservationCoverage::Unavailable);
}

// ═══ Independence is reported, never silently skipped ═══

#[test]
fn v09_a_package_assembled_without_the_agent_key_reports_that_it_was_unchecked() {
    let s = common::verified_execution();
    // Assembled with the independence checks skipped.
    let claim = aip_reconcile::reconcile_expectation(
        &s.a.ee,
        Some(&s.evidence),
        &aip_reconcile::ReconciliationContext {
            agent_public_key: None,
            ..s.ctx()
        },
    );
    let p = NexoraProof::builder(s.a.agent_id.clone(), claim)
        .issued_at(s.at + 1)
        .authority(s.a.root.clone(), s.a.chain.clone())
        .expectation(s.a.ee.clone())
        .observer(s.evidence.batches.clone(), s.evidence.health.clone())
        .parameters(DeclaredParameters {
            verification_time_ms: s.at,
            health_max_age_ms: common::HEALTH_MAX_AGE,
            window_tolerance_ms: 0,
            agent_key_supplied: false,
        })
        .build();
    let v = verify_nexora_proof(&p, &anchors(&s));
    assert_eq!(v.verdict, ProofVerdict::Valid, "{v:#?}");
    assert_eq!(
        v.independence,
        Independence::NotChecked,
        "a skipped check is reported, never a pass"
    );
}

// ═══ Gate 3 — the commitment, at the level of a proof ═══

#[test]
fn v10_a_commitment_is_checked_against_the_head_and_the_verifiers_anchors() {
    let s = common::verified_execution();
    let (commitment, nexora_anchors) = common::commit(&s.reconciliation);
    let mut p = package(&s);
    p.commitment = Some(commitment);

    // Without the NEXORA anchor the head cannot be checked.
    let v = verify_nexora_proof(&p, &anchors(&s));
    assert!(
        matches!(v.commitment, ComponentVerdict::Unverifiable(_)),
        "{v:#?}"
    );
    assert_ne!(v.verdict, ProofVerdict::Valid);

    // With it, the inclusion is established and named.
    let mut a = anchors(&s);
    a.nexora = nexora_anchors;
    let v = verify_nexora_proof(&p, &a);
    assert_eq!(v.verdict, ProofVerdict::Valid, "{v:#?}");
    assert_eq!(v.commitment, ComponentVerdict::Verified);
    let inclusion = v
        .inclusion
        .expect("the verifier names where it was committed");
    assert_eq!(inclusion.index, 0);
    assert_eq!(inclusion.size, 1);
    assert_eq!(inclusion.kind, aip_nexora::LeafKind::Reconciliation);
    assert_eq!(
        inclusion.record_digest,
        aip_crypto::sha256(&s.reconciliation.canonical_bytes())
    );
}

#[test]
fn v11_a_commitment_of_other_bytes_or_under_a_broken_head_is_refused() {
    let s = common::verified_execution();
    let other = common::verified_execution();

    // A commitment of somebody else's record.
    let (commitment, nexora_anchors) = common::commit(&other.reconciliation);
    let mut p = package(&s);
    p.commitment = Some(commitment);
    let mut a = anchors(&s);
    a.nexora = nexora_anchors;
    assert!(matches!(
        verify_nexora_proof(&p, &a).verdict,
        ProofVerdict::Invalid(_)
    ));

    // The right record, with the head's root altered after signing.
    let (mut commitment, nexora_anchors) = common::commit(&s.reconciliation);
    commitment.head.root[0] ^= 1;
    let mut p = package(&s);
    p.commitment = Some(commitment);
    let mut a = anchors(&s);
    a.nexora = nexora_anchors;
    let v = verify_nexora_proof(&p, &a);
    assert!(
        matches!(v.commitment, ComponentVerdict::Unverifiable(_)),
        "{v:#?}"
    );
    assert_ne!(v.verdict, ProofVerdict::Valid);
}

// ═══ The envelope, and the structural gates ═══

#[test]
fn v12_a_sealed_package_reports_who_sealed_it_and_an_unsealed_one_is_no_weaker() {
    let s = common::verified_execution();
    let kp = aip_crypto::generate_ed25519_keypair();
    let asm = ProofAssembler::new("assembler-1", 1, &kp.private_key, &kp.public_key).unwrap();
    let sealed = asm.seal(package(&s)).unwrap();
    let mut a = anchors(&s);
    a.nexora = aip_nexora::NexoraTrustAnchors::new().trust("assembler-1", 1, &kp.public_key);

    let v = verify_nexora_proof(&sealed, &a);
    assert_eq!(v.verdict, ProofVerdict::Valid, "{v:#?}");
    assert_eq!(v.envelope, ComponentVerdict::Verified);
    assert_eq!(v.assembled_by.as_deref(), Some("assembler-1"));

    // Unsealed: exactly as valid, with no assembler named.
    let v = verify_nexora_proof(&package(&s), &a);
    assert_eq!(v.verdict, ProofVerdict::Valid);
    assert_eq!(v.envelope, ComponentVerdict::Absent);
    assert_eq!(v.assembled_by, None);

    // Sealed by a party the verifier does not anchor: the seal is
    // unverifiable, and that is not a licence to ignore it.
    let stranger = aip_crypto::generate_ed25519_keypair();
    let asm2 = ProofAssembler::new(
        "assembler-2",
        1,
        &stranger.private_key,
        &stranger.public_key,
    )
    .unwrap();
    let sealed2 = asm2.seal(package(&s)).unwrap();
    let v = verify_nexora_proof(&sealed2, &a);
    assert!(matches!(v.envelope, ComponentVerdict::Unverifiable(_)));
    assert_ne!(v.verdict, ProofVerdict::Valid);
}

#[test]
fn v13_structural_and_binding_faults_stop_verification_before_any_verdict() {
    let s = common::verified_execution();
    let other = common::verified_execution();

    // Binding: another observer's records.
    let mut p = package(&s);
    p.observer = Some(ObserverBundle {
        batches: other.evidence.batches.clone(),
        health: other.evidence.health.clone(),
    });
    let v = verify_nexora_proof(&p, &anchors(&s));
    assert!(
        matches!(v.verdict, ProofVerdict::Invalid(InvalidReason::Binding(_))),
        "{v:#?}"
    );

    // Structural: a claim citing an expectation the package does not carry.
    let mut p = package(&s);
    p.expectation = None;
    let v = verify_nexora_proof(&p, &anchors(&s));
    assert!(
        matches!(
            v.verdict,
            ProofVerdict::Invalid(InvalidReason::Structural(_))
        ),
        "{v:#?}"
    );

    // Version: a package from a future NEXORA.
    let mut p = package(&s);
    p.version = NEXORA_PROOF_VERSION + 1;
    let v = verify_nexora_proof(&p, &anchors(&s));
    assert!(
        matches!(
            v.verdict,
            ProofVerdict::Invalid(InvalidReason::UnsupportedVersion(_))
        ),
        "{v:#?}"
    );
}

#[test]
fn v14_the_verifier_states_nothing_the_evidence_does_not_carry() {
    let s = common::verified_execution();
    let v = verify_nexora_proof(&package(&s), &anchors(&s));
    let json = serde_json::to_string(&v).unwrap().to_lowercase();
    for forbidden in [
        "trusted",
        "permitted",
        "malicious",
        "confidence",
        "score",
        "risk",
    ] {
        assert!(!json.contains(forbidden), "{forbidden} in {json}");
    }
    // The verdict names a result only because the reconciler produced one.
    assert!(json.contains("verifiedexecution") || json.contains("verified_execution"));
}
