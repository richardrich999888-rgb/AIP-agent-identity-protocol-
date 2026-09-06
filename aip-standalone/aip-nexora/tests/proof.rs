//! Skill 10 Gate 1 — the NEXORA proof object, RED.
//!
//! A NEXORA proof is a *package of evidence somebody else signed*, plus the
//! verdict the repository's reconciler drew from it. This suite pins what
//! the object is allowed to be:
//!
//! - it carries the reconciliation result and evidence strength **verbatim**,
//!   and offers no way to state a different one;
//! - absence is a value, not an omission: a proof with no expectation says
//!   so, and its bytes differ from a proof that has one;
//! - the bytes are canonical, domain-separated and injective over every
//!   component, so nothing can be transplanted between proofs;
//! - a claim that references evidence the package does not carry is a
//!   *structural fault* the object itself reports, never a silent omission.
//!
//! What it must never be: a place where `Attested` becomes `Proven`, where
//! `CANNOT_PROVE` becomes a verdict, or where NEXORA states anything about
//! the world in its own voice.

mod common;

use aip_crypto::sha256;
use aip_nexora::proof::*;
use aip_reconcile::{EvidenceStrength, ReconciliationResult};

/// Everything one scenario has, packaged.
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

/// One scenario and its package. Every test that compares a proof with the
/// evidence it came from must use one call: a second scenario has fresh
/// keys and a fresh clock and is a different execution entirely.
fn scenario() -> (common::Scenario, NexoraProof) {
    let s = common::verified_execution();
    let p = package(&s);
    (s, p)
}

// ═══ The result and the strength are carried, never restated ═══

#[test]
fn p01_the_claim_is_carried_verbatim_and_cannot_be_relabelled() {
    let (s, p) = scenario();
    assert_eq!(p.result(), ReconciliationResult::VerifiedExecution);
    assert_eq!(p.strength(), EvidenceStrength::Attested);
    assert_eq!(p.claim, s.reconciliation, "the record is carried as it was");
    assert_eq!(p.claim.digest(), s.reconciliation.digest());

    // A CANNOT_PROVE scenario stays CANNOT_PROVE in the package.
    let c = common::cannot_prove();
    let pc = NexoraProof::builder(c.a.agent_id.clone(), c.reconciliation.clone())
        .expectation(c.a.ee.clone())
        .build();
    assert_eq!(pc.result(), ReconciliationResult::CannotProve);
    assert_eq!(pc.claim.strength, c.reconciliation.strength);

    // There is no API that sets a result or a strength: the only way a
    // result enters a proof is by carrying a Reconciliation somebody else
    // computed. This is a structural property; the compiler enforces it,
    // and the vocabulary check below states it for a reader.
    let json = serde_json::to_string(&p).unwrap().to_lowercase();
    for forbidden in [
        "\"proven\"",
        "trusted",
        "permitted",
        "\"safe\"",
        "confidence",
        "score",
        "risk",
    ] {
        assert!(!json.contains(forbidden), "{forbidden} appears in {json}");
    }
}

// ═══ Absence is explicit ═══

#[test]
fn p02_every_absent_component_is_a_value_and_changes_the_bytes() {
    let (s, full) = scenario();
    let bare = NexoraProof::builder(s.a.agent_id.clone(), s.reconciliation.clone()).build();
    assert_eq!(bare.expectation, None);
    assert_eq!(bare.observer, None);
    assert_eq!(bare.authority, None);
    assert_eq!(bare.continuity, None);
    assert_eq!(bare.lineage, None);
    assert_eq!(bare.warrant, None);
    assert_eq!(bare.commitment, None);
    assert_eq!(bare.envelope, None);

    // Presence is reported, not inferred from a field being defaulted.
    assert!(!bare.present(Component::Expectation));
    assert!(full.present(Component::Expectation));

    // The canonical bytes distinguish absent from present.
    let with_ee = NexoraProof::builder(s.a.agent_id.clone(), s.reconciliation.clone())
        .expectation(s.a.ee.clone())
        .build();
    assert_ne!(bare.canonical_bytes(), with_ee.canonical_bytes());
    assert_ne!(bare.proof_id(), with_ee.proof_id());

    // An empty collection is not the same as an absent one.
    let empty_chain = NexoraProof::builder(s.a.agent_id.clone(), s.reconciliation.clone())
        .authority(s.a.root.clone(), vec![])
        .build();
    let no_authority = bare.clone();
    assert_ne!(
        empty_chain.canonical_bytes(),
        no_authority.canonical_bytes(),
        "an authority with an empty chain is not the absence of an authority"
    );
}

// ═══ A claim may not reference evidence the package does not carry ═══

#[test]
fn p03_a_claim_that_outruns_its_package_is_a_structural_fault() {
    let (s, full) = scenario();
    // The scenario's record cites the expectation and the observer's
    // batches and health. A package carrying none of them is structurally
    // incomplete, and the object says so itself.
    let bare = NexoraProof::builder(s.a.agent_id.clone(), s.reconciliation.clone()).build();
    let faults = bare.structural_faults();
    assert!(
        faults.contains(&StructuralFault::ClaimCitesExpectationNotCarried),
        "{faults:?}"
    );
    assert!(
        faults.contains(&StructuralFault::ClaimCitesObserverNotCarried {
            observer_id: common::OBSERVER_ID.to_string()
        }),
        "{faults:?}"
    );
    assert!(
        full.structural_faults().is_empty(),
        "the full package cites nothing it does not carry"
    );

    // A package whose expectation is for another decision than the claim's.
    let other = common::authorized_for([10, 0, 0, 9], 8443);
    let mismatched = NexoraProof::builder(s.a.agent_id.clone(), s.reconciliation.clone())
        .expectation(other.ee.clone())
        .observer(s.evidence.batches.clone(), s.evidence.health.clone())
        .build();
    assert!(
        mismatched
            .structural_faults()
            .contains(&StructuralFault::ExpectationDecisionMismatch),
        "{:?}",
        mismatched.structural_faults()
    );

    // A package for another agent than the expectation names.
    let wrong_subject =
        NexoraProof::builder("aip1someoneelse".to_string(), s.reconciliation.clone())
            .expectation(s.a.ee.clone())
            .observer(s.evidence.batches.clone(), s.evidence.health.clone())
            .build();
    assert!(wrong_subject
        .structural_faults()
        .contains(&StructuralFault::SubjectNotTheExpectationsAgent));
}

// ═══ Canonical bytes: domain, version, injectivity ═══

#[test]
fn p04_the_bytes_are_domain_separated_versioned_and_injective() {
    let (s, p) = scenario();
    assert_eq!(p.version, NEXORA_PROOF_VERSION);
    assert!(PROOF_BUNDLE_DOMAIN.starts_with("SYNTRIASS/NEXORA/"));
    let bytes = p.canonical_bytes();
    assert!(bytes
        .windows(PROOF_BUNDLE_DOMAIN.len())
        .any(|w| w == PROOF_BUNDLE_DOMAIN.as_bytes()));
    assert_eq!(p.proof_id(), sha256(&bytes));

    // The version is inside the bytes.
    let mut other_version = p.clone();
    other_version.version = NEXORA_PROOF_VERSION + 1;
    assert_ne!(other_version.canonical_bytes(), bytes);

    // Every component moves the digest.
    let mut mutated = p.clone();
    mutated.subject.agent_id.push('x');
    assert_ne!(mutated.proof_id(), p.proof_id());

    let mut mutated = p.clone();
    mutated.issued_at_ms += 1;
    assert_ne!(mutated.proof_id(), p.proof_id());

    let mut mutated = p.clone();
    mutated.parameters.window_tolerance_ms += 1;
    assert_ne!(
        mutated.proof_id(),
        p.proof_id(),
        "the declared parameters are inside the bytes"
    );

    let mut mutated = p.clone();
    mutated.parameters.agent_key_supplied = false;
    assert_ne!(
        mutated.proof_id(),
        p.proof_id(),
        "whether the independence checks could run is inside the bytes"
    );

    let mut mutated = p.clone();
    mutated.expectation = Some(s.a.ee.clone());
    mutated.expectation.as_mut().unwrap().decision_id[0] ^= 1;
    assert_ne!(mutated.proof_id(), p.proof_id());

    let mut mutated = p.clone();
    mutated.claim.verification_time_ms += 1;
    assert_ne!(mutated.proof_id(), p.proof_id());
}

#[test]
fn p05_the_bundle_bytes_cannot_be_read_as_any_other_signed_object() {
    // Domain separation across NEXORA's own three domains.
    let (_s, p) = scenario();
    let bytes = p.canonical_bytes();
    for other in [
        aip_nexora::HEAD_DOMAIN,
        aip_nexora::PROOF_DOMAIN,
        aip_nexora::LEAF_DOMAIN,
    ] {
        assert!(
            !bytes.starts_with(other.as_bytes()),
            "bundle bytes must not open with {other}"
        );
        assert_ne!(PROOF_BUNDLE_DOMAIN, other);
    }
    // And the leaf kind for a bundle is its own code, appended after the
    // frozen five.
    assert_eq!(aip_nexora::LeafKind::Reconciliation.code(), 0x01);
    assert_eq!(aip_nexora::LeafKind::AttestedBatch.code(), 0x02);
    assert_eq!(aip_nexora::LeafKind::SignedHealth.code(), 0x03);
    assert_eq!(aip_nexora::LeafKind::Warrant.code(), 0x04);
    assert_eq!(aip_nexora::LeafKind::Expectation.code(), 0x05);
    assert_eq!(aip_nexora::LeafKind::ProofBundle.code(), 0x08);
    let mut codes: Vec<u8> = aip_nexora::LeafKind::ALL.iter().map(|k| k.code()).collect();
    let n = codes.len();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), n, "leaf codes stay distinct");
}

// ═══ The envelope means what it says and nothing more ═══

#[test]
fn p06_an_assembler_signature_binds_the_package_and_grants_nothing() {
    let kp = aip_crypto::generate_ed25519_keypair();
    let assembler = ProofAssembler::new("assembler-1", 1, &kp.private_key, &kp.public_key).unwrap();
    let (_s, p) = scenario();
    let sealed = assembler.seal(p.clone()).unwrap();
    assert!(sealed.envelope.is_some());
    let anchors = aip_nexora::NexoraTrustAnchors::new().trust("assembler-1", 1, &kp.public_key);
    assert!(verify_envelope(&sealed, &anchors).is_ok());

    // The envelope covers the package: one byte changed anywhere and it
    // no longer verifies.
    let mut tampered = sealed.clone();
    tampered.claim.verification_time_ms += 1;
    assert!(verify_envelope(&tampered, &anchors).is_err());
    let mut tampered = sealed.clone();
    tampered.subject.agent_id.push('x');
    assert!(verify_envelope(&tampered, &anchors).is_err());

    // Under a key the verifier does not anchor: refused.
    let stranger = aip_crypto::generate_ed25519_keypair();
    let other_anchors =
        aip_nexora::NexoraTrustAnchors::new().trust("assembler-1", 1, &stranger.public_key);
    assert!(verify_envelope(&sealed, &other_anchors).is_err());

    // And sealing changes nothing about the claim.
    assert_eq!(sealed.claim, p.claim);
    assert_eq!(sealed.result(), p.result());
    assert_eq!(sealed.strength(), p.strength());
}

// ═══ Serde round trip ═══

#[test]
fn p07_the_package_round_trips_without_changing_its_identity() {
    let (_s, p) = scenario();
    let json = serde_json::to_string(&p).unwrap();
    let back: NexoraProof = serde_json::from_str(&json).unwrap();
    assert_eq!(back, p);
    assert_eq!(
        back.proof_id(),
        p.proof_id(),
        "the identity is the canonical bytes, not the container"
    );
    // Re-serialising after a round trip is byte-identical, so the container
    // is deterministic too.
    assert_eq!(serde_json::to_string(&back).unwrap(), json);
}

#[test]
fn p08_the_component_vocabulary_is_closed_and_distinct() {
    let all = Component::ALL;
    assert_eq!(all.len(), 9);
    let mut codes: Vec<u8> = all.iter().map(|c| c.code()).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), all.len());
    let s = common::verified_execution();
    let bare = NexoraProof::builder(s.a.agent_id.clone(), s.reconciliation.clone()).build();
    for c in all {
        if c != Component::Subject && c != Component::Claim {
            assert!(!bare.present(c), "{c:?} must be absent in a bare package");
        } else {
            assert!(bare.present(c), "{c:?} is always present");
        }
    }
}
