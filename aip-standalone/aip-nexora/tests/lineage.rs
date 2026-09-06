//! Skill 10 Gate 7 — lineage in the proof, RED.
//!
//! Three concepts, never merged and never inferred from each other:
//!
//! | kind      | the question                                          | its evidence |
//! |-----------|-------------------------------------------------------|--------------|
//! | identity  | is this agent's document descended from that one?     | two signed identity documents, the child's lineage proof made by the parent's key |
//! | authority | did the authority this decision rests on reach it by a chain of delegations? | the root token and every hop, each signed by the party the previous hop granted to |
//! | process   | did the observed process instance come from that one? | kernel fork and exec events, both ends bound |
//!
//! Similar-looking identifiers establish nothing. An agent saying who its
//! parent is establishes nothing. Every edge is either backed by evidence
//! the package carries and the verifier checks, or it is **unavailable** —
//! which is `CANNOT_PROVE`, not `assumed related`.
//!
//! The adversarial cases §5 names are each a test below: forged parent,
//! wrong issuer, wrong grantee, same jti under a different identity,
//! process lineage mismatch, a child created without delegated authority,
//! and cross-agent attribution.

mod common;

use aip_nexora::proof::*;
use aip_nexora::verify::*;

fn base(s: &common::Scenario) -> ProofBuilder {
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
}

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

// ═══ Absence is CANNOT_PROVE, never "related" ═══

#[test]
fn g7_01_a_package_with_no_lineage_evidence_claims_no_lineage() {
    let s = common::verified_execution();
    let v = verify_nexora_proof(&base(&s).build(), &anchors(&s));
    assert_eq!(v.verdict, ProofVerdict::Valid, "{v:#?}");
    let l = v.lineage_report;
    assert_eq!(l.identity, LineageStanding::Unavailable);
    assert_eq!(l.process, LineageStanding::Unavailable);
    // The authority chain *is* carried, so that one axis is established.
    assert_eq!(l.authority, LineageStanding::Verified);
    // No axis is ever Verified merely because nothing contradicted it.
    for standing in [l.identity, l.process] {
        assert_ne!(standing, LineageStanding::Verified);
    }
}

// ═══ Identity lineage ═══

#[test]
fn g7_02_identity_lineage_needs_the_parents_signature_not_a_similar_name() {
    let s = common::verified_execution();
    let (child, parent, _parent_kp) = common::identity_lineage();

    // The real pair: the child's document carries a lineage proof the
    // parent's key made.
    let p = base(&s)
        .lineage(LineageEvidence {
            peer_expectations: vec![],
            identity: Some((child.clone(), parent.clone())),
            revoked_jtis: vec![],
        })
        .build();
    let v = verify_nexora_proof(&p, &anchors(&s));
    assert_eq!(v.lineage_report.identity, LineageStanding::Verified, "{v:#?}");

    // A forged parent: an unrelated document put in the parent slot. The
    // child's proof was not made by that key, so nothing is established.
    let (_c2, stranger, _k2) = common::identity_lineage();
    let p = base(&s)
        .lineage(LineageEvidence {
            peer_expectations: vec![],
            identity: Some((child.clone(), stranger)),
            revoked_jtis: vec![],
        })
        .build();
    let v = verify_nexora_proof(&p, &anchors(&s));
    assert_eq!(
        v.lineage_report.identity,
        LineageStanding::Contradicted,
        "a forged parent must contradict, never verify: {v:#?}"
    );

    // A child with no lineage proof at all: unavailable, not verified.
    let (orphan, _k) = aip_core::create_identity(common::provenance("orphan"), None).unwrap();
    let p = base(&s)
        .lineage(LineageEvidence {
            peer_expectations: vec![],
            identity: Some((orphan, parent)),
            revoked_jtis: vec![],
        })
        .build();
    let v = verify_nexora_proof(&p, &anchors(&s));
    assert_eq!(v.lineage_report.identity, LineageStanding::Incomplete);
}

// ═══ Authority lineage ═══

#[test]
fn g7_03_authority_lineage_is_the_chain_the_expectation_names() {
    let s = common::verified_execution();
    let v = verify_nexora_proof(&base(&s).build(), &anchors(&s));
    assert_eq!(v.lineage_report.authority, LineageStanding::Verified);

    // No authority carried: the axis is unavailable, and the package is
    // not thereby less valid — it simply establishes less.
    let p = NexoraProof::builder(s.a.agent_id.clone(), s.reconciliation.clone())
        .issued_at(s.at + 1)
        .expectation(s.a.ee.clone())
        .observer(s.evidence.batches.clone(), s.evidence.health.clone())
        .parameters(DeclaredParameters {
            verification_time_ms: s.at,
            health_max_age_ms: common::HEALTH_MAX_AGE,
            window_tolerance_ms: 0,
            agent_key_supplied: true,
        })
        .build();
    let v = verify_nexora_proof(&p, &anchors(&s));
    assert_eq!(v.verdict, ProofVerdict::Valid, "{v:#?}");
    assert_eq!(v.lineage_report.authority, LineageStanding::Unavailable);
}

#[test]
fn g7_04_a_hop_from_the_wrong_issuer_or_to_the_wrong_grantee_breaks_the_chain() {
    let s = common::verified_execution();

    // Wrong grantee: the hop grants to somebody who is not the
    // expectation's agent. The expectation's AuthorityRef no longer
    // matches the chain, so the package does not bind.
    let mut p = base(&s).build();
    let a = p.authority.as_mut().unwrap();
    a.chain[0].grantee_id = "aip1someone-else".into();
    let v = verify_nexora_proof(&p, &anchors(&s));
    assert!(matches!(v.verdict, ProofVerdict::Invalid(_)), "{v:#?}");
    assert_ne!(v.lineage_report.authority, LineageStanding::Verified);

    // Wrong issuer: a hop signed by a party that never held the parent.
    // aip-core refuses it (AUDIT P0-2) and the axis is not established.
    let mut p = base(&s).build();
    let a = p.authority.as_mut().unwrap();
    a.chain[0].issuer_id = "aip1not-the-holder".into();
    let v = verify_nexora_proof(&p, &anchors(&s));
    assert!(matches!(v.verdict, ProofVerdict::Invalid(_)));
    assert_ne!(v.lineage_report.authority, LineageStanding::Verified);
}

#[test]
fn g7_05_the_same_jti_under_a_different_identity_is_not_the_same_authority() {
    let s = common::verified_execution();
    let other = common::verified_execution();
    // Keep this chain's jti, take the other execution's issuer identity.
    let mut p = base(&s).build();
    let a = p.authority.as_mut().unwrap();
    a.root.agent_id = other.a.root.agent_id.clone();
    let v = verify_nexora_proof(&p, &anchors(&s));
    assert!(
        matches!(v.verdict, ProofVerdict::Invalid(_)),
        "a jti is not an identity: {v:#?}"
    );
    assert_ne!(v.lineage_report.authority, LineageStanding::Verified);
}

// ═══ Process lineage ═══

#[test]
fn g7_06_process_lineage_needs_kernel_fork_evidence_and_says_so_when_it_lacks_it() {
    let s = common::verified_execution();
    // Lineage evidence is carried, but nothing in it establishes that this
    // process instance was spawned by another: no peer expectation, no
    // fork/exec pair. The engine's own answer is Incomplete, and the
    // report must carry that rather than round it up.
    let p = base(&s)
        .lineage(LineageEvidence::default())
        .build();
    let v = verify_nexora_proof(&p, &anchors(&s));
    assert_eq!(v.verdict, ProofVerdict::Valid, "{v:#?}");
    assert_ne!(
        v.lineage_report.process,
        LineageStanding::Verified,
        "no fork evidence can never read as verified process lineage"
    );
    assert!(matches!(
        v.lineage_report.process,
        LineageStanding::Incomplete | LineageStanding::Unavailable
    ));
}

#[test]
fn g7_07_a_peer_expectation_for_another_agent_does_not_attribute_this_one() {
    let s = common::verified_execution();
    let other = common::verified_execution();
    // Cross-agent attribution: another agent's expectation offered as the
    // spawning parent. It is signed and it verifies as a document — and it
    // still establishes nothing about this execution.
    let p = base(&s)
        .lineage(LineageEvidence {
            peer_expectations: vec![other.a.ee.clone()],
            identity: None,
            revoked_jtis: vec![],
        })
        .build();
    let v = verify_nexora_proof(&p, &anchors(&s));
    assert_ne!(v.lineage_report.process, LineageStanding::Verified);
}

// ═══ The vocabulary ═══

#[test]
fn g7_08_the_standings_are_closed_and_only_one_of_them_asserts_a_link() {
    let all = LineageStanding::ALL;
    assert_eq!(all.len(), 5);
    let mut codes: Vec<u8> = all.iter().map(|x| x.code()).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), all.len());
    assert!(LineageStanding::Verified.asserts_a_link());
    for x in all {
        if x != LineageStanding::Verified {
            assert!(
                !x.asserts_a_link(),
                "{x:?} must not assert that two things are related"
            );
        }
    }
}
