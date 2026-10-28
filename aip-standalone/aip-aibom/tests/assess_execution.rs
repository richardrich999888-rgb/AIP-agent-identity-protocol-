//! C7 — the agent's executable: authorised by a decision point, observed
//! through NEXORA. The assessor never reconciles; it reads `VerifiedProof`.

mod common;

use aip_aibom::evidence::{AssessorContext, EvidenceBundle};
use aip_aibom::finding::FindingKind;
use aip_aibom::model::Binary;
use aip_aibom::standing::{Standing, Verifier};
use aip_crypto::sha256;
use common::staging::*;
use common::*;

const BIN: &str = "$.environment.binary.exe_sha256";

fn declaring(a: &Authorised, exe: &[u8]) -> aip_aibom::Manifest {
    let mut m = manifest(&a.agent_id);
    m.environment.binary = Some(Binary {
        exe_sha256: hex::encode(sha256(exe)),
        exe_path: None,
    });
    m
}

fn ctx(a: &Authorised) -> AssessorContext {
    let mut c = AssessorContext::trusting_nothing(at_of(a));
    c.decision_points = a.dp_anchors.clone();
    c
}

#[test]
fn the_authorised_binary_is_verified_by_the_decision_point() {
    let a = authorised();
    let b = EvidenceBundle {
        expectations: vec![a.ee.clone()],
        ..Default::default()
    };
    let r = run(&declaring(&a, exe_bytes()), &b, &ctx(&a), &[]);
    assert_eq!(
        standing(&r, BIN),
        Standing::Verified {
            verifier: Verifier::DecisionPoint
        }
    );
}

#[test]
fn a_declared_binary_the_decision_point_did_not_authorise_is_contradicted() {
    let a = authorised();
    let b = EvidenceBundle {
        expectations: vec![a.ee.clone()],
        ..Default::default()
    };
    let r = run(&declaring(&a, b"some other build"), &b, &ctx(&a), &[]);
    assert!(matches!(standing(&r, BIN), Standing::Contradicted { .. }));
}

#[test]
fn an_expectation_from_an_untrusted_decision_point_is_rejected() {
    let a = authorised();
    let b = EvidenceBundle {
        expectations: vec![a.ee.clone()],
        ..Default::default()
    };
    let r = run(
        &declaring(&a, exe_bytes()),
        &b,
        &AssessorContext::trusting_nothing(at_of(&a)),
        &[],
    );
    assert!(matches!(
        standing(&r, BIN),
        Standing::EvidenceRejected { .. }
    ));
}

#[test]
fn an_authorised_binary_the_manifest_omits_is_a_finding() {
    let a = authorised();
    let b = EvidenceBundle {
        expectations: vec![a.ee.clone()],
        ..Default::default()
    };
    let r = run(&manifest(&a.agent_id), &b, &ctx(&a), &[]);
    assert!(has_finding(&r, |k| *k == FindingKind::UndeclaredBinary));
}

/// **A4.** `Observed` carries NEXORA's own verdict and strength, read
/// verbatim. Here the instance matched and no action evidence exists, so NEXORA
/// says `CANNOT_PROVE` — and the assessor does not round that up.
#[test]
fn an_observed_binary_carries_nexoras_verdict_and_strength_unraised() {
    let a = authorised();
    let mut o = observer();
    let ev = evidence(&a, &mut o, exe_bytes());
    let p = proof(&a, &o, &ev);
    let mut c = ctx(&a);
    c.nexora = Some(verifier_anchors(&a, &o));
    let v = aip_nexora::verify_nexora_proof(&p, c.nexora.as_ref().unwrap());
    assert!(v.is_valid(), "{:?}", v.verdict);

    let b = EvidenceBundle {
        proofs: vec![p],
        ..Default::default()
    };
    let r = run(&declaring(&a, exe_bytes()), &b, &c, &[]);
    assert_eq!(
        standing(&r, BIN),
        Standing::Observed {
            verdict: v.result.unwrap(),
            strength: v.strength.unwrap()
        }
    );
}

#[test]
fn nexora_observing_a_different_binary_is_contradicted() {
    let a = authorised();
    let mut o = observer();
    let ev = evidence(&a, &mut o, b"attacker patched build");
    let p = proof(&a, &o, &ev);
    let mut c = ctx(&a);
    c.nexora = Some(verifier_anchors(&a, &o));
    let b = EvidenceBundle {
        proofs: vec![p],
        expectations: vec![a.ee.clone()],
        ..Default::default()
    };
    let r = run(&declaring(&a, exe_bytes()), &b, &c, &[]);
    assert!(
        matches!(standing(&r, BIN), Standing::Contradicted { .. }),
        "{:?}",
        standing(&r, BIN)
    );
}

/// No verifier anchors, no observation. The proofs are reported as not
/// evaluated — never silently counted.
#[test]
fn proofs_without_verifier_anchors_are_reported_and_never_credited() {
    let a = authorised();
    let mut o = observer();
    let ev = evidence(&a, &mut o, exe_bytes());
    let b = EvidenceBundle {
        proofs: vec![proof(&a, &o, &ev)],
        ..Default::default()
    };
    let r = run(&declaring(&a, exe_bytes()), &b, &ctx(&a), &[]);
    assert_eq!(standing(&r, BIN), Standing::SelfReported);
    assert!(has_finding(&r, |k| *k == FindingKind::ProofsNotEvaluated { count: 1 }));
}

#[test]
fn a_proof_nexora_refuses_is_rejected() {
    let a = authorised();
    let mut o = observer();
    let ev = evidence(&a, &mut o, exe_bytes());
    let p = proof(&a, &o, &ev);
    let stranger = observer();
    let mut c = ctx(&a);
    c.nexora = Some(verifier_anchors(&a, &stranger));
    let b = EvidenceBundle {
        proofs: vec![p],
        ..Default::default()
    };
    let r = run(&declaring(&a, exe_bytes()), &b, &c, &[]);
    assert!(matches!(
        standing(&r, BIN),
        Standing::EvidenceRejected { .. }
    ));
}

#[test]
fn runtime_and_network_are_the_authors_word() {
    let a = authorised();
    let r = run(
        &manifest(&a.agent_id),
        &EvidenceBundle::default(),
        &ctx(&a),
        &[],
    );
    assert_eq!(
        standing(&r, "$.environment.runtime"),
        Standing::SelfReported
    );
    assert_eq!(
        standing(&r, "$.environment.network"),
        Standing::SelfReported
    );
}
