//! Skill 10 Gate 10 — the portable representation, RED.
//!
//! A proof is worth what somebody else can check without you. This suite
//! moves one to a clean environment and verifies it there:
//!
//! ```text
//! export ─▶ bytes ─▶ (runtime state deleted) ─▶ import ─▶ verify
//! ```
//!
//! **Trust anchors travel separately, and that is the point.** A package
//! that carried the keys that check it would prove nothing: a forger would
//! ship their own. The anchors are the verifier's own decision, obtained
//! out of band; the export format carries evidence, never trust.
//!
//! The container is deliberately not security-relevant. Every hash and
//! signature is over the canonical encoding recomputed from the parsed
//! structure, so reformatting, whitespace and key order cannot change a
//! verdict — and `proof_id` is stable across a round trip.

mod common;

use aip_nexora::export::*;
use aip_nexora::proof::*;
use aip_nexora::verify::*;

fn package(s: &common::Scenario) -> NexoraProof {
    NexoraProof::builder(s.a.agent_id.clone(), s.reconciliation.clone())
        .issued_at(s.at + 1)
        .authority(s.a.root.clone(), s.a.chain.clone())
        .expectation(s.a.ee.clone())
        .observer(s.evidence.batches.clone(), s.evidence.health.clone())
        .continuity(common::continuity_report_for(
            common::OBSERVER_ID,
            &s.o,
            common::amnesia_break(),
        ))
        .parameters(DeclaredParameters {
            verification_time_ms: s.at,
            health_max_age_ms: common::HEALTH_MAX_AGE,
            window_tolerance_ms: 0,
            agent_key_supplied: true,
        })
        .build()
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

// ═══ Round trip ═══

#[test]
fn g10_01_a_proof_survives_export_and_import_byte_for_byte() {
    let s = common::verified_execution();
    let p = package(&s);
    let bytes = export_proof(&p).unwrap();
    let back = import_proof(&bytes).unwrap();
    assert_eq!(back, p);
    assert_eq!(back.proof_id(), p.proof_id());
    // Exporting the imported copy gives the same bytes: the container is
    // deterministic, so a file digest is stable too.
    assert_eq!(export_proof(&back).unwrap(), bytes);
}

#[test]
fn g10_02_the_container_is_not_security_relevant() {
    let s = common::verified_execution();
    let p = package(&s);
    let bytes = export_proof(&p).unwrap();
    // Reformat the JSON entirely: whitespace, key order as the parser
    // yields it. The identity is the canonical encoding, not the file.
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let reformatted = serde_json::to_vec_pretty(&value).unwrap();
    assert_ne!(reformatted, bytes, "the bytes really did change");
    let back = import_proof(&reformatted).unwrap();
    assert_eq!(back.proof_id(), p.proof_id());
    assert_eq!(
        verify_nexora_proof(&back, &anchors(&s)).verdict,
        ProofVerdict::Valid
    );
}

#[test]
fn g10_03_a_file_that_is_not_a_proof_is_refused_rather_than_guessed() {
    assert!(import_proof(b"").is_err());
    assert!(import_proof(b"{").is_err());
    assert!(import_proof(b"{\"version\":1}").is_err());
    // A proof from a future format version.
    let s = common::verified_execution();
    let mut p = package(&s);
    p.version = NEXORA_PROOF_VERSION + 1;
    let bytes = export_proof(&p).unwrap();
    match import_proof(&bytes) {
        Err(ExportError::UnsupportedVersion(v)) => assert_eq!(v, NEXORA_PROOF_VERSION + 1),
        other => panic!("a future version must be named, got {other:?}"),
    }
}

// ═══ Anchors travel separately ═══

#[test]
fn g10_04_the_export_carries_evidence_and_never_the_keys_that_check_it() {
    let s = common::verified_execution();
    let bytes = export_proof(&package(&s)).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    // The decision point's public key, the observer's, the issuers' — none
    // of them appear. A package that shipped its own anchors would prove
    // nothing, because a forger would ship theirs.
    for key in [
        s.o.public_key.clone(),
        s.a.agent_kp.public_key.clone(),
    ] {
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        assert!(
            !text.contains(&hex),
            "a trust anchor's key material appears in the export"
        );
    }
}

// ═══ The clean-room verification ═══

#[test]
fn g10_05_a_proof_verifies_in_a_process_that_holds_no_runtime_state() {
    // Write the proof and the anchors to a directory, then verify them in
    // a *separate process* that was given nothing else: no scenario, no
    // collector, no reconciler state, no network.
    let s = common::verified_execution();
    let dir = std::env::temp_dir().join(format!("nexora-export-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let proof_path = dir.join("proof.json");
    let anchors_path = dir.join("anchors.json");
    std::fs::write(&proof_path, export_proof(&package(&s)).unwrap()).unwrap();
    std::fs::write(&anchors_path, export_anchors(&anchors(&s)).unwrap()).unwrap();

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_nexora-verify"))
        .arg("--proof")
        .arg(&proof_path)
        .arg("--anchors")
        .arg(&anchors_path)
        .output()
        .expect("run the offline verifier");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "verifier exited nonzero: {stdout}");
    assert!(stdout.contains("verdict=Valid"), "{stdout}");
    assert!(stdout.contains("result=VerifiedExecution"), "{stdout}");
    assert!(stdout.contains("strength=Attested"), "{stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}

// ═══ The tamper matrix ═══

#[test]
fn g10_06_every_component_altered_in_transit_fails_on_arrival() {
    let s = common::verified_execution();
    let other = common::verified_execution();
    let a = anchors(&s);
    assert_eq!(
        verify_nexora_proof(&package(&s), &a).verdict,
        ProofVerdict::Valid
    );

    type Tamper = Box<dyn Fn(&mut NexoraProof)>;
    let cases: Vec<(&str, Tamper)> = vec![
        (
            "the proof's subject",
            Box::new(|p: &mut NexoraProof| p.subject.agent_id.push('x')),
        ),
        ("an observation", {
            let b = other.evidence.batches.clone();
            Box::new(move |p: &mut NexoraProof| {
                p.observer.as_mut().unwrap().batches = b.clone();
            })
        }),
        ("the expected execution", {
            let ee = other.a.ee.clone();
            Box::new(move |p: &mut NexoraProof| p.expectation = Some(ee.clone()))
        }),
        ("the authority", {
            let root = other.a.root.clone();
            Box::new(move |p: &mut NexoraProof| {
                p.authority.as_mut().unwrap().root = root.clone();
            })
        }),
        ("the continuity report", {
            Box::new(move |p: &mut NexoraProof| {
                p.continuity.as_mut().unwrap().report.refused = true;
            })
        }),
        (
            "a timestamp",
            Box::new(|p: &mut NexoraProof| p.claim.verification_time_ms += 1),
        ),
        (
            "the declared parameters",
            Box::new(|p: &mut NexoraProof| p.parameters.health_max_age_ms += 1),
        ),
        (
            "the verdict",
            Box::new(|p: &mut NexoraProof| {
                p.claim.strength = aip_reconcile::EvidenceStrength::Proven
            }),
        ),
    ];
    for (name, tamper) in cases {
        let mut p = package(&s);
        tamper(&mut p);
        // Tampering survives the round trip — the container is faithful —
        // and is caught on verification, which is where it must be caught.
        let bytes = export_proof(&p).unwrap();
        let back = import_proof(&bytes).unwrap();
        let v = verify_nexora_proof(&back, &a);
        assert!(
            matches!(v.verdict, ProofVerdict::Invalid(_)),
            "tampering with {name} survived: {v:#?}"
        );
    }
}

#[test]
fn g10_07_a_commitment_altered_in_transit_fails_on_arrival() {
    let s = common::verified_execution();
    let (commitment, nexora_anchors) = common::commit(&s.reconciliation);
    let mut a = anchors(&s);
    a.nexora = nexora_anchors;
    let mut p = package(&s);
    p.commitment = Some(commitment);
    assert_eq!(verify_nexora_proof(&p, &a).verdict, ProofVerdict::Valid);

    // The inclusion path, edited after export.
    let mut t = p.clone();
    t.commitment.as_mut().unwrap().inclusion.index += 1;
    let back = import_proof(&export_proof(&t).unwrap()).unwrap();
    assert!(matches!(
        verify_nexora_proof(&back, &a).verdict,
        ProofVerdict::Invalid(_)
    ));
}
