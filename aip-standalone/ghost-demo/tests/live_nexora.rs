//! Skill 10 Gate 14 — the live, offline demonstrator.
//!
//! Everything before this gate proves the proof layer against a scenario
//! built in memory. This one starts from a real process on this kernel:
//!
//! ```text
//! spawn a real agent
//!   → a real decision point authorises a real TCP connection
//!   → the agent makes it
//!   → the kernel's own socket table is read under a pidfd anchor
//!   → a real collector attests what was read
//!   → the real reconciler draws the verdict
//!   → NEXORA packages exactly that
//!   → the package is written to disk and every runtime value dropped
//!   → a separate process verifies the file with nothing but the file,
//!     the anchors, and its own copy of the code
//! ```
//!
//! The isolation is the point, so it is real isolation: `nexora-verify` is
//! spawned as its own process, given two paths, and told nothing else. It
//! shares no memory with the run that produced them and reads no clock the
//! package chose.
//!
//! **What this demonstrates, and what it does not.** The live evidence here
//! is the kernel's socket table read by a probe that holds no key, attested
//! off-host by a collector that does. That is `Attested`. It is not
//! `Proven`, and this suite asserts that it is not: `Proven` in this
//! repository means a record the verifier can recompute end to end from
//! independently anchored material, and a socket-table read is not that.
//! Claiming otherwise would be the exact substitution the whole design
//! exists to prevent, so the demonstrator states the ceiling rather than
//! reaching past it.
//!
//! Linux only: it needs procfs, pidfd, and a real kernel to observe.

#![cfg(target_os = "linux")]

use aip_nexora::export::*;
use aip_nexora::proof::*;
use aip_nexora::verify::*;
use aip_reconcile::{EvidenceStrength, ReconciliationResult};
use ghost_demo::{run, Demo, ProofInputs, Scenario};

const AGENT: &str = env!("CARGO_BIN_EXE_ghost-demo-agent");

/// `nexora-verify` belongs to another crate, so cargo does not hand this
/// test its path. It sits beside every other binary of this build, which is
/// two directories up from the test executable in `target/<profile>/deps`.
/// Resolved rather than assumed: if it is not there the demonstrator says
/// so instead of quietly checking the proof in-process, which would not be
/// isolation at all.
fn verifier_path() -> std::path::PathBuf {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile_dir = exe
        .parent()
        .and_then(|deps| deps.parent())
        .expect("target/<profile>/deps/<test>");
    let p = profile_dir.join("nexora-verify");
    assert!(
        p.is_file(),
        "the offline verifier was not built at {}; run `cargo build -p aip-nexora --bin nexora-verify`",
        p.display()
    );
    p
}

/// Package a live run exactly as it happened. Nothing is substituted: the
/// expectation is the one the decision point signed, the batches are the
/// ones the collector attested, and the claim is the record the reconciler
/// produced from them.
fn package(d: &Demo) -> (NexoraProof, VerifierAnchors) {
    let i: &ProofInputs = d
        .inputs
        .as_ref()
        .expect("this scenario carries its proof inputs");
    let proof = NexoraProof::builder(i.agent_id.clone(), d.reconciliation.clone())
        .issued_at(i.at + 1)
        .authority(i.root.clone(), i.chain.clone())
        .expectation(i.expectation.clone())
        .observer(i.evidence.batches.clone(), i.evidence.health.clone())
        .parameters(DeclaredParameters {
            verification_time_ms: i.at,
            health_max_age_ms: ghost_demo::HEALTH_MAX_AGE_MS,
            window_tolerance_ms: 0,
            agent_key_supplied: true,
        })
        .build();
    let anchors = VerifierAnchors {
        decision_point: i.decision_point_anchors.clone(),
        observer: i.observer_anchors.clone(),
        warrant: aip_warrant::WarrantTrustAnchors::new(),
        nexora: aip_nexora::NexoraTrustAnchors::new(),
        issuers: i.issuer_keys.clone(),
        agent_public_key: Some(i.agent_public_key.clone()),
        ..Default::default()
    };
    (proof, anchors)
}

struct Files {
    dir: std::path::PathBuf,
    proof: std::path::PathBuf,
    anchors: std::path::PathBuf,
}

impl Drop for Files {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn write_out(tag: &str, proof: &NexoraProof, anchors: &VerifierAnchors) -> Files {
    let dir = std::env::temp_dir().join(format!("nexora-g14-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = Files {
        proof: dir.join("proof.json"),
        anchors: dir.join("anchors.json"),
        dir,
    };
    std::fs::write(&f.proof, export_proof(proof).unwrap()).unwrap();
    std::fs::write(&f.anchors, export_anchors(anchors).unwrap()).unwrap();
    f
}

/// Run the verifier as its own process. It gets two paths and nothing else.
fn verify_in_another_process(f: &Files) -> (bool, String) {
    let out = std::process::Command::new(verifier_path())
        .arg("--proof")
        .arg(&f.proof)
        .arg("--anchors")
        .arg(&f.anchors)
        .output()
        .expect("the offline verifier must be runnable");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

// ═══ The whole pipeline, end to end, on this kernel ═══

#[test]
fn g14_01_a_live_authorized_execution_verifies_offline_in_another_process() {
    let d = run(Scenario::Positive, AGENT);
    // The live run really did produce a verified execution. If it did not,
    // there is nothing here to package and the demonstrator says so rather
    // than packaging something weaker and calling it a success.
    assert_eq!(
        d.reconciliation.result,
        ReconciliationResult::VerifiedExecution,
        "the live run must be a verified execution: {:?}",
        d.reconciliation.reason
    );
    assert!(d.reconciliation.is_engine_produced());

    let (proof, anchors) = package(&d);
    let files = write_out("positive", &proof, &anchors);

    // Everything from the run is dropped here. What survives is two files.
    drop(d);
    drop(proof);
    drop(anchors);

    let (ok, report) = verify_in_another_process(&files);
    assert!(ok, "the offline verifier refused a live proof:\n{report}");
    assert!(report.contains("verdict=Valid"), "{report}");
    assert!(report.contains("result=VerifiedExecution"), "{report}");
    assert!(report.contains("strength=Attested"), "{report}");
    // The verifier says what it is and what it is not, in the same breath.
    assert!(
        report.contains("not authority to act now"),
        "the report must not read as permission:\n{report}"
    );
}

#[test]
fn g14_02_the_package_verifies_from_the_file_alone_with_no_runtime_state() {
    let d = run(Scenario::Positive, AGENT);
    let (proof, anchors) = package(&d);
    let files = write_out("reimport", &proof, &anchors);
    let expected_id = proof.proof_id();
    drop(d);
    drop(proof);

    // Read back from disk, in this process but from nothing but the bytes.
    let back = import_proof(&std::fs::read(&files.proof).unwrap()).unwrap();
    assert_eq!(
        back.proof_id(),
        expected_id,
        "identity survives the round trip"
    );
    let v = verify_nexora_proof(&back, &anchors);
    assert!(v.is_valid(), "{:?}", v.verdict);
    assert_eq!(v.result, Some(ReconciliationResult::VerifiedExecution));
    assert_eq!(v.strength, Some(EvidenceStrength::Attested));
    assert_eq!(v.independence, Independence::Checked);
    assert_eq!(v.observer, ComponentVerdict::Verified);
    assert_eq!(v.expectation, ComponentVerdict::Verified);
    assert_eq!(v.authority, ComponentVerdict::Verified);
}

// ═══ Attested, Proven, CANNOT_PROVE — the three the directive names ═══

#[test]
fn g14_03_live_socket_table_evidence_is_attested_and_deliberately_not_proven() {
    let d = run(Scenario::Positive, AGENT);
    let (proof, anchors) = package(&d);
    let v = verify_nexora_proof(&proof, &anchors);
    assert_eq!(v.strength, Some(EvidenceStrength::Attested));
    assert_ne!(
        v.strength,
        Some(EvidenceStrength::Proven),
        "a socket-table read is attested metadata, never a proof of the act"
    );
    // The record names the mechanism, so a reader can see why.
    let named = format!("{:?}", d.reconciliation.action);
    assert!(
        named.contains("ProcNetTable") || named.contains("SockStateTracepoint"),
        "the record must name the mechanism it rests on: {named}"
    );
    // And the ceiling is not raisable by packaging: the verifier re-derives
    // the strength rather than reading the one the package carries.
    let mut inflated = proof.clone();
    inflated.claim.strength = EvidenceStrength::Proven;
    let v = verify_nexora_proof(&inflated, &anchors);
    assert!(!v.is_valid());
    assert_eq!(v.strength, None, "a refused package establishes nothing");
}

#[test]
fn g14_04_a_live_execution_that_did_not_happen_is_cannot_prove_offline_too() {
    let d = run(Scenario::ExpectedNotExecuted, AGENT);
    assert_eq!(d.reconciliation.result, ReconciliationResult::CannotProve);
    assert_ne!(
        d.reconciliation.result,
        ReconciliationResult::PhantomClaim,
        "polled coverage can never turn silence into non-execution"
    );

    let (proof, anchors) = package(&d);
    let files = write_out("cannot-prove", &proof, &anchors);
    drop(d);

    // A package of CANNOT_PROVE is a perfectly valid package. It says, in a
    // form somebody else can check, that the evidence does not settle the
    // question — which is a useful thing to be able to say offline.
    let (ok, report) = verify_in_another_process(&files);
    assert!(ok, "a CANNOT_PROVE package must still verify:\n{report}");
    assert!(report.contains("verdict=Valid"), "{report}");
    assert!(report.contains("result=CannotProve"), "{report}");
    assert!(
        !report.contains("PhantomClaim"),
        "absence of evidence must not read as evidence of absence:\n{report}"
    );

    // And it cannot be promoted on the way to the verifier.
    let mut promoted = proof.clone();
    promoted.claim.result = ReconciliationResult::VerifiedExecution;
    promoted.claim.strength = EvidenceStrength::Proven;
    std::fs::write(&files.proof, export_proof(&promoted).unwrap()).unwrap();
    let (ok, report) = verify_in_another_process(&files);
    assert!(!ok, "a promoted verdict was accepted:\n{report}");
    assert!(report.contains("verdict=Invalid("), "{report}");
}

// ═══ Mutation, on the wire, caught by a verifier that never saw the run ═══

#[test]
fn g14_05_every_mutation_of_a_live_package_is_refused_offline() {
    let d = run(Scenario::Positive, AGENT);
    let (proof, anchors) = package(&d);
    let files = write_out("mutation", &proof, &anchors);

    // The honest package first, so a refusal below means the mutation and
    // not the setup.
    let (ok, _) = verify_in_another_process(&files);
    assert!(
        ok,
        "the honest live package must verify before it is attacked"
    );

    let mutations: Vec<(&str, Box<dyn Fn(&mut NexoraProof)>)> = vec![
        (
            "the observed window moved by one millisecond",
            Box::new(|p: &mut NexoraProof| {
                p.observer.as_mut().unwrap().batches[1].batch.claimed_to_ms += 1;
            }),
        ),
        (
            "the authorised window widened",
            Box::new(|p: &mut NexoraProof| {
                p.expectation.as_mut().unwrap().valid_until += 60_000;
            }),
        ),
        (
            "the expiry of the root token extended",
            Box::new(|p: &mut NexoraProof| {
                p.authority.as_mut().unwrap().root.expires_at = Some(u64::MAX);
            }),
        ),
        (
            "the subject relabelled",
            Box::new(|p: &mut NexoraProof| {
                p.subject.agent_id.push_str("-someone-else");
            }),
        ),
        (
            "the reported loss zeroed",
            Box::new(|p: &mut NexoraProof| {
                p.observer.as_mut().unwrap().batches[1].batch.dropped_events = Some(0);
                p.observer.as_mut().unwrap().batches[0].batch.dropped_events = Some(0);
            }),
        ),
        (
            "the declared health tolerance widened",
            Box::new(|p: &mut NexoraProof| {
                p.parameters.health_max_age_ms = u64::MAX;
            }),
        ),
        (
            "the collector's health record dropped",
            Box::new(|p: &mut NexoraProof| {
                p.observer = None;
            }),
        ),
        (
            "the verdict raised to Proven",
            Box::new(|p: &mut NexoraProof| {
                p.claim.strength = EvidenceStrength::Proven;
            }),
        ),
    ];

    for (what, mutate) in mutations {
        let mut tampered = proof.clone();
        mutate(&mut tampered);
        assert_ne!(
            tampered.proof_id(),
            proof.proof_id(),
            "{what}: the mutation did not even change the package's identity"
        );
        std::fs::write(&files.proof, export_proof(&tampered).unwrap()).unwrap();
        let (ok, report) = verify_in_another_process(&files);
        assert!(!ok, "{what}: accepted offline\n{report}");
        assert!(report.contains("verdict=Invalid("), "{what}: {report}");
        // A refusal never leaves a result standing behind it.
        assert!(
            !report.contains("result=VerifiedExecution"),
            "{what}: a refused package still reported a result\n{report}"
        );
    }
}

#[test]
fn g14_06_a_verifier_that_takes_its_anchors_from_the_forger_verifies_nothing() {
    let d = run(Scenario::Positive, AGENT);
    let (proof, anchors) = package(&d);
    let files = write_out("anchors", &proof, &anchors);

    // A forger re-signs the whole story under their own keys. Against the
    // real verifier's anchors it fails, because the keys are not the ones
    // the verifier holds.
    let forged = run(Scenario::Positive, AGENT);
    let (forged_proof, forged_anchors) = package(&forged);
    std::fs::write(&files.proof, export_proof(&forged_proof).unwrap()).unwrap();
    let (ok, report) = verify_in_another_process(&files);
    assert!(!ok, "another run's package passed these anchors:\n{report}");

    // Ship the forger's anchors beside it and it "verifies" — which is
    // exactly why anchors must never travel with the artifact they check.
    // The anchor file says so in its own text, so a reader who never read
    // the docs still meets the warning.
    std::fs::write(&files.anchors, export_anchors(&forged_anchors).unwrap()).unwrap();
    let (ok, _) = verify_in_another_process(&files);
    assert!(
        ok,
        "the forger's own anchors accept the forger's own package"
    );
    let note = String::from_utf8(std::fs::read(&files.anchors).unwrap()).unwrap();
    assert!(
        note.contains("has verified nothing"),
        "the anchor file must carry its own warning: {note}"
    );
}
