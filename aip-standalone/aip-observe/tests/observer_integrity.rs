//! Adversarial tests for the observation-integrity boundary (Skill 6 §21/§22,
//! extending the four properties with a fifth the AIRI validation exposed):
//!
//! ```text
//! observer continuity verified      ≠  observation mechanism still capable
//! ```
//!
//! A foreign eBPF program on a tracepoint the observer samples suppresses that
//! tracepoint's perf submission host-wide, with no dropped-record accounting
//! and no continuity break. The observer is live, its chain is intact, and it
//! is blind. These tests pin that such an observer signs
//! `ObserverState::IntegrityUnknown` — carried inside the signed health, so a
//! forger holding the collector key cannot quietly restore `Active` — and that
//! its silence never licenses a statement about non-occurrence.
//!
//! This is a synthetic exercise of the real `CollectorSigner`: no kernel, no
//! perf fd. The Linux detector (`ProcessTracer::mechanism_integrity`) feeds
//! this same `note_mechanism_integrity` input in production; the synthetic
//! harness is where the adversary — forged state, replayed health — is driven.

use aip_crypto::{generate_ed25519_keypair, sign_ed25519};
use aip_observe::*;
use aip_types::ProcessInstance;

const OBSERVER_ID: &str = "collector.syntriass.example";
const KEY_V1: u32 = 1;

struct Fx {
    signer: CollectorSigner,
    kp: aip_types::KeyPair,
    anchors: ObserverTrustAnchors,
    probe: ProcfsProbe,
}

fn fixture() -> Fx {
    let kp = generate_ed25519_keypair();
    let mut signer =
        CollectorSigner::new(OBSERVER_ID, KEY_V1, &kp.private_key, &kp.public_key).unwrap();
    // Register the connector so a batch may declare kernel-pushed, gate-
    // independent coverage — the mechanism a real deployment corroborates with.
    signer.register_probe("probe-host-1", &SourceMechanism::ALL);
    let anchors = ObserverTrustAnchors::new().trust(OBSERVER_ID, KEY_V1, &kp.public_key);
    Fx {
        signer,
        kp,
        anchors,
        probe: ProcfsProbe::new("probe-host-1"),
    }
}

fn process(pid: u32) -> ObservedProcess {
    ObservedProcess {
        process: ProcessInstance {
            pid,
            pid_start_time_ticks: 1000,
            boot_id: [0xb0; 16],
        },
        exe_content_sha256: [0xe0; 32],
        exe_path: "/opt/agent/bin/payments-agent".into(),
    }
}

/// A batch declaring a live mechanism, so the signer accrues coverage.
fn attest_batch(f: &mut Fx, id: u8, from: u64, to: u64, mech: SourceMechanism) {
    let obs = f
        .probe
        .observation(process(42), ObservedEffect::ProcessPresent, None, from);
    let mut batch = f.probe.batch([id; 16], from, to, vec![obs]);
    batch.active_mechanisms = vec![mech];
    f.signer.attest(batch).unwrap();
}

/// Two chaining batches, so continuity is `Verified` and the observer reaches
/// `Active` with real coverage — the state the finding must be able to leave.
/// (A single batch is always `Unverified`: it links to nothing witnessed.)
fn warm_up_to_active(f: &mut Fx, mech: SourceMechanism) {
    attest_batch(f, 1, 100, 200, mech);
    attest_batch(f, 2, 200, 300, mech);
    assert_eq!(f.signer.state(), ObserverState::Active);
}

fn resign(kp: &aip_types::KeyPair, mut h: SignedSensorHealth) -> SignedSensorHealth {
    h.attestation =
        sign_ed25519(&kp.private_key, OBSERVER_ID, &h.health.canonical_bytes()).unwrap();
    h
}

// ── The finding: a blinded observer must not sign healthy coverage ──────────

#[test]
fn a_foreign_tracepoint_gate_makes_the_signed_state_integrity_unknown() {
    let mut f = fixture();
    warm_up_to_active(&mut f, SourceMechanism::SchedTracepoint);

    // Clean: the observer is Active with real coverage.
    let healthy = f.signer.health(400).unwrap();
    assert_eq!(healthy.health.state, ObserverState::Active);
    assert!(healthy.health.attested_coverage.is_some());

    // A foreign eBPF program is found gating the sampled tracepoint.
    f.signer
        .note_mechanism_integrity(MechanismIntegrity::ForeignTracepointGate {
            foreign_programs: 1,
        });

    let blinded = f.signer.health(500).unwrap();
    assert_eq!(
        blinded.health.state,
        ObserverState::IntegrityUnknown,
        "a gated tracepoint must not be reported as Active"
    );
    // The honest state is inside the signature (Invariant 1): it verifies.
    assert_eq!(verify_signed_health(&blinded, &f.anchors), Ok(()));

    // A blinded observer vouches for no coverage: the builder withholds it.
    assert!(blinded.health.attested_coverage.is_none());
    assert!(blinded.health.covered_by.is_empty());
    assert!(!blinded.covered_by_kernel_pushed_source());
    let w = CoverageWindow {
        from_ms: 200,
        to_ms: 300,
    };
    assert_eq!(
        blinded.availability_for(&w, 500, 60_000),
        ObservationAvailability::Unavailable {
            reason: UnavailableReason::ObserverIntegrityUnknown
        }
    );
}

#[test]
fn a_forger_with_the_key_cannot_relabel_integrity_unknown_as_active() {
    let mut f = fixture();
    warm_up_to_active(&mut f, SourceMechanism::ProcConnector);
    f.signer
        .note_mechanism_integrity(MechanismIntegrity::ForeignTracepointGate {
            foreign_programs: 3,
        });
    let blinded = f.signer.health(400).unwrap();
    assert_eq!(blinded.health.state, ObserverState::IntegrityUnknown);

    // A forger holding the collector key flips the state to Active and
    // re-signs. The state is in the signed preimage, so the signature is
    // valid — but this is now a *dishonest signer*, the compromised-key case,
    // not silent blinding. The defense that does not depend on the signer's
    // honesty is the coverage predicate (below); this test documents the
    // boundary between the two.
    let mut lie = blinded.clone();
    lie.health.state = ObserverState::Active;
    let lie = resign(&f.kp, lie);
    assert_eq!(
        verify_signed_health(&lie, &f.anchors),
        Ok(()),
        "a valid key produces a valid signature over the lie — key custody is the separate boundary"
    );
    // But the forger cannot mint gate-independent coverage they never had:
    // the blinded health carries no covered_by, and re-signing does not add
    // one. Even asserting Active, there is no coverage to stand on.
    assert!(lie.health.covered_by.is_empty());
    assert!(!lie.covered_by_kernel_pushed_source());
}

#[test]
fn integrity_recovers_on_the_next_clean_cycle() {
    let mut f = fixture();
    warm_up_to_active(&mut f, SourceMechanism::ProcConnector);
    f.signer
        .note_mechanism_integrity(MechanismIntegrity::ForeignTracepointGate {
            foreign_programs: 1,
        });
    assert_eq!(
        f.signer.health(400).unwrap().health.state,
        ObserverState::IntegrityUnknown
    );
    // The gate is removed; the next check is clean. Integrity is not a
    // permanent verdict (unlike quarantine): the observer reports Active again.
    f.signer
        .note_mechanism_integrity(MechanismIntegrity::Verified);
    attest_batch(&mut f, 3, 300, 400, SourceMechanism::ProcConnector);
    assert_eq!(
        f.signer.health(500).unwrap().health.state,
        ObserverState::Active
    );
}
