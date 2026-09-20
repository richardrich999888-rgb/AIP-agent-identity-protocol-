//! Building genuine attested observations for the platform tests.
//!
//! Every `ObservedBoot` in these tests comes through a real
//! `CollectorSigner`, a real signature and a real verification against real
//! anchors. There is no shortcut, because the absence of a shortcut is the
//! property Skill 19's binding rests on.

#![allow(dead_code)]

use aip_observe::*;
use aip_types::{KeyPair, ProcessInstance};

pub const OBSERVER_ID: &str = "collector-p";
pub const PROBE_ID: &str = "probe-p";

/// An observer with a fresh key, and the anchors that trust it.
pub fn observer() -> (CollectorSigner, ProcfsProbe, ObserverTrustAnchors, KeyPair) {
    let kp = aip_crypto::generate_ed25519_keypair();
    let mut signer = CollectorSigner::new(OBSERVER_ID, 1, &kp.private_key, &kp.public_key).unwrap();
    signer.register_probe(PROBE_ID, &SourceMechanism::ALL);
    let mut probe = ProcfsProbe::new(PROBE_ID);
    probe.declare_source(SourceMechanism::ProcNetTable);
    let anchors = ObserverTrustAnchors::new().trust(OBSERVER_ID, 1, &kp.public_key);
    (signer, probe, anchors, kp)
}

fn observed_process(boot_id: [u8; 16]) -> ObservedProcess {
    ObservedProcess {
        process: ProcessInstance {
            pid: 4321,
            pid_start_time_ticks: 777_000,
            boot_id,
        },
        exe_content_sha256: [0x11; 32],
        exe_path: "/opt/agent/bin/autonomy".into(),

        container: None,
    }
}

/// A batch, attested by an anchored observer, carrying one observation of a
/// process on the host with `boot_id`.
pub fn attested_batch_on(boot_id: [u8; 16]) -> (AttestedBatch, ObserverTrustAnchors) {
    let (mut signer, mut probe, anchors, _) = observer();
    let obs = probe.observation_with(
        observed_process(boot_id),
        ObservedEffect::ProcessPresent,
        SourceMechanism::ProcNetTable,
        None,
        1_000,
    );
    let batch = signer
        .attest(probe.batch([1; 16], 0, 2_000, vec![obs]))
        .expect("attest");
    (batch, anchors)
}

/// The same batch, but the verifier anchors a *different* observer — so the
/// batch is validly signed by a key the verifier does not trust.
pub fn attested_batch_from_untrusted_observer(
    boot_id: [u8; 16],
) -> (AttestedBatch, ObserverTrustAnchors) {
    let (batch, _) = attested_batch_on(boot_id);
    let stranger = aip_crypto::generate_ed25519_keypair();
    let anchors = ObserverTrustAnchors::new().trust("collector-other", 1, &stranger.public_key);
    (batch, anchors)
}

/// A batch carrying no observations at all — verified, but silent.
pub fn empty_attested_batch() -> (AttestedBatch, ObserverTrustAnchors) {
    let (mut signer, mut probe, anchors, _) = observer();
    let batch = signer
        .attest(probe.batch([2; 16], 0, 2_000, vec![]))
        .expect("attest");
    (batch, anchors)
}
