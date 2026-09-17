//! SD-09 end to end: a verdict from the real reconciliation engine can be
//! signed by an independent reconciler authority and verified offline against
//! anchors the verifier supplies. This is the proof that the signer works on
//! genuine engine output, not only on hand-built sample verdicts.
#![cfg(target_os = "linux")]

use aip_crypto::generate_ed25519_keypair;
use aip_reconcile::{ReconcilerSigner, ReconcilerTrustAnchors, ReconciliationAttestationError};
use ghost_demo::{run, Scenario};

const AGENT: &str = env!("CARGO_BIN_EXE_ghost-demo-agent");
const RID: &str = "reconciler.demo.example";
const KV: u32 = 1;

#[test]
fn a_real_engine_verdict_signs_and_verifies() {
    // A real scenario against the real agent, socket table, collector and
    // reconciler produces the verdict we sign.
    let demo = run(Scenario::Positive, AGENT);

    let kp = generate_ed25519_keypair();
    let signer = ReconcilerSigner::new(RID, KV, &kp.private_key, &kp.public_key).unwrap();
    let signed = signer.sign(&demo.reconciliation).unwrap();

    let anchors = ReconcilerTrustAnchors::new().trust(RID, KV, &kp.public_key);
    assert_eq!(signed.verify(&anchors), Ok(()));

    // Signing attributes the verdict; it does not change it or strengthen it.
    assert_eq!(signed.reconciliation().result, demo.reconciliation.result);
    assert_eq!(
        signed.reconciliation().strength,
        demo.reconciliation.strength
    );
}

#[test]
fn a_tampered_real_verdict_is_refused() {
    let demo = run(Scenario::Positive, AGENT);
    let kp = generate_ed25519_keypair();
    let signer = ReconcilerSigner::new(RID, KV, &kp.private_key, &kp.public_key).unwrap();
    let mut signed = signer.sign(&demo.reconciliation).unwrap();
    let anchors = ReconcilerTrustAnchors::new().trust(RID, KV, &kp.public_key);

    // Alter the signed verdict's reason after the fact (to a value the Positive
    // scenario does not carry, so the bytes genuinely change).
    signed.reconciliation.reason = aip_reconcile::ReasonCode::ActionEvidenceUnavailable;
    assert_eq!(
        signed.verify(&anchors),
        Err(ReconciliationAttestationError::PayloadHashMismatch)
    );
}
