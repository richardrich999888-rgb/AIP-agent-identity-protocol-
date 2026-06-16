//! End-to-End & CLI Tests — Full pipeline verification.

use aip_core::nonce::NonceTracker;
use aip_core::runtime::{bind_identity_to_runtime, verify_runtime_binding};
use aip_core::simulation::simulate_network_verification;
use aip_core::store::IdentityStore;
use aip_core::*;
use aip_crypto::*;
use aip_types::*;

fn test_provenance(label: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(label.as_bytes()),
        environment_commitment: sha256(b"e2e-env"),
        toolchain_commitment: sha256(b"e2e-toolchain"),
    }
}

// ═══════════════════════════════════════════════════════════════
// CROSS-PROCESS SIGNATURE VERIFICATION (via store file)
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_cross_process_sign_verify_via_store() {
    let tmp_path = std::env::temp_dir().join("aip_e2e_cross_process.json");
    let _ = std::fs::remove_file(&tmp_path);

    let payload = b"cross-process verified data";
    let sig_json;
    let agent_id;

    // "Process A" — creates identity and signs
    {
        let mut store = IdentityStore::with_file(&tmp_path).unwrap();
        let (aid, kp) = create_identity(test_provenance("process-a-model"), None).unwrap();
        agent_id = aid.id.clone();
        store.put_identity(aid, kp.clone());
        store.save().unwrap();

        let sig = sign_ed25519(&kp.private_key, &agent_id, payload).unwrap();
        sig_json = serde_json::to_string(&sig).unwrap();
    }

    // "Process B" — loads store and verifies
    {
        let store = IdentityStore::with_file(&tmp_path).unwrap();
        let entry = store
            .get_identity(&agent_id)
            .expect("Process B must find the identity");

        let sig: Signature = serde_json::from_str(&sig_json).unwrap();

        // Freshness check
        let mut tracker = NonceTracker::new();
        assert!(
            tracker.validate_and_record(&sig).is_ok(),
            "Signature must pass freshness check"
        );

        // Crypto verification
        let valid = verify_ed25519(&entry.keypair.public_key, &sig).unwrap();
        assert!(
            valid,
            "Process B must successfully verify Process A's signature"
        );

        // Replay rejection
        assert_eq!(
            tracker.validate_and_record(&sig),
            Err(AipError::NonceReuse),
            "Same signature replayed must be rejected"
        );
    }

    let _ = std::fs::remove_file(&tmp_path);
}

// ═══════════════════════════════════════════════════════════════
// FULL E2E PIPELINE
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_full_e2e_identity_pipeline() {
    let tmp_path = std::env::temp_dir().join("aip_e2e_full_pipeline.json");
    let _ = std::fs::remove_file(&tmp_path);

    let mut store = IdentityStore::with_file(&tmp_path).unwrap();
    let mut tracker = NonceTracker::new();

    // 1. Create 3 agents
    let mut agents: Vec<(String, KeyPair)> = Vec::new();
    for i in 0..3 {
        let (aid, kp) = create_identity(test_provenance(&format!("agent-{}", i)), None).unwrap();
        let id = aid.id.clone();
        assert!(validate_aid(&aid).is_ok(), "AID {} must validate", i);
        store.put_identity(aid, kp.clone());
        agents.push((id, kp));
    }

    // 2. Activate all agents
    for (id, _) in &agents {
        let entry = store.get_identity_mut(id).unwrap();
        activate_identity(&mut entry.aid).unwrap();
    }
    store.save().unwrap();

    // 3. Each agent signs a payload, others verify
    let message = b"e2e pipeline test message";
    for (signer_id, signer_kp) in &agents {
        let sig = sign_ed25519(&signer_kp.private_key, signer_id, message).unwrap();

        // Nonce check
        assert!(tracker.validate_and_record(&sig).is_ok());

        // Every other agent verifies
        for (verifier_id, _) in &agents {
            if verifier_id == signer_id {
                continue;
            }
            let valid = verify_ed25519(&signer_kp.public_key, &sig).unwrap();
            assert!(
                valid,
                "{} must verify {}'s signature",
                verifier_id, signer_id
            );
        }

        // Replay rejected
        assert_eq!(tracker.validate_and_record(&sig), Err(AipError::NonceReuse));
    }

    // 4. Liveness challenge-response between agent 0 and agent 1
    {
        let (id_0, kp_0) = &agents[0];
        let (id_1, _kp_1) = &agents[1];
        let challenge = issue_liveness_challenge(id_1, id_0);
        let response = respond_to_challenge(&challenge, &kp_0.private_key, id_0).unwrap();
        let valid = verify_liveness(&challenge, &response, &kp_0.public_key).unwrap();
        assert!(valid, "Liveness challenge must pass in e2e pipeline");
    }

    // 5. Runtime binding
    {
        let (id_0, _) = &agents[0];
        let binding = bind_identity_to_runtime(id_0);
        let verification = verify_runtime_binding(&binding);
        assert!(verification.is_same_environment);
    }

    // 6. Reload store from disk and verify
    {
        let reloaded = IdentityStore::with_file(&tmp_path).unwrap();
        assert_eq!(reloaded.identity_count(), 3);
        for (id, kp) in &agents {
            let entry = reloaded.get_identity(id).unwrap();
            assert_eq!(entry.aid.status, IdentityStatus::Active);
            // Verify the loaded key still works
            let sig = sign_ed25519(&kp.private_key, id, b"reload test").unwrap();
            let valid = verify_ed25519(&entry.keypair.public_key, &sig).unwrap();
            assert!(valid, "Reloaded identity must still sign/verify");
        }
    }

    let _ = std::fs::remove_file(&tmp_path);
}

// ═══════════════════════════════════════════════════════════════
// CLI SIMULATE VERIFICATION
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_simulate_exit_passes() {
    let result = simulate_network_verification(5);
    assert!(result.all_passed);
    assert_eq!(result.agents_created, 5);
    assert_eq!(result.liveness_challenges_passed, 5);
    assert_eq!(result.replay_attacks_rejected, 5);
    assert_eq!(result.reputation_votes_cast, 20);
    assert!(result.verifications_passed > 0);
}

// ═══════════════════════════════════════════════════════════════
// IDENTITY LIFECYCLE → STORE → VERIFY CHAIN
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_lifecycle_transitions_persist_through_store() {
    let tmp_path = std::env::temp_dir().join("aip_e2e_lifecycle.json");
    let _ = std::fs::remove_file(&tmp_path);

    let (aid, kp) = create_identity(test_provenance("lifecycle-test"), None).unwrap();
    let id = aid.id.clone();

    // Create → Activate → Suspend → Reactivate → Revoke, persisting each step
    {
        let mut store = IdentityStore::with_file(&tmp_path).unwrap();
        store.put_identity(aid, kp);
        let e = store.get_identity_mut(&id).unwrap();
        activate_identity(&mut e.aid).unwrap();
        store.save().unwrap();
    }

    {
        let mut store = IdentityStore::with_file(&tmp_path).unwrap();
        let e = store.get_identity_mut(&id).unwrap();
        assert_eq!(e.aid.status, IdentityStatus::Active);
        suspend_identity(&mut e.aid).unwrap();
        store.save().unwrap();
    }

    {
        let mut store = IdentityStore::with_file(&tmp_path).unwrap();
        let e = store.get_identity_mut(&id).unwrap();
        assert_eq!(e.aid.status, IdentityStatus::Suspended);
        reactivate_identity(&mut e.aid).unwrap();
        store.save().unwrap();
    }

    {
        let mut store = IdentityStore::with_file(&tmp_path).unwrap();
        let e = store.get_identity_mut(&id).unwrap();
        assert_eq!(e.aid.status, IdentityStatus::Active);
        revoke_identity(&mut e.aid).unwrap();
        store.save().unwrap();
    }

    // Final reload — must be Revoked
    {
        let store = IdentityStore::with_file(&tmp_path).unwrap();
        let e = store.get_identity(&id).unwrap();
        assert_eq!(e.aid.status, IdentityStatus::Revoked);
    }

    let _ = std::fs::remove_file(&tmp_path);
}

#[test]
fn test_tampered_signature_rejected_via_store() {
    let tmp_path = std::env::temp_dir().join("aip_e2e_tamper.json");
    let _ = std::fs::remove_file(&tmp_path);

    let (aid, kp) = create_identity(test_provenance("tamper-test"), None).unwrap();
    let id = aid.id.clone();

    {
        let mut store = IdentityStore::with_file(&tmp_path).unwrap();
        store.put_identity(aid, kp.clone());
        store.save().unwrap();
    }

    // Sign a message
    let sig = sign_ed25519(&kp.private_key, &id, b"original data").unwrap();
    let mut sig_json = serde_json::to_string(&sig).unwrap();

    // Tamper with the JSON (change payload_hash)
    sig_json = sig_json.replace(
        &format!("{}", sig.payload_hash[0]),
        &format!("{}", (sig.payload_hash[0].wrapping_add(1))),
    );

    // Load and verify tampered signature
    let store = IdentityStore::with_file(&tmp_path).unwrap();
    let entry = store.get_identity(&id).unwrap();
    let tampered_sig: Signature = serde_json::from_str(&sig_json).unwrap();

    let valid = verify_ed25519(&entry.keypair.public_key, &tampered_sig).unwrap();
    assert!(
        !valid,
        "Tampered signature loaded from JSON must not verify"
    );

    let _ = std::fs::remove_file(&tmp_path);
}
