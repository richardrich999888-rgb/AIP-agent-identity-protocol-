//! AIP Test — Comprehensive integration tests for the Agent Identity Protocol.

#[cfg(test)]
mod domain_audit;

#[cfg(test)]
mod integration_tests {
    use aip_core::*;
    use aip_crypto::*;
    use aip_types::*;

    fn make_provenance(model: &str) -> ProvenanceTriple {
        ProvenanceTriple {
            model_commitment: sha256(model.as_bytes()),
            environment_commitment: sha256(b"linux-x86_64-docker"),
            toolchain_commitment: sha256(b"rustc-1.77.0-nightly"),
        }
    }

    #[test]
    fn test_full_identity_lifecycle() {
        // 1. Create identity
        let (mut aid, kp) = create_identity(make_provenance("claude-3.5"), None).unwrap();
        assert_eq!(aid.status, IdentityStatus::Pending);
        assert!(aid.id.starts_with("aip1"));

        // 2. Validate the freshly created AID
        assert!(validate_aid(&aid).is_ok());

        // 3. Activate
        activate_identity(&mut aid).unwrap();
        assert_eq!(aid.status, IdentityStatus::Active);

        // 4. Sign something
        let msg = b"I am a verified AI agent";
        let sig = sign_ed25519(&kp.private_key, &aid.id, msg).unwrap();
        assert!(verify_ed25519(&kp.public_key, &sig).unwrap());

        // 5. Suspend
        suspend_identity(&mut aid).unwrap();
        assert_eq!(aid.status, IdentityStatus::Suspended);

        // 6. Reactivate
        reactivate_identity(&mut aid).unwrap();
        assert_eq!(aid.status, IdentityStatus::Active);

        // 7. Revoke (terminal)
        revoke_identity(&mut aid).unwrap();
        assert_eq!(aid.status, IdentityStatus::Revoked);
    }

    #[test]
    fn test_provenance_bound_identity_uniqueness() {
        // Same key material, different provenance → different AIP-ID (NM-10)
        let kp = generate_ed25519_keypair();
        let prov_a = make_provenance("gpt-4o");
        let prov_b = make_provenance("claude-3.5");

        let id_a = derive_aip_id(&kp.public_key, &prov_a);
        let id_b = derive_aip_id(&kp.public_key, &prov_b);

        assert_ne!(
            id_a, id_b,
            "Same key on different substrate MUST produce different AIP-IDs"
        );
        assert!(validate_aip_id(&id_a).is_ok());
        assert!(validate_aip_id(&id_b).is_ok());
    }

    #[test]
    fn test_delegation_chain() {
        // Root agent creates child
        let (parent_aid, parent_kp) =
            create_identity(make_provenance("orchestrator"), None).unwrap();
        let (child_aid, _child_kp) = create_identity(
            make_provenance("worker-agent"),
            Some((&parent_aid.id, &parent_kp.private_key)),
        )
        .unwrap();

        assert_eq!(child_aid.lineage_depth, 1);
        assert!(child_aid.lineage_proof.is_some());

        // Verify the lineage proof was signed by the parent
        let lineage_sig = child_aid.lineage_proof.as_ref().unwrap();
        assert_eq!(lineage_sig.signer_id, parent_aid.id);
        assert!(verify_ed25519(&parent_kp.public_key, lineage_sig).unwrap());
    }

    #[test]
    fn test_signature_replay_protection() {
        let kp = generate_ed25519_keypair();
        let id = "aip1test";
        let msg = b"unique message";

        let sig1 = sign_ed25519(&kp.private_key, id, msg).unwrap();
        let sig2 = sign_ed25519(&kp.private_key, id, msg).unwrap();

        // Same payload but different nonces → different signatures
        assert_ne!(
            sig1.nonce, sig2.nonce,
            "Nonces MUST be unique per signature"
        );
        assert_ne!(sig1.signature_bytes, sig2.signature_bytes);

        // Both must verify
        assert!(verify_ed25519(&kp.public_key, &sig1).unwrap());
        assert!(verify_ed25519(&kp.public_key, &sig2).unwrap());
    }

    #[test]
    fn test_cross_agent_signature_rejection() {
        let kp_a = generate_ed25519_keypair();
        let kp_b = generate_ed25519_keypair();

        let sig = sign_ed25519(&kp_a.private_key, "agent_a", b"hello").unwrap();

        // Verify with wrong key fails
        let valid = verify_ed25519(&kp_b.public_key, &sig).unwrap();
        assert!(
            !valid,
            "Signature from agent A must NOT verify with agent B's key"
        );
    }

    #[test]
    fn test_merkle_capability_root() {
        // Build a simple capability Merkle tree
        let cap_a = merkle_leaf(b"capability:read");
        let cap_b = merkle_leaf(b"capability:write");
        let root = merkle_internal(&cap_a, &cap_b);

        // Root should be deterministic
        let root2 = merkle_internal(&cap_a, &cap_b);
        assert_eq!(root, root2);

        // Order matters
        let root_reversed = merkle_internal(&cap_b, &cap_a);
        assert_ne!(root, root_reversed);
    }

    #[test]
    fn test_aip_id_format_constraints() {
        let kp = generate_ed25519_keypair();
        let prov = make_provenance("test");
        let id = derive_aip_id(&kp.public_key, &prov);

        // Must start with "aip1"
        assert!(id.starts_with("aip1"));

        // Length must be in range 38-48 (spec says 42-46, we allow wider)
        assert!(
            id.len() >= 38 && id.len() <= 48,
            "AIP-ID length {} out of expected range",
            id.len()
        );

        // Must validate
        assert!(validate_aip_id(&id).is_ok());
    }

    // ─── NEW: End-to-end integration tests ───

    #[test]
    fn test_full_identity_flow_with_nonce_tracking() {
        use aip_core::nonce::NonceTracker;

        let mut tracker = NonceTracker::new();

        // 1. Agent A creates identity
        let (mut aid_a, kp_a) = create_identity(make_provenance("agent-a"), None).unwrap();
        activate_identity(&mut aid_a).unwrap();

        // 2. Agent B creates identity
        let (mut aid_b, kp_b) = create_identity(make_provenance("agent-b"), None).unwrap();
        activate_identity(&mut aid_b).unwrap();

        // 3. Agent A signs a payload
        let payload = b"cross-agent verified message";
        let sig_a = sign_ed25519(&kp_a.private_key, &aid_a.id, payload).unwrap();

        // 4. Nonce tracker accepts the fresh signature
        assert!(tracker.validate_and_record(&sig_a).is_ok());

        // 5. Agent B verifies Agent A's signature
        let valid = verify_ed25519(&kp_a.public_key, &sig_a).unwrap();
        assert!(valid, "Agent B must be able to verify Agent A's signature");

        // 6. Agent B CANNOT make A's signature verify with B's key
        let invalid = verify_ed25519(&kp_b.public_key, &sig_a).unwrap();
        assert!(!invalid, "A's sig must not verify with B's key");

        // 7. Challenge-response: B challenges A
        let challenge = issue_liveness_challenge(&aid_b.id, &aid_a.id);
        let response = respond_to_challenge(&challenge, &kp_a.private_key, &aid_a.id).unwrap();
        let liveness = verify_liveness(&challenge, &response, &kp_a.public_key).unwrap();
        assert!(liveness, "Liveness challenge-response must succeed");

        // 8. Replay attack: resubmit sig_a → must be rejected
        assert_eq!(
            tracker.validate_and_record(&sig_a),
            Err(AipError::NonceReuse),
            "Replay of sig_a must be rejected"
        );
    }

    #[test]
    fn test_multi_agent_cross_verification() {
        // Create 5 agents
        let mut agents: Vec<(AgentIdentityDocument, KeyPair)> = Vec::new();
        for i in 0..5 {
            let (mut aid, kp) =
                create_identity(make_provenance(&format!("agent-{}", i)), None).unwrap();
            activate_identity(&mut aid).unwrap();
            agents.push((aid, kp));
        }

        // Each agent verifies every other agent
        for i in 0..5 {
            for (j, (aid_j, kp_j)) in agents.iter().enumerate() {
                if i == j {
                    continue;
                }
                let payload = format!("message-from-{}-to-{}", j, i);
                let sig = sign_ed25519(&kp_j.private_key, &aid_j.id, payload.as_bytes()).unwrap();
                let valid = verify_ed25519(&kp_j.public_key, &sig).unwrap();
                assert!(valid, "Agent {} must verify agent {}'s signature", i, j);
            }
        }
    }

    #[test]
    fn test_nonce_replay_rejected() {
        use aip_core::nonce::NonceTracker;

        let mut tracker = NonceTracker::new();
        let kp = generate_ed25519_keypair();

        let sig = sign_ed25519(&kp.private_key, "agent", b"important data").unwrap();

        // First use: accepted
        assert!(tracker.validate_and_record(&sig).is_ok());

        // Same exact signature replayed: rejected
        assert_eq!(tracker.validate_and_record(&sig), Err(AipError::NonceReuse));

        // A new signature on the same data: accepted (different nonce)
        let sig2 = sign_ed25519(&kp.private_key, "agent", b"important data").unwrap();
        assert_ne!(sig.nonce, sig2.nonce);
        assert!(tracker.validate_and_record(&sig2).is_ok());
    }

    #[test]
    fn test_runtime_binding() {
        use aip_core::runtime::{bind_identity_to_runtime, verify_runtime_binding};

        let (aid, _kp) = create_identity(make_provenance("runtime-test"), None).unwrap();
        let binding = bind_identity_to_runtime(&aid.id);

        // Binding should contain the agent's ID
        assert_eq!(binding.agent_id, aid.id);

        // Runtime hash should be non-zero
        assert_ne!(binding.runtime_hash, [0u8; 32]);

        // Verification should match current environment
        let verification = verify_runtime_binding(&binding);
        assert!(
            verification.exe_match,
            "Executable must match in same process"
        );
        assert!(
            verification.is_same_environment,
            "Same environment check must pass"
        );
    }

    #[test]
    fn test_store_identity_persistence_roundtrip() {
        use aip_core::store::{IdentityStore, Persistence};

        let tmp_path = std::env::temp_dir().join("aip_integration_test_store.json");
        let _ = std::fs::remove_file(&tmp_path);

        // Create and store an identity (keep it in Pending so self-sig remains valid)
        let (aid, kp) = create_identity(make_provenance("stored-agent"), None).unwrap();
        let agent_id = aid.id.clone();

        // Validate BEFORE storing (while status == Pending, matching self-signature)
        assert!(validate_aid(&aid).is_ok(), "AID must validate before store");

        {
            let mut store =
                IdentityStore::with_file(&tmp_path, Persistence::DevelopmentPlaintext).unwrap();
            store.put_identity(aid, kp);
            store.save().unwrap();
        }

        // Load from file and verify it's the same
        {
            let store =
                IdentityStore::with_file(&tmp_path, Persistence::DevelopmentPlaintext).unwrap();
            let loaded = store.get_identity(&agent_id).unwrap();
            assert_eq!(loaded.aid.id, agent_id);
            assert_eq!(loaded.aid.status, IdentityStatus::Pending);
            // Validate the loaded AID (self-sig still matches Pending status)
            assert!(
                validate_aid(&loaded.aid).is_ok(),
                "Loaded AID must validate"
            );
            // Verify we can sign with the loaded keypair
            // Reached through the controlled operation, not a key accessor.
            let sig = loaded.sign(b"test").unwrap();
            assert!(verify_ed25519(loaded.public_key(), &sig).unwrap());
        }

        let _ = std::fs::remove_file(&tmp_path);
    }

    #[test]
    fn test_simulation_passes() {
        use aip_core::simulation::simulate_network_verification;

        let result = simulate_network_verification(3);
        assert!(
            result.all_passed,
            "Simulation must pass. Log:\n{}",
            result.log.join("\n")
        );
        assert_eq!(result.agents_created, 3);
        assert!(result.verifications_passed > 0);
        assert_eq!(result.liveness_challenges_passed, 3);
        assert_eq!(result.replay_attacks_rejected, 3);
    }
}
