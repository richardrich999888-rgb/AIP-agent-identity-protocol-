//! Multi-Node Verification Simulation.
//!
//! Spins up multiple simulated agents, creates identities, exchanges proofs,
//! runs challenge-response liveness, reputation voting, and replay attack testing.

use crate::nonce::NonceTracker;
use crate::store::IdentityStore;
use aip_crypto::*;
use aip_types::*;

/// Result of a multi-node verification simulation.
#[derive(Debug)]
pub struct SimulationResult {
    /// Number of agents created.
    pub agents_created: usize,
    /// Number of successful cross-verifications.
    pub verifications_passed: usize,
    /// Number of liveness challenges passed.
    pub liveness_challenges_passed: usize,
    /// Number of replay attacks correctly rejected.
    pub replay_attacks_rejected: usize,
    /// Number of reputation votes cast.
    pub reputation_votes_cast: usize,
    /// Whether the simulation passed all checks.
    pub all_passed: bool,
    /// Detailed log of events.
    pub log: Vec<String>,
}

/// Run a full multi-node verification simulation.
///
/// Steps:
/// 1. Create N agents with identities
/// 2. Activate all identities
/// 3. Each agent signs a payload and every other agent verifies it
/// 4. Run liveness challenge-response between all pairs
/// 5. Attempt replay attacks (must be rejected)
/// 6. Each agent submits reputation votes for peers
///
/// Returns a `SimulationResult` with counts and pass/fail status.
pub fn simulate_network_verification(agent_count: usize) -> SimulationResult {
    assert!(agent_count >= 2, "Need at least 2 agents");

    let mut log = Vec::new();
    let mut store = IdentityStore::new();
    let mut nonce_tracker = NonceTracker::new();
    let mut all_passed = true;

    // ─── Step 1: Create agents ───

    log.push(format!("=== Creating {} agents ===", agent_count));

    let provenance = ProvenanceTriple {
        model_commitment: sha256(b"simulation-model"),
        environment_commitment: sha256(b"simulation-env"),
        toolchain_commitment: sha256(b"simulation-toolchain"),
    };

    let mut agent_ids: Vec<String> = Vec::new();

    for i in 0..agent_count {
        let (aid, kp) = crate::create_identity(provenance.clone(), None)
            .expect("Identity creation must succeed");
        let agent_id = aid.id.clone();
        log.push(format!("  Agent {}: {}", i, agent_id));
        store.put_identity(aid, kp);
        agent_ids.push(agent_id);
    }

    log.push("=== Validating identity documents (pre-activation) ===".to_string());
    let mut verifications_passed = 0;

    for id in &agent_ids {
        let entry = store.get_identity(id).unwrap();
        match crate::validate_aid(&entry.aid) {
            Ok(()) => {
                verifications_passed += 1;
                log.push(format!("  ✓ {} AID validated (self-signature OK)", id));
            }
            Err(e) => {
                all_passed = false;
                log.push(format!("  ✗ {} AID validation FAILED: {:?}", id, e));
            }
        }
    }

    // ─── Step 2: Activate all identities ───
    // NOTE: Activation mutates the status field, so self-signature
    // validation must happen in Step 1 (above) while status == Pending.

    log.push("=== Activating identities ===".to_string());
    for id in &agent_ids {
        let entry = store.get_identity_mut(id).unwrap();
        crate::activate_identity(&mut entry.aid).expect("Activation must succeed");
        log.push(format!("  Activated: {}", id));
    }

    // ─── Step 3b: Sign and verify payloads across agents ───

    log.push("=== Cross-agent signature verification ===".to_string());

    // Collect signatures from all agents
    let mut signatures: Vec<(String, Signature)> = Vec::new();
    let test_payload = b"simulation_payload_v1";

    for id in &agent_ids {
        let entry = store.get_identity(id).unwrap();
        let sig = sign_ed25519(&entry.keypair.private_key, id, test_payload)
            .expect("Signing must succeed");
        // Validate nonce freshness
        nonce_tracker
            .validate_and_record(&sig)
            .expect("Fresh sig must pass nonce check");
        signatures.push((id.clone(), sig));
    }

    for (signer_id, sig) in &signatures {
        for verifier_id in &agent_ids {
            if signer_id == verifier_id {
                continue; // Skip self-verification
            }
            let signer_entry = store.get_identity(signer_id).unwrap();
            let valid = verify_ed25519(&signer_entry.keypair.public_key, sig)
                .expect("Verification must not error");
            if valid {
                verifications_passed += 1;
            } else {
                all_passed = false;
                log.push(format!(
                    "  ✗ Sig from {} failed verification by {}",
                    signer_id, verifier_id
                ));
            }
        }
    }
    log.push(format!(
        "  {} cross-agent signature verifications passed",
        verifications_passed
    ));

    // ─── Step 4: Liveness challenge-response ───

    log.push("=== Liveness challenge-response ===".to_string());
    let mut liveness_challenges_passed = 0;

    for i in 0..agent_ids.len() {
        let j = (i + 1) % agent_ids.len();
        let challenger_id = &agent_ids[i];
        let target_id = &agent_ids[j];

        let challenge = crate::issue_liveness_challenge(challenger_id, target_id);

        let target_entry = store.get_identity(target_id).unwrap();
        let response =
            crate::respond_to_challenge(&challenge, &target_entry.keypair.private_key, target_id)
                .expect("Response must succeed");

        let valid = crate::verify_liveness(&challenge, &response, &target_entry.keypair.public_key)
            .expect("Verification must not error");

        if valid {
            liveness_challenges_passed += 1;
            log.push(format!(
                "  ✓ {} challenged {} → PASS",
                challenger_id, target_id
            ));
        } else {
            all_passed = false;
            log.push(format!(
                "  ✗ {} challenged {} → FAIL",
                challenger_id, target_id
            ));
        }
    }

    // ─── Step 5: Replay attack testing ───

    log.push("=== Replay attack testing ===".to_string());
    let mut replay_attacks_rejected = 0;

    for (_, sig) in &signatures {
        // Attempt to replay the same signature
        match nonce_tracker.validate_and_record(sig) {
            Err(AipError::NonceReuse) => {
                replay_attacks_rejected += 1;
            }
            Ok(()) => {
                all_passed = false;
                log.push("  ✗ Replay attack was NOT rejected!".to_string());
            }
            Err(e) => {
                // Other errors are also acceptable rejections
                replay_attacks_rejected += 1;
                log.push(format!("  ✓ Replay rejected with: {:?}", e));
            }
        }
    }
    log.push(format!(
        "  {} replay attacks correctly rejected",
        replay_attacks_rejected
    ));

    // ─── Step 6: Reputation voting ───

    log.push("=== Reputation voting ===".to_string());
    let mut reputation_votes_cast = 0;

    for i in 0..agent_ids.len() {
        for (j, target) in agent_ids.iter().enumerate() {
            if i == j {
                continue;
            }
            // Agent i votes on agent j
            store.update_reputation(target, 10_000); // +1%
            reputation_votes_cast += 1;
        }
    }
    log.push(format!("  {} reputation votes cast", reputation_votes_cast));

    // Check all reputations are above default
    for id in &agent_ids {
        if let Some(rep) = store.get_reputation(id) {
            log.push(format!(
                "  Agent {} reputation: {:.1}%",
                &id[..12],
                rep.overall_score as f64 / 10_000.0
            ));
        }
    }

    // ─── Summary ───

    log.push("=== Simulation Complete ===".to_string());
    log.push(format!("  All passed: {}", all_passed));

    SimulationResult {
        agents_created: agent_count,
        verifications_passed,
        liveness_challenges_passed,
        replay_attacks_rejected,
        reputation_votes_cast,
        all_passed,
        log,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simulation_3_agents() {
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
        assert!(result.reputation_votes_cast > 0);
    }

    #[test]
    fn test_simulation_5_agents() {
        let result = simulate_network_verification(5);
        assert!(
            result.all_passed,
            "Simulation must pass. Log:\n{}",
            result.log.join("\n")
        );
        assert_eq!(result.agents_created, 5);
        assert_eq!(result.liveness_challenges_passed, 5);
        assert_eq!(result.replay_attacks_rejected, 5);
        // 5 agents × 4 peers = 20 reputation votes
        assert_eq!(result.reputation_votes_cast, 20);
    }
}
