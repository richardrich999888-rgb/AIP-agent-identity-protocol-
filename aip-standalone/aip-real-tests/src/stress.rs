//! Stress & Performance Tests — Verifying AIP at scale.

use aip_core::nonce::NonceTracker;
use aip_core::simulation::simulate_network_verification;
use aip_core::store::IdentityStore;
use aip_core::*;
use aip_crypto::*;
use aip_types::*;
use std::collections::HashSet;

fn test_provenance() -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(b"stress-model"),
        environment_commitment: sha256(b"stress-env"),
        toolchain_commitment: sha256(b"stress-toolchain"),
    }
}

#[test]
fn test_create_1000_identities_no_collision() {
    let mut ids = HashSet::new();

    for i in 0..1000 {
        let prov = ProvenanceTriple {
            model_commitment: sha256(format!("model-{}", i).as_bytes()),
            environment_commitment: sha256(b"stress-env"),
            toolchain_commitment: sha256(b"stress-toolchain"),
        };
        let (aid, _kp) = create_identity(prov, None).unwrap();
        assert!(
            ids.insert(aid.id.clone()),
            "AIP-ID collision at identity {}: {}",
            i,
            aid.id
        );
    }
    assert_eq!(ids.len(), 1000, "Must have 1000 unique identities");
}

#[test]
fn test_sign_verify_10000_messages() {
    let kp = generate_ed25519_keypair();
    let id = "stress-agent";

    for i in 0u64..10_000 {
        let payload = format!("message-{}", i);
        let sig = sign_ed25519(&kp.private_key, id, payload.as_bytes())
            .unwrap_or_else(|_| panic!("Sign failed at {}", i));
        let valid = verify_ed25519(&kp.public_key, &sig)
            .unwrap_or_else(|_| panic!("Verify error at {}", i));
        assert!(valid, "Verify failed at message {}", i);
    }
}

#[test]
fn test_nonce_tracker_100000_signatures() {
    let mut tracker = NonceTracker::new();
    let kp = generate_ed25519_keypair();

    let mut accepted = 0u64;
    for i in 0u64..100_000 {
        let sig = sign_ed25519(&kp.private_key, &format!("agent-{}", i % 100), b"data").unwrap();
        if tracker.validate_and_record(&sig).is_ok() {
            accepted += 1;
        }
    }

    assert_eq!(
        accepted, 100_000,
        "All 100K unique signatures must be accepted"
    );
}

#[test]
fn test_nonce_tracker_eviction_under_pressure() {
    let mut tracker = NonceTracker::with_config(aip_core::nonce::NonceTrackerConfig {
        max_signature_age_ms: 300_000,
        max_tracked_nonces: 1_000, // Low limit
    });
    let kp = generate_ed25519_keypair();

    for i in 0..5_000 {
        let sig = sign_ed25519(&kp.private_key, &format!("agent-{}", i), b"data").unwrap();
        let result = tracker.validate_and_record(&sig);
        assert!(result.is_ok(), "Sig {} should be accepted", i);
    }

    // After eviction, count should be bounded
    assert!(
        tracker.tracked_count() <= 1_100, // Allow some slack
        "Tracked count {} should be near limit 1000",
        tracker.tracked_count()
    );
}

#[test]
fn test_simulation_20_agents() {
    let result = simulate_network_verification(20);
    assert!(
        result.all_passed,
        "20-agent simulation must pass. Log:\n{}",
        result.log.join("\n")
    );
    assert_eq!(result.agents_created, 20);
    assert_eq!(result.liveness_challenges_passed, 20);
    assert_eq!(result.replay_attacks_rejected, 20);
    // 20 * 19 = 380 reputation votes
    assert_eq!(result.reputation_votes_cast, 380);
}

#[test]
fn test_simulation_50_agents() {
    let result = simulate_network_verification(50);
    assert!(result.all_passed, "50-agent simulation must pass");
    assert_eq!(result.agents_created, 50);
    assert_eq!(result.liveness_challenges_passed, 50);
    assert_eq!(result.replay_attacks_rejected, 50);
    // 50 * 49 = 2450 reputation votes
    assert_eq!(result.reputation_votes_cast, 2450);
}

#[test]
fn test_store_save_load_1000_identities() {
    let tmp_path = std::env::temp_dir().join("aip_stress_store_1000.json");
    let _ = std::fs::remove_file(&tmp_path);

    {
        let mut store = IdentityStore::with_file(&tmp_path).unwrap();
        for i in 0..1000 {
            let prov = ProvenanceTriple {
                model_commitment: sha256(format!("model-{}", i).as_bytes()),
                environment_commitment: sha256(b"stress"),
                toolchain_commitment: sha256(b"stress"),
            };
            let (aid, kp) = create_identity(prov, None).unwrap();
            store.put_identity(aid, kp);
        }
        store.save().expect("Save must succeed");
    }

    {
        let store = IdentityStore::with_file(&tmp_path).unwrap();
        assert_eq!(
            store.identity_count(),
            1000,
            "Must reload all 1000 identities"
        );
    }

    let _ = std::fs::remove_file(&tmp_path);
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "wall-clock throughput gate — meaningful only under `cargo test --release`"
)]
fn test_signing_throughput() {
    let kp = generate_ed25519_keypair();
    let id = "bench-agent";
    let payload = b"benchmark payload data for throughput test";

    let start = std::time::Instant::now();
    let count = 5_000;
    for _ in 0..count {
        let _ = sign_ed25519(&kp.private_key, id, payload).unwrap();
    }
    let elapsed = start.elapsed();

    let per_sec = count as f64 / elapsed.as_secs_f64();
    eprintln!(
        "Signing throughput: {:.0} signs/sec ({} in {:.2?})",
        per_sec, count, elapsed
    );
    assert!(
        per_sec > 1000.0,
        "Signing must exceed 1000/sec, got {:.0}/sec",
        per_sec
    );
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "wall-clock throughput gate — meaningful only under `cargo test --release`"
)]
fn test_verification_throughput() {
    let kp = generate_ed25519_keypair();
    let id = "bench-agent";
    let payload = b"benchmark payload data for throughput test";
    let sig = sign_ed25519(&kp.private_key, id, payload).unwrap();

    let start = std::time::Instant::now();
    let count = 5_000;
    for _ in 0..count {
        let valid = verify_ed25519(&kp.public_key, &sig).unwrap();
        assert!(valid);
    }
    let elapsed = start.elapsed();

    let per_sec = count as f64 / elapsed.as_secs_f64();
    eprintln!(
        "Verification throughput: {:.0} verifies/sec ({} in {:.2?})",
        per_sec, count, elapsed
    );
    assert!(
        per_sec > 2000.0,
        "Verification must exceed 2000/sec, got {:.0}/sec",
        per_sec
    );
}

#[test]
fn test_rapid_challenge_response_100() {
    let kp = generate_ed25519_keypair();
    let id = derive_aip_id(&kp.public_key, &test_provenance());

    for i in 0..100 {
        let challenge = issue_liveness_challenge("verifier", &id);
        let response = respond_to_challenge(&challenge, &kp.private_key, &id)
            .unwrap_or_else(|_| panic!("Response failed at round {}", i));
        let valid = verify_liveness(&challenge, &response, &kp.public_key)
            .unwrap_or_else(|_| panic!("Verify error at round {}", i));
        assert!(valid, "Liveness round {} failed", i);
    }
}
