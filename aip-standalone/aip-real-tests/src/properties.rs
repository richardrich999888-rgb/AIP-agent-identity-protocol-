//! Property-Based / Invariant Tests — Verifying algebraic and cryptographic properties.

use aip_core::*;
use aip_crypto::*;
use aip_types::*;
use std::collections::HashSet;

fn test_provenance() -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(b"property-model"),
        environment_commitment: sha256(b"property-env"),
        toolchain_commitment: sha256(b"property-toolchain"),
    }
}

// ═══════════════════════════════════════════════════════════════
// SIGNATURE PROPERTIES
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_sign_verify_roundtrip_any_payload() {
    let kp = generate_ed25519_keypair();
    let id = "property-agent";

    // Test various payload types
    let payloads: Vec<&[u8]> = vec![
        b"",                       // Empty
        b"a",                      // Single byte
        b"hello world",            // Normal string
        &[0u8; 1024],              // 1KB zeros
        &[0xFF; 4096],             // 4KB all-ones
        b"\x00\x01\x02\x03",       // Binary data
        "🔐🤖💡".as_bytes(),       // UTF-8 emoji
        &[0xDE, 0xAD, 0xBE, 0xEF], // Classic hex
    ];

    for (i, payload) in payloads.iter().enumerate() {
        let sig = sign_ed25519(&kp.private_key, id, payload)
            .expect(&format!("Sign failed for payload {}", i));
        let valid =
            verify_ed25519(&kp.public_key, &sig).expect(&format!("Verify error for payload {}", i));
        assert!(
            valid,
            "Roundtrip failed for payload {} (len={})",
            i,
            payload.len()
        );
    }
}

#[test]
fn test_sign_verify_different_key_never_valid() {
    let id = "property-agent";
    let payload = b"test data";

    for _ in 0..100 {
        let kp_signer = generate_ed25519_keypair();
        let kp_verifier = generate_ed25519_keypair();

        let sig = sign_ed25519(&kp_signer.private_key, id, payload).unwrap();
        let valid = verify_ed25519(&kp_verifier.public_key, &sig).unwrap();
        assert!(
            !valid,
            "Different keys must NEVER produce valid cross-verification"
        );
    }
}

// ═══════════════════════════════════════════════════════════════
// AIP-ID PROPERTIES
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_aip_id_deterministic() {
    let kp = generate_ed25519_keypair();
    let prov = test_provenance();

    let id1 = derive_aip_id(&kp.public_key, &prov);
    let id2 = derive_aip_id(&kp.public_key, &prov);
    let id3 = derive_aip_id(&kp.public_key, &prov);

    assert_eq!(id1, id2);
    assert_eq!(id2, id3);
}

#[test]
fn test_aip_id_unique_per_key_500_pairs() {
    let prov = test_provenance();
    let mut ids = HashSet::new();

    for _ in 0..500 {
        let kp = generate_ed25519_keypair();
        let id = derive_aip_id(&kp.public_key, &prov);
        assert!(ids.insert(id), "AIP-ID collision detected among 500 keys!");
    }
    assert_eq!(ids.len(), 500);
}

// ═══════════════════════════════════════════════════════════════
// LIFECYCLE STATE MACHINE PROPERTIES
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_lifecycle_exhaustive_transitions() {
    // Test ALL 20 possible (state × action) combinations
    let actions = vec![
        (
            "activate",
            activate_identity as fn(&mut AgentIdentityDocument) -> Result<(), AipError>,
        ),
        (
            "suspend",
            suspend_identity as fn(&mut AgentIdentityDocument) -> Result<(), AipError>,
        ),
        (
            "reactivate",
            reactivate_identity as fn(&mut AgentIdentityDocument) -> Result<(), AipError>,
        ),
        (
            "revoke",
            revoke_identity as fn(&mut AgentIdentityDocument) -> Result<(), AipError>,
        ),
    ];

    // Actual behavior: transitions are idempotent where it makes sense.
    // activate(Active)=Ok, suspend(Suspended)=Ok, reactivate(Active)=Ok,
    // revoke(ANY)=Ok, revoke(Revoked)=Ok (idempotent).
    let expected: Vec<(IdentityStatus, &str, bool)> = vec![
        // From Pending
        (IdentityStatus::Pending, "activate", true), // Primary transition
        (IdentityStatus::Pending, "suspend", false), // MissingRequiredField
        (IdentityStatus::Pending, "reactivate", false), // MissingRequiredField
        (IdentityStatus::Pending, "revoke", true),   // ANY→Revoked
        // From Active
        (IdentityStatus::Active, "activate", true), // Idempotent
        (IdentityStatus::Active, "suspend", true),  // Primary transition
        (IdentityStatus::Active, "reactivate", true), // Idempotent (already active)
        (IdentityStatus::Active, "revoke", true),   // ANY→Revoked
        // From Suspended
        (IdentityStatus::Suspended, "activate", false), // IdentitySuspended
        (IdentityStatus::Suspended, "suspend", true),   // Idempotent
        (IdentityStatus::Suspended, "reactivate", true), // Primary transition
        (IdentityStatus::Suspended, "revoke", true),    // ANY→Revoked
        // From Revoked (terminal — only revoke is idempotent)
        (IdentityStatus::Revoked, "activate", false), // IdentityRevoked
        (IdentityStatus::Revoked, "suspend", false),  // IdentityRevoked
        (IdentityStatus::Revoked, "reactivate", false), // IdentityRevoked
        (IdentityStatus::Revoked, "revoke", true),    // Idempotent
    ];

    for (initial_status, action_name, should_succeed) in &expected {
        let (mut aid, _kp) = create_identity(test_provenance(), None).unwrap();

        // Set up initial state
        match initial_status {
            IdentityStatus::Pending => {} // Already Pending
            IdentityStatus::Active => {
                activate_identity(&mut aid).unwrap();
            }
            IdentityStatus::Suspended => {
                activate_identity(&mut aid).unwrap();
                suspend_identity(&mut aid).unwrap();
            }
            IdentityStatus::Revoked => {
                activate_identity(&mut aid).unwrap();
                revoke_identity(&mut aid).unwrap();
            }
        }

        let (_, action_fn) = actions
            .iter()
            .find(|(name, _)| name == action_name)
            .unwrap();

        let result = action_fn(&mut aid);
        assert_eq!(
            result.is_ok(),
            *should_succeed,
            "Transition {:?} → {} expected {}",
            initial_status,
            action_name,
            if *should_succeed { "OK" } else { "ERR" }
        );
    }
}

// ═══════════════════════════════════════════════════════════════
// CAPABILITY PROPERTIES
// ═══════════════════════════════════════════════════════════════

fn make_grant(ns: &str, actions: Vec<Action>) -> CapabilityGrant {
    let kp = generate_ed25519_keypair();
    let sig = sign_ed25519(&kp.private_key, "grantor", b"grant").unwrap();
    CapabilityGrant {
        id: [0u8; 16],
        grantor_id: "grantor".into(),
        grantee_id: "agent".into(),
        namespace: ns.into(),
        actions,
        constraints: vec![],
        delegatable: true,
        issued_at: 0,
        expires_at: None,
        grantor_sig: sig,
    }
}

#[test]
fn test_capability_meet_commutative() {
    let a = make_grant(
        "com.test",
        vec![Action::Read, Action::Write, Action::Delete],
    );
    let b = make_grant("com.test", vec![Action::Read, Action::Write]);

    let meet_ab = capability_meet(&a, &b);
    let meet_ba = capability_meet(&b, &a);

    match (meet_ab, meet_ba) {
        (Some(ab), Some(ba)) => {
            let mut actions_ab = ab.resolved_actions.clone();
            let mut actions_ba = ba.resolved_actions.clone();
            actions_ab.sort_by_key(|a| *a as u8);
            actions_ba.sort_by_key(|a| *a as u8);
            assert_eq!(
                actions_ab, actions_ba,
                "MEET must be commutative: A∧B == B∧A"
            );
        }
        (None, None) => {} // Both empty is also commutative
        _ => panic!("MEET commutativity violated: one is Some, other is None"),
    }
}

#[test]
fn test_capability_meet_idempotent() {
    let a = make_grant("com.test", vec![Action::Read, Action::Write]);
    let meet_aa = capability_meet(&a, &a);
    assert!(meet_aa.is_some(), "MEET(A, A) must not be empty");
    let eff = meet_aa.unwrap();
    let mut result_actions = eff.resolved_actions.clone();
    result_actions.sort_by_key(|a| *a as u8);
    let mut orig_actions = a.actions.clone();
    orig_actions.sort_by_key(|a| *a as u8);
    assert_eq!(
        result_actions, orig_actions,
        "MEET(A, A) must equal A (idempotent)"
    );
}

// ═══════════════════════════════════════════════════════════════
// TEMPORAL DECAY PROPERTIES
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_temporal_decay_monotonic() {
    let policy = TemporalDecayPolicy {
        decay_type: DecayType::Value,
        half_life_seconds: 3600,
        minimum_floor: 0,
        reauthorization_at: Some(0),
    };

    let mut prev = 1_000_000u32;
    for elapsed in (0..=36000).step_by(3600) {
        let value = effective_decay_value(1_000_000, &policy, elapsed);
        assert!(
            value <= prev,
            "Decay must be monotonically decreasing: at t={}, {} > {}",
            elapsed,
            value,
            prev
        );
        prev = value;
    }
}

#[test]
fn test_temporal_decay_floor_never_breached() {
    let policy = TemporalDecayPolicy {
        decay_type: DecayType::Value,
        half_life_seconds: 100,
        minimum_floor: 42_000,
        reauthorization_at: Some(0),
    };

    for elapsed in (0..=1_000_000).step_by(1000) {
        let value = effective_decay_value(1_000_000, &policy, elapsed);
        assert!(
            value >= 42_000,
            "Value {} breached floor 42_000 at t={}",
            value,
            elapsed
        );
    }
}

// ═══════════════════════════════════════════════════════════════
// REPUTATION PROPERTIES
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_reputation_score_always_bounded() {
    let values: Vec<i32> = vec![-1_000_000, -100_000, -1, 0, 1, 100_000, 400_000, 1_000_000];

    for attester_type in [
        AttesterType::Authority,
        AttesterType::Oracle,
        AttesterType::Governance,
        AttesterType::Peer,
        AttesterType::SelfAttest,
    ] {
        for &value in &values {
            let attestation = Attestation {
                id: [0u8; 16],
                subject_id: "agent".into(),
                attester_id: "authority".into(),
                attester_type,
                claim_type: ClaimType::TaskCompletion,
                claim_value: value,
                claim_context: "test".into(),
                evidence_hash: None,
                attested_at: 0,
                valid_until: None,
                attester_sig: sign_ed25519(
                    &generate_ed25519_keypair().private_key,
                    "authority",
                    b"attest",
                )
                .unwrap(),
            };

            let rep = calculate_reputation("agent", &[attestation], 0);
            assert!(
                rep.overall_score <= 1_000_000,
                "Score {} out of range at claim_value={} ({:?})",
                rep.overall_score,
                value,
                attester_type
            );
        }
    }
}

#[test]
fn test_nonce_uniqueness_csprng() {
    let kp = generate_ed25519_keypair();
    let mut nonces = HashSet::new();

    for _ in 0..10_000 {
        let sig = sign_ed25519(&kp.private_key, "agent", b"data").unwrap();
        assert!(nonces.insert(sig.nonce), "CSPRNG produced duplicate nonce!");
    }
    assert_eq!(nonces.len(), 10_000);
}

#[test]
fn test_merkle_collision_resistant() {
    let mut roots = HashSet::new();

    for i in 0u64..1000 {
        let left = merkle_leaf(&i.to_le_bytes());
        let right = merkle_leaf(&(i + 1000).to_le_bytes());
        let root = merkle_internal(&left, &right);
        assert!(
            roots.insert(root),
            "Merkle root collision at pair ({}, {})",
            i,
            i + 1000
        );
    }
}
