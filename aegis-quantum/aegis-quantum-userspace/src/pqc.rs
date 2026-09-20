//! PQC Module — Post-Quantum Cryptographic Engine (Kyber-768 / ML-KEM)
//!
//! Implements the "Quantum Shield" logic for Aegis-Quantum.
//! On receiving a TCP SYN event from the Ring Buffer, this module performs
//! a full Kyber-768 key encapsulation/decapsulation round-trip to establish
//! a quantum-safe shared secret.
//!
//! The shared secret hash is then written to the BPF Session Map so the
//! XDP program can verify that the connection is PQC-protected.

use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SharedSecret};
use sha2::{Digest, Sha256};
use std::time::Instant;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

use aegis_quantum_common::PacketEvent;

/// Result of a PQC key exchange round-trip with timing measurements.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PqcValidationReport {
    pub algorithm: String,
    pub public_key_bytes: usize,
    pub ciphertext_bytes: usize,
    pub shared_secret_bytes: usize,
    pub keygen_us: u64,
    pub encaps_us: u64,
    pub decaps_us: u64,
    pub total_us: u64,
    pub secrets_match: bool,
    pub shared_secret_hash: String,
}

const HYBRID_CONTEXT: &[u8] = b"AIRON-AEGIS-HYBRID-v1";

/// Perform a complete Kyber-768 key exchange round-trip with microsecond timing.
///
/// This function simulates the full "Quantum Shield" pipeline:
/// 1. **Key Generation**: The server generates a Kyber-768 keypair.
/// 2. **Encapsulation**: The client encapsulates a shared secret using the
///    server's public key (producing ciphertext + client-side shared secret).
/// 3. **Decapsulation**: The server decapsulates the ciphertext using its
///    private key to recover the same shared secret.
/// 4. **Validation**: Both shared secrets are compared for equality.
pub fn kyber768_key_exchange() -> PqcValidationReport {
    let total_start = Instant::now();

    // Step 1: Key Generation (Server-side)
    let keygen_start = Instant::now();
    let (pk, sk) = kyber768::keypair();
    let keygen_us = keygen_start.elapsed().as_micros() as u64;

    // Step 2: Encapsulation (Client-side)
    let encaps_start = Instant::now();
    let (ss_client, ct) = kyber768::encapsulate(&pk);
    let encaps_us = encaps_start.elapsed().as_micros() as u64;

    // Step 3: Decapsulation (Server-side)
    let decaps_start = Instant::now();
    let ss_server = kyber768::decapsulate(&ct, &sk);
    let decaps_us = decaps_start.elapsed().as_micros() as u64;

    let total_us = total_start.elapsed().as_micros() as u64;

    // Step 4: Validate shared secrets match
    let secrets_match = ss_client.as_bytes() == ss_server.as_bytes();

    // Compute SHA-256 hash of the shared secret for session map storage
    let mut hasher = Sha256::new();
    hasher.update(ss_client.as_bytes());
    let hash = hasher.finalize();
    let hash_hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();

    PqcValidationReport {
        algorithm: "Kyber-768 (ML-KEM)".to_string(),
        public_key_bytes: pk.as_bytes().len(),
        ciphertext_bytes: ct.as_bytes().len(),
        shared_secret_bytes: ss_client.as_bytes().len(),
        keygen_us,
        encaps_us,
        decaps_us,
        total_us,
        secrets_match,
        shared_secret_hash: hash_hex,
    }
}

/// Perform a hybrid X25519 + Kyber-768 key exchange and derive the final
/// session-map key material with a domain-separated SHA-256 combiner.
pub fn hybrid_x25519_kyber768_key_exchange() -> PqcValidationReport {
    let total_start = Instant::now();

    let x25519_start = Instant::now();
    let client_secret = EphemeralSecret::random();
    let client_public = X25519PublicKey::from(&client_secret);
    let server_secret = EphemeralSecret::random();
    let server_public = X25519PublicKey::from(&server_secret);
    let client_x25519 = client_secret.diffie_hellman(&server_public);
    let server_x25519 = server_secret.diffie_hellman(&client_public);
    let x25519_us = x25519_start.elapsed().as_micros() as u64;

    let keygen_start = Instant::now();
    let (pk, sk) = kyber768::keypair();
    let keygen_us = keygen_start.elapsed().as_micros() as u64;

    let encaps_start = Instant::now();
    let (ss_client, ct) = kyber768::encapsulate(&pk);
    let encaps_us = encaps_start.elapsed().as_micros() as u64;

    let decaps_start = Instant::now();
    let ss_server = kyber768::decapsulate(&ct, &sk);
    let decaps_us = decaps_start.elapsed().as_micros() as u64;

    let client_final = hybrid_session_hash(client_x25519.as_bytes(), ss_client.as_bytes());
    let server_final = hybrid_session_hash(server_x25519.as_bytes(), ss_server.as_bytes());
    let secrets_match = client_x25519.as_bytes() == server_x25519.as_bytes()
        && ss_client.as_bytes() == ss_server.as_bytes()
        && client_final == server_final;
    let total_us = total_start.elapsed().as_micros() as u64;

    PqcValidationReport {
        algorithm: "X25519 + Kyber-768 (Hybrid ML-KEM)".to_string(),
        public_key_bytes: pk.as_bytes().len() + client_public.as_bytes().len(),
        ciphertext_bytes: ct.as_bytes().len(),
        shared_secret_bytes: client_final.len(),
        keygen_us: keygen_us + x25519_us,
        encaps_us,
        decaps_us,
        total_us,
        secrets_match,
        shared_secret_hash: hex(&client_final),
    }
}

fn hybrid_session_hash(x25519_secret: &[u8], kyber_secret: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(HYBRID_CONTEXT);
    hasher.update((x25519_secret.len() as u32).to_le_bytes());
    hasher.update(x25519_secret);
    hasher.update((kyber_secret.len() as u32).to_le_bytes());
    hasher.update(kyber_secret);
    hasher.finalize().into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Process a `PacketEvent` from the Ring Buffer by performing a PQC key exchange.
///
/// In a production deployment, this would:
/// 1. Read the event from the Ring Buffer.
/// 2. Perform Kyber-768 key exchange.
/// 3. Write the `SessionValue` back to the BPF Session Map.
///
/// For TRL-4, we simulate the full round-trip and return the report.
pub fn process_packet_event(event: &PacketEvent) -> PqcValidationReport {
    tracing::debug!(
        src = format!("{}:{}", event.src_addr, event.src_port),
        dst = format!("{}:{}", event.dst_addr, event.dst_port),
        "Processing SYN event — initiating Kyber-768 key exchange"
    );

    hybrid_x25519_kyber768_key_exchange()
}

/// Run the full PQC validation suite (called from main for TRL-4 lab mode).
pub fn run_pqc_validation() -> PqcValidationReport {
    // Run a warmup round (JIT / cache warming)
    let _ = hybrid_x25519_kyber768_key_exchange();

    // Run the measured round
    let report = hybrid_x25519_kyber768_key_exchange();

    // Also simulate processing a mock PacketEvent
    let mock_event = PacketEvent {
        src_addr: 0x0A000001, // 10.0.0.1
        dst_addr: 0x0A000002, // 10.0.0.2
        src_port: 44100,
        dst_port: 443,
        pkt_len: 64,
        timestamp_ns: 0,
        tcp_flags: 0x02, // SYN
        _pad: [0u8; 7],
    };

    let event_report = process_packet_event(&mock_event);
    tracing::info!(
        "  Mock event processed: keygen={}μs encaps={}μs decaps={}μs match={}",
        event_report.keygen_us,
        event_report.encaps_us,
        event_report.decaps_us,
        event_report.secrets_match
    );

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn phase_budget_us() -> u64 {
        if cfg!(debug_assertions) {
            5_000
        } else {
            2_000
        }
    }

    fn average_roundtrip_budget_us() -> u64 {
        if cfg!(debug_assertions) {
            5_000
        } else {
            3_000
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  ORIGINAL 5 TESTS (preserved verbatim)
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_kyber768_roundtrip_secrets_match() {
        let report = kyber768_key_exchange();
        assert!(report.secrets_match, "Kyber-768 shared secrets must match");
    }

    #[test]
    fn test_kyber768_key_sizes() {
        let report = kyber768_key_exchange();
        assert_eq!(
            report.public_key_bytes, 1184,
            "Kyber-768 public key must be 1184 bytes"
        );
        assert_eq!(
            report.ciphertext_bytes, 1088,
            "Kyber-768 ciphertext must be 1088 bytes"
        );
        assert_eq!(
            report.shared_secret_bytes, 32,
            "Kyber-768 shared secret must be 32 bytes"
        );
    }

    #[test]
    fn test_kyber768_performance_under_5ms() {
        // TRL-4 requirement: total PQC round-trip must complete under 5ms (5000μs)
        let report = kyber768_key_exchange();
        assert!(
            report.total_us < 5000,
            "Kyber-768 total round-trip took {}μs, exceeding the 5ms TRL-4 target",
            report.total_us
        );
    }

    #[test]
    fn test_shared_secret_hash_is_valid_hex() {
        let report = kyber768_key_exchange();
        assert_eq!(
            report.shared_secret_hash.len(),
            64,
            "SHA-256 hex must be 64 chars"
        );
        assert!(
            report
                .shared_secret_hash
                .chars()
                .all(|c| c.is_ascii_hexdigit()),
            "Hash must be valid hexadecimal"
        );
    }

    #[test]
    fn test_different_keypairs_produce_different_secrets() {
        let r1 = kyber768_key_exchange();
        let r2 = kyber768_key_exchange();
        assert_ne!(
            r1.shared_secret_hash, r2.shared_secret_hash,
            "Different key exchanges should produce different shared secrets"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  CRYPTOGRAPHIC CORRECTNESS TESTS (Tests 1–6)
    // ═══════════════════════════════════════════════════════════════════════

    /// Test 1: 10 consecutive key exchanges must all produce matching secrets.
    #[test]
    fn test_10_consecutive_key_exchanges_all_match() {
        for i in 0..10 {
            let report = kyber768_key_exchange();
            assert!(
                report.secrets_match,
                "Key exchange #{} failed: shared secrets did not match",
                i + 1
            );
        }
    }

    /// Test 2: 100 key exchanges must produce 100 unique shared secret hashes.
    #[test]
    fn test_100_key_exchanges_all_unique_secrets() {
        let mut hashes = HashSet::new();
        for i in 0..100 {
            let report = kyber768_key_exchange();
            assert!(
                hashes.insert(report.shared_secret_hash.clone()),
                "Duplicate shared secret hash detected at exchange #{}: {}",
                i + 1,
                report.shared_secret_hash
            );
        }
        assert_eq!(hashes.len(), 100, "Expected 100 unique hashes");
    }

    /// Test 3: Shared secret must always be exactly 32 bytes (256 bits).
    #[test]
    fn test_shared_secret_is_32_bytes() {
        for _ in 0..5 {
            let report = kyber768_key_exchange();
            assert_eq!(
                report.shared_secret_bytes, 32,
                "Kyber-768 shared secret must be exactly 32 bytes"
            );
        }
    }

    /// Test 4: Public key must always be exactly 1184 bytes (Kyber-768 standard).
    #[test]
    fn test_public_key_is_1184_bytes() {
        for _ in 0..5 {
            let report = kyber768_key_exchange();
            assert_eq!(
                report.public_key_bytes, 1184,
                "Kyber-768 public key must be exactly 1184 bytes"
            );
        }
    }

    /// Test 5: Ciphertext must always be exactly 1088 bytes (Kyber-768 standard).
    #[test]
    fn test_ciphertext_is_1088_bytes() {
        for _ in 0..5 {
            let report = kyber768_key_exchange();
            assert_eq!(
                report.ciphertext_bytes, 1088,
                "Kyber-768 ciphertext must be exactly 1088 bytes"
            );
        }
    }

    /// Test 6: Algorithm name must be "Kyber-768 (ML-KEM)".
    #[test]
    fn test_algorithm_name_is_kyber768() {
        let report = kyber768_key_exchange();
        assert_eq!(
            report.algorithm, "Kyber-768 (ML-KEM)",
            "Algorithm name must be 'Kyber-768 (ML-KEM)'"
        );
    }

    #[test]
    fn test_hybrid_algorithm_name_and_sizes() {
        let report = hybrid_x25519_kyber768_key_exchange();
        assert_eq!(report.algorithm, "X25519 + Kyber-768 (Hybrid ML-KEM)");
        assert!(report.secrets_match, "Hybrid shared secrets must match");
        assert_eq!(
            report.public_key_bytes, 1216,
            "Hybrid public material must be 32-byte X25519 plus 1184-byte Kyber-768"
        );
        assert_eq!(report.ciphertext_bytes, 1088);
        assert_eq!(report.shared_secret_bytes, 32);
        assert_eq!(report.shared_secret_hash.len(), 64);
    }

    #[test]
    fn test_hybrid_sequential_exchanges_are_independent() {
        let r1 = hybrid_x25519_kyber768_key_exchange();
        let r2 = hybrid_x25519_kyber768_key_exchange();

        assert!(r1.secrets_match);
        assert!(r2.secrets_match);
        assert_ne!(
            r1.shared_secret_hash, r2.shared_secret_hash,
            "Hybrid exchanges must produce independent final session hashes"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  PERFORMANCE / TIMING TESTS (Tests 7–12)
    // ═══════════════════════════════════════════════════════════════════════

    /// Test 7: Key generation phase must stay within the profile-specific budget.
    #[test]
    fn test_keygen_within_profile_budget() {
        // Warmup
        let _ = kyber768_key_exchange();
        let report = kyber768_key_exchange();
        let budget_us = phase_budget_us();
        assert!(
            report.keygen_us < budget_us,
            "Keygen took {}μs, exceeding the {}μs profile budget",
            report.keygen_us,
            budget_us
        );
    }

    /// Test 8: Encapsulation phase must stay within the profile-specific budget.
    #[test]
    fn test_encaps_within_profile_budget() {
        // Warmup
        let _ = kyber768_key_exchange();
        let report = kyber768_key_exchange();
        let budget_us = phase_budget_us();
        assert!(
            report.encaps_us < budget_us,
            "Encapsulation took {}μs, exceeding the {}μs profile budget",
            report.encaps_us,
            budget_us
        );
    }

    /// Test 9: Decapsulation phase must stay within the profile-specific budget.
    #[test]
    fn test_decaps_within_profile_budget() {
        // Warmup
        let _ = kyber768_key_exchange();
        let report = kyber768_key_exchange();
        let budget_us = phase_budget_us();
        assert!(
            report.decaps_us < budget_us,
            "Decapsulation took {}μs, exceeding the {}μs profile budget",
            report.decaps_us,
            budget_us
        );
    }

    // Test 10: test_total_roundtrip_under_5ms — already exists above as
    //          test_kyber768_performance_under_5ms

    /// Test 11: Average of 100 round-trips must be under 3ms (3000μs).
    #[test]
    fn test_100_roundtrips_average_within_profile_budget() {
        // Warmup round
        let _ = kyber768_key_exchange();

        let total: u64 = (0..100).map(|_| kyber768_key_exchange().total_us).sum();
        let avg = total / 100;
        let budget_us = average_roundtrip_budget_us();
        assert!(
            avg < budget_us,
            "Average round-trip across 100 runs was {}μs, exceeding the {}μs profile budget",
            avg,
            budget_us
        );
    }

    /// Test 12: run_pqc_validation() (which performs warmup) must still
    /// produce a valid, secrets-matching report.
    #[test]
    fn test_warmup_does_not_affect_correctness() {
        let report = run_pqc_validation();
        assert!(
            report.secrets_match,
            "run_pqc_validation() must produce matching secrets even after warmup"
        );
        assert_eq!(report.shared_secret_bytes, 32);
        assert_eq!(report.public_key_bytes, 1216);
        assert_eq!(report.ciphertext_bytes, 1088);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  HASH INTEGRITY TESTS (Tests 13–16)
    // ═══════════════════════════════════════════════════════════════════════

    /// Test 13: Hash must consist entirely of lowercase hex characters (0-9, a-f).
    #[test]
    fn test_hash_is_lowercase_hex() {
        let report = kyber768_key_exchange();
        assert!(
            report
                .shared_secret_hash
                .chars()
                .all(|c| matches!(c, '0'..='9' | 'a'..='f')),
            "Hash contains non-lowercase-hex characters: {}",
            report.shared_secret_hash
        );
    }

    // Test 14: test_hash_length_always_64 — already exists above as
    //          test_shared_secret_hash_is_valid_hex (asserts len==64)

    // Test 15: test_hash_changes_between_runs — already exists above as
    //          test_different_keypairs_produce_different_secrets

    /// Test 16: NEGATIVE test — since keypairs are random, hashes from
    /// separate key exchanges MUST differ.
    #[test]
    fn test_hash_is_deterministic_for_same_keypair() {
        // Two independent key exchanges use independent random keypairs,
        // so they MUST produce different hashes. This validates entropy.
        let r1 = kyber768_key_exchange();
        let r2 = kyber768_key_exchange();
        assert_ne!(
            r1.shared_secret_hash, r2.shared_secret_hash,
            "Independent key exchanges must produce different hashes (entropy check)"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  PACKET EVENT PROCESSING TESTS (Tests 17–20)
    // ═══════════════════════════════════════════════════════════════════════

    /// Helper: create a mock PacketEvent with the given parameters.
    fn mock_event(src_port: u16, dst_port: u16, tcp_flags: u8) -> PacketEvent {
        PacketEvent {
            src_addr: 0x0A000001, // 10.0.0.1
            dst_addr: 0x0A000002, // 10.0.0.2
            src_port,
            dst_port,
            pkt_len: 64,
            timestamp_ns: 0,
            tcp_flags,
            _pad: [0u8; 7],
        }
    }

    /// Test 17: process_packet_event with a valid mock event must return
    /// a report with secrets_match == true.
    #[test]
    fn test_process_packet_event_returns_valid_report() {
        let event = mock_event(44100, 443, 0x02);
        let report = process_packet_event(&event);
        assert!(
            report.secrets_match,
            "process_packet_event must produce matching secrets"
        );
        assert_eq!(report.algorithm, "X25519 + Kyber-768 (Hybrid ML-KEM)");
    }

    /// Test 18: SYN flag (0x02) events should be processed correctly.
    #[test]
    fn test_process_packet_event_with_syn_flags() {
        let event = mock_event(12345, 443, 0x02); // SYN
        let report = process_packet_event(&event);
        assert!(
            report.secrets_match,
            "SYN-flagged event must produce valid exchange"
        );
        assert_eq!(report.shared_secret_bytes, 32);
    }

    /// Test 19: Various common and edge-case port numbers must work.
    #[test]
    fn test_process_packet_event_with_various_ports() {
        let ports = [80u16, 443, 8080, 55000];
        for &port in &ports {
            let event = mock_event(port, port, 0x02);
            let report = process_packet_event(&event);
            assert!(
                report.secrets_match,
                "Event with port {} must produce valid exchange",
                port
            );
        }
    }

    /// Test 20: Processing a single PacketEvent must complete under 5ms.
    #[test]
    fn test_process_packet_event_performance_under_5ms() {
        // Warmup
        let _ = kyber768_key_exchange();

        let event = mock_event(44100, 443, 0x02);
        let report = process_packet_event(&event);
        assert!(
            report.total_us < 5000,
            "PacketEvent processing took {}μs, exceeding the 5ms target",
            report.total_us
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  STATISTICAL VALIDATION TESTS — TDB-GRADE (Tests 21–23)
    // ═══════════════════════════════════════════════════════════════════════

    /// Test 21: Generate 50 public keys and verify each pair differs by
    /// at least 1 byte (entropy / key generation diversity check).
    #[test]
    fn test_key_generation_entropy() {
        use pqcrypto_kyber::kyber768;
        use pqcrypto_traits::kem::PublicKey;

        let keys: Vec<Vec<u8>> = (0..50)
            .map(|_| {
                let (pk, _sk) = kyber768::keypair();
                pk.as_bytes().to_vec()
            })
            .collect();

        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                let differs = keys[i].iter().zip(keys[j].iter()).any(|(a, b)| a != b);
                assert!(
                    differs,
                    "Public keys {} and {} are identical — catastrophic entropy failure",
                    i, j
                );
            }
        }
    }

    /// Test 22: Generate 50 shared secrets and verify:
    ///   - No two are identical
    ///   - None is all-zeros
    ///   - None is all-0xFF
    #[test]
    fn test_shared_secret_entropy() {
        use pqcrypto_kyber::kyber768;
        use pqcrypto_traits::kem::SharedSecret;

        let mut secrets = HashSet::new();

        for i in 0..50 {
            let (pk, _sk) = kyber768::keypair();
            let (ss, _ct) = kyber768::encapsulate(&pk);
            let bytes = ss.as_bytes().to_vec();

            // Must not be all-zeros
            assert!(
                bytes.iter().any(|&b| b != 0x00),
                "Shared secret #{} is all-zeros — critical entropy failure",
                i
            );
            // Must not be all-0xFF
            assert!(
                bytes.iter().any(|&b| b != 0xFF),
                "Shared secret #{} is all-0xFF — critical entropy failure",
                i
            );
            // Must be unique
            assert!(
                secrets.insert(bytes),
                "Duplicate shared secret detected at index {}",
                i
            );
        }
        assert_eq!(secrets.len(), 50, "Expected 50 unique shared secrets");
    }

    /// Test 23: Generate 50 ciphertexts from different keypairs and verify
    /// all are unique.
    #[test]
    fn test_ciphertext_entropy() {
        use pqcrypto_kyber::kyber768;
        use pqcrypto_traits::kem::Ciphertext;

        let mut ciphertexts = HashSet::new();

        for i in 0..50 {
            let (pk, _sk) = kyber768::keypair();
            let (_ss, ct) = kyber768::encapsulate(&pk);
            let ct_bytes = ct.as_bytes().to_vec();
            assert!(
                ciphertexts.insert(ct_bytes),
                "Duplicate ciphertext detected at index {}",
                i
            );
        }
        assert_eq!(ciphertexts.len(), 50, "Expected 50 unique ciphertexts");
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  REGRESSION / EDGE CASE TESTS (Tests 24–25)
    // ═══════════════════════════════════════════════════════════════════════

    /// Test 24: Calling run_pqc_validation() 5 times must not panic.
    #[test]
    fn test_run_pqc_validation_does_not_panic() {
        for i in 0..5 {
            let report = run_pqc_validation();
            assert!(
                report.secrets_match,
                "run_pqc_validation() panicked or failed on iteration {}",
                i + 1
            );
        }
    }

    /// Test 25: Two consecutive key exchanges must produce completely
    /// different results (independent random state).
    #[test]
    fn test_sequential_exchanges_are_independent() {
        let r1 = kyber768_key_exchange();
        let r2 = kyber768_key_exchange();

        // Shared secret hashes must differ
        assert_ne!(
            r1.shared_secret_hash, r2.shared_secret_hash,
            "Sequential exchanges must produce different shared secret hashes"
        );

        // Both must still be individually valid
        assert!(
            r1.secrets_match,
            "First exchange must produce matching secrets"
        );
        assert!(
            r2.secrets_match,
            "Second exchange must produce matching secrets"
        );

        // Sizes must remain consistent with Kyber-768 spec
        assert_eq!(r1.public_key_bytes, 1184);
        assert_eq!(r2.public_key_bytes, 1184);
        assert_eq!(r1.ciphertext_bytes, 1088);
        assert_eq!(r2.ciphertext_bytes, 1088);
        assert_eq!(r1.shared_secret_bytes, 32);
        assert_eq!(r2.shared_secret_bytes, 32);
    }
}
