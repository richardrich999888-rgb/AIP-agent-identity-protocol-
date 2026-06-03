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

    kyber768_key_exchange()
}

/// Run the full PQC validation suite (called from main for TRL-4 lab mode).
pub fn run_pqc_validation() -> PqcValidationReport {
    // Run a warmup round (JIT / cache warming)
    let _ = kyber768_key_exchange();

    // Run the measured round
    let report = kyber768_key_exchange();

    // Also simulate processing a mock PacketEvent
    let mock_event = PacketEvent {
        src_addr: 0x0A000001,   // 10.0.0.1
        dst_addr: 0x0A000002,   // 10.0.0.2
        src_port: 44100,
        dst_port: 443,
        pkt_len: 64,
        timestamp_ns: 0,
        tcp_flags: 0x02,        // SYN
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

    #[test]
    fn test_kyber768_roundtrip_secrets_match() {
        let report = kyber768_key_exchange();
        assert!(report.secrets_match, "Kyber-768 shared secrets must match");
    }

    #[test]
    fn test_kyber768_key_sizes() {
        let report = kyber768_key_exchange();
        assert_eq!(report.public_key_bytes, 1184, "Kyber-768 public key must be 1184 bytes");
        assert_eq!(report.ciphertext_bytes, 1088, "Kyber-768 ciphertext must be 1088 bytes");
        assert_eq!(report.shared_secret_bytes, 32, "Kyber-768 shared secret must be 32 bytes");
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
        assert_eq!(report.shared_secret_hash.len(), 64, "SHA-256 hex must be 64 chars");
        assert!(
            report.shared_secret_hash.chars().all(|c| c.is_ascii_hexdigit()),
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
}
