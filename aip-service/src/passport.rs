//! AgentPassport state and verification helpers.

use std::{fs::OpenOptions, io::Write, path::Path};

use aip_core::passport::{canonical_passport_body_bytes, AgentPassport};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassportRecord {
    pub passport_id: String,
    pub agent_id: String,
    pub passport_hash: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

pub fn passport_hash(passport: &AgentPassport) -> Result<String, String> {
    let bytes = serde_json::to_vec(passport)
        .map_err(|e| format!("failed to serialize passport for hash: {e}"))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub fn append_passport_record(path: &str, record: &PassportRecord) -> Result<(), String> {
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create passport log directory: {e}"))?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("failed to open passport log: {e}"))?;

    let line = serde_json::to_string(record)
        .map_err(|e| format!("failed to serialize passport record: {e}"))?;
    writeln!(file, "{line}").map_err(|e| format!("failed to append passport record: {e}"))?;
    Ok(())
}

pub fn verify_passport_ed25519(
    passport: &AgentPassport,
    now_unix_seconds: u64,
) -> Result<(), String> {
    if passport.header.alg != "Ed25519" {
        return Err(format!(
            "unsupported passport algorithm in Phase 1 verifier: {}",
            passport.header.alg
        ));
    }
    if passport.proof.pqc_signature.is_some() {
        return Err(
            "PQC signature verification is not enabled in this Phase 1 verifier".to_owned(),
        );
    }

    passport
        .structural_check()
        .map_err(|e| format!("structural check failed: {e}"))?;
    passport
        .temporal_check(now_unix_seconds)
        .map_err(|e| format!("temporal check failed: {e}"))?;

    let public_key_bytes = B64URL
        .decode(passport.body.issuer.classical_pubkey.as_bytes())
        .map_err(|e| format!("issuer public key decode failed: {e}"))?;
    let public_key: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| "issuer classical public key must be 32 bytes".to_owned())?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|e| format!("issuer public key parse failed: {e}"))?;

    let signature_bytes = B64URL
        .decode(passport.proof.signature.as_bytes())
        .map_err(|e| format!("passport signature decode failed: {e}"))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|e| format!("passport signature parse failed: {e}"))?;

    let body_bytes = canonical_passport_body_bytes(&passport.body)
        .map_err(|e| format!("canonical body encoding failed: {e}"))?;
    verifying_key
        .verify(&body_bytes, &signature)
        .map_err(|_| "passport Ed25519 signature mismatch".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aip_core::passport::{
        EnvironmentalLock, LineageEntry, PassportBody, PassportConstraints, PassportHeader,
        PassportIssuer, PassportProof, PassportSubject,
    };

    use crate::keys::KeyPair;

    fn signed_passport(kp: &KeyPair) -> AgentPassport {
        let body = PassportBody {
            passport_id: "urn:aip:passport:550e8400-e29b-41d4-a716-446655440000".to_owned(),
            subject: PassportSubject {
                agent_id: "550e8400-e29b-41d4-a716-446655440001".to_owned(),
                friendly_name: "InvoiceBot".to_owned(),
                pqc_pubkey: None,
                classical_pubkey: None,
            },
            issuer: PassportIssuer {
                name: "AIRON AIP Root".to_owned(),
                id: "airon.aip.root".to_owned(),
                registry_url: "http://127.0.0.1:8081".to_owned(),
                public_key_fingerprint: kp.fingerprint.clone(),
                classical_pubkey: kp.public_key_b64url(),
                pqc_pubkey: None,
            },
            constraints: PassportConstraints {
                issued_at: 1_717_441_200,
                expires_at: 1_720_033_200,
                capabilities: vec!["invoice.read".to_owned(), "ledger.post".to_owned()],
                max_delegation_depth: 3,
            },
            lineage: vec![LineageEntry {
                actor: "550e8400-e29b-41d4-a716-446655440002".to_owned(),
                action: "AUTHORIZE".to_owned(),
                timestamp: 1_717_441_199,
                signature: "lineage-signature".to_owned(),
            }],
            environmental_lock: EnvironmentalLock {
                runtime: "python-3.11".to_owned(),
                image_hash: "sha256:unknown".to_owned(),
            },
        };
        let signature = kp.sign_bytes_b64url(&canonical_passport_body_bytes(&body).unwrap());
        AgentPassport {
            header: PassportHeader::default(),
            body,
            proof: PassportProof {
                signature,
                pqc_signature: None,
            },
        }
    }

    #[test]
    fn ed25519_passport_verifies() {
        let kp = KeyPair::generate();
        let passport = signed_passport(&kp);
        verify_passport_ed25519(&passport, 1_717_441_201).unwrap();
    }

    #[test]
    fn tampered_passport_is_rejected() {
        let kp = KeyPair::generate();
        let mut passport = signed_passport(&kp);
        passport
            .body
            .constraints
            .capabilities
            .push("ledger.admin".to_owned());

        let err = verify_passport_ed25519(&passport, 1_717_441_201).unwrap_err();
        assert!(err.contains("signature mismatch") || err.contains("duplicate capability"));
    }

    #[test]
    fn pqc_signature_is_not_silently_accepted_in_phase_1() {
        let kp = KeyPair::generate();
        let mut passport = signed_passport(&kp);
        passport.proof.pqc_signature = Some("future-pqc-sig".to_owned());

        let err = verify_passport_ed25519(&passport, 1_717_441_201).unwrap_err();
        assert!(err.contains("PQC signature verification is not enabled"));
    }
}
