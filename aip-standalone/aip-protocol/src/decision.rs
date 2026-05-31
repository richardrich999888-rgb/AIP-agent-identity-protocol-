//! AIP v4 L2 Runtime: session identity and decision identity.

use crate::errors::{AipError, AipResult};
use crate::primitives::{sha256, verify_payload_signature, KeyPair, PublicKey, Signature};
use crate::signing::sign_payload;

pub fn derive_session_id(agent_id: &str, session_nonce: &[u8; 16], started_at: u64) -> [u8; 32] {
    let mut input = Vec::new();
    input.extend_from_slice(agent_id.as_bytes());
    input.extend_from_slice(session_nonce);
    input.extend_from_slice(&started_at.to_le_bytes());
    sha256(&input)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionContext {
    pub magic: [u8; 4],
    pub session_id: [u8; 32],
    pub agent_id: String,
    pub operator_did: Option<String>,
    pub authorization_ref: [u8; 32],
    pub started_at: u64,
    pub ended_at: Option<u64>,
    pub decision_chain_head: [u8; 32],
    pub decision_count: u32,
    pub session_sig: Signature,
}

impl SessionContext {
    pub const MAGIC: [u8; 4] = [0x53, 0x45, 0x53, 0x4E]; // "SESN"

    pub fn open(
        key_pair: &KeyPair,
        agent_id: &str,
        operator_did: Option<String>,
        authorization_ref: [u8; 32],
        session_nonce: &[u8; 16],
        started_at: u64,
    ) -> AipResult<Self> {
        let session_id = derive_session_id(agent_id, session_nonce, started_at);
        let decision_chain_head = sha256(&session_id);
        let payload = Self::signing_payload(&session_id, agent_id, &authorization_ref, started_at);
        let session_sig = sign_payload(key_pair, agent_id, &payload, started_at)?;
        Ok(Self {
            magic: Self::MAGIC,
            session_id,
            agent_id: agent_id.to_string(),
            operator_did,
            authorization_ref,
            started_at,
            ended_at: None,
            decision_chain_head,
            decision_count: 0,
            session_sig,
        })
    }

    pub fn close(&mut self, key_pair: &KeyPair, ended_at: u64) -> AipResult<()> {
        self.ended_at = Some(ended_at);
        let payload = self.signing_payload_current();
        self.session_sig = sign_payload(key_pair, &self.agent_id, &payload, ended_at)?;
        Ok(())
    }

    fn signing_payload(
        session_id: &[u8; 32],
        agent_id: &str,
        authorization_ref: &[u8; 32],
        started_at: u64,
    ) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(session_id);
        p.extend_from_slice(agent_id.as_bytes());
        p.extend_from_slice(authorization_ref);
        p.extend_from_slice(&started_at.to_le_bytes());
        p
    }

    fn signing_payload_current(&self) -> Vec<u8> {
        let mut p = Self::signing_payload(
            &self.session_id,
            &self.agent_id,
            &self.authorization_ref,
            self.started_at,
        );
        if let Some(ended_at) = self.ended_at {
            p.extend_from_slice(&ended_at.to_le_bytes());
        }
        p.extend_from_slice(&self.decision_chain_head);
        p.extend_from_slice(&self.decision_count.to_le_bytes());
        p
    }

    pub fn verify(&self, agent_pubkey: &PublicKey) -> AipResult<()> {
        if self.magic != Self::MAGIC {
            return Err(AipError::InvalidMagic {
                expected: "SESN",
                got: self.magic,
            });
        }
        let payload = if self.ended_at.is_some() {
            self.signing_payload_current()
        } else {
            Self::signing_payload(
                &self.session_id,
                &self.agent_id,
                &self.authorization_ref,
                self.started_at,
            )
        };
        verify_payload_signature(agent_pubkey, &payload, &self.session_sig)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn derive_decision_id(
    agent_id: &str,
    session_id: &[u8; 32],
    provenance_commitment: &[u8; 32],
    input_commitment: &[u8; 32],
    output_commitment: &[u8; 32],
    authorization_ref: &[u8; 32],
    decided_at: u64,
    decision_nonce: &[u8; 16],
) -> [u8; 32] {
    let mut input = Vec::new();
    input.extend_from_slice(agent_id.as_bytes());
    input.extend_from_slice(session_id);
    input.extend_from_slice(provenance_commitment);
    input.extend_from_slice(input_commitment);
    input.extend_from_slice(output_commitment);
    input.extend_from_slice(authorization_ref);
    input.extend_from_slice(&decided_at.to_le_bytes());
    input.extend_from_slice(decision_nonce);
    sha256(&input)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DecisionRecord {
    pub magic: [u8; 4],
    pub decision_id: [u8; 32],
    pub agent_id: String,
    pub session_id: [u8; 32],
    pub provenance_commitment: [u8; 32],
    pub sequence: u64,
    pub prev_decision: [u8; 32],
    pub input_commitment: [u8; 32],
    pub output_commitment: [u8; 32],
    pub authorization_ref: [u8; 32],
    pub decision_class: String,
    pub decided_at: u64,
    pub decision_nonce: [u8; 16],
    pub agent_sig: Signature,
}

impl DecisionRecord {
    pub const MAGIC: [u8; 4] = [0x44, 0x45, 0x43, 0x4E]; // "DECN"

    #[allow(clippy::too_many_arguments)]
    pub fn create(
        key_pair: &KeyPair,
        agent_id: &str,
        session: &SessionContext,
        provenance_commitment: [u8; 32],
        input_commitment: [u8; 32],
        output_commitment: [u8; 32],
        decision_class: &str,
        decided_at: u64,
        decision_nonce: [u8; 16],
    ) -> AipResult<Self> {
        let decision_id = derive_decision_id(
            agent_id,
            &session.session_id,
            &provenance_commitment,
            &input_commitment,
            &output_commitment,
            &session.authorization_ref,
            decided_at,
            &decision_nonce,
        );
        let record = Self {
            magic: Self::MAGIC,
            decision_id,
            agent_id: agent_id.to_string(),
            session_id: session.session_id,
            provenance_commitment,
            sequence: session.decision_count as u64,
            prev_decision: session.decision_chain_head,
            input_commitment,
            output_commitment,
            authorization_ref: session.authorization_ref,
            decision_class: decision_class.to_string(),
            decided_at,
            decision_nonce,
            agent_sig: Signature {
                algorithm: key_pair.public_key.algorithm,
                signer_id: agent_id.to_string(),
                timestamp: decided_at,
                nonce: [0u8; 16],
                payload_hash: [0u8; 32],
                signature_bytes: Vec::new(),
            },
        };
        let payload = record.signing_payload();
        let sig = sign_payload(key_pair, agent_id, &payload, decided_at)?;
        Ok(Self {
            agent_sig: sig,
            ..record
        })
    }

    fn signing_payload(&self) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&self.decision_id);
        p.extend_from_slice(self.agent_id.as_bytes());
        p.extend_from_slice(&self.session_id);
        p.extend_from_slice(&self.provenance_commitment);
        p.extend_from_slice(&self.sequence.to_le_bytes());
        p.extend_from_slice(&self.prev_decision);
        p.extend_from_slice(&self.input_commitment);
        p.extend_from_slice(&self.output_commitment);
        p.extend_from_slice(&self.authorization_ref);
        p.extend_from_slice(self.decision_class.as_bytes());
        p.extend_from_slice(&self.decided_at.to_le_bytes());
        p.extend_from_slice(&self.decision_nonce);
        p
    }

    pub fn verify(&self, agent_pubkey: &PublicKey) -> AipResult<()> {
        if self.magic != Self::MAGIC {
            return Err(AipError::InvalidMagic {
                expected: "DECN",
                got: self.magic,
            });
        }
        let expected_id = derive_decision_id(
            &self.agent_id,
            &self.session_id,
            &self.provenance_commitment,
            &self.input_commitment,
            &self.output_commitment,
            &self.authorization_ref,
            self.decided_at,
            &self.decision_nonce,
        );
        if expected_id != self.decision_id {
            return Err(AipError::ValidationFailed {
                reason: "decision_id does not match committed context".into(),
            });
        }
        let payload = self.signing_payload();
        verify_payload_signature(agent_pubkey, &payload, &self.agent_sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{current_timestamp_ms, generate_nonce, KeyPair};

    fn fixture() -> (KeyPair, String, SessionContext) {
        let kp = KeyPair::generate_ed25519();
        let agent_id = "aip1testAgentIdentifierForUnitTests0001";
        let auth_ref = sha256(b"capability-grant-blob");
        let session = SessionContext::open(
            &kp,
            agent_id,
            Some("did:web:operator.example".into()),
            auth_ref,
            &[7u8; 16],
            1_739_000_000_000,
        )
        .unwrap();
        (kp, agent_id.to_string(), session)
    }

    #[test]
    fn test_session_open_and_verify() {
        let (kp, _aid, session) = fixture();
        assert!(session.verify(&kp.public_key).is_ok());
        assert_eq!(session.decision_count, 0);
    }

    #[test]
    fn test_session_id_is_deterministic() {
        let a = derive_session_id("aip1abc", &[1u8; 16], 1000);
        let b = derive_session_id("aip1abc", &[1u8; 16], 1000);
        let c = derive_session_id("aip1abc", &[2u8; 16], 1000);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_decision_create_and_verify() {
        let (kp, agent_id, session) = fixture();
        let rec = DecisionRecord::create(
            &kp,
            &agent_id,
            &session,
            sha256(b"provenance"),
            sha256(b"inputs"),
            sha256(b"outputs"),
            "financial.approval",
            current_timestamp_ms(),
            generate_nonce(),
        )
        .unwrap();
        assert!(rec.verify(&kp.public_key).is_ok());
    }

    #[test]
    fn test_decision_id_binds_provenance() {
        let id1 = derive_decision_id(
            "aip1abc",
            &[1u8; 32],
            &sha256(b"model-A"),
            &sha256(b"in"),
            &sha256(b"out"),
            &[2u8; 32],
            1000,
            &[3u8; 16],
        );
        let id2 = derive_decision_id(
            "aip1abc",
            &[1u8; 32],
            &sha256(b"model-B"),
            &sha256(b"in"),
            &sha256(b"out"),
            &[2u8; 32],
            1000,
            &[3u8; 16],
        );
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_decision_tamper_detected() {
        let (kp, agent_id, session) = fixture();
        let mut rec = DecisionRecord::create(
            &kp,
            &agent_id,
            &session,
            sha256(b"provenance"),
            sha256(b"inputs"),
            sha256(b"outputs"),
            "financial.approval",
            1_739_000_001_000,
            [9u8; 16],
        )
        .unwrap();
        rec.output_commitment = sha256(b"forged-outputs");
        assert!(rec.verify(&kp.public_key).is_err());
    }
}
