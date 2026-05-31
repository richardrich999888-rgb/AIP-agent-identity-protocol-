//! AIP v4 L3 Evidence ports and in-memory mock adapters.

use crate::attestation::ActionAttestation;
use crate::errors::{AipError, AipResult};
use crate::primitives::{sha256, verify_payload_signature, KeyPair, PublicKey, Signature};
use crate::signing::sign_payload;
use std::collections::HashMap;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TraceBinding {
    pub trace_id: [u8; 32],
    pub trace_root: [u8; 32],
    pub system: String,
    pub sig: Signature,
}

impl TraceBinding {
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&self.trace_id);
        payload.extend_from_slice(&self.trace_root);
        payload.extend_from_slice(self.system.as_bytes());
        payload
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReceiptBinding {
    pub receipt_id: [u8; 32],
    pub receipt_hash: [u8; 32],
    pub authority: String,
    pub sig: Signature,
}

impl ReceiptBinding {
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&self.receipt_id);
        payload.extend_from_slice(&self.receipt_hash);
        payload.extend_from_slice(self.authority.as_bytes());
        payload
    }
}

pub trait ToolAttestationPort {
    fn attest_action(&self, action: &ActionAttestation) -> Option<Signature>;
    fn public_key(&self) -> Option<PublicKey>;
}

pub trait TraceBindingPort {
    fn bind_trace(&self, decision_id: [u8; 32]) -> AipResult<TraceBinding>;
    fn resolve_payload(&self, commitment: [u8; 32]) -> AipResult<Vec<u8>>;
}

pub trait ReceiptBindingPort {
    fn bind_receipt(&self, output_commitment: [u8; 32]) -> AipResult<ReceiptBinding>;
    fn verify_receipt(&self, binding: &ReceiptBinding) -> AipResult<bool>;
}

pub struct SigningToolAdapter {
    key_pair: KeyPair,
    tool_id: String,
}

impl SigningToolAdapter {
    pub fn new(tool_id: &str) -> Self {
        Self {
            key_pair: KeyPair::generate_ed25519(),
            tool_id: tool_id.to_string(),
        }
    }
}

impl ToolAttestationPort for SigningToolAdapter {
    fn attest_action(&self, action: &ActionAttestation) -> Option<Signature> {
        let payload = ActionAttestation::counterparty_payload(
            &action.decision_id,
            &action.input_commitment,
            &action.output_commitment,
        );
        sign_payload(&self.key_pair, &self.tool_id, &payload, action.attested_at).ok()
    }

    fn public_key(&self) -> Option<PublicKey> {
        Some(self.key_pair.public_key.clone())
    }
}

pub struct NonSigningToolAdapter;

impl ToolAttestationPort for NonSigningToolAdapter {
    fn attest_action(&self, _action: &ActionAttestation) -> Option<Signature> {
        None
    }

    fn public_key(&self) -> Option<PublicKey> {
        None
    }
}

pub struct MockTraceSystem {
    key_pair: KeyPair,
    payloads: HashMap<[u8; 32], Vec<u8>>,
}

impl MockTraceSystem {
    pub fn new() -> Self {
        Self {
            key_pair: KeyPair::generate_ed25519(),
            payloads: HashMap::new(),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        self.key_pair.public_key.clone()
    }

    pub fn store_payload(&mut self, payload: Vec<u8>) -> [u8; 32] {
        let commitment = sha256(&payload);
        self.payloads.insert(commitment, payload);
        commitment
    }
}

impl Default for MockTraceSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceBindingPort for MockTraceSystem {
    fn bind_trace(&self, decision_id: [u8; 32]) -> AipResult<TraceBinding> {
        let trace_id = sha256(&decision_id);
        let trace_root = sha256(&trace_id);
        let mut binding = TraceBinding {
            trace_id,
            trace_root,
            system: "chrono".into(),
            sig: Signature {
                algorithm: self.key_pair.public_key.algorithm,
                signer_id: "aip1chronoAuthority".into(),
                timestamp: 0,
                nonce: [0u8; 16],
                payload_hash: [0u8; 32],
                signature_bytes: Vec::new(),
            },
        };
        binding.sig = sign_payload(
            &self.key_pair,
            "aip1chronoAuthority",
            &binding.signing_payload(),
            0,
        )?;
        Ok(binding)
    }

    fn resolve_payload(&self, commitment: [u8; 32]) -> AipResult<Vec<u8>> {
        self.payloads
            .get(&commitment)
            .cloned()
            .ok_or_else(|| AipError::ValidationFailed {
                reason: "no payload for commitment".into(),
            })
    }
}

pub struct MockReceiptSystem {
    key_pair: KeyPair,
}

impl MockReceiptSystem {
    pub fn new() -> Self {
        Self {
            key_pair: KeyPair::generate_ed25519(),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        self.key_pair.public_key.clone()
    }
}

impl Default for MockReceiptSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl ReceiptBindingPort for MockReceiptSystem {
    fn bind_receipt(&self, output_commitment: [u8; 32]) -> AipResult<ReceiptBinding> {
        let receipt_id = sha256(&output_commitment);
        let receipt_hash = sha256(&receipt_id);
        let mut binding = ReceiptBinding {
            receipt_id,
            receipt_hash,
            authority: "aip1rcvaAuthority".into(),
            sig: Signature {
                algorithm: self.key_pair.public_key.algorithm,
                signer_id: "aip1rcvaAuthority".into(),
                timestamp: 0,
                nonce: [0u8; 16],
                payload_hash: [0u8; 32],
                signature_bytes: Vec::new(),
            },
        };
        binding.sig = sign_payload(
            &self.key_pair,
            "aip1rcvaAuthority",
            &binding.signing_payload(),
            0,
        )?;
        Ok(binding)
    }

    fn verify_receipt(&self, binding: &ReceiptBinding) -> AipResult<bool> {
        match verify_payload_signature(
            &self.key_pair.public_key,
            &binding.signing_payload(),
            &binding.sig,
        ) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signing_tool_produces_signature() {
        let tool = SigningToolAdapter::new("sap_connector");
        let action = ActionAttestation::create_self_attested(
            &KeyPair::generate_ed25519(),
            "aip1agent",
            [1u8; 32],
            "x",
            "y",
            "z",
            sha256(b"in"),
            sha256(b"out"),
            1000,
            [0u8; 32],
        )
        .unwrap();
        assert!(tool.attest_action(&action).is_some());
        assert!(tool.public_key().is_some());
    }

    #[test]
    fn test_non_signing_tool_returns_none() {
        let tool = NonSigningToolAdapter;
        let action = ActionAttestation::create_self_attested(
            &KeyPair::generate_ed25519(),
            "aip1agent",
            [1u8; 32],
            "x",
            "y",
            "z",
            sha256(b"in"),
            sha256(b"out"),
            1000,
            [0u8; 32],
        )
        .unwrap();
        assert!(tool.attest_action(&action).is_none());
    }

    #[test]
    fn test_trace_roundtrip() {
        let mut trace = MockTraceSystem::new();
        let commitment = trace.store_payload(b"decision-inputs".to_vec());
        assert_eq!(
            trace.resolve_payload(commitment).unwrap(),
            b"decision-inputs"
        );
        let binding = trace.bind_trace([9u8; 32]).unwrap();
        assert_eq!(binding.system, "chrono");
    }

    #[test]
    fn test_receipt_verify() {
        let receipt = MockReceiptSystem::new();
        let binding = receipt.bind_receipt([3u8; 32]).unwrap();
        assert!(receipt.verify_receipt(&binding).unwrap());
    }
}
