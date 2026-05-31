//! AIP v4 L2 Runtime: action attestation.

use crate::errors::{AipError, AipResult};
use crate::primitives::{verify_payload_signature, KeyPair, PublicKey, Signature};
use crate::signing::sign_payload;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[repr(u8)]
pub enum AttestationStrength {
    SelfAttested = 0x01,
    CounterpartySigned = 0x02,
    ThirdPartyNotarized = 0x03,
}

impl AttestationStrength {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> AipResult<Self> {
        match v {
            0x01 => Ok(Self::SelfAttested),
            0x02 => Ok(Self::CounterpartySigned),
            0x03 => Ok(Self::ThirdPartyNotarized),
            _ => Err(AipError::EncodingError {
                reason: format!("invalid attestation strength: {v:#04x}"),
            }),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ActionAttestation {
    pub magic: [u8; 4],
    pub decision_id: [u8; 32],
    pub agent_id: String,
    pub action_verb: String,
    pub resource_ref: String,
    pub tool_ref: String,
    pub input_commitment: [u8; 32],
    pub output_commitment: [u8; 32],
    pub strength: AttestationStrength,
    pub counterparty_sig: Option<Signature>,
    pub notary_proof: Option<Vec<u8>>,
    pub attested_at: u64,
    pub prev_attestation: [u8; 32],
    pub agent_sig: Signature,
}

impl ActionAttestation {
    pub const MAGIC: [u8; 4] = [0x41, 0x54, 0x54, 0x4E]; // "ATTN"

    pub fn counterparty_payload(
        decision_id: &[u8; 32],
        input_commitment: &[u8; 32],
        output_commitment: &[u8; 32],
    ) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(decision_id);
        p.extend_from_slice(input_commitment);
        p.extend_from_slice(output_commitment);
        p
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_self_attested(
        key_pair: &KeyPair,
        agent_id: &str,
        decision_id: [u8; 32],
        action_verb: &str,
        resource_ref: &str,
        tool_ref: &str,
        input_commitment: [u8; 32],
        output_commitment: [u8; 32],
        attested_at: u64,
        prev_attestation: [u8; 32],
    ) -> AipResult<Self> {
        Self::build(
            key_pair,
            agent_id,
            decision_id,
            action_verb,
            resource_ref,
            tool_ref,
            input_commitment,
            output_commitment,
            AttestationStrength::SelfAttested,
            None,
            None,
            attested_at,
            prev_attestation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_counterparty_signed(
        key_pair: &KeyPair,
        agent_id: &str,
        decision_id: [u8; 32],
        action_verb: &str,
        resource_ref: &str,
        tool_ref: &str,
        input_commitment: [u8; 32],
        output_commitment: [u8; 32],
        counterparty_sig: Signature,
        attested_at: u64,
        prev_attestation: [u8; 32],
    ) -> AipResult<Self> {
        Self::build(
            key_pair,
            agent_id,
            decision_id,
            action_verb,
            resource_ref,
            tool_ref,
            input_commitment,
            output_commitment,
            AttestationStrength::CounterpartySigned,
            Some(counterparty_sig),
            None,
            attested_at,
            prev_attestation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        key_pair: &KeyPair,
        agent_id: &str,
        decision_id: [u8; 32],
        action_verb: &str,
        resource_ref: &str,
        tool_ref: &str,
        input_commitment: [u8; 32],
        output_commitment: [u8; 32],
        strength: AttestationStrength,
        counterparty_sig: Option<Signature>,
        notary_proof: Option<Vec<u8>>,
        attested_at: u64,
        prev_attestation: [u8; 32],
    ) -> AipResult<Self> {
        let mut att = Self {
            magic: Self::MAGIC,
            decision_id,
            agent_id: agent_id.to_string(),
            action_verb: action_verb.to_string(),
            resource_ref: resource_ref.to_string(),
            tool_ref: tool_ref.to_string(),
            input_commitment,
            output_commitment,
            strength,
            counterparty_sig,
            notary_proof,
            attested_at,
            prev_attestation,
            agent_sig: Signature {
                algorithm: key_pair.public_key.algorithm,
                signer_id: agent_id.to_string(),
                timestamp: attested_at,
                nonce: [0u8; 16],
                payload_hash: [0u8; 32],
                signature_bytes: Vec::new(),
            },
        };
        let payload = att.signing_payload();
        att.agent_sig = sign_payload(key_pair, agent_id, &payload, attested_at)?;
        Ok(att)
    }

    fn signing_payload(&self) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&self.decision_id);
        p.extend_from_slice(self.agent_id.as_bytes());
        p.extend_from_slice(self.action_verb.as_bytes());
        p.extend_from_slice(self.resource_ref.as_bytes());
        p.extend_from_slice(self.tool_ref.as_bytes());
        p.extend_from_slice(&self.input_commitment);
        p.extend_from_slice(&self.output_commitment);
        p.push(self.strength.as_u8());
        p.extend_from_slice(&self.attested_at.to_le_bytes());
        p.extend_from_slice(&self.prev_attestation);
        p
    }

    pub fn verify(
        &self,
        agent_pubkey: &PublicKey,
        counterparty_pubkey: Option<&PublicKey>,
    ) -> AipResult<()> {
        if self.magic != Self::MAGIC {
            return Err(AipError::InvalidMagic {
                expected: "ATTN",
                got: self.magic,
            });
        }

        match self.strength {
            AttestationStrength::SelfAttested => {
                if self.counterparty_sig.is_some() || self.notary_proof.is_some() {
                    return Err(AipError::ValidationFailed {
                        reason: "self-attested action carries counterparty/notary evidence".into(),
                    });
                }
            }
            AttestationStrength::CounterpartySigned => {
                if self.counterparty_sig.is_none() {
                    return Err(AipError::ValidationFailed {
                        reason: "counterparty-signed action missing counterparty_sig".into(),
                    });
                }
            }
            AttestationStrength::ThirdPartyNotarized => {
                if self.counterparty_sig.is_none() || self.notary_proof.is_none() {
                    return Err(AipError::ValidationFailed {
                        reason:
                            "third-party-notarized action missing counterparty_sig or notary_proof"
                                .into(),
                    });
                }
            }
        }

        let payload = self.signing_payload();
        verify_payload_signature(agent_pubkey, &payload, &self.agent_sig)?;

        if let Some(cp_sig) = &self.counterparty_sig {
            let cp_key = counterparty_pubkey.ok_or_else(|| AipError::ValidationFailed {
                reason: "counterparty signature present but no counterparty key supplied".into(),
            })?;
            let cp_payload = Self::counterparty_payload(
                &self.decision_id,
                &self.input_commitment,
                &self.output_commitment,
            );
            verify_payload_signature(cp_key, &cp_payload, cp_sig)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{sha256, KeyPair};

    #[test]
    fn test_strength_ordering() {
        assert!(AttestationStrength::SelfAttested < AttestationStrength::CounterpartySigned);
        assert!(AttestationStrength::CounterpartySigned < AttestationStrength::ThirdPartyNotarized);
    }

    #[test]
    fn test_self_attested_create_and_verify() {
        let kp = KeyPair::generate_ed25519();
        let att = ActionAttestation::create_self_attested(
            &kp,
            "aip1agent",
            [1u8; 32],
            "approve_invoice",
            "invoice:INV-1",
            "sap_connector@1.4.2",
            sha256(b"in"),
            sha256(b"out"),
            1_739_000_000_000,
            [0u8; 32],
        )
        .unwrap();
        assert_eq!(att.strength, AttestationStrength::SelfAttested);
        assert!(att.verify(&kp.public_key, None).is_ok());
    }

    #[test]
    fn test_counterparty_signed_roundtrip() {
        let agent = KeyPair::generate_ed25519();
        let tool = KeyPair::generate_ed25519();
        let decision_id = [5u8; 32];
        let inp = sha256(b"in");
        let outp = sha256(b"out");
        let cp_payload = ActionAttestation::counterparty_payload(&decision_id, &inp, &outp);
        let cp_sig = sign_payload(&tool, "aip1tool", &cp_payload, 1_739_000_000_000).unwrap();

        let att = ActionAttestation::create_counterparty_signed(
            &agent,
            "aip1agent",
            decision_id,
            "approve_invoice",
            "invoice:INV-1",
            "sap_connector@1.4.2",
            inp,
            outp,
            cp_sig,
            1_739_000_000_000,
            [0u8; 32],
        )
        .unwrap();

        assert_eq!(att.strength, AttestationStrength::CounterpartySigned);
        assert!(att
            .verify(&agent.public_key, Some(&tool.public_key))
            .is_ok());
    }

    #[test]
    fn test_counterparty_wrong_key_rejected() {
        let agent = KeyPair::generate_ed25519();
        let tool = KeyPair::generate_ed25519();
        let wrong = KeyPair::generate_ed25519();
        let decision_id = [5u8; 32];
        let inp = sha256(b"in");
        let outp = sha256(b"out");
        let cp_payload = ActionAttestation::counterparty_payload(&decision_id, &inp, &outp);
        let cp_sig = sign_payload(&tool, "aip1tool", &cp_payload, 1_739_000_000_000).unwrap();
        let att = ActionAttestation::create_counterparty_signed(
            &agent,
            "aip1agent",
            decision_id,
            "approve_invoice",
            "invoice:INV-1",
            "sap_connector",
            inp,
            outp,
            cp_sig,
            1_739_000_000_000,
            [0u8; 32],
        )
        .unwrap();
        assert!(att
            .verify(&agent.public_key, Some(&wrong.public_key))
            .is_err());
    }

    #[test]
    fn test_inconsistent_strength_rejected() {
        let kp = KeyPair::generate_ed25519();
        let mut att = ActionAttestation::create_self_attested(
            &kp,
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
        att.strength = AttestationStrength::CounterpartySigned;
        assert!(att.verify(&kp.public_key, None).is_err());
    }
}
