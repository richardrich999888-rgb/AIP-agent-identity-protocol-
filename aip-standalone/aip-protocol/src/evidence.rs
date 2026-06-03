//! AIP v4 L3 Evidence: exportable evidence packets.

use crate::attestation::{ActionAttestation, AttestationStrength};
use crate::decision::DecisionRecord;
use crate::errors::{AipError, AipResult};
use crate::graph::AccountabilityGraph;
use crate::ports::{ReceiptBinding, TraceBinding};
use crate::primitives::{sha256, verify_payload_signature, KeyPair, PublicKey, Signature};
use crate::signing::sign_payload;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EvidencePacket {
    pub magic: [u8; 4],
    pub decision_id: [u8; 32],
    pub graph: AccountabilityGraph,
    pub decision_record: DecisionRecord,
    pub action_attestations: Vec<ActionAttestation>,
    pub trace_binding: TraceBinding,
    pub receipt_binding: ReceiptBinding,
    pub trust_floor: u8,
    pub assembled_at: u64,
    pub assembler_sig: Signature,
}

impl EvidencePacket {
    pub const MAGIC: [u8; 4] = [0x45, 0x56, 0x50, 0x4B]; // "EVPK"

    #[allow(clippy::too_many_arguments)]
    pub fn assemble(
        assembler: &KeyPair,
        assembler_id: &str,
        graph: AccountabilityGraph,
        decision_record: DecisionRecord,
        action_attestations: Vec<ActionAttestation>,
        trace_binding: TraceBinding,
        receipt_binding: ReceiptBinding,
        assembled_at: u64,
    ) -> AipResult<Self> {
        graph.validate()?;
        let floor = graph
            .trust_floor()
            .ok_or_else(|| AipError::ValidationFailed {
                reason: "cannot assemble evidence for an incomplete accountability chain".into(),
            })?;

        if graph.root_decision_id != decision_record.decision_id {
            return Err(AipError::ValidationFailed {
                reason: "graph root does not match decision record".into(),
            });
        }

        let decision_id = decision_record.decision_id;
        let mut packet = Self {
            magic: Self::MAGIC,
            decision_id,
            graph,
            decision_record,
            action_attestations,
            trace_binding,
            receipt_binding,
            trust_floor: floor.as_u8(),
            assembled_at,
            assembler_sig: Signature {
                algorithm: assembler.public_key.algorithm,
                signer_id: assembler_id.to_string(),
                timestamp: assembled_at,
                nonce: [0u8; 16],
                payload_hash: [0u8; 32],
                signature_bytes: Vec::new(),
            },
        };
        let digest = packet.digest();
        packet.assembler_sig = sign_payload(assembler, assembler_id, &digest, assembled_at)?;
        Ok(packet)
    }

    fn digest(&self) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&self.decision_id);
        d.extend_from_slice(&self.graph.root_decision_id);
        d.extend_from_slice(&(self.graph.nodes.len() as u32).to_le_bytes());
        for node in &self.graph.nodes {
            d.extend_from_slice(&node.node_id);
            d.push(node.kind as u8);
            d.extend_from_slice(&node.object_ref);
        }
        d.extend_from_slice(&(self.graph.edges.len() as u32).to_le_bytes());
        for edge in &self.graph.edges {
            d.extend_from_slice(&edge.from);
            d.extend_from_slice(&edge.to);
            d.push(edge.relation as u8);
            d.push(edge.strength.as_u8());
            d.extend_from_slice(&edge.evidence_ref);
        }
        d.extend_from_slice(&self.decision_record.decision_id);
        for attestation in &self.action_attestations {
            d.extend_from_slice(&attestation.decision_id);
            d.extend_from_slice(attestation.action_verb.as_bytes());
            d.extend_from_slice(attestation.resource_ref.as_bytes());
            d.extend_from_slice(attestation.tool_ref.as_bytes());
            d.extend_from_slice(&attestation.input_commitment);
            d.extend_from_slice(&attestation.output_commitment);
            d.push(attestation.strength.as_u8());
        }
        d.extend_from_slice(&self.trace_binding.trace_id);
        d.extend_from_slice(&self.trace_binding.trace_root);
        d.extend_from_slice(&self.receipt_binding.receipt_id);
        d.extend_from_slice(&self.receipt_binding.receipt_hash);
        d.push(self.trust_floor);
        d.extend_from_slice(&self.assembled_at.to_le_bytes());
        sha256(&d).to_vec()
    }

    pub fn packet_digest(&self) -> [u8; 32] {
        let digest = self.digest();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    pub fn verify_assembler_signature(&self, assembler_pubkey: &PublicKey) -> AipResult<()> {
        verify_payload_signature(assembler_pubkey, &self.digest(), &self.assembler_sig)
    }

    pub fn verify_trace_binding(&self, trace_authority_pubkey: &PublicKey) -> AipResult<()> {
        verify_payload_signature(
            trace_authority_pubkey,
            &self.trace_binding.signing_payload(),
            &self.trace_binding.sig,
        )
    }

    pub fn verify_receipt_binding(&self, receipt_authority_pubkey: &PublicKey) -> AipResult<()> {
        verify_payload_signature(
            receipt_authority_pubkey,
            &self.receipt_binding.signing_payload(),
            &self.receipt_binding.sig,
        )
    }

    pub fn verify_external_receipt_digest(&self, expected_digest: &[u8; 32]) -> AipResult<()> {
        if &self.receipt_binding.receipt_hash == expected_digest {
            Ok(())
        } else {
            Err(AipError::ValidationFailed {
                reason: "receipt_binding.receipt_hash does not match external digest".into(),
            })
        }
    }

    pub fn verify(
        &self,
        assembler_pubkey: &PublicKey,
        agent_pubkey: &PublicKey,
        counterparty_key_for: impl Fn(&str) -> Option<PublicKey>,
    ) -> AipResult<()> {
        if self.magic != Self::MAGIC {
            return Err(AipError::InvalidMagic {
                expected: "EVPK",
                got: self.magic,
            });
        }

        let digest = self.digest();
        verify_payload_signature(assembler_pubkey, &digest, &self.assembler_sig)?;
        self.graph.validate()?;

        let computed = self
            .graph
            .trust_floor()
            .ok_or_else(|| AipError::ValidationFailed {
                reason: "packet graph is incomplete".into(),
            })?;
        if computed.as_u8() != self.trust_floor {
            return Err(AipError::ValidationFailed {
                reason: format!(
                    "materialized trust_floor {} != recomputed {}",
                    self.trust_floor,
                    computed.as_u8()
                ),
            });
        }

        if self.graph.root_decision_id != self.decision_id {
            return Err(AipError::ValidationFailed {
                reason: "graph root does not match packet decision_id".into(),
            });
        }

        self.decision_record.verify(agent_pubkey)?;
        if self.decision_record.decision_id != self.decision_id {
            return Err(AipError::ValidationFailed {
                reason: "decision_record id does not match packet decision_id".into(),
            });
        }

        for attestation in &self.action_attestations {
            if attestation.decision_id != self.decision_id {
                return Err(AipError::ValidationFailed {
                    reason: "action attestation references a different decision".into(),
                });
            }
            let cp_key = match attestation.strength {
                AttestationStrength::SelfAttested => None,
                _ => counterparty_key_for(&attestation.tool_ref),
            };
            attestation.verify(agent_pubkey, cp_key.as_ref())?;
        }

        Ok(())
    }

    pub fn verify_with_authorities(
        &self,
        assembler_pubkey: &PublicKey,
        agent_pubkey: &PublicKey,
        trace_authority_pubkey: &PublicKey,
        receipt_authority_pubkey: &PublicKey,
        counterparty_key_for: impl Fn(&str) -> Option<PublicKey>,
        expected_receipt_digest: &[u8; 32],
    ) -> AipResult<()> {
        self.verify(assembler_pubkey, agent_pubkey, counterparty_key_for)?;
        self.verify_trace_binding(trace_authority_pubkey)?;
        self.verify_receipt_binding(receipt_authority_pubkey)?;
        self.verify_external_receipt_digest(expected_receipt_digest)
    }

    pub fn trust_floor_label(&self) -> &'static str {
        match AttestationStrength::from_u8(self.trust_floor) {
            Ok(AttestationStrength::SelfAttested) => "SELF_ATTESTED (agent claim only)",
            Ok(AttestationStrength::CounterpartySigned) => {
                "COUNTERPARTY_SIGNED (independently corroborated)"
            }
            Ok(AttestationStrength::ThirdPartyNotarized) => "THIRD_PARTY_NOTARIZED (notary-backed)",
            Err(_) => "UNKNOWN",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{AccountabilityEdge, AccountabilityNode, EdgeRelation, NodeKind};

    #[test]
    fn test_trust_floor_label() {
        let labels = [
            (1u8, "SELF_ATTESTED (agent claim only)"),
            (2u8, "COUNTERPARTY_SIGNED (independently corroborated)"),
            (3u8, "THIRD_PARTY_NOTARIZED (notary-backed)"),
        ];
        for (value, expected) in labels {
            let strength = AttestationStrength::from_u8(value).unwrap();
            let got = match strength {
                AttestationStrength::SelfAttested => "SELF_ATTESTED (agent claim only)",
                AttestationStrength::CounterpartySigned => {
                    "COUNTERPARTY_SIGNED (independently corroborated)"
                }
                AttestationStrength::ThirdPartyNotarized => "THIRD_PARTY_NOTARIZED (notary-backed)",
            };
            assert_eq!(got, expected);
        }
    }

    #[test]
    fn test_graph_validate_used_in_assembly() {
        let mut g = AccountabilityGraph::new([1u8; 32]);
        g.add_node(AccountabilityNode {
            node_id: [1u8; 32],
            kind: NodeKind::Decision,
            object_ref: [1u8; 32],
        });
        g.add_edge(AccountabilityEdge {
            from: [1u8; 32],
            to: [2u8; 32],
            relation: EdgeRelation::CausedAction,
            strength: AttestationStrength::SelfAttested,
            evidence_ref: [0u8; 32],
        });
        assert!(g.validate().is_err());
    }
}
