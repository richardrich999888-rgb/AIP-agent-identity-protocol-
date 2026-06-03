use aip_protocol::attestation::AttestationStrength;
use aip_protocol::evidence::EvidencePacket;
use aip_protocol::primitives::{sha256, verify_payload_signature, PublicKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Debug)]
pub enum VerifyError {
    Io(String),
    Json(String),
    Hex(String),
    InvalidInput(String),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(msg) | Self::Json(msg) | Self::Hex(msg) | Self::InvalidInput(msg) => {
                write!(f, "{msg}")
            }
        }
    }
}

impl std::error::Error for VerifyError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationKeyring {
    #[serde(alias = "authority", alias = "assembler_authority")]
    pub assembler: PublicKey,
    #[serde(alias = "session_key", alias = "agent_session")]
    pub agent: PublicKey,
    #[serde(alias = "trace", alias = "trace_authority")]
    pub trace_authority: PublicKey,
    #[serde(alias = "receipt", alias = "receipt_authority")]
    pub receipt_authority: PublicKey,
    #[serde(default)]
    pub counterparties: BTreeMap<String, PublicKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CheckStatus {
    Pass,
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub name: String,
    pub status: CheckStatus,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    pub status: String,
    pub toxic: bool,
    pub decision_id_hex: String,
    pub packet_digest_hex: String,
    pub trust_floor: u8,
    pub trust_floor_label: String,
    pub checks: Vec<CheckResult>,
}

#[derive(Debug, Clone)]
pub enum ReceiptDigestInput {
    Hex(String),
    Payload(Vec<u8>),
}

impl ReceiptDigestInput {
    pub fn expected_digest(&self) -> Result<[u8; 32], VerifyError> {
        match self {
            Self::Hex(hex) => decode_hex_32(hex),
            Self::Payload(payload) => Ok(sha256(payload)),
        }
    }
}

pub fn read_packet(path: &Path) -> Result<EvidencePacket, VerifyError> {
    let data = fs::read_to_string(path)
        .map_err(|e| VerifyError::Io(format!("failed to read packet {}: {e}", path.display())))?;
    serde_json::from_str(&data).map_err(|e| {
        VerifyError::Json(format!(
            "failed to parse EvidencePacket JSON {}: {e}",
            path.display()
        ))
    })
}

pub fn read_keyring(path: &Path) -> Result<VerificationKeyring, VerifyError> {
    let data = fs::read_to_string(path)
        .map_err(|e| VerifyError::Io(format!("failed to read keyring {}: {e}", path.display())))?;
    serde_json::from_str(&data)
        .map_err(|e| VerifyError::Json(format!("failed to parse keyring {}: {e}", path.display())))
}

pub fn read_receipt_payload(path: &Path) -> Result<Vec<u8>, VerifyError> {
    fs::read(path).map_err(|e| {
        VerifyError::Io(format!(
            "failed to read receipt payload {}: {e}",
            path.display()
        ))
    })
}

pub fn verify_packet(
    packet: &EvidencePacket,
    keyring: &VerificationKeyring,
    receipt_digest: Option<[u8; 32]>,
) -> VerificationReport {
    let mut checks = Vec::new();

    push_check(&mut checks, "packet_magic", || {
        if packet.magic == EvidencePacket::MAGIC {
            Ok("EVPK magic accepted".to_string())
        } else {
            Err(format!("invalid packet magic: {:?}", packet.magic))
        }
    });

    push_check(&mut checks, "assembler_authority_signature", || {
        packet
            .verify_assembler_signature(&keyring.assembler)
            .map(|_| "assembler signature verified over packet digest".to_string())
            .map_err(|e| format!("{e:?}"))
    });

    push_check(&mut checks, "accountability_graph", || {
        packet.graph.validate().map_err(|e| format!("{e:?}"))?;
        let recomputed = packet.graph.trust_floor().ok_or_else(|| {
            "packet graph has no complete authorization-to-receipt path".to_string()
        })?;
        if packet.graph.root_decision_id != packet.decision_id {
            return Err("graph root does not match packet decision_id".to_string());
        }
        if packet.decision_record.decision_id != packet.decision_id {
            return Err("decision record does not match packet decision_id".to_string());
        }
        if recomputed.as_u8() != packet.trust_floor {
            return Err(format!(
                "materialized trust_floor {} != recomputed {}",
                packet.trust_floor,
                recomputed.as_u8()
            ));
        }
        Ok(format!(
            "graph valid; trust floor {}",
            packet.trust_floor_label()
        ))
    });

    push_check(&mut checks, "agent_decision_signature", || {
        packet
            .decision_record
            .verify(&keyring.agent)
            .map(|_| "agent decision signature verified".to_string())
            .map_err(|e| format!("{e:?}"))
    });

    push_check(
        &mut checks,
        "agent_action_and_counterparty_signatures",
        || {
            if packet.action_attestations.is_empty() {
                return Err("packet has no action attestations".to_string());
            }

            for attestation in &packet.action_attestations {
                if attestation.decision_id != packet.decision_id {
                    return Err("action attestation references a different decision".to_string());
                }
                let counterparty_key = match attestation.strength {
                    AttestationStrength::SelfAttested => None,
                    _ => keyring.counterparties.get(&attestation.tool_ref),
                };
                attestation
                    .verify(&keyring.agent, counterparty_key)
                    .map_err(|e| format!("{}: {e:?}", attestation.tool_ref))?;
            }

            Ok(format!(
                "{} action attestation(s) verified",
                packet.action_attestations.len()
            ))
        },
    );

    push_check(&mut checks, "trace_authority_signature", || {
        verify_payload_signature(
            &keyring.trace_authority,
            &packet.trace_binding.signing_payload(),
            &packet.trace_binding.sig,
        )
        .map(|_| "trace authority signature verified".to_string())
        .map_err(|e| format!("{e:?}"))
    });

    push_check(&mut checks, "receipt_authority_signature", || {
        verify_payload_signature(
            &keyring.receipt_authority,
            &packet.receipt_binding.signing_payload(),
            &packet.receipt_binding.sig,
        )
        .map(|_| "receipt authority signature verified".to_string())
        .map_err(|e| format!("{e:?}"))
    });

    push_check(&mut checks, "receipt_external_digest", || {
        let expected = receipt_digest
            .as_ref()
            .ok_or_else(|| "external receipt digest is required".to_string())?;
        packet
            .verify_external_receipt_digest(expected)
            .map(|_| "receipt hash matches external digest".to_string())
            .map_err(|e| format!("{e:?}"))
    });

    push_check(&mut checks, "strict_chain_verification", || {
        let expected = receipt_digest
            .as_ref()
            .ok_or_else(|| "external receipt digest is required".to_string())?;
        packet
            .verify_with_authorities(
                &keyring.assembler,
                &keyring.agent,
                &keyring.trace_authority,
                &keyring.receipt_authority,
                |tool_ref| keyring.counterparties.get(tool_ref).cloned(),
                expected,
            )
            .map(|_| "complete EvidencePacket chain verified".to_string())
            .map_err(|e| format!("{e:?}"))
    });

    let toxic = checks.iter().any(|check| check.status == CheckStatus::Fail);
    VerificationReport {
        status: if toxic { "TOXIC" } else { "PASS" }.to_string(),
        toxic,
        decision_id_hex: encode_hex(&packet.decision_id),
        packet_digest_hex: encode_hex(&packet.packet_digest()),
        trust_floor: packet.trust_floor,
        trust_floor_label: packet.trust_floor_label().to_string(),
        checks,
    }
}

fn push_check(
    checks: &mut Vec<CheckResult>,
    name: impl Into<String>,
    run: impl FnOnce() -> Result<String, String>,
) {
    match run() {
        Ok(detail) => checks.push(CheckResult {
            name: name.into(),
            status: CheckStatus::Pass,
            detail,
        }),
        Err(detail) => checks.push(CheckResult {
            name: name.into(),
            status: CheckStatus::Fail,
            detail,
        }),
    }
}

pub fn decode_hex_32(input: &str) -> Result<[u8; 32], VerifyError> {
    let stripped = input.trim().strip_prefix("0x").unwrap_or(input.trim());
    if stripped.len() != 64 {
        return Err(VerifyError::Hex(format!(
            "expected 32-byte hex digest (64 chars), got {} chars",
            stripped.len()
        )));
    }
    let bytes = decode_hex(stripped)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex(input: &str) -> Result<Vec<u8>, VerifyError> {
    if input.len() % 2 != 0 {
        return Err(VerifyError::Hex(
            "hex string must contain an even number of chars".into(),
        ));
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    let chars: Vec<u8> = input.bytes().collect();
    for pair in chars.chunks_exact(2) {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8, VerifyError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(VerifyError::Hex(format!(
            "invalid hex char '{}'",
            byte as char
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aip_protocol::attestation::{ActionAttestation, AttestationStrength};
    use aip_protocol::decision::{DecisionRecord, SessionContext};
    use aip_protocol::graph::{
        AccountabilityEdge, AccountabilityGraph, AccountabilityNode, EdgeRelation, NodeKind,
    };
    use aip_protocol::ports::{
        MockReceiptSystem, MockTraceSystem, ReceiptBindingPort, SigningToolAdapter,
        ToolAttestationPort, TraceBindingPort,
    };
    use aip_protocol::primitives::KeyPair;

    const T0: u64 = 1_739_000_000_000;

    fn build_graph(
        decision_id: [u8; 32],
        action_strength: AttestationStrength,
        attestation_ref: [u8; 32],
    ) -> AccountabilityGraph {
        let human = sha256(b"did:web:cfo.acme.example");
        let auth = sha256(b"capability-grant:financial.approval");
        let agent = sha256(b"aip1invoiceAgent");
        let action = sha256(b"action:approve_invoice:INV-2025-0042");
        let output = sha256(b"output:approved");
        let receipt = sha256(b"receipt:rcva");

        let mut graph = AccountabilityGraph::new(decision_id);
        graph.add_node(AccountabilityNode {
            node_id: human,
            kind: NodeKind::Human,
            object_ref: human,
        });
        graph.add_node(AccountabilityNode {
            node_id: auth,
            kind: NodeKind::Authorization,
            object_ref: auth,
        });
        graph.add_node(AccountabilityNode {
            node_id: agent,
            kind: NodeKind::Agent,
            object_ref: agent,
        });
        graph.add_node(AccountabilityNode {
            node_id: decision_id,
            kind: NodeKind::Decision,
            object_ref: decision_id,
        });
        graph.add_node(AccountabilityNode {
            node_id: action,
            kind: NodeKind::Action,
            object_ref: action,
        });
        graph.add_node(AccountabilityNode {
            node_id: output,
            kind: NodeKind::Output,
            object_ref: output,
        });
        graph.add_node(AccountabilityNode {
            node_id: receipt,
            kind: NodeKind::Receipt,
            object_ref: receipt,
        });

        graph.add_edge(AccountabilityEdge {
            from: auth,
            to: human,
            relation: EdgeRelation::AuthorizedBy,
            strength: AttestationStrength::CounterpartySigned,
            evidence_ref: auth,
        });
        graph.add_edge(AccountabilityEdge {
            from: auth,
            to: agent,
            relation: EdgeRelation::AuthorizedBy,
            strength: AttestationStrength::CounterpartySigned,
            evidence_ref: auth,
        });
        graph.add_edge(AccountabilityEdge {
            from: agent,
            to: decision_id,
            relation: EdgeRelation::Decided,
            strength: AttestationStrength::CounterpartySigned,
            evidence_ref: decision_id,
        });
        graph.add_edge(AccountabilityEdge {
            from: decision_id,
            to: action,
            relation: EdgeRelation::CausedAction,
            strength: action_strength,
            evidence_ref: attestation_ref,
        });
        graph.add_edge(AccountabilityEdge {
            from: action,
            to: output,
            relation: EdgeRelation::ProducedOutput,
            strength: action_strength,
            evidence_ref: attestation_ref,
        });
        graph.add_edge(AccountabilityEdge {
            from: output,
            to: receipt,
            relation: EdgeRelation::GeneratedReceipt,
            strength: AttestationStrength::CounterpartySigned,
            evidence_ref: receipt,
        });
        graph
    }

    fn fixture() -> (EvidencePacket, VerificationKeyring, [u8; 32]) {
        let agent = KeyPair::generate_ed25519();
        let agent_id = "aip1invoiceAgentForVerifier00000000001";
        let assembler = KeyPair::generate_ed25519();
        let assembler_id = "aip1evidenceAssemblerVerifier0000001";
        let trace = MockTraceSystem::new();
        let receipts = MockReceiptSystem::new();
        let tool = SigningToolAdapter::new("sap_connector@1.4.2");

        let auth_ref = sha256(b"capability-grant:financial.approval");
        let session = SessionContext::open(
            &agent,
            agent_id,
            Some("did:web:cfo.acme.example".into()),
            auth_ref,
            &[42u8; 16],
            T0,
        )
        .unwrap();

        let input_commitment = sha256(b"invoice:INV-2025-0042;amount:48150.00;vendor:Globex");
        let output_commitment = sha256(b"decision:APPROVE");
        let decision = DecisionRecord::create(
            &agent,
            agent_id,
            &session,
            [0xABu8; 32],
            input_commitment,
            output_commitment,
            "financial.approval",
            T0 + 10,
            [7u8; 16],
        )
        .unwrap();

        let action_in = sha256(b"sap:post_approval;INV-2025-0042");
        let action_out = sha256(b"sap:status=POSTED;doc=4500001234");
        let provisional = ActionAttestation::create_self_attested(
            &agent,
            agent_id,
            decision.decision_id,
            "approve_invoice",
            "invoice:INV-2025-0042",
            "sap_connector@1.4.2",
            action_in,
            action_out,
            T0 + 20,
            [0u8; 32],
        )
        .unwrap();
        let counterparty_sig = tool.attest_action(&provisional).unwrap();
        let attestation = ActionAttestation::create_counterparty_signed(
            &agent,
            agent_id,
            decision.decision_id,
            "approve_invoice",
            "invoice:INV-2025-0042",
            "sap_connector@1.4.2",
            action_in,
            action_out,
            counterparty_sig,
            T0 + 20,
            [0u8; 32],
        )
        .unwrap();

        let trace_binding = trace.bind_trace(decision.decision_id).unwrap();
        let receipt_binding = receipts.bind_receipt(output_commitment).unwrap();
        let receipt_digest = receipt_binding.receipt_hash;
        let graph = build_graph(
            decision.decision_id,
            AttestationStrength::CounterpartySigned,
            sha256(&attestation.input_commitment),
        );
        let packet = EvidencePacket::assemble(
            &assembler,
            assembler_id,
            graph,
            decision,
            vec![attestation],
            trace_binding,
            receipt_binding,
            T0 + 30,
        )
        .unwrap();

        let mut counterparties = BTreeMap::new();
        counterparties.insert(
            "sap_connector@1.4.2".to_string(),
            tool.public_key().unwrap(),
        );
        let keyring = VerificationKeyring {
            assembler: assembler.public_key,
            agent: agent.public_key,
            trace_authority: trace.public_key(),
            receipt_authority: receipts.public_key(),
            counterparties,
        };

        (packet, keyring, receipt_digest)
    }

    fn failed(report: &VerificationReport, name: &str) -> bool {
        report
            .checks
            .iter()
            .any(|check| check.name == name && check.status == CheckStatus::Fail)
    }

    #[test]
    fn valid_packet_passes_all_terminal_checks() {
        let (packet, keyring, receipt_digest) = fixture();
        let report = verify_packet(&packet, &keyring, Some(receipt_digest));

        assert!(!report.toxic);
        assert_eq!(report.status, "PASS");
        assert!(report
            .checks
            .iter()
            .all(|check| check.status == CheckStatus::Pass));
    }

    #[test]
    fn wrong_agent_key_marks_packet_toxic() {
        let (packet, mut keyring, receipt_digest) = fixture();
        keyring.agent = KeyPair::generate_ed25519().public_key;

        let report = verify_packet(&packet, &keyring, Some(receipt_digest));

        assert!(report.toxic);
        assert!(failed(&report, "agent_decision_signature"));
        assert!(failed(&report, "strict_chain_verification"));
    }

    #[test]
    fn missing_counterparty_key_marks_packet_toxic() {
        let (packet, mut keyring, receipt_digest) = fixture();
        keyring.counterparties.clear();

        let report = verify_packet(&packet, &keyring, Some(receipt_digest));

        assert!(report.toxic);
        assert!(failed(&report, "agent_action_and_counterparty_signatures"));
        assert!(failed(&report, "strict_chain_verification"));
    }

    #[test]
    fn wrong_receipt_digest_marks_packet_toxic() {
        let (packet, keyring, mut receipt_digest) = fixture();
        receipt_digest[0] ^= 0xFF;

        let report = verify_packet(&packet, &keyring, Some(receipt_digest));

        assert!(report.toxic);
        assert!(failed(&report, "receipt_external_digest"));
        assert!(failed(&report, "strict_chain_verification"));
    }

    #[test]
    fn wrong_receipt_authority_key_marks_packet_toxic() {
        let (packet, mut keyring, receipt_digest) = fixture();
        keyring.receipt_authority = KeyPair::generate_ed25519().public_key;

        let report = verify_packet(&packet, &keyring, Some(receipt_digest));

        assert!(report.toxic);
        assert!(failed(&report, "receipt_authority_signature"));
        assert!(failed(&report, "strict_chain_verification"));
    }

    #[test]
    fn receipt_digest_is_required() {
        let (packet, keyring, _) = fixture();

        let report = verify_packet(&packet, &keyring, None);

        assert!(report.toxic);
        assert!(failed(&report, "receipt_external_digest"));
        assert!(failed(&report, "strict_chain_verification"));
    }

    #[test]
    fn packet_and_keyring_json_roundtrip() {
        let (packet, keyring, receipt_digest) = fixture();
        let packet_json = serde_json::to_string(&packet).unwrap();
        let keyring_json = serde_json::to_string(&keyring).unwrap();
        let decoded_packet: EvidencePacket = serde_json::from_str(&packet_json).unwrap();
        let decoded_keyring: VerificationKeyring = serde_json::from_str(&keyring_json).unwrap();

        let report = verify_packet(&decoded_packet, &decoded_keyring, Some(receipt_digest));

        assert!(!report.toxic);
    }

    #[test]
    fn hex_digest_decoding_accepts_prefixed_and_plain_values() {
        let digest = [0xABu8; 32];
        let plain = encode_hex(&digest);
        let prefixed = format!("0x{plain}");

        assert_eq!(decode_hex_32(&plain).unwrap(), digest);
        assert_eq!(decode_hex_32(&prefixed).unwrap(), digest);
    }
}
