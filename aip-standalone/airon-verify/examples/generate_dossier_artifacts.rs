use aip_protocol::attestation::{ActionAttestation, AttestationStrength};
use aip_protocol::decision::{DecisionRecord, SessionContext};
use aip_protocol::graph::{
    AccountabilityEdge, AccountabilityGraph, AccountabilityNode, EdgeRelation, NodeKind,
};
use aip_protocol::ports::{ReceiptBinding, TraceBinding};
use aip_protocol::primitives::{sha256, AlgorithmId, KeyPair, PublicKey, Signature};
use airon_verify::{encode_hex, verify_packet, VerificationKeyring};
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

const T0: u64 = 1_739_000_000_000;

fn main() -> Result<(), Box<dyn Error>> {
    let out_dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("dossier/artifacts"));
    fs::create_dir_all(&out_dir)?;

    let (packet, keyring, receipt_digest) = fixture()?;

    let pass_report = verify_packet(&packet, &keyring, Some(receipt_digest));
    assert!(
        !pass_report.toxic,
        "nominal dossier EvidencePacket must verify before writing artifacts"
    );

    let mut toxic_digest = receipt_digest;
    toxic_digest[0] ^= 0xFF;
    let toxic_report = verify_packet(&packet, &keyring, Some(toxic_digest));
    assert!(
        toxic_report.toxic,
        "tampered receipt digest must trigger fail-closed TOXIC report"
    );

    write_json(&out_dir.join("evidence_packet_nominal.json"), &packet)?;
    write_json(&out_dir.join("verification_keyring.json"), &keyring)?;
    write_json(
        &out_dir.join("airon_verify_toxic_report.json"),
        &toxic_report,
    )?;
    fs::write(
        out_dir.join("external_receipt_digest.hex"),
        format!("{}\n", encode_hex(&receipt_digest)),
    )?;

    println!(
        "wrote AIRON dossier verifier artifacts to {}",
        out_dir.display()
    );
    Ok(())
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), Box<dyn Error>> {
    fs::write(path, format!("{}\n", serde_json::to_string_pretty(value)?))?;
    Ok(())
}

fn fixture() -> Result<
    (
        aip_protocol::evidence::EvidencePacket,
        VerificationKeyring,
        [u8; 32],
    ),
    Box<dyn Error>,
> {
    let agent = keypair(0x11);
    let assembler = keypair(0x22);
    let trace_authority = keypair(0x33);
    let receipt_authority = keypair(0x44);
    let tool = keypair(0x55);

    let agent_id = "aip1invoiceAgentForVerifier00000000001";
    let assembler_id = "aip1evidenceAssemblerVerifier0000001";
    let tool_id = "sap_connector@1.4.2";
    let auth_ref = sha256(b"capability-grant:financial.approval");

    let session = SessionContext::open(
        &agent,
        agent_id,
        Some("did:web:cfo.acme.example".into()),
        auth_ref,
        &[42u8; 16],
        T0,
    )?;

    let input_commitment = sha256(b"invoice:INV-2025-0042;amount:48150.00;vendor:Globex");
    let output_commitment = sha256(b"decision:APPROVE");
    let mut decision = DecisionRecord::create(
        &agent,
        agent_id,
        &session,
        [0xABu8; 32],
        input_commitment,
        output_commitment,
        "financial.approval",
        T0 + 10,
        [7u8; 16],
    )?;
    decision.agent_sig = deterministic_signature(
        &agent,
        agent_id,
        &decision_payload(&decision),
        T0 + 10,
        [0x71; 16],
    )?;

    let action_in = sha256(b"sap:post_approval;INV-2025-0042");
    let action_out = sha256(b"sap:status=POSTED;doc=4500001234");
    let provisional = ActionAttestation::create_self_attested(
        &agent,
        agent_id,
        decision.decision_id,
        "approve_invoice",
        "invoice:INV-2025-0042",
        tool_id,
        action_in,
        action_out,
        T0 + 20,
        [0u8; 32],
    )?;
    let counterparty_payload = ActionAttestation::counterparty_payload(
        &provisional.decision_id,
        &provisional.input_commitment,
        &provisional.output_commitment,
    );
    let counterparty_sig =
        deterministic_signature(&tool, tool_id, &counterparty_payload, T0 + 20, [0x72; 16])?;

    let mut attestation = ActionAttestation::create_counterparty_signed(
        &agent,
        agent_id,
        decision.decision_id,
        "approve_invoice",
        "invoice:INV-2025-0042",
        tool_id,
        action_in,
        action_out,
        counterparty_sig,
        T0 + 20,
        [0u8; 32],
    )?;
    attestation.agent_sig = deterministic_signature(
        &agent,
        agent_id,
        &action_payload(&attestation),
        T0 + 20,
        [0x73; 16],
    )?;

    let trace_binding = deterministic_trace_binding(&trace_authority, decision.decision_id)?;
    let receipt_binding = deterministic_receipt_binding(&receipt_authority, output_commitment)?;
    let receipt_digest = receipt_binding.receipt_hash;
    let graph = build_graph(
        decision.decision_id,
        AttestationStrength::CounterpartySigned,
        sha256(&attestation.input_commitment),
    );

    let mut packet = aip_protocol::evidence::EvidencePacket::assemble(
        &assembler,
        assembler_id,
        graph,
        decision,
        vec![attestation],
        trace_binding,
        receipt_binding,
        T0 + 30,
    )?;
    packet.assembler_sig = deterministic_signature(
        &assembler,
        assembler_id,
        &packet.packet_digest(),
        T0 + 30,
        [0x74; 16],
    )?;

    let mut counterparties = BTreeMap::new();
    counterparties.insert(tool_id.to_string(), tool.public_key);
    let keyring = VerificationKeyring {
        assembler: assembler.public_key,
        pqc_assembler: None,
        agent: agent.public_key,
        trace_authority: trace_authority.public_key,
        receipt_authority: receipt_authority.public_key,
        counterparties,
    };

    Ok((packet, keyring, receipt_digest))
}

fn keypair(seed: u8) -> KeyPair {
    let seed_bytes = [seed; 32];
    let signing_key = SigningKey::from_bytes(&seed_bytes);
    let verifying_key = signing_key.verifying_key();
    KeyPair {
        algorithm: AlgorithmId::Ed25519,
        public_key: PublicKey {
            algorithm: AlgorithmId::Ed25519,
            key_bytes: verifying_key.to_bytes().to_vec(),
        },
        private_key: signing_key.to_bytes().to_vec(),
    }
}

fn deterministic_signature(
    key_pair: &KeyPair,
    signer_id: &str,
    payload: &[u8],
    timestamp: u64,
    nonce: [u8; 16],
) -> Result<Signature, Box<dyn Error>> {
    let private_key: [u8; 32] = key_pair.private_key.as_slice().try_into()?;
    let signing_key = SigningKey::from_bytes(&private_key);
    let mut signature = Signature {
        algorithm: key_pair.algorithm,
        signer_id: signer_id.to_string(),
        timestamp,
        nonce,
        payload_hash: sha256(payload),
        signature_bytes: Vec::new(),
    };
    signature.signature_bytes = signing_key
        .sign(&signed_metadata_hash(&signature))
        .to_bytes()
        .to_vec();
    Ok(signature)
}

fn signed_metadata_hash(signature: &Signature) -> [u8; 32] {
    let mut input = Vec::new();
    input.push(signature.algorithm as u8);
    input.extend_from_slice(signature.signer_id.as_bytes());
    input.extend_from_slice(&signature.timestamp.to_le_bytes());
    input.extend_from_slice(&signature.nonce);
    input.extend_from_slice(&signature.payload_hash);
    sha256(&input)
}

fn decision_payload(record: &DecisionRecord) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&record.decision_id);
    payload.extend_from_slice(record.agent_id.as_bytes());
    payload.extend_from_slice(&record.session_id);
    payload.extend_from_slice(&record.provenance_commitment);
    payload.extend_from_slice(&record.sequence.to_le_bytes());
    payload.extend_from_slice(&record.prev_decision);
    payload.extend_from_slice(&record.input_commitment);
    payload.extend_from_slice(&record.output_commitment);
    payload.extend_from_slice(&record.authorization_ref);
    payload.extend_from_slice(record.decision_class.as_bytes());
    payload.extend_from_slice(&record.decided_at.to_le_bytes());
    payload.extend_from_slice(&record.decision_nonce);
    payload
}

fn action_payload(attestation: &ActionAttestation) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&attestation.decision_id);
    payload.extend_from_slice(attestation.agent_id.as_bytes());
    payload.extend_from_slice(attestation.action_verb.as_bytes());
    payload.extend_from_slice(attestation.resource_ref.as_bytes());
    payload.extend_from_slice(attestation.tool_ref.as_bytes());
    payload.extend_from_slice(&attestation.input_commitment);
    payload.extend_from_slice(&attestation.output_commitment);
    payload.push(attestation.strength.as_u8());
    payload.extend_from_slice(&attestation.attested_at.to_le_bytes());
    payload.extend_from_slice(&attestation.prev_attestation);
    payload
}

fn deterministic_trace_binding(
    authority: &KeyPair,
    decision_id: [u8; 32],
) -> Result<TraceBinding, Box<dyn Error>> {
    let trace_id = sha256(&decision_id);
    let trace_root = sha256(&trace_id);
    let mut binding = TraceBinding {
        trace_id,
        trace_root,
        system: "chrono".into(),
        sig: empty_signature(authority, "aip1chronoAuthority"),
    };
    binding.sig = deterministic_signature(
        authority,
        "aip1chronoAuthority",
        &binding.signing_payload(),
        0,
        [0x75; 16],
    )?;
    Ok(binding)
}

fn deterministic_receipt_binding(
    authority: &KeyPair,
    output_commitment: [u8; 32],
) -> Result<ReceiptBinding, Box<dyn Error>> {
    let receipt_id = sha256(&output_commitment);
    let receipt_hash = sha256(&receipt_id);
    let mut binding = ReceiptBinding {
        receipt_id,
        receipt_hash,
        authority: "aip1rcvaAuthority".into(),
        sig: empty_signature(authority, "aip1rcvaAuthority"),
    };
    binding.sig = deterministic_signature(
        authority,
        "aip1rcvaAuthority",
        &binding.signing_payload(),
        0,
        [0x76; 16],
    )?;
    Ok(binding)
}

fn empty_signature(key_pair: &KeyPair, signer_id: &str) -> Signature {
    Signature {
        algorithm: key_pair.algorithm,
        signer_id: signer_id.to_string(),
        timestamp: 0,
        nonce: [0u8; 16],
        payload_hash: [0u8; 32],
        signature_bytes: Vec::new(),
    }
}

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
