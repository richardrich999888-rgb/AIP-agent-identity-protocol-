use std::time::Instant;

use aip_protocol::attestation::{ActionAttestation, AttestationStrength};
use aip_protocol::decision::{DecisionRecord, SessionContext};
use aip_protocol::evidence::EvidencePacket;
use aip_protocol::graph::{
    AccountabilityEdge, AccountabilityGraph, AccountabilityNode, EdgeRelation, NodeKind,
};
use aip_protocol::ports::{
    MockReceiptSystem, MockTraceSystem, ReceiptBindingPort, SigningToolAdapter,
    ToolAttestationPort, TraceBindingPort,
};
use aip_protocol::primitives::{sha256, KeyPair};
use serde_json::json;

const PROVENANCE_COMMITMENT: [u8; 32] = [0xABu8; 32];
const T0: u64 = 1_739_000_000_000;

fn parse_samples() -> usize {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--samples" {
            return args
                .next()
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(500);
        }
    }
    500
}

fn build_graph(
    decision_id: [u8; 32],
    action_strength: AttestationStrength,
    attestation_ref: [u8; 32],
) -> AccountabilityGraph {
    let human = sha256(b"did:web:cfo.bank-pilot.example");
    let auth = sha256(b"capability-grant:upi.clearway.approval");
    let agent = sha256(b"aip1clearwayAgent");
    let action = sha256(b"action:approve_payment:TXN-000042");
    let output = sha256(b"output:approved");
    let receipt = sha256(b"receipt:rcva");

    let mut graph = AccountabilityGraph::new(decision_id);
    for (node_id, kind) in [
        (human, NodeKind::Human),
        (auth, NodeKind::Authorization),
        (agent, NodeKind::Agent),
        (decision_id, NodeKind::Decision),
        (action, NodeKind::Action),
        (output, NodeKind::Output),
        (receipt, NodeKind::Receipt),
    ] {
        graph.add_node(AccountabilityNode {
            node_id,
            kind,
            object_ref: node_id,
        });
    }

    for (from, to, relation, strength, evidence_ref) in [
        (
            auth,
            human,
            EdgeRelation::AuthorizedBy,
            AttestationStrength::CounterpartySigned,
            auth,
        ),
        (
            auth,
            agent,
            EdgeRelation::AuthorizedBy,
            AttestationStrength::CounterpartySigned,
            auth,
        ),
        (
            agent,
            decision_id,
            EdgeRelation::Decided,
            AttestationStrength::CounterpartySigned,
            decision_id,
        ),
        (
            decision_id,
            action,
            EdgeRelation::CausedAction,
            action_strength,
            attestation_ref,
        ),
        (
            action,
            output,
            EdgeRelation::ProducedOutput,
            action_strength,
            attestation_ref,
        ),
        (
            output,
            receipt,
            EdgeRelation::GeneratedReceipt,
            AttestationStrength::CounterpartySigned,
            receipt,
        ),
    ] {
        graph.add_edge(AccountabilityEdge {
            from,
            to,
            relation,
            strength,
            evidence_ref,
        });
    }

    graph
}

fn packet_inputs(
    sample_idx: usize,
    agent_kp: &KeyPair,
    tool: &SigningToolAdapter,
    trace: &MockTraceSystem,
    receipts: &MockReceiptSystem,
) -> (
    AccountabilityGraph,
    DecisionRecord,
    Vec<ActionAttestation>,
    aip_protocol::ports::TraceBinding,
    aip_protocol::ports::ReceiptBinding,
) {
    let agent_id = "aip1clearwayAgentForPilot00000000000001";
    let auth_ref = sha256(b"capability-grant:upi.clearway.approval");
    let mut session_nonce = [42u8; 16];
    session_nonce[0..8].copy_from_slice(&(sample_idx as u64).to_le_bytes());
    let session = SessionContext::open(
        agent_kp,
        agent_id,
        Some("did:web:ops.bank-pilot.example".into()),
        auth_ref,
        &session_nonce,
        T0 + sample_idx as u64,
    )
    .expect("session must open");

    let input_commitment = sha256(format!("txn:TXN-{sample_idx:06};amount:48150.00").as_bytes());
    let output_commitment = sha256(b"decision:APPROVE");
    let mut decision_nonce = [7u8; 16];
    decision_nonce[0..8].copy_from_slice(&(sample_idx as u64).to_le_bytes());
    let decision = DecisionRecord::create(
        agent_kp,
        agent_id,
        &session,
        PROVENANCE_COMMITMENT,
        input_commitment,
        output_commitment,
        "upi.clearway.approval",
        T0 + 10 + sample_idx as u64,
        decision_nonce,
    )
    .expect("decision must create");

    let action_in = sha256(format!("upi:approve;TXN-{sample_idx:06}").as_bytes());
    let action_out = sha256(b"upi:status=APPROVED");
    let provisional = ActionAttestation::create_self_attested(
        agent_kp,
        agent_id,
        decision.decision_id,
        "approve_payment",
        "upi:TXN-000042",
        "upi_switch_adapter@pilot",
        action_in,
        action_out,
        T0 + 20 + sample_idx as u64,
        [0u8; 32],
    )
    .expect("self attestation must create");
    let counterparty_sig = tool
        .attest_action(&provisional)
        .expect("pilot tool signs attestations");
    let attestation = ActionAttestation::create_counterparty_signed(
        agent_kp,
        agent_id,
        decision.decision_id,
        "approve_payment",
        "upi:TXN-000042",
        "upi_switch_adapter@pilot",
        action_in,
        action_out,
        counterparty_sig,
        T0 + 20 + sample_idx as u64,
        [0u8; 32],
    )
    .expect("counterparty attestation must create");

    let trace_binding = trace
        .bind_trace(decision.decision_id)
        .expect("trace binding must create");
    let receipt_binding = receipts
        .bind_receipt(output_commitment)
        .expect("receipt binding must create");
    let attestation_ref = sha256(&attestation.input_commitment);
    let graph = build_graph(
        decision.decision_id,
        AttestationStrength::CounterpartySigned,
        attestation_ref,
    );

    (
        graph,
        decision,
        vec![attestation],
        trace_binding,
        receipt_binding,
    )
}

fn main() {
    let samples = parse_samples();
    let agent_kp = KeyPair::generate_ed25519();
    let assembler_kp = KeyPair::generate_ed25519();
    let tool = SigningToolAdapter::new("upi_switch_adapter@pilot");
    let trace = MockTraceSystem::new();
    let receipts = MockReceiptSystem::new();

    let mut assembly_ms = Vec::with_capacity(samples);
    let mut export_ms = Vec::with_capacity(samples);
    let mut storage_kb = Vec::with_capacity(samples);

    for i in 0..samples {
        let (graph, decision, attestations, trace_binding, receipt_binding) =
            packet_inputs(i, &agent_kp, &tool, &trace, &receipts);
        let start = Instant::now();
        let packet = EvidencePacket::assemble(
            &assembler_kp,
            "aip1evidenceAssemblerForPilot0000000001",
            graph,
            decision,
            attestations,
            trace_binding,
            receipt_binding,
            T0 + 30 + i as u64,
        )
        .expect("packet assembly must succeed");
        assembly_ms.push(start.elapsed().as_secs_f64() * 1000.0);

        let start = Instant::now();
        let encoded = serde_json::to_vec(&packet).expect("packet must serialize");
        let decoded: EvidencePacket =
            serde_json::from_slice(&encoded).expect("packet must deserialize");
        assert_eq!(decoded.magic, EvidencePacket::MAGIC);
        export_ms.push(start.elapsed().as_secs_f64() * 1000.0);
        storage_kb.push(encoded.len() as f64 / 1024.0);
    }

    println!(
        "{}",
        json!({
            "evidence_packet_assembly_ms": assembly_ms,
            "audit_export_ms": export_ms,
            "storage_overhead_kb": storage_kb
        })
    );
}
