use aip_protocol::attestation::{ActionAttestation, AttestationStrength};
use aip_protocol::decision::{DecisionRecord, SessionContext};
use aip_protocol::evidence::EvidencePacket;
use aip_protocol::graph::{
    AccountabilityEdge, AccountabilityGraph, AccountabilityNode, EdgeRelation, NodeKind,
};
use aip_protocol::policy::TrustFloorPolicy;
use aip_protocol::ports::{
    MockReceiptSystem, MockTraceSystem, NonSigningToolAdapter, ReceiptBindingPort,
    SigningToolAdapter, ToolAttestationPort, TraceBindingPort,
};
use aip_protocol::primitives::{sha256, KeyPair, PublicKey};

const PROVENANCE_COMMITMENT: [u8; 32] = [0xABu8; 32];
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

fn run_flow(tool: &dyn ToolAttestationPort) -> (EvidencePacket, PublicKey, PublicKey) {
    let agent_kp = KeyPair::generate_ed25519();
    let agent_id = "aip1invoiceAgentForWorkedExample00000001";
    let assembler_kp = KeyPair::generate_ed25519();
    let assembler_id = "aip1evidenceAssembler00000000000000000001";

    let trace = MockTraceSystem::new();
    let receipts = MockReceiptSystem::new();

    let auth_ref = sha256(b"capability-grant:financial.approval");
    let session = SessionContext::open(
        &agent_kp,
        agent_id,
        Some("did:web:cfo.acme.example".into()),
        auth_ref,
        &[42u8; 16],
        T0,
    )
    .unwrap();
    assert!(session.verify(&agent_kp.public_key).is_ok());

    let input_commitment = sha256(b"invoice:INV-2025-0042;amount:48150.00;vendor:Globex");
    let output_commitment = sha256(b"decision:APPROVE");
    let decision = DecisionRecord::create(
        &agent_kp,
        agent_id,
        &session,
        PROVENANCE_COMMITMENT,
        input_commitment,
        output_commitment,
        "financial.approval",
        T0 + 10,
        [7u8; 16],
    )
    .unwrap();
    assert!(decision.verify(&agent_kp.public_key).is_ok());

    let action_in = sha256(b"sap:post_approval;INV-2025-0042");
    let action_out = sha256(b"sap:status=POSTED;doc=4500001234");

    let provisional = ActionAttestation::create_self_attested(
        &agent_kp,
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

    let (attestation, action_strength, tool_key) = match tool.attest_action(&provisional) {
        Some(counterparty_sig) => {
            let attestation = ActionAttestation::create_counterparty_signed(
                &agent_kp,
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
            (
                attestation,
                AttestationStrength::CounterpartySigned,
                tool.public_key(),
            )
        }
        None => (provisional, AttestationStrength::SelfAttested, None),
    };
    assert!(attestation
        .verify(&agent_kp.public_key, tool_key.as_ref())
        .is_ok());

    let trace_binding = trace.bind_trace(decision.decision_id).unwrap();
    let receipt_binding = receipts.bind_receipt(output_commitment).unwrap();
    assert!(receipts.verify_receipt(&receipt_binding).unwrap());

    let attestation_ref = sha256(&attestation.input_commitment);
    let graph = build_graph(decision.decision_id, action_strength, attestation_ref);
    graph.validate().unwrap();

    let packet = EvidencePacket::assemble(
        &assembler_kp,
        assembler_id,
        graph,
        decision,
        vec![attestation],
        trace_binding,
        receipt_binding,
        T0 + 30,
    )
    .unwrap();

    let tool_key_for_verify = tool_key.clone();
    packet
        .verify(
            &assembler_kp.public_key,
            &agent_kp.public_key,
            |_tool_ref| tool_key_for_verify.clone(),
        )
        .unwrap();

    (packet, assembler_kp.public_key, agent_kp.public_key)
}

#[test]
fn invoice_approval_with_signing_tool_is_counterparty_strong() {
    let tool = SigningToolAdapter::new("sap_connector@1.4.2");
    let (packet, _assembler_pk, _agent_pk) = run_flow(&tool);

    assert_eq!(
        packet.trust_floor,
        AttestationStrength::CounterpartySigned.as_u8()
    );

    let policy = TrustFloorPolicy::new(AttestationStrength::SelfAttested).require(
        "financial.approval",
        AttestationStrength::CounterpartySigned,
    );
    assert!(policy.enforce("financial.approval", &packet.graph).is_ok());
}

#[test]
fn invoice_approval_with_nonsigning_tool_is_rejected_by_policy() {
    let tool = NonSigningToolAdapter;
    let (packet, _assembler_pk, _agent_pk) = run_flow(&tool);

    assert_eq!(
        packet.trust_floor,
        AttestationStrength::SelfAttested.as_u8()
    );

    let policy = TrustFloorPolicy::new(AttestationStrength::SelfAttested).require(
        "financial.approval",
        AttestationStrength::CounterpartySigned,
    );
    let result = policy.enforce("financial.approval", &packet.graph);
    assert!(result.is_err());

    let lax = TrustFloorPolicy::new(AttestationStrength::SelfAttested);
    assert!(lax.enforce("logistics.routing", &packet.graph).is_ok());
}

#[test]
fn evidence_packet_overclaim_is_detected() {
    let tool = NonSigningToolAdapter;
    let (mut packet, assembler_pk, agent_pk) = run_flow(&tool);

    packet.trust_floor = AttestationStrength::CounterpartySigned.as_u8();

    let result = packet.verify(&assembler_pk, &agent_pk, |_| None);
    assert!(result.is_err());
}
