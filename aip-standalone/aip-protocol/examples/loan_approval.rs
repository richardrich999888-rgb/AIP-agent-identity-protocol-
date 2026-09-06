//! Design-partner demo: a ₹5 crore loan approval, end to end.
//!
//!   Human Manager  (principal, issues scoped authority)
//!        │
//!        ▼  root token: orchestrator scope (read/write/execute/delegate)
//!   Loan Agent     (holds root token, delegates a narrower scope)
//!        │
//!        ▼  delegation: submitter scope (write only — cannot re-delegate/admin)
//!   Sub-Agent      (acts: approves the loan, posts the ledger entry)
//!
//! Run: `cargo run -p aip-protocol --example loan_approval`
//! (printed sections are extracted verbatim into the evaluation package).

use std::collections::HashMap;

use aip_core::capability::{issue_scoped_token, scope_orchestrator, scope_submitter};
use aip_core::create_identity;
use aip_core::delegation::create_delegation;
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};
use aip_protocol::{
    verify_packet, AccountabilityGraph, ActionAttestation, AgentIdentitySummary, DecisionRecord,
    EvidencePacketBuilder, ReceiptBinding, RootAuthority, TrustFloor, VerificationContext,
};
use aip_types::{Action, AlgorithmId, ProvenanceTriple, PublicKey, ScopeAction};

fn prov(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(format!("model:{tag}").as_bytes()),
        environment_commitment: sha256(format!("env:{tag}").as_bytes()),
        toolchain_commitment: sha256(format!("tool:{tag}").as_bytes()),
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn main() {
    // ── Principal: a human branch manager ──
    let mgr_kp = generate_ed25519_keypair();
    let mgr_id = derive_aip_id(&mgr_kp.public_key, &prov("human:branch-manager"));

    // ── Loan agent holds the manager's delegated authority ──
    let (loan_aid, loan_kp) = create_identity(prov("ai:loan-agent-v4"), None).unwrap();
    // ── Sub-agent performs the underwriting sub-task ──
    let (sub_aid, sub_kp) = create_identity(prov("ai:underwriting-subagent-v2"), None).unwrap();

    // Manager issues a scoped, time-boxed root token to the loan agent.
    let root_token = issue_scoped_token(
        &mgr_id,
        &mgr_kp.private_key,
        &loan_aid.id,
        scope_orchestrator(), // read/write/execute/delegate; admin denied
        Some(3_600_000),      // 1 hour
    )
    .unwrap();

    // Loan agent delegates a STRICTLY NARROWER authority to the sub-agent:
    // write only — it cannot re-delegate, cannot admin, cannot delete.
    let hop = create_delegation(
        &root_token,
        &loan_kp.private_key,
        &sub_aid.id,
        scope_submitter(),
    )
    .unwrap();

    // ── The sub-agent decides and acts ──
    let now = now_ms();
    let decision = DecisionRecord {
        decision_id: aip_core::capability::random_jti(),
        action_kind: ScopeAction::Standard(Action::Write),
        summary: "Approve term loan LN-2026-5512 for INR 5,00,00,000 (Rs 5 crore) to Meridian Infra Pvt Ltd".into(),
        input_hash: sha256(b"applicant=Meridian Infra Pvt Ltd;amount=50000000000 paise;tenor=84m;CIBIL=781;DSCR=1.42;collateral=verified"),
        rationale_hash: sha256(b"policy CR-7 satisfied: DSCR>=1.25, CIBIL>=750, collateral cover 1.3x; within delegated underwriting limit"),
        decided_at: now,
    };

    let action_payload =
        "POST /v1/core-banking/loans/approve {\"loan_id\":\"LN-2026-5512\",\"amount_paise\":50000000000}";
    let action = ActionAttestation::create(
        &sub_aid.id,
        &sub_kp.private_key,
        &decision.decision_id,
        ScopeAction::Standard(Action::Write),
        action_payload,
        sha256(action_payload.as_bytes()),
        now + 9,
    )
    .unwrap();

    // Core banking system countersigns the ledger receipt (bilateral evidence).
    let ledger_kp = generate_ed25519_keypair();
    let ledger_id = "core-banking.examplebank.in";
    let receipt_content = "LEDGER-LN-2026-5512|disbursement-pending|INR 5,00,00,000";
    let mut receipt = ReceiptBinding {
        receipt_system: ledger_id.to_string(),
        receipt_id: "LEDGER-LN-2026-5512".to_string(),
        receipt_hash: sha256(receipt_content.as_bytes()),
        counterparty_id: None,
        counterparty_sig: None,
    };
    receipt
        .countersign(&decision.decision_id, ledger_id, &ledger_kp.private_key)
        .unwrap();

    let packet = EvidencePacketBuilder::new(
        AgentIdentitySummary {
            aip_id: sub_aid.id.clone(),
            public_key: PublicKey {
                algorithm: AlgorithmId::Ed25519,
                key_bytes: sub_kp.public_key.clone(),
            },
            provenance: sub_aid.provenance.clone(),
        },
        RootAuthority {
            principal_id: mgr_id.clone(),
            display_role: "Branch Manager".into(),
            root_token,
        },
    )
    .delegation_chain(vec![hop])
    .decision(decision)
    .action(action)
    .receipt(receipt)
    .claimed_trust_floor(TrustFloor::CounterpartySigned)
    .build_and_sign(&sub_kp.private_key)
    .unwrap();

    // Verifier (an auditor) trusts the manager's and loan agent's keys.
    let ctx = VerificationContext {
        issuer_public_keys: HashMap::from([
            (mgr_id.clone(), mgr_kp.public_key.clone()),
            (loan_aid.id.clone(), loan_kp.public_key.clone()),
        ]),
        counterparty_public_keys: HashMap::from([(
            ledger_id.to_string(),
            ledger_kp.public_key.clone(),
        )]),
        revoked_jtis: Default::default(),
        trace_data: None,
        receipt_data: Some(receipt_content.as_bytes().to_vec()),
        verification_time_ms: None,
        future_tolerance_ms: 0,
        trusted_bundle_signers: Default::default(),
    };
    let report = verify_packet(&packet, &ctx);
    let graph = AccountabilityGraph::from_packet(&packet).with_report(&report);

    println!("===== EVIDENCE_PACKET_JSON =====");
    println!("{}", packet.to_json().unwrap());
    println!("===== VERIFICATION_REPORT_JSON =====");
    println!("{}", report.to_json().unwrap());
    println!("===== AUTHORITY_GRAPH_DOT =====");
    println!("{}", graph.to_dot());

    // ── Now show why a log is insufficient: tamper with the amount ──
    let mut tampered = packet.clone();
    tampered.decision.summary =
        "Approve term loan LN-2026-5512 for INR 50,00,00,000 (Rs 50 crore) to Meridian Infra Pvt Ltd".into();
    tampered.packet_hash = tampered.compute_hash(); // attacker "fixes" the hash too
    let tampered_report = verify_packet(&tampered, &ctx);
    println!("===== TAMPER_REPORT_JSON =====");
    println!("{}", tampered_report.to_json().unwrap());
}
