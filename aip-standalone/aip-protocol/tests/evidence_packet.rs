//! EvidencePacket end-to-end tests: build → verify → tamper → detect.
//!
//! Every tampering scenario must flip a specific, named verification rule.
//! No fake checks, no hardcoded passes.

use std::collections::HashMap;

use aip_core::capability::{issue_scoped_token, scope_orchestrator, scope_submitter};
use aip_core::create_identity;
use aip_core::delegation::{create_delegation, create_sub_delegation};
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};
use aip_protocol::verification_report::rules;
use aip_protocol::{
    verify_packet, AccountabilityGraph, ActionAttestation, AgentIdentitySummary, DecisionRecord,
    EvidencePacket, EvidencePacketBuilder, ReceiptBinding, RootAuthority, TraceBinding, TrustFloor,
    VerificationContext,
};
use aip_types::{Action, CapabilityScope, KeyPair, ProvenanceTriple, ScopeAction};

// ─── Test fixture: CFO → treasury orchestrator → payments agent ───

struct Fixture {
    packet: EvidencePacket,
    ctx: VerificationContext,
    agent_kp: KeyPair,
    receipt_data: Vec<u8>,
}

fn provenance(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(format!("model-{tag}").as_bytes()),
        environment_commitment: sha256(format!("env-{tag}").as_bytes()),
        toolchain_commitment: sha256(format!("toolchain-{tag}").as_bytes()),
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Build a complete, honest, countersigned packet plus the matching context.
fn build_fixture() -> Fixture {
    // Principal (CFO) and intermediary (treasury orchestrator) and agent.
    let cfo_kp = generate_ed25519_keypair();
    let cfo_id = derive_aip_id(&cfo_kp.public_key, &provenance("cfo"));

    let (orch_aid, orch_kp) = create_identity(provenance("orchestrator"), None).unwrap();
    let (agent_aid, agent_kp) = create_identity(provenance("payments-agent"), None).unwrap();

    // CFO issues a root token to the orchestrator.
    let root_token = issue_scoped_token(
        &cfo_id,
        &cfo_kp.private_key,
        &orch_aid.id,
        scope_orchestrator(), // Read, Write, Execute, Delegate; Admin denied
        Some(3_600_000),
    )
    .unwrap();

    // Orchestrator delegates an attenuated scope to the payments agent.
    let hop1 = create_delegation(
        &root_token,
        &orch_kp.private_key,
        &agent_aid.id,
        scope_submitter(), // Write only
    )
    .unwrap();

    // Decision + signed action. The decision must postdate token issuance
    // (TEMPORAL_VALIDITY enforces decided_at ≥ issued_at for every token).
    let now = now_ms();
    let decision = DecisionRecord {
        decision_id: aip_core::capability::random_jti(),
        action_kind: ScopeAction::Standard(Action::Write),
        summary: "Approve vendor payment INV-2026-0142 for $48,200".into(),
        input_hash: sha256(b"invoice INV-2026-0142, vendor Acme GmbH, $48,200"),
        rationale_hash: sha256(b"3-way match passed; within delegated limit"),
        decided_at: now,
    };

    let action = ActionAttestation::create(
        &agent_aid.id,
        &agent_kp.private_key,
        &decision.decision_id,
        ScopeAction::Standard(Action::Write),
        "POST /ledger/payments {invoice: INV-2026-0142}",
        sha256(b"{\"invoice\":\"INV-2026-0142\",\"amount\":48200}"),
        now + 5,
    )
    .unwrap();

    // External ledger receipt, countersigned by the ledger system.
    let ledger_kp = generate_ed25519_keypair();
    let receipt_data = b"LEDGER-ENTRY-90211: payment INV-2026-0142 posted".to_vec();
    let mut receipt = ReceiptBinding {
        receipt_system: "ledger.example-bank.com".into(),
        receipt_id: "LEDGER-ENTRY-90211".into(),
        receipt_hash: sha256(&receipt_data),
        counterparty_id: None,
        counterparty_sig: None,
    };
    receipt
        .countersign(
            &decision.decision_id,
            "ledger.example-bank.com",
            &ledger_kp.private_key,
        )
        .unwrap();

    let trace_data = b"otel-trace-export-bytes".to_vec();
    let trace = TraceBinding {
        trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".into(),
        trace_hash: sha256(&trace_data),
    };

    let agent_summary = AgentIdentitySummary {
        aip_id: agent_aid.id.clone(),
        public_key: agent_aid.primary_key.clone(),
        provenance: agent_aid.provenance.clone(),
    };
    let root_authority = RootAuthority {
        principal_id: cfo_id.clone(),
        display_role: "CFO".into(),
        root_token,
    };

    let packet = EvidencePacketBuilder::new(agent_summary, root_authority)
        .delegation_chain(vec![hop1])
        .decision(decision)
        .action(action)
        .trace(trace)
        .receipt(receipt)
        .claimed_trust_floor(TrustFloor::CounterpartySigned)
        .build_and_sign(&agent_kp.private_key)
        .unwrap();

    let mut issuer_keys = HashMap::new();
    issuer_keys.insert(cfo_id, cfo_kp.public_key.clone());
    issuer_keys.insert(orch_aid.id.clone(), orch_kp.public_key.clone());

    let ctx = VerificationContext {
        issuer_public_keys: issuer_keys,
        counterparty_public_keys: HashMap::from([(
            "ledger.example-bank.com".to_string(),
            ledger_kp.public_key.clone(),
        )]),
        revoked_jtis: Default::default(),
        trace_data: Some(trace_data),
        receipt_data: Some(receipt_data.clone()),
    };

    Fixture {
        packet,
        ctx,
        agent_kp,
        receipt_data,
    }
}

fn assert_rule_failed(report: &aip_protocol::VerificationReport, rule: &str) {
    let r = report
        .rule(rule)
        .unwrap_or_else(|| panic!("rule {rule} missing from report"));
    assert!(
        !r.pass,
        "expected rule {rule} to FAIL, but it passed: {}",
        r.detail
    );
    assert!(!report.valid, "report must be invalid when {rule} fails");
}

// ─── Happy path ───

#[test]
fn test_honest_packet_verifies_at_counterparty_floor() {
    let f = build_fixture();
    let report = verify_packet(&f.packet, &f.ctx);

    for check in &report.checks {
        assert!(check.pass, "rule {} failed: {}", check.rule, check.detail);
    }
    assert!(report.valid);
    assert!(!report.tampered);
    assert_eq!(report.trust_floor, TrustFloor::CounterpartySigned);
    assert!(report.authority_chain_verified);
    assert!(report.delegation_chain_verified);
    assert!(report.scope_verified);
    assert!(report.receipt_verified);
    assert!(report.trace_verified);
    assert!(report.revocation_clear);
}

#[test]
fn test_json_roundtrip_preserves_verification() {
    let f = build_fixture();
    let json = f.packet.to_json().unwrap();
    let restored = EvidencePacket::from_json(&json).unwrap();
    assert_eq!(restored.packet_hash, f.packet.packet_hash);

    let report = verify_packet(&restored, &f.ctx);
    assert!(report.valid, "failures: {:?}", report.failures());
    assert_eq!(report.trust_floor, TrustFloor::CounterpartySigned);
}

#[test]
fn test_report_json_shape() {
    let f = build_fixture();
    let report = verify_packet(&f.packet, &f.ctx);
    let json = report.to_json().unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["valid"], true);
    assert_eq!(value["trust_floor"], "COUNTERPARTY_SIGNED");
    assert_eq!(value["authority_chain_verified"], true);
    assert_eq!(value["receipt_verified"], true);
    assert_eq!(value["tampered"], false);
}

// ─── Tampering: every scenario flips a real rule ───

#[test]
fn test_tamper_decision_summary_detected() {
    let f = build_fixture();
    let mut p = f.packet.clone();
    p.decision.summary = "Approve vendor payment INV-2026-0142 for $4,820,000".into();

    let report = verify_packet(&p, &f.ctx);
    assert_rule_failed(&report, rules::CANONICAL_HASH);
    assert!(report.tampered, "hash mismatch is tamper evidence");
}

#[test]
fn test_tamper_recompute_hash_still_caught_by_signature() {
    // A smarter attacker recomputes packet_hash after editing. The agent
    // signature must then catch it.
    let f = build_fixture();
    let mut p = f.packet.clone();
    p.decision.summary = "Approve vendor payment for $4,820,000".into();
    p.packet_hash = p.compute_hash(); // attacker fixes the hash

    let report = verify_packet(&p, &f.ctx);
    assert_rule_failed(&report, rules::AGENT_SIGNATURE);
    assert!(report.tampered);
}

#[test]
fn test_tamper_action_payload_detected() {
    let f = build_fixture();
    let mut p = f.packet.clone();
    p.actions[0].payload_hash = sha256(b"different payload");
    p.packet_hash = p.compute_hash();

    let report = verify_packet(&p, &f.ctx);
    // Packet-level signature fails AND the per-action attestation fails.
    assert_rule_failed(&report, rules::ACTION_ATTESTATIONS);
    assert!(report.tampered);
}

#[test]
fn test_scope_escalation_in_chain_detected() {
    // Attacker swaps the delegated (attenuated) scope for a wider one.
    let f = build_fixture();
    let mut p = f.packet.clone();
    p.delegation_chain[0].scope = CapabilityScope::all();
    p.packet_hash = p.compute_hash();

    let report = verify_packet(&p, &f.ctx);
    // The hop signature no longer covers the scope → chain verification fails.
    assert_rule_failed(&report, rules::DELEGATION_CHAIN);
    assert!(report.tampered);
}

#[test]
fn test_action_outside_scope_rejected() {
    // Agent holds Write-only delegation but the packet claims a Delete action.
    let f = build_fixture();
    let mut p = f.packet.clone();
    p.decision.action_kind = ScopeAction::Standard(Action::Delete);
    let action = ActionAttestation::create(
        &p.agent.aip_id,
        &f.agent_kp.private_key,
        &p.decision.decision_id,
        ScopeAction::Standard(Action::Delete),
        "DELETE /ledger/payments/90211",
        sha256(b"delete"),
        p.decision.decided_at + 1,
    )
    .unwrap();
    p.actions = vec![action];
    p.packet_hash = p.compute_hash();
    // Re-sign as the agent (insider trying to overreach with valid keys).
    p.agent_sig = aip_crypto::sign_ed25519(
        &f.agent_kp.private_key,
        &p.agent.aip_id,
        &p.canonical_bytes(),
    )
    .unwrap();

    let report = verify_packet(&p, &f.ctx);
    assert_rule_failed(&report, rules::SCOPE_AUTHORITY);
    assert!(
        !report.scope_verified,
        "scope_verified must be false on scope violation"
    );
}

#[test]
fn test_revoked_delegation_invalidates_packet() {
    let f = build_fixture();
    let mut ctx = f.ctx.clone();
    ctx.revoked_jtis.insert(f.packet.delegation_chain[0].jti);

    let report = verify_packet(&f.packet, &ctx);
    assert_rule_failed(&report, rules::REVOCATION);
    assert!(!report.revocation_clear);
    // Revocation is invalidity, not tampering.
    assert!(!report.tampered);
    assert!(report.trust_floor < TrustFloor::AuthorityBound);
}

#[test]
fn test_unknown_root_issuer_fails() {
    let f = build_fixture();
    let mut ctx = f.ctx.clone();
    ctx.issuer_public_keys
        .remove(&f.packet.root_authority.root_token.issuer_id);

    let report = verify_packet(&f.packet, &ctx);
    assert_rule_failed(&report, rules::ROOT_TOKEN_SIGNATURE);
}

#[test]
fn test_agent_identity_substitution_detected() {
    // Attacker replaces the agent identity block with their own keypair,
    // re-signs the packet and fixes the hash. AGENT_ID_BINDING and the
    // authority chain must catch it: the substituted identity was never
    // the delegation grantee.
    let f = build_fixture();
    let mut p = f.packet.clone();

    let attacker_kp = generate_ed25519_keypair();
    let attacker_prov = provenance("attacker");
    let attacker_id = derive_aip_id(&attacker_kp.public_key, &attacker_prov);
    p.agent.aip_id = attacker_id.clone();
    p.agent.public_key.key_bytes = attacker_kp.public_key.clone();
    p.agent.provenance = attacker_prov;
    p.packet_hash = p.compute_hash();
    p.agent_sig =
        aip_crypto::sign_ed25519(&attacker_kp.private_key, &attacker_id, &p.canonical_bytes())
            .unwrap();

    let report = verify_packet(&p, &f.ctx);
    // The original action attestations are signed by the real agent, and the
    // delegation leaf names the real agent — both must fail.
    assert_rule_failed(&report, rules::AUTHORITY_CHAIN);
    assert_rule_failed(&report, rules::ACTION_ATTESTATIONS);
}

#[test]
fn test_tampered_receipt_data_detected() {
    let f = build_fixture();
    let mut ctx = f.ctx.clone();
    let mut forged = f.receipt_data.clone();
    forged[0] ^= 0xFF;
    ctx.receipt_data = Some(forged);

    let report = verify_packet(&f.packet, &ctx);
    assert_rule_failed(&report, rules::RECEIPT_BINDING);
    assert!(report.tampered);
    assert!(!report.receipt_verified);
}

#[test]
fn test_trace_data_mismatch_detected() {
    let f = build_fixture();
    let mut ctx = f.ctx.clone();
    ctx.trace_data = Some(b"a different trace export".to_vec());

    let report = verify_packet(&f.packet, &ctx);
    assert_rule_failed(&report, rules::TRACE_BINDING);
    assert!(!report.trace_verified);
}

#[test]
fn test_claimed_floor_above_evidence_fails() {
    // Build a packet WITHOUT a countersigned receipt but claim
    // COUNTERPARTY_SIGNED. The trust-floor rule must fail.
    let f = build_fixture();
    let mut p = f.packet.clone();
    if let Some(r) = &mut p.receipt_binding {
        r.counterparty_id = None;
        r.counterparty_sig = None;
    }
    p.packet_hash = p.compute_hash();
    p.agent_sig = aip_crypto::sign_ed25519(
        &f.agent_kp.private_key,
        &p.agent.aip_id,
        &p.canonical_bytes(),
    )
    .unwrap();

    let report = verify_packet(&p, &f.ctx);
    assert_rule_failed(&report, rules::TRUST_FLOOR);
    assert_eq!(report.trust_floor, TrustFloor::AuthorityBound);
    assert_eq!(report.claimed_trust_floor, TrustFloor::CounterpartySigned);
}

#[test]
fn test_action_after_token_expiry_rejected() {
    let f = build_fixture();
    let mut p = f.packet.clone();
    let expiry = p.root_authority.root_token.expires_at.unwrap();
    // Re-sign the action and packet with the legitimate agent key —
    // temporal validity must fail even with valid signatures.
    let kind = p.actions[0].action_kind.clone();
    let description = p.actions[0].description.clone();
    let payload_hash = p.actions[0].payload_hash;
    p.actions[0] = ActionAttestation::create(
        &p.agent.aip_id,
        &f.agent_kp.private_key,
        &p.decision.decision_id,
        kind,
        &description,
        payload_hash,
        expiry + 1,
    )
    .unwrap();
    p.packet_hash = p.compute_hash();
    p.agent_sig = aip_crypto::sign_ed25519(
        &f.agent_kp.private_key,
        &p.agent.aip_id,
        &p.canonical_bytes(),
    )
    .unwrap();

    let report = verify_packet(&p, &f.ctx);
    assert_rule_failed(&report, rules::TEMPORAL_VALIDITY);
}

// ─── Multi-hop chains ───

#[test]
fn test_two_hop_chain_verifies_and_attenuates() {
    let cfo_kp = generate_ed25519_keypair();
    let cfo_id = derive_aip_id(&cfo_kp.public_key, &provenance("cfo2"));
    let (orch_aid, orch_kp) = create_identity(provenance("orch2"), None).unwrap();
    let (mid_aid, mid_kp) = create_identity(provenance("mid2"), None).unwrap();
    let (agent_aid, agent_kp) = create_identity(provenance("agent2"), None).unwrap();

    let root_token = issue_scoped_token(
        &cfo_id,
        &cfo_kp.private_key,
        &orch_aid.id,
        scope_orchestrator(),
        Some(3_600_000),
    )
    .unwrap();
    let hop1 = create_delegation(
        &root_token,
        &orch_kp.private_key,
        &mid_aid.id,
        scope_orchestrator(),
    )
    .unwrap();
    let hop2 = create_sub_delegation(&hop1, &mid_kp.private_key, &agent_aid.id, scope_submitter())
        .unwrap();

    let now = now_ms(); // after token issuance — see TEMPORAL_VALIDITY
    let decision = DecisionRecord {
        decision_id: aip_core::capability::random_jti(),
        action_kind: ScopeAction::Standard(Action::Write),
        summary: "submit batch".into(),
        input_hash: sha256(b"batch"),
        rationale_hash: sha256(b"ok"),
        decided_at: now,
    };
    let action = ActionAttestation::create(
        &agent_aid.id,
        &agent_kp.private_key,
        &decision.decision_id,
        ScopeAction::Standard(Action::Write),
        "submit",
        sha256(b"payload"),
        now + 1,
    )
    .unwrap();

    let packet = EvidencePacketBuilder::new(
        AgentIdentitySummary {
            aip_id: agent_aid.id.clone(),
            public_key: agent_aid.primary_key.clone(),
            provenance: agent_aid.provenance.clone(),
        },
        RootAuthority {
            principal_id: cfo_id.clone(),
            display_role: "CFO".into(),
            root_token,
        },
    )
    .delegation_chain(vec![hop1, hop2])
    .decision(decision)
    .action(action)
    .claimed_trust_floor(TrustFloor::AuthorityBound)
    .build_and_sign(&agent_kp.private_key)
    .unwrap();

    let ctx = VerificationContext::new()
        .trust_issuer(&cfo_id, &cfo_kp.public_key)
        .trust_issuer(&orch_aid.id, &orch_kp.public_key)
        .trust_issuer(&mid_aid.id, &mid_kp.public_key);

    let report = verify_packet(&packet, &ctx);
    assert!(report.valid, "failures: {:?}", report.failures());
    assert_eq!(report.trust_floor, TrustFloor::AuthorityBound);
}

// ─── Accountability graph ───

#[test]
fn test_graph_reconstruction_and_connectivity() {
    let f = build_fixture();
    let report = verify_packet(&f.packet, &f.ctx);
    let graph = AccountabilityGraph::from_packet(&f.packet).with_report(&report);

    assert_eq!(graph.packet_id, f.packet.packet_id_hex());
    assert_eq!(
        graph.derived_trust_floor,
        Some(TrustFloor::CounterpartySigned)
    );

    // Human → Authority → Delegation → Agent → Decision → Action → Receipt
    use aip_protocol::NodeKind::*;
    for kind in [
        Principal,
        AuthorityGrant,
        Delegation,
        Agent,
        Decision,
        Action,
        Receipt,
    ] {
        assert!(
            graph.nodes.iter().any(|n| n.kind == kind),
            "graph missing node kind {kind:?}"
        );
    }
    assert!(
        graph.validate_chain().is_empty(),
        "chain must be fully connected: {:?}",
        graph.validate_chain()
    );

    let dot = graph.to_dot();
    assert!(dot.starts_with("digraph accountability"));
    assert!(dot.contains("CFO"));

    let json = graph.to_json().unwrap();
    assert!(json.contains("\"principal\""));
}
