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
use aip_types::{
    Action, CapabilityScope, ExecutionBinding, KeyPair, ProcessInstance, ProvenanceTriple,
    ScopeAction, EXECUTION_BINDING_VERSION,
};

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

/// A deterministic, synthetic execution binding for `agent_id`. Fixtures do
/// not read procfs so they stay platform-independent; the live collector is
/// covered by `aip_core::execution_binding` unit tests.
fn test_binding(agent_id: &str) -> ExecutionBinding {
    ExecutionBinding {
        version: EXECUTION_BINDING_VERSION,
        agent_id: agent_id.to_string(),
        process: ProcessInstance {
            pid: 4242,
            pid_start_time_ticks: 433_843,
            boot_id: [0x0c; 16],
        },
        exe_content_sha256: sha256(b"payments-agent binary v1"),
        exe_path: "/opt/agent/bin/payments-agent".into(),
        bound_at_ms: now_ms(),
    }
}

/// Build a complete, honest, countersigned packet plus the matching context.
fn build_fixture() -> Fixture {
    build_fixture_opts(Some(3_600_000), true)
}

/// Same as [`build_fixture`] but with a caller-chosen root-token lifetime
/// (`None` = the principal issued an unbounded token).
fn build_fixture_with_root_expiry(root_expires_in_ms: Option<u64>) -> Fixture {
    build_fixture_opts(root_expires_in_ms, true)
}

fn build_fixture_opts(root_expires_in_ms: Option<u64>, with_binding: bool) -> Fixture {
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
        root_expires_in_ms,
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

    let mut builder = EvidencePacketBuilder::new(agent_summary, root_authority)
        .delegation_chain(vec![hop1])
        .decision(decision)
        .action(action)
        .trace(trace)
        .receipt(receipt)
        .claimed_trust_floor(TrustFloor::CounterpartySigned);
    if with_binding {
        builder = builder.execution_binding(test_binding(&agent_aid.id));
    }
    let packet = builder.build_and_sign(&agent_kp.private_key).unwrap();

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
        verification_time_ms: None,
        future_tolerance_ms: 0,
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
        if !check.evaluated {
            // The only rule a verifier can decline to run is the one whose
            // input it did not supply. Naming it here keeps the exemption
            // from becoming a blanket skip (AUDIT P0-1).
            assert_eq!(
                check.rule,
                rules::VERIFICATION_TIME_BOUND,
                "rule {} was not evaluated: {}",
                check.rule,
                check.detail
            );
            continue;
        }
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

// ─── Temporal semantics (R10): explicit, offline, inclusive expiry ───
//
// R10 compares the packet's own `decided_at` / `performed_at` against the
// signed `issued_at` / `expires_at` of every token in the chain. It never
// consults the verifier's clock. A timestamp exactly equal to `expires_at`
// is inside the window; `expires_at + 1` is outside.

/// Replace the packet's single action with one performed at `performed_at`
/// and re-seal with the legitimate agent key.
fn replace_action_at(p: &mut EvidencePacket, f: &Fixture, performed_at: u64) {
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
        performed_at,
    )
    .unwrap();
    reseal(p, f);
}

#[test]
fn test_action_at_exact_expiry_boundary_accepted() {
    let f = build_fixture();
    let mut p = f.packet.clone();
    let expiry = p.root_authority.root_token.expires_at.unwrap();
    replace_action_at(&mut p, &f, expiry);
    let report = verify_packet(&p, &f.ctx);
    assert!(
        report.rule(rules::TEMPORAL_VALIDITY).unwrap().pass,
        "{:?}",
        report
    );
    assert!(report.valid);
}

#[test]
fn test_action_one_past_expiry_rejected() {
    let f = build_fixture();
    let mut p = f.packet.clone();
    let expiry = p.root_authority.root_token.expires_at.unwrap();
    replace_action_at(&mut p, &f, expiry + 1);
    let report = verify_packet(&p, &f.ctx);
    assert_rule_failed(&report, rules::TEMPORAL_VALIDITY);
}

#[test]
fn test_decision_after_expiry_rejected() {
    let f = build_fixture();
    let mut p = f.packet.clone();
    let expiry = p.root_authority.root_token.expires_at.unwrap();
    p.decision.decided_at = expiry + 1;
    replace_action_at(&mut p, &f, expiry + 2);
    let report = verify_packet(&p, &f.ctx);
    assert_rule_failed(&report, rules::TEMPORAL_VALIDITY);
}

#[test]
fn test_unbounded_root_token_accepts_far_future_action() {
    let f = build_fixture_with_root_expiry(None);
    assert!(f.packet.root_authority.root_token.expires_at.is_none());
    assert!(f.packet.delegation_chain[0].expires_at.is_none());
    let mut p = f.packet.clone();
    let ten_years = 10 * 365 * 24 * 3_600_000u64;
    let far_future = p.decision.decided_at + ten_years;
    replace_action_at(&mut p, &f, far_future);
    let report = verify_packet(&p, &f.ctx);
    assert!(report.valid, "{:?}", report);
}

#[test]
fn test_delegation_hop_expiry_bounds_action() {
    // The hop inherits the root expiry; an action past it fails R10 and the
    // detail names the hop, proving hop expiry is evaluated, not just root.
    let f = build_fixture();
    let mut p = f.packet.clone();
    let hop_exp = p.delegation_chain[0].expires_at.unwrap();
    replace_action_at(&mut p, &f, hop_exp + 1);
    let report = verify_packet(&p, &f.ctx);
    assert_rule_failed(&report, rules::TEMPORAL_VALIDITY);
    assert!(report
        .rule(rules::TEMPORAL_VALIDITY)
        .unwrap()
        .detail
        .contains("delegation hop 0"));
}

// ─── Execution binding (Ghost Stage 1) ───
//
/// A named in-place mutation of a binding field.
type BindingMutation = (&'static str, Box<dyn Fn(&mut ExecutionBinding)>);
//
// The binding is agent-signed content: any post-sealing mutation or
// transplant is caught by R3/R4. What the packet CANNOT prove is that the
// binding is true — it is a self-report until an observer attests it. The
// tests below pin both halves of that statement.

#[test]
fn test_execution_binding_rule_passes_but_is_flagged_self_reported() {
    let f = build_fixture();
    let report = verify_packet(&f.packet, &f.ctx);
    assert!(report.valid);
    let r = report.rule(rules::EXECUTION_BINDING).unwrap();
    assert!(r.pass);
    assert!(r.detail.contains("self-reported"), "{}", r.detail);
    assert!(
        r.detail.contains("NOT independently observed"),
        "{}",
        r.detail
    );
    // A binding never raises the trust floor.
    assert_eq!(report.trust_floor, TrustFloor::CounterpartySigned);
}

#[test]
fn test_packet_without_binding_verifies_and_reports_absence() {
    let f = build_fixture_opts(Some(3_600_000), false);
    assert!(f.packet.execution_binding.is_none());
    let report = verify_packet(&f.packet, &f.ctx);
    assert!(report.valid, "{:?}", report.failures());
    let r = report.rule(rules::EXECUTION_BINDING).unwrap();
    assert!(r.pass);
    assert!(
        r.detail.contains("no execution binding present"),
        "{}",
        r.detail
    );
}

/// Test F — every security-sensitive binding field, mutated after sealing,
/// is caught by the canonical hash.
#[test]
fn test_binding_field_mutations_detected_by_hash() {
    let f = build_fixture();
    let mutations: Vec<BindingMutation> = vec![
        ("pid", Box::new(|b| b.process.pid += 1)),
        (
            "start_ticks",
            Box::new(|b| b.process.pid_start_time_ticks += 1),
        ),
        ("boot_id", Box::new(|b| b.process.boot_id[0] ^= 0xFF)),
        ("exe_hash", Box::new(|b| b.exe_content_sha256[31] ^= 0x01)),
        ("exe_path", Box::new(|b| b.exe_path.push('x'))),
        ("agent_id", Box::new(|b| b.agent_id.push('x'))),
        ("bound_at", Box::new(|b| b.bound_at_ms += 1)),
        ("version", Box::new(|b| b.version += 1)),
    ];
    for (name, mutate) in mutations {
        let mut p = f.packet.clone();
        mutate(p.execution_binding.as_mut().unwrap());
        let report = verify_packet(&p, &f.ctx);
        assert!(
            !report.rule(rules::CANONICAL_HASH).unwrap().pass,
            "mutating {name} was not detected"
        );
        assert!(report.tampered, "mutating {name} must be tamper evidence");
    }
}

/// Test G — transplanting a different binding into a sealed packet is caught.
#[test]
fn test_binding_transplant_detected_by_hash_and_signature() {
    let f = build_fixture();
    let mut p = f.packet.clone();
    let mut other = test_binding(&p.agent.aip_id);
    other.process.pid_start_time_ticks += 10_000; // a different instance
    p.execution_binding = Some(other);
    let report = verify_packet(&p, &f.ctx);
    assert_rule_failed(&report, rules::CANONICAL_HASH);

    // Recomputing the hash without the key still fails on the signature.
    p.packet_hash = p.compute_hash();
    let report = verify_packet(&p, &f.ctx);
    assert_rule_failed(&report, rules::AGENT_SIGNATURE);
    assert!(report.tampered);
}

/// Adding a binding to a packet sealed without one (or removing one) is a
/// canonical change — absence and presence are never confusable.
#[test]
fn test_binding_presence_is_part_of_canonical_bytes() {
    let f = build_fixture();
    let mut p = f.packet.clone();
    p.execution_binding = None;
    let report = verify_packet(&p, &f.ctx);
    assert_rule_failed(&report, rules::CANONICAL_HASH);

    let g = build_fixture_opts(Some(3_600_000), false);
    let mut q = g.packet.clone();
    q.execution_binding = Some(test_binding(&q.agent.aip_id));
    let report = verify_packet(&q, &g.ctx);
    assert_rule_failed(&report, rules::CANONICAL_HASH);
}

/// JSON produced before the field existed (no `execution_binding` key) still
/// parses — as `None` — and is then correctly reported as hash-mismatched if
/// it was sealed with a binding.
#[test]
fn test_json_without_binding_key_parses_as_none() {
    let f = build_fixture();
    let mut v: serde_json::Value = serde_json::from_str(&f.packet.to_json().unwrap()).unwrap();
    v.as_object_mut().unwrap().remove("execution_binding");
    let restored = EvidencePacket::from_json(&v.to_string()).unwrap();
    assert!(restored.execution_binding.is_none());
    let report = verify_packet(&restored, &f.ctx);
    assert_rule_failed(&report, rules::CANONICAL_HASH);
}

/// R15 consistency: a binding for a different agent, even when the agent
/// re-seals the packet, is rejected.
#[test]
fn test_binding_for_other_agent_rejected_even_when_resealed() {
    let f = build_fixture();
    let mut p = f.packet.clone();
    p.execution_binding = Some(test_binding("aip1someoneElse"));
    reseal(&mut p, &f);
    let report = verify_packet(&p, &f.ctx);
    assert_rule_failed(&report, rules::EXECUTION_BINDING);
    assert!(
        !report.tampered,
        "producer inconsistency is not post-signing modification"
    );
    // Hash and signature themselves are fine — it was legitimately re-sealed.
    assert!(report.rule(rules::CANONICAL_HASH).unwrap().pass);
    assert!(report.rule(rules::AGENT_SIGNATURE).unwrap().pass);
}

/// R15 consistency: degenerate identity fields are rejected — a binding may
/// be absent, but it may not be present and empty.
#[test]
fn test_degenerate_binding_fields_rejected() {
    let f = build_fixture();
    let cases: Vec<BindingMutation> = vec![
        ("pid 0", Box::new(|b| b.process.pid = 0)),
        ("start 0", Box::new(|b| b.process.pid_start_time_ticks = 0)),
        ("zero boot", Box::new(|b| b.process.boot_id = [0u8; 16])),
        ("zero exe", Box::new(|b| b.exe_content_sha256 = [0u8; 32])),
        ("bad version", Box::new(|b| b.version = 0)),
    ];
    for (name, mutate) in cases {
        let mut p = f.packet.clone();
        mutate(p.execution_binding.as_mut().unwrap());
        reseal(&mut p, &f);
        let report = verify_packet(&p, &f.ctx);
        assert!(
            !report.rule(rules::EXECUTION_BINDING).unwrap().pass,
            "{name} was accepted"
        );
        assert!(!report.valid);
    }
}

/// Test H / self-report limit (documented, not a defect of this stage):
/// the agent, holding its own key, CAN re-seal a packet with a different but
/// well-formed binding for itself. The packet verifies, because the packet
/// only proves what the agent signed. Catching a false binding requires an
/// independent observer (Stage 3) — this test pins the boundary so a later
/// stage cannot claim the packet alone already proves it.
#[test]
fn test_resealed_self_binding_swap_verifies_documenting_self_report_limit() {
    let f = build_fixture();
    let mut p = f.packet.clone();
    let mut other = test_binding(&p.agent.aip_id);
    other.process.pid = 99_999;
    other.process.pid_start_time_ticks = 1;
    other.exe_content_sha256 = sha256(b"a completely different binary");
    p.execution_binding = Some(other);
    reseal(&mut p, &f);
    let report = verify_packet(&p, &f.ctx);
    assert!(report.valid, "{:?}", report.failures());
    let r = report.rule(rules::EXECUTION_BINDING).unwrap();
    assert!(r.detail.contains("NOT independently observed"));
}

// ─── Characterization of the pre-Stage-2 decision semantics (Skill 5) ───
//
// `verify_packet` answers "is this packet consistent with the anchors I was
// given?" — correctly. What it cannot do, and what this test pins, is
// require that anyone other than the agent decided the action was permitted.
// With the agent's own key named as the trusted issuer, a fully self-issued
// packet verifies at AUTHORITY_BOUND. That closed loop is what Stage 2's
// decision point exists to break; it is NOT a defect in verify_packet, and
// this test must keep passing so the boundary stays visible.

#[test]
fn weakness_packet_verifies_when_agent_is_its_own_root_issuer() {
    let (agent_aid, agent_kp) =
        create_identity(provenance("self-authorizing-agent"), None).unwrap();
    // The agent issues ITSELF an admin token.
    let root_token = issue_scoped_token(
        &agent_aid.id,
        &agent_kp.private_key,
        &agent_aid.id,
        aip_core::capability::scope_admin(),
        Some(3_600_000),
    )
    .unwrap();
    let now = now_ms();
    let decision = DecisionRecord {
        decision_id: aip_core::capability::random_jti(),
        action_kind: ScopeAction::Standard(Action::Admin),
        summary: "grant myself everything".into(),
        input_hash: sha256(b"x"),
        rationale_hash: sha256(b"because"),
        decided_at: now,
    };
    let action = ActionAttestation::create(
        &agent_aid.id,
        &agent_kp.private_key,
        &decision.decision_id,
        ScopeAction::Standard(Action::Admin),
        "DELETE /ledger",
        sha256(b"{}"),
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
            principal_id: agent_aid.id.clone(),
            display_role: "self".into(),
            root_token,
        },
    )
    .decision(decision)
    .action(action)
    .execution_binding(test_binding(&agent_aid.id))
    .claimed_trust_floor(TrustFloor::AuthorityBound)
    .build_and_sign(&agent_kp.private_key)
    .unwrap();

    // The caller names the agent's own key as the trusted issuer.
    let ctx = VerificationContext::new().trust_issuer(&agent_aid.id, &agent_kp.public_key);
    let report = verify_packet(&packet, &ctx);
    assert!(
        report.valid,
        "verify_packet now refuses self-issued authority on its own — update DECISION_POINT.md"
    );
    assert_eq!(report.trust_floor, TrustFloor::AuthorityBound);
    assert!(report.authority_chain_verified);
    // Nothing in the report can say whether an independent party authorized this.
    assert!(report.checks.iter().all(|c| c.rule != "EXPECTED_EXECUTION"));
}

// ─── Wire versioning ───

#[test]
fn test_version_1_packet_rejected_explicitly() {
    let f = build_fixture();
    let mut p = f.packet.clone();
    p.version = 1;
    reseal(&mut p, &f);
    let report = verify_packet(&p, &f.ctx);
    assert_rule_failed(&report, rules::STRUCTURE);
    let detail = &report.rule(rules::STRUCTURE).unwrap().detail;
    assert!(detail.contains("unsupported version 1"), "{detail}");
}

// ─── Adversarial: authority expiry extension through the real packet path (I6) ───
//
// The agent legitimately holds its own packet key.  It rewrites ONLY the
// expiry of an authority token it did NOT issue, recomputes packet_hash and
// re-signs the packet (both of which the current implementation permits an
// agent to do), and presents the packet.  The issuer signatures on the token
// and the hop are byte-for-byte the originals.  The verifier must reject via
// the rule that checks that issuer signature — not merely via the packet hash.

/// Recompute packet_hash and agent_sig with the legitimate agent key.
fn reseal(p: &mut EvidencePacket, f: &Fixture) {
    p.packet_hash = p.compute_hash();
    p.agent_sig = aip_crypto::sign_ed25519(
        &f.agent_kp.private_key,
        &p.agent.aip_id,
        &p.canonical_bytes(),
    )
    .unwrap();
}

#[test]
fn test_root_token_expiry_extension_resealed_packet_rejected() {
    let f = build_fixture();
    let mut p = f.packet.clone();
    let original_sig = p.root_authority.root_token.issuer_sig.clone();

    p.root_authority.root_token.expires_at = Some(u64::MAX);
    reseal(&mut p, &f);

    // Sanity: the issuer signature was not touched by the attacker.
    assert_eq!(p.root_authority.root_token.issuer_sig, original_sig);

    let report = verify_packet(&p, &f.ctx);
    assert_rule_failed(&report, rules::ROOT_TOKEN_SIGNATURE);
}

#[test]
fn test_root_token_expiry_removal_resealed_packet_rejected() {
    let f = build_fixture();
    let mut p = f.packet.clone();

    p.root_authority.root_token.expires_at = None;
    reseal(&mut p, &f);

    let report = verify_packet(&p, &f.ctx);
    assert_rule_failed(&report, rules::ROOT_TOKEN_SIGNATURE);
}

#[test]
fn test_delegation_hop_expiry_extension_resealed_packet_rejected() {
    let f = build_fixture();
    let mut p = f.packet.clone();
    let original_sig = p.delegation_chain[0].issuer_sig.clone();

    p.delegation_chain[0].expires_at = Some(u64::MAX);
    reseal(&mut p, &f);

    assert_eq!(p.delegation_chain[0].issuer_sig, original_sig);

    let report = verify_packet(&p, &f.ctx);
    assert_rule_failed(&report, rules::DELEGATION_CHAIN);
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

// ═══ AUDIT P0-1 — the verifier's trusted verification-time bound ═══
//
// Every temporal check above compares values that come from *inside* the
// packet: `decided_at` and `performed_at` against windows the issuer chose.
// The single clock read feeds the report's `verified_at` field and no rule.
// So a packet dated arbitrarily in the future verified, provided its own
// tokens said it was fine — and a holder of a legitimately issued
// long-lived token can mint exactly that.
//
// The fix is a bound the *verifier* supplies, with two properties that
// matter equally: when a verification time is given, nothing in the packet
// may be dated after it beyond a declared tolerance; when none is given,
// the rule is recorded as NOT EVALUATED rather than as a pass, so a
// verifier that did not check cannot present a report that looks as if it
// had.
//
// What the bound is deliberately not: "the tokens must still be valid now".
// A historical packet stays verifiable after its authority expires — that
// is what offline and delayed verification are for, and whether the
// authority was valid *when the decision was made* is R10's question.

const P01_HOUR: u64 = 3_600_000;
const P01_YEAR: u64 = 365 * 24 * P01_HOUR;

/// A packet whose decision and action are `ahead` in the future, under a
/// root token whose window covers them.
fn future_dated_packet(ahead: u64) -> Fixture {
    let mut f = build_fixture_with_root_expiry(Some(2 * P01_YEAR));
    let base = f.packet.decision.decided_at;
    f.packet.decision.decided_at = base + ahead;
    let p = &mut f.packet;
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
        base + ahead + 1,
    )
    .unwrap();
    let packet = &mut f.packet;
    packet.packet_hash = packet.compute_hash();
    packet.agent_sig = aip_crypto::sign_ed25519(
        &f.agent_kp.private_key,
        &packet.agent.aip_id,
        &packet.canonical_bytes(),
    )
    .unwrap();
    f
}

#[test]
fn p0_1_a_future_dated_packet_is_refused_against_a_supplied_bound() {
    let f = future_dated_packet(P01_YEAR);
    let now = f.packet.decision.decided_at - P01_YEAR;

    // Unbounded, this is the finding: it verifies.
    let report = verify_packet(&f.packet, &f.ctx);
    assert!(
        report.valid,
        "the finding: with no verifier clock a future-dated packet passes"
    );
    assert!(!report.verification_time_checked);

    // Bounded, it is refused by a named rule.
    let report = verify_packet(&f.packet, &f.ctx.clone().at_time(now));
    assert!(!report.valid, "a future-dated packet must not verify");
    assert!(report.verification_time_checked);
    assert_rule_failed(&report, rules::VERIFICATION_TIME_BOUND);
}

#[test]
fn p0_1_an_action_after_the_bound_is_refused_even_when_the_decision_is_not() {
    let f = build_fixture();
    let now = f.packet.decision.decided_at;
    let mut p = f.packet.clone();
    replace_action_at(&mut p, &f, now + P01_HOUR);
    let report = verify_packet(&p, &f.ctx.clone().at_time(now + 60_000));
    assert!(!report.valid, "an action in the future must not verify");
    assert_rule_failed(&report, rules::VERIFICATION_TIME_BOUND);
}

#[test]
fn p0_1_authority_issued_after_the_bound_is_refused() {
    let f = build_fixture();
    let before_issue = f.packet.root_authority.root_token.issued_at - 1;
    let report = verify_packet(&f.packet, &f.ctx.clone().at_time(before_issue));
    assert!(
        !report.valid,
        "authority issued after the verifier's own time must not verify"
    );
    assert_rule_failed(&report, rules::VERIFICATION_TIME_BOUND);
}

#[test]
fn p0_1_without_a_bound_the_rule_is_not_evaluated_rather_than_passed() {
    let f = build_fixture();
    let report = verify_packet(&f.packet, &f.ctx);
    let r = report.rule(rules::VERIFICATION_TIME_BOUND).unwrap();
    assert!(
        !r.evaluated,
        "a verifier that supplied no time did not check the bound"
    );
    assert!(!report.verification_time_checked);
    assert_eq!(report.verification_time_ms, None);
    assert!(
        r.detail.to_lowercase().contains("no verification time"),
        "the report must say why: {}",
        r.detail
    );
    // Still valid — an unevaluated rule is not a failure — but a consumer
    // can tell the difference, which is the whole point.
    assert!(report.valid);

    let at = f.packet.decision.decided_at + 5;
    let report = verify_packet(&f.packet, &f.ctx.clone().at_time(at));
    let r = report.rule(rules::VERIFICATION_TIME_BOUND).unwrap();
    assert!(r.evaluated && r.pass);
    assert!(report.verification_time_checked);
    assert_eq!(report.verification_time_ms, Some(at));
}

#[test]
fn p0_1_a_historical_packet_stays_verifiable_after_its_authority_expires() {
    // One hour of authority; the verifier looks a year later. The decision
    // and action happened inside the window, so the packet remains a valid
    // record — offline and delayed verification depend on this.
    let f = build_fixture_with_root_expiry(Some(P01_HOUR));
    let long_after = f.packet.decision.decided_at + P01_YEAR;
    let report = verify_packet(&f.packet, &f.ctx.clone().at_time(long_after));
    assert!(
        report.valid,
        "a historical packet must stay verifiable after its authority expires: {report:#?}"
    );
    assert!(report.rule(rules::VERIFICATION_TIME_BOUND).unwrap().pass);
    assert!(report.rule(rules::TEMPORAL_VALIDITY).unwrap().pass);
}

#[test]
fn p0_1_a_declared_tolerance_absorbs_skew_and_nothing_more() {
    let f = build_fixture();
    let now = f.packet.decision.decided_at;
    // The verifier's clock is a second behind the packet's action.
    let behind = now - 1_000;
    assert!(!verify_packet(&f.packet, &f.ctx.clone().at_time(behind)).valid);
    assert!(
        verify_packet(
            &f.packet,
            &f.ctx.clone().at_time(behind).with_future_tolerance(10_000)
        )
        .valid,
        "a declared tolerance absorbs clock skew"
    );

    // A tolerance is a bound, not a licence.
    let g = future_dated_packet(P01_YEAR);
    let base = g.packet.decision.decided_at - P01_YEAR;
    assert!(
        !verify_packet(
            &g.packet,
            &g.ctx.clone().at_time(base).with_future_tolerance(10_000)
        )
        .valid
    );
}

#[test]
fn p0_1_every_existing_rule_survives_the_new_one() {
    let f = build_fixture();
    let report = verify_packet(
        &f.packet,
        &f.ctx.clone().at_time(f.packet.decision.decided_at + 5),
    );
    for name in [
        rules::STRUCTURE,
        rules::AGENT_ID_BINDING,
        rules::CANONICAL_HASH,
        rules::AGENT_SIGNATURE,
        rules::ROOT_TOKEN_SIGNATURE,
        rules::DELEGATION_CHAIN,
        rules::AUTHORITY_CHAIN,
        rules::SCOPE_AUTHORITY,
        rules::REVOCATION,
        rules::TEMPORAL_VALIDITY,
        rules::ACTION_ATTESTATIONS,
        rules::TRACE_BINDING,
        rules::RECEIPT_BINDING,
        rules::TRUST_FLOOR,
        rules::EXECUTION_BINDING,
        rules::VERIFICATION_TIME_BOUND,
    ] {
        assert!(
            report.checks.iter().any(|c| c.rule == name),
            "rule {name} missing from the report"
        );
    }
    assert!(report.valid);
}
