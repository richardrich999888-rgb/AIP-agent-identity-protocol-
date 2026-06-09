//! Banking design-partner demo — the pilot artifact.
//!
//! Workflow:
//!
//! ```text
//! Human CFO
//!   → scoped root token (orchestrator scope, 1h TTL)
//!     → delegation to payments agent (Write-only, attenuated)
//!       → payment approval decision
//!         → ledger entry (countersigned receipt)
//!           → EvidencePacket
//! ```
//!
//! The demo then:
//! 1. Verifies the honest packet → VALID at COUNTERPARTY_SIGNED floor.
//! 2. Tampers with exactly one field (the payment amount in the decision)
//!    and re-verifies → verification FAILS on a named cryptographic rule.
//!
//! Every check is real cryptography. Exit code is non-zero if the honest
//! packet fails OR the tampered packet passes.

use std::collections::HashMap;

use aip_core::capability::{issue_scoped_token, scope_orchestrator, scope_submitter};
use aip_core::create_identity;
use aip_core::delegation::create_delegation;
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};
use aip_protocol::{
    verify_packet, AccountabilityGraph, ActionAttestation, AgentIdentitySummary, DecisionRecord,
    EvidencePacketBuilder, ReceiptBinding, RootAuthority, TraceBinding, TrustFloor,
    VerificationContext,
};
use aip_types::{Action, ProvenanceTriple, ScopeAction};

fn provenance(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(format!("model:{tag}").as_bytes()),
        environment_commitment: sha256(format!("env:{tag}").as_bytes()),
        toolchain_commitment: sha256(format!("toolchain:{tag}").as_bytes()),
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn header(title: &str) {
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  {title}");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}

fn main() {
    println!("AIP Banking Demo — \"Prove what the agent did and who authorized it.\"");

    // ── Step 1: The human principal ───────────────────────────────────────
    header("1. Human authority: CFO");
    let cfo_kp = generate_ed25519_keypair();
    let cfo_id = derive_aip_id(&cfo_kp.public_key, &provenance("human:cfo"));
    println!("  CFO identity (AIP-ID): {cfo_id}");

    // ── Step 2: CFO issues a scoped root token to the treasury system ─────
    header("2. CFO issues a scoped authority token (1h TTL, Admin denied)");
    let (treasury_aid, treasury_kp) = create_identity(provenance("svc:treasury"), None).unwrap();
    let root_token = issue_scoped_token(
        &cfo_id,
        &cfo_kp.private_key,
        &treasury_aid.id,
        scope_orchestrator(),
        Some(3_600_000),
    )
    .unwrap();
    println!("  Holder (treasury orchestrator): {}", treasury_aid.id);
    println!("  Root token JTI: {}", hex::encode(root_token.jti));
    println!("  Scope: Read, Write, Execute, Delegate — Admin DENIED");

    // ── Step 3: Treasury delegates Write-only to the payments agent ───────
    header("3. Treasury delegates ATTENUATED scope to the payments agent");
    let (agent_aid, agent_kp) = create_identity(provenance("ai:payments-agent-v3"), None).unwrap();
    let delegation = create_delegation(
        &root_token,
        &treasury_kp.private_key,
        &agent_aid.id,
        scope_submitter(), // Write only — cannot read, delete, admin, or re-delegate
    )
    .unwrap();
    println!("  Payments agent (AIP-ID): {}", agent_aid.id);
    println!("  Delegation JTI: {} (depth {})", hex::encode(delegation.jti), delegation.depth);
    println!("  Attenuated scope: Write ONLY (lattice MEET of parent ∩ requested)");

    // ── Step 4: The agent decides and acts ────────────────────────────────
    header("4. Agent approves a payment and posts the ledger entry");
    let now = now_ms();
    let invoice = "INV-2026-0142";
    let amount = "$48,200.00";
    let decision = DecisionRecord {
        decision_id: aip_core::capability::random_jti(),
        action_kind: ScopeAction::Standard(Action::Write),
        summary: format!("Approve vendor payment {invoice} for {amount} to Acme GmbH"),
        input_hash: sha256(format!("{invoice}|Acme GmbH|{amount}|3-way-match").as_bytes()),
        rationale_hash: sha256(b"PO match: OK; goods receipt: OK; within delegated limit"),
        decided_at: now,
    };
    let action_payload = format!("POST /v1/ledger/payments {{\"invoice\":\"{invoice}\",\"amount\":\"{amount}\"}}");
    let action = ActionAttestation::create(
        &agent_aid.id,
        &agent_kp.private_key,
        &decision.decision_id,
        ScopeAction::Standard(Action::Write),
        &action_payload,
        sha256(action_payload.as_bytes()),
        now + 12,
    )
    .unwrap();
    println!("  Decision: {}", decision.summary);
    println!("  Action:   {action_payload}");

    // ── Step 5: The ledger countersigns a receipt ─────────────────────────
    header("5. Core ledger countersigns the receipt (bilateral evidence)");
    let ledger_kp = generate_ed25519_keypair();
    let ledger_id = "ledger.example-bank.com";
    let receipt_content = format!("LEDGER-90211|{invoice}|{amount}|POSTED");
    let mut receipt = ReceiptBinding {
        receipt_system: ledger_id.to_string(),
        receipt_id: "LEDGER-90211".to_string(),
        receipt_hash: sha256(receipt_content.as_bytes()),
        counterparty_id: None,
        counterparty_sig: None,
    };
    receipt
        .countersign(&decision.decision_id, ledger_id, &ledger_kp.private_key)
        .unwrap();
    println!("  Receipt {} countersigned by {}", receipt.receipt_id, ledger_id);

    let trace_export = b"otel: spans for payment approval run".to_vec();
    let trace = TraceBinding {
        trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".into(),
        trace_hash: sha256(&trace_export),
    };

    // ── Step 6: Seal the EvidencePacket ───────────────────────────────────
    header("6. Agent seals the EvidencePacket");
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
    .delegation_chain(vec![delegation])
    .decision(decision)
    .action(action)
    .trace(trace)
    .receipt(receipt)
    .claimed_trust_floor(TrustFloor::CounterpartySigned)
    .build_and_sign(&agent_kp.private_key)
    .unwrap();
    println!("  Packet ID:   {}", packet.packet_id_hex());
    println!("  Packet hash: {}", hex::encode(packet.packet_hash));

    // ── Step 7: Verify the honest packet ──────────────────────────────────
    header("7. VERIFY — honest packet");
    let ctx = VerificationContext {
        issuer_public_keys: HashMap::from([
            (cfo_id.clone(), cfo_kp.public_key.clone()),
            (treasury_aid.id.clone(), treasury_kp.public_key.clone()),
        ]),
        counterparty_public_keys: HashMap::from([(
            ledger_id.to_string(),
            ledger_kp.public_key.clone(),
        )]),
        revoked_jtis: Default::default(),
        trace_data: Some(trace_export),
        receipt_data: Some(receipt_content.into_bytes()),
    };
    let report = verify_packet(&packet, &ctx);
    for check in &report.checks {
        println!("  [{}] {:<20} {}", if check.pass { "PASS" } else { "FAIL" }, check.rule, check.detail);
    }
    println!("\n  valid: {}   trust_floor: {:?}   tampered: {}", report.valid, report.trust_floor, report.tampered);

    let graph = AccountabilityGraph::from_packet(&packet).with_report(&report);
    println!("\n  Accountability chain ({} nodes, fully connected: {}):", graph.nodes.len(), graph.validate_chain().is_empty());
    for node in &graph.nodes {
        println!("    {:?}: {}", node.kind, node.label);
    }

    // ── Step 8: Tamper with ONE field and re-verify ───────────────────────
    header("8. TAMPER — change the payment amount in the sealed packet");
    let mut tampered = packet.clone();
    tampered.decision.summary =
        format!("Approve vendor payment {invoice} for $4,820,000.00 to Acme GmbH");
    println!("  Forged decision: {}", tampered.decision.summary);
    let tampered_report = verify_packet(&tampered, &ctx);
    for check in tampered_report.failures() {
        println!("  [FAIL] {:<20} {}", check.rule, check.detail);
    }
    println!("\n  valid: {}   tampered: {}", tampered_report.valid, tampered_report.tampered);

    // A smarter attacker also fixes the hash — the agent signature catches it.
    header("9. TAMPER harder — attacker recomputes packet_hash after editing");
    let mut tampered2 = tampered.clone();
    tampered2.packet_hash = tampered2.compute_hash();
    let report2 = verify_packet(&tampered2, &ctx);
    for check in report2.failures() {
        println!("  [FAIL] {:<20} {}", check.rule, check.detail);
    }
    println!("\n  valid: {}   tampered: {}", report2.valid, report2.tampered);

    // ── Verdict ───────────────────────────────────────────────────────────
    header("VERDICT");
    let honest_ok = report.valid && report.trust_floor == TrustFloor::CounterpartySigned;
    let tamper_caught = !tampered_report.valid && tampered_report.tampered;
    let tamper2_caught = !report2.valid && report2.tampered;
    println!("  Honest packet verifies at COUNTERPARTY_SIGNED ... {}", if honest_ok { "YES" } else { "NO" });
    println!("  One-field tamper detected ..................... {}", if tamper_caught { "YES" } else { "NO" });
    println!("  Hash-fixing attacker detected ................. {}", if tamper2_caught { "YES" } else { "NO" });

    if honest_ok && tamper_caught && tamper2_caught {
        println!("\n  EvidencePacket: cryptographic accountability demonstrated end-to-end.");
    } else {
        eprintln!("\n  DEMO FAILED — see failures above.");
        std::process::exit(1);
    }
}
