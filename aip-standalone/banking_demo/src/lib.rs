use std::collections::HashMap;

use aip_core::capability::{issue_scoped_token, scope_orchestrator, scope_submitter};
use aip_core::create_identity;
use aip_core::delegation::create_delegation;
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256, sign_ed25519};
use aip_protocol::{
    verify_packet, ActionAttestation, AgentIdentitySummary, DecisionRecord, EvidencePacket,
    EvidencePacketBuilder, ReceiptBinding, RootAuthority, TraceBinding, TrustFloor,
    VerificationContext, VerificationReport,
};
use aip_types::{Action, ProvenanceTriple, ScopeAction};

pub struct BankingEvidence {
    pub packet: EvidencePacket,
    pub context: VerificationContext,
    // Kept private: used only to generate controlled, correctly signed
    // replay fixtures. Never exposed through the HTTP API.
    agent_private_key: Vec<u8>,
}

impl BankingEvidence {
    /// Generate a distinct, correctly signed packet reusing the original
    /// decision ID. This is a controlled fixture for testing AIP replay
    /// detection, not a real second banking transaction.
    pub fn generate_replay_packet(&self) -> Result<EvidencePacket, String> {
        let original = &self.packet;
        let payload =
            "POST /v1/ledger/payments {\"invoice\":\"INV-REPLAY-0001\",\"amount\":\"$999,999.00\"}";

        let action = ActionAttestation::create(
            &original.agent.aip_id,
            &self.agent_private_key,
            &original.decision.decision_id,
            original.decision.action_kind.clone(),
            payload,
            sha256(payload.as_bytes()),
            now_ms() + 20,
        )
        .map_err(|e| format!("Replay action signing: {e:?}"))?;

        let mut builder =
            EvidencePacketBuilder::new(original.agent.clone(), original.root_authority.clone())
                .delegation_chain(original.delegation_chain.clone())
                .decision(original.decision.clone())
                .action(action)
                .claimed_trust_floor(original.claimed_trust_floor.clone());

        if let Some(trace) = original.trace_binding.clone() {
            builder = builder.trace(trace);
        }

        if let Some(receipt) = original.receipt_binding.clone() {
            builder = builder.receipt(receipt);
        }

        builder
            .build_and_sign(&self.agent_private_key)
            .map_err(|e| format!("Replay packet signing: {e:?}"))
    }

    /// Create a validly signed packet with a new decision ID but the
    /// original action ID, for controlled replay-scope testing.
    pub fn generate_action_replay_packet(&self) -> Result<EvidencePacket, String> {
        let original = &self.packet;

        let mut decision = original.decision.clone();
        decision.decision_id = aip_core::capability::random_jti();
        decision.summary = "Controlled action replay fixture".into();
        decision.input_hash = sha256(b"action-replay-fixture-new-input");
        decision.rationale_hash = sha256(b"action-replay-fixture-new-rationale");
        decision.decided_at = now_ms();

        let mut action = original
            .actions
            .first()
            .ok_or_else(|| "Original packet has no action".to_string())?
            .clone();

        // Preserve action_id deliberately; change and re-sign its content.
        action.description = "Controlled action replay fixture".into();
        action.payload_hash = sha256(b"action-replay-fixture-payload-v2");
        action.performed_at = now_ms();

        let action_bytes = action.canonical_bytes(&decision.decision_id);
        action.agent_sig = sign_ed25519(
            &self.agent_private_key,
            &original.agent.aip_id,
            &action_bytes,
        )
        .map_err(|e| format!("Action replay signature: {e:?}"))?;

        let mut builder =
            EvidencePacketBuilder::new(original.agent.clone(), original.root_authority.clone())
                .delegation_chain(original.delegation_chain.clone())
                .decision(decision)
                .action(action)
                .claimed_trust_floor(TrustFloor::AgentSigned);

        if let Some(trace) = original.trace_binding.clone() {
            builder = builder.trace(trace);
        }

        builder
            .build_and_sign(&self.agent_private_key)
            .map_err(|e| format!("Action replay packet signing: {e:?}"))
    }
}

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

/// Generate a real, cryptographically signed banking EvidencePacket.
pub fn generate_banking_evidence() -> Result<BankingEvidence, String> {
    let cfo_kp = generate_ed25519_keypair();
    let cfo_id = derive_aip_id(&cfo_kp.public_key, &provenance("human:cfo"));

    let (treasury_aid, treasury_kp) = create_identity(provenance("svc:treasury"), None)
        .map_err(|e| format!("Treasury identity: {e:?}"))?;

    let root_token = issue_scoped_token(
        &cfo_id,
        &cfo_kp.private_key,
        &treasury_aid.id,
        scope_orchestrator(),
        Some(3_600_000),
    )
    .map_err(|e| format!("Root token: {e:?}"))?;

    let (agent_aid, agent_kp) = create_identity(provenance("ai:payments-agent-v3"), None)
        .map_err(|e| format!("Agent identity: {e:?}"))?;

    let delegation = create_delegation(
        &root_token,
        &treasury_kp.private_key,
        &agent_aid.id,
        scope_submitter(),
    )
    .map_err(|e| format!("Delegation: {e:?}"))?;

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

    let action_payload =
        format!("POST /v1/ledger/payments {{\"invoice\":\"{invoice}\",\"amount\":\"{amount}\"}}");

    let action = ActionAttestation::create(
        &agent_aid.id,
        &agent_kp.private_key,
        &decision.decision_id,
        ScopeAction::Standard(Action::Write),
        &action_payload,
        sha256(action_payload.as_bytes()),
        now + 12,
    )
    .map_err(|e| format!("Action attestation: {e:?}"))?;

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
        .map_err(|e| format!("Receipt signature: {e:?}"))?;

    let trace_export = b"otel: spans for payment approval run".to_vec();

    let trace = TraceBinding {
        trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".into(),
        trace_hash: sha256(&trace_export),
    };

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
    .map_err(|e| format!("Evidence packet signing: {e:?}"))?;

    let context = VerificationContext {
        issuer_public_keys: HashMap::from([
            (cfo_id, cfo_kp.public_key),
            (treasury_aid.id, treasury_kp.public_key),
        ]),
        counterparty_public_keys: HashMap::from([(ledger_id.to_string(), ledger_kp.public_key)]),
        trace_data: Some(trace_export),
        receipt_data: Some(receipt_content.into_bytes()),
        ..Default::default()
    };

    Ok(BankingEvidence {
        packet,
        context,
        agent_private_key: agent_kp.private_key.clone(),
    })
}

/// Run the actual AIP verification engine.
pub fn verify_banking_packet(
    packet: &EvidencePacket,
    context: &VerificationContext,
) -> VerificationReport {
    verify_packet(packet, context)
}
