use std::collections::HashMap;
use std::io::Cursor;

use aip_core::capability::{issue_scoped_token, scope_orchestrator, scope_submitter};
use aip_core::delegation::create_delegation;
use aip_crypto::{derive_aip_id, sha256};
use aip_protocol::bundle::{build_zip, verify_zip, BundleStatus};
use aip_protocol::{
    verify_packet, ActionAttestation, AgentIdentitySummary, DecisionRecord, EvidencePacket,
    EvidencePacketBuilder, ReceiptBinding, RootAuthority, TraceBinding, TrustFloor,
    VerificationContext,
};
use aip_types::{Action, AlgorithmId, CapabilityScope, ProvenanceTriple, PublicKey, ScopeAction};
use ed25519_dalek::SigningKey;

pub fn seed_keypair(seed_str: &str) -> (Vec<u8>, Vec<u8>) {
    let seed = sha256(seed_str.as_bytes());
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    (verifying_key.to_bytes().to_vec(), signing_key.to_bytes().to_vec())
}

pub fn prov(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(format!("syntriass:model:{tag}").as_bytes()),
        environment_commitment: sha256(format!("syntriass:env:{tag}").as_bytes()),
        toolchain_commitment: sha256(format!("syntriass:tool:{tag}").as_bytes()),
    }
}

pub struct FixtureRecord {
    pub id: String,
    pub filename: String,
    pub context_filename: Option<String>,
    pub title: String,
    pub category: String,
    pub description: String,
    pub claimed_trust_floor: String,
    pub expected_derived_floor: String,
    pub expected_valid: bool,
    pub expected_tampered: bool,
    pub expected_failed_rules: Vec<String>,
    pub packet: EvidencePacket,
    pub context: VerificationContext,
    pub context_json: String,
}

pub struct AllFixtures {
    pub honest_counterparty: FixtureRecord,
    pub authority_bound: FixtureRecord,
    pub agent_signed: FixtureRecord,
    pub tampered_summary: FixtureRecord,
    pub tampered_hash: FixtureRecord,
    pub tampered_signature: FixtureRecord,
    pub scope_escalation: FixtureRecord,
    pub revoked_token: FixtureRecord,
    pub valid_bundle_zip: Vec<u8>,
    pub tampered_bundle_zip: Vec<u8>,
    pub index_json: String,
}

/// Helper to serialize VerificationContext to JSON
pub fn serialize_context(ctx: &VerificationContext) -> String {
    let mut issuers = serde_json::Map::new();
    for (id, pk) in &ctx.issuer_public_keys {
        issuers.insert(id.clone(), serde_json::Value::String(hex::encode(pk)));
    }
    let mut counterparties = serde_json::Map::new();
    for (id, pk) in &ctx.counterparty_public_keys {
        counterparties.insert(id.clone(), serde_json::Value::String(hex::encode(pk)));
    }
    let revoked: Vec<String> = ctx.revoked_jtis.iter().map(|jti| hex::encode(jti)).collect();
    let val = serde_json::json!({
        "trusted_issuers": issuers,
        "trusted_counterparties": counterparties,
        "revoked_jtis": revoked,
        "trace_data": ctx.trace_data.as_ref().map(|d| String::from_utf8_lossy(d).to_string()),
        "receipt_data": ctx.receipt_data.as_ref().map(|d| String::from_utf8_lossy(d).to_string()),
    });
    serde_json::to_string_pretty(&val).unwrap_or_default()
}

pub fn build_honest_counterparty() -> (EvidencePacket, VerificationContext) {
    let (cfo_pk, cfo_sk) = seed_keypair("syntriass:aip:seed:cfo:v1");
    let cfo_prov = prov("human:cfo");
    let cfo_id = derive_aip_id(&cfo_pk, &cfo_prov);

    let (orch_pk, orch_sk) = seed_keypair("syntriass:aip:seed:orchestrator:v1");
    let orch_prov = prov("agent:treasury-orchestrator-v2");
    let orch_id = derive_aip_id(&orch_pk, &orch_prov);

    let (agent_pk, agent_sk) = seed_keypair("syntriass:aip:seed:payments_agent:v1");
    let agent_prov = prov("agent:payments-agent-v1");
    let agent_id = derive_aip_id(&agent_pk, &agent_prov);

    // Root token issued by CFO to Orchestrator
    let root_token = issue_scoped_token(
        &cfo_id,
        &cfo_sk,
        &orch_id,
        scope_orchestrator(),
        Some(3_600_000),
    ).expect("issue root token");

    // Delegation hop from Orchestrator to Payments Agent
    let hop = create_delegation(
        &root_token,
        &orch_sk,
        &agent_id,
        scope_submitter(),
    ).expect("create delegation hop");

    let decision_id = [0x55u8; 16];
    let decided_at = root_token.issued_at + 10_000;
    let decision = DecisionRecord {
        decision_id,
        action_kind: ScopeAction::Standard(Action::Write),
        summary: "Approve vendor payment INV-2026-0142 for $48,200.00 to Acme Industrial GmbH".into(),
        input_hash: sha256(b"invoice=INV-2026-0142;vendor=Acme Industrial GmbH;amount=48200.00 USD;po=PO-9912"),
        rationale_hash: sha256(b"PO matched 3-way match, budget approved by department head, vendor verified in SAP"),
        decided_at,
    };

    let action_payload = "POST /v1/ledger/payments {\"invoice\":\"INV-2026-0142\",\"amount\":\"$48,200.00\"}";
    let action = ActionAttestation::create(
        &agent_id,
        &agent_sk,
        &decision_id,
        ScopeAction::Standard(Action::Write),
        action_payload,
        sha256(action_payload.as_bytes()),
        decided_at + 1_000,
    ).expect("create action attestation");

    // Countersigned Receipt Binding
    let (ledger_pk, ledger_sk) = seed_keypair("syntriass:aip:seed:ledger_counterparty:v1");
    let ledger_id = "ledger.example-bank.com";
    let receipt_data = "LEDGER-90211|INV-2026-0142|$48,200.00|POSTED";
    let mut receipt = ReceiptBinding {
        receipt_system: ledger_id.to_string(),
        receipt_id: "LEDGER-90211".to_string(),
        receipt_hash: sha256(receipt_data.as_bytes()),
        counterparty_id: None,
        counterparty_sig: None,
    };
    receipt.countersign(&decision_id, ledger_id, &ledger_sk).expect("countersign receipt");

    // Trace Binding
    let trace_data = "OTel:trace_id=4bf92f3577b34da6a3ce929d0e0e4736;span_id=00f067aa0ba902b7;sampled=1";
    let trace = TraceBinding {
        trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_string(),
        trace_hash: sha256(trace_data.as_bytes()),
    };

    let agent_summary = AgentIdentitySummary {
        aip_id: agent_id.clone(),
        public_key: PublicKey {
            algorithm: AlgorithmId::Ed25519,
            key_bytes: agent_pk.clone(),
        },
        provenance: agent_prov,
    };
    let root_authority = RootAuthority {
        principal_id: cfo_id.clone(),
        display_role: "CFO".into(),
        root_token,
    };

    let packet = EvidencePacketBuilder::new(agent_summary, root_authority)
        .delegation_chain(vec![hop])
        .decision(decision)
        .action(action)
        .trace(trace)
        .receipt(receipt)
        .claimed_trust_floor(TrustFloor::CounterpartySigned)
        .build_and_sign(&agent_sk)
        .expect("build and sign packet");

    let ctx = VerificationContext {
        issuer_public_keys: HashMap::from([
            (cfo_id, cfo_pk),
            (orch_id, orch_pk),
        ]),
        counterparty_public_keys: HashMap::from([
            (ledger_id.to_string(), ledger_pk),
        ]),
        revoked_jtis: Default::default(),
        trace_data: Some(trace_data.as_bytes().to_vec()),
        receipt_data: Some(receipt_data.as_bytes().to_vec()),
    };

    (packet, ctx)
}

pub fn build_authority_bound() -> (EvidencePacket, VerificationContext) {
    let (vp_pk, vp_sk) = seed_keypair("syntriass:aip:seed:vp_eng:v1");
    let vp_prov = prov("human:vp-engineering");
    let vp_id = derive_aip_id(&vp_pk, &vp_prov);

    let (infra_pk, infra_sk) = seed_keypair("syntriass:aip:seed:infra_orch:v1");
    let infra_prov = prov("agent:cloud-infrastructure-orchestrator-v1");
    let infra_id = derive_aip_id(&infra_pk, &infra_prov);

    let (agent_pk, agent_sk) = seed_keypair("syntriass:aip:seed:autoscale_agent:v1");
    let agent_prov = prov("agent:kubernetes-autoscaling-agent-v3");
    let agent_id = derive_aip_id(&agent_pk, &agent_prov);

    let root_token = issue_scoped_token(
        &vp_id,
        &vp_sk,
        &infra_id,
        scope_orchestrator(),
        Some(3_600_000),
    ).expect("issue root token");

    let hop = create_delegation(
        &root_token,
        &infra_sk,
        &agent_id,
        scope_submitter(),
    ).expect("create delegation hop");

    let decision_id = [0x66u8; 16];
    let decided_at = root_token.issued_at + 10_000;
    let decision = DecisionRecord {
        decision_id,
        action_kind: ScopeAction::Standard(Action::Write),
        summary: "Scale Kubernetes cluster production-east from 12 to 18 worker nodes".into(),
        input_hash: sha256(b"cluster=production-east;current_replicas=12;desired_replicas=18;metric=cpu_utilization>85%"),
        rationale_hash: sha256(b"hpa threshold exceeded: sustained 89% CPU over 5 minute evaluation window"),
        decided_at,
    };

    let action_payload = "PATCH /apis/apps/v1/namespaces/default/deployments/worker-pool {\"spec\":{\"replicas\":18}}";
    let action = ActionAttestation::create(
        &agent_id,
        &agent_sk,
        &decision_id,
        ScopeAction::Standard(Action::Write),
        action_payload,
        sha256(action_payload.as_bytes()),
        decided_at + 1_000,
    ).expect("create action attestation");

    // Internal cluster event receipt without countersignature
    let receipt_data = "K8S-EVENT-77192: Deployment worker-pool scaled to 18 replicas";
    let receipt = ReceiptBinding {
        receipt_system: "k8s-apiserver.prod-east".to_string(),
        receipt_id: "K8S-EVENT-77192".to_string(),
        receipt_hash: sha256(receipt_data.as_bytes()),
        counterparty_id: None,
        counterparty_sig: None,
    };

    let agent_summary = AgentIdentitySummary {
        aip_id: agent_id.clone(),
        public_key: PublicKey {
            algorithm: AlgorithmId::Ed25519,
            key_bytes: agent_pk.clone(),
        },
        provenance: agent_prov,
    };
    let root_authority = RootAuthority {
        principal_id: vp_id.clone(),
        display_role: "VP Engineering".into(),
        root_token,
    };

    let packet = EvidencePacketBuilder::new(agent_summary, root_authority)
        .delegation_chain(vec![hop])
        .decision(decision)
        .action(action)
        .receipt(receipt)
        .claimed_trust_floor(TrustFloor::AuthorityBound)
        .build_and_sign(&agent_sk)
        .expect("build and sign packet");

    let ctx = VerificationContext {
        issuer_public_keys: HashMap::from([
            (vp_id, vp_pk),
            (infra_id, infra_pk),
        ]),
        counterparty_public_keys: HashMap::new(),
        revoked_jtis: Default::default(),
        trace_data: None,
        receipt_data: Some(receipt_data.as_bytes().to_vec()),
    };

    (packet, ctx)
}

pub fn build_agent_signed() -> (EvidencePacket, VerificationContext) {
    let (unregistered_pk, unregistered_sk) = seed_keypair("syntriass:aip:seed:unregistered_principal:v1");
    let unregistered_prov = prov("entity:unregistered-principal");
    let unregistered_id = derive_aip_id(&unregistered_pk, &unregistered_prov);

    let (agent_pk, agent_sk) = seed_keypair("syntriass:aip:seed:research_agent:v1");
    let agent_prov = prov("agent:autonomous-sec-researcher-v1");
    let agent_id = derive_aip_id(&agent_pk, &agent_prov);

    let root_token = issue_scoped_token(
        &unregistered_id,
        &unregistered_sk,
        &agent_id,
        scope_submitter(),
        Some(3_600_000),
    ).expect("issue root token");

    let decision_id = [0x77u8; 16];
    let decided_at = root_token.issued_at + 10_000;
    let decision = DecisionRecord {
        decision_id,
        action_kind: ScopeAction::Standard(Action::Write),
        summary: "Fetch and summarize SEC 10-K filings for Q3 2026 analysis".into(),
        input_hash: sha256(b"source=sec.gov/edgar;filings=10-K;period=Q3-2026;companies=AAPL,MSFT,GOOG"),
        rationale_hash: sha256(b"scheduled quarterly financial research crawl"),
        decided_at,
    };

    let action_payload = "GET /Archives/edgar/data/320193/000032019326000106/aapl-20260926.htm";
    let action = ActionAttestation::create(
        &agent_id,
        &agent_sk,
        &decision_id,
        ScopeAction::Standard(Action::Write),
        action_payload,
        sha256(action_payload.as_bytes()),
        decided_at + 1_000,
    ).expect("create action attestation");

    let agent_summary = AgentIdentitySummary {
        aip_id: agent_id.clone(),
        public_key: PublicKey {
            algorithm: AlgorithmId::Ed25519,
            key_bytes: agent_pk.clone(),
        },
        provenance: agent_prov,
    };
    let root_authority = RootAuthority {
        principal_id: unregistered_id.clone(),
        display_role: "Self-Asserted Principal".into(),
        root_token,
    };

    let packet = EvidencePacketBuilder::new(agent_summary, root_authority)
        .delegation_chain(vec![])
        .decision(decision)
        .action(action)
        .claimed_trust_floor(TrustFloor::AgentSigned)
        .build_and_sign(&agent_sk)
        .expect("build and sign packet");

    // Empty context: verifier does NOT have the unregistered principal key
    let ctx = VerificationContext::new();

    (packet, ctx)
}

pub fn generate_all_fixtures() -> AllFixtures {
    // 1. Honest Counterparty
    let (honest_packet, honest_ctx) = build_honest_counterparty();
    let honest_ctx_json = serialize_context(&honest_ctx);
    let honest_rec = FixtureRecord {
        id: "honest_counterparty".into(),
        filename: "honest_counterparty.json".into(),
        context_filename: Some("honest_counterparty.context.json".into()),
        title: "Honest Counterparty-Signed Payment".into(),
        category: "valid".into(),
        description: "Full enterprise payment approval chain with bilateral bank ledger countersignature. Passes all 14 engine verification rules.".into(),
        claimed_trust_floor: "COUNTERPARTY_SIGNED".into(),
        expected_derived_floor: "COUNTERPARTY_SIGNED".into(),
        expected_valid: true,
        expected_tampered: false,
        expected_failed_rules: vec![],
        packet: honest_packet.clone(),
        context: honest_ctx.clone(),
        context_json: honest_ctx_json.clone(),
    };

    // 2. Authority Bound
    let (auth_packet, auth_ctx) = build_authority_bound();
    let auth_ctx_json = serialize_context(&auth_ctx);
    let auth_rec = FixtureRecord {
        id: "authority_bound".into(),
        filename: "authority_bound.json".into(),
        context_filename: Some("authority_bound.context.json".into()),
        title: "Authority-Bound Cloud Scaling".into(),
        category: "valid".into(),
        description: "Autonomous infrastructure scaling action with attenuated delegation. Passes rules 1-12 without external countersignature.".into(),
        claimed_trust_floor: "AUTHORITY_BOUND".into(),
        expected_derived_floor: "AUTHORITY_BOUND".into(),
        expected_valid: true,
        expected_tampered: false,
        expected_failed_rules: vec![],
        packet: auth_packet.clone(),
        context: auth_ctx.clone(),
        context_json: auth_ctx_json,
    };

    // 3. Agent Signed
    let (agent_packet, agent_ctx) = build_agent_signed();
    let agent_ctx_json = serialize_context(&agent_ctx);
    let agent_rec = FixtureRecord {
        id: "agent_signed".into(),
        filename: "agent_signed.json".into(),
        context_filename: Some("agent_signed.context.json".into()),
        title: "Agent-Signed Autonomous Task".into(),
        category: "unverified_authority".into(),
        description: "Self-signed web scraping task lacking enterprise principal delegation. Derives AgentSigned trust floor.".into(),
        claimed_trust_floor: "AGENT_SIGNED".into(),
        expected_derived_floor: "AGENT_SIGNED".into(),
        expected_valid: false,
        expected_tampered: false,
        expected_failed_rules: vec!["ROOT_TOKEN_SIGNATURE".into()],
        packet: agent_packet.clone(),
        context: agent_ctx.clone(),
        context_json: agent_ctx_json,
    };

    // 4. Tampered Summary (modified summary, hash & signature untouched)
    let mut tampered_summary_packet = honest_packet.clone();
    tampered_summary_packet.decision.summary =
        "Approve vendor payment INV-2026-0142 for $4,820,000.00 to Acme Industrial GmbH".into();
    let tampered_summary_rec = FixtureRecord {
        id: "tampered_summary".into(),
        filename: "tampered_summary.json".into(),
        context_filename: Some("honest_counterparty.context.json".into()),
        title: "Tampered Decision Summary".into(),
        category: "adversarial".into(),
        description: "Payment amount modified in sealed packet without hash update. Violates CANONICAL_HASH.".into(),
        claimed_trust_floor: "COUNTERPARTY_SIGNED".into(),
        expected_derived_floor: "UNVERIFIED".into(),
        expected_valid: false,
        expected_tampered: true,
        expected_failed_rules: vec!["CANONICAL_HASH".into(), "TRUST_FLOOR".into()],
        packet: tampered_summary_packet,
        context: honest_ctx.clone(),
        context_json: honest_ctx_json.clone(),
    };

    // 5. Tampered Hash (modified summary + recomputed hash, signature untouched)
    let mut tampered_hash_packet = honest_packet.clone();
    tampered_hash_packet.decision.summary =
        "Approve vendor payment INV-2026-0142 for $4,820,000.00 to Acme Industrial GmbH".into();
    tampered_hash_packet.packet_hash = tampered_hash_packet.compute_hash();
    let tampered_hash_rec = FixtureRecord {
        id: "tampered_hash".into(),
        filename: "tampered_hash.json".into(),
        context_filename: Some("honest_counterparty.context.json".into()),
        title: "Tampered Payload with Recalculated Hash".into(),
        category: "adversarial".into(),
        description: "Attacker updated packet_hash after editing payload. Bypasses CANONICAL_HASH but caught by AGENT_SIGNATURE.".into(),
        claimed_trust_floor: "COUNTERPARTY_SIGNED".into(),
        expected_derived_floor: "UNVERIFIED".into(),
        expected_valid: false,
        expected_tampered: true,
        expected_failed_rules: vec!["AGENT_SIGNATURE".into(), "TRUST_FLOOR".into()],
        packet: tampered_hash_packet,
        context: honest_ctx.clone(),
        context_json: honest_ctx_json.clone(),
    };

    // 6. Tampered Signature (corrupted signature byte)
    let mut tampered_sig_packet = honest_packet.clone();
    tampered_sig_packet.agent_sig.signature_bytes[0] ^= 0xFF;
    let tampered_sig_rec = FixtureRecord {
        id: "tampered_signature".into(),
        filename: "tampered_signature.json".into(),
        context_filename: Some("honest_counterparty.context.json".into()),
        title: "Corrupted Agent Signature".into(),
        category: "adversarial".into(),
        description: "Corrupted signature bytes in transit. Violates AGENT_SIGNATURE.".into(),
        claimed_trust_floor: "COUNTERPARTY_SIGNED".into(),
        expected_derived_floor: "UNVERIFIED".into(),
        expected_valid: false,
        expected_tampered: true,
        expected_failed_rules: vec!["AGENT_SIGNATURE".into(), "TRUST_FLOOR".into()],
        packet: tampered_sig_packet,
        context: honest_ctx.clone(),
        context_json: honest_ctx_json.clone(),
    };

    // 7. Scope Escalation (delegation hop modified to CapabilityScope::all() + hash recomputed)
    let mut scope_esc_packet = honest_packet.clone();
    scope_esc_packet.delegation_chain[0].scope = CapabilityScope::all();
    scope_esc_packet.packet_hash = scope_esc_packet.compute_hash();
    let scope_esc_rec = FixtureRecord {
        id: "scope_escalation".into(),
        filename: "scope_escalation.json".into(),
        context_filename: Some("honest_counterparty.context.json".into()),
        title: "Privilege Scope Escalation".into(),
        category: "adversarial".into(),
        description: "Delegation hop claims wider scope than granted by root token. Violates DELEGATION_CHAIN.".into(),
        claimed_trust_floor: "COUNTERPARTY_SIGNED".into(),
        expected_derived_floor: "UNVERIFIED".into(),
        expected_valid: false,
        expected_tampered: true,
        expected_failed_rules: vec!["DELEGATION_CHAIN".into(), "TRUST_FLOOR".into()],
        packet: scope_esc_packet,
        context: honest_ctx.clone(),
        context_json: honest_ctx_json.clone(),
    };

    // 8. Revoked Token (valid packet, but hop JTI is marked revoked in context)
    let revoked_packet = honest_packet.clone();
    let mut revoked_ctx = honest_ctx.clone();
    let hop_jti = honest_packet.delegation_chain[0].jti;
    revoked_ctx.revoked_jtis.insert(hop_jti);
    let revoked_ctx_json = serialize_context(&revoked_ctx);
    let revoked_rec = FixtureRecord {
        id: "revoked_token".into(),
        filename: "revoked_token.json".into(),
        context_filename: Some("revoked_token.context.json".into()),
        title: "Revoked Delegation Token".into(),
        category: "revocation".into(),
        description: "Validly sealed packet whose delegation token was revoked after issuance. Violates REVOCATION (not tampered).".into(),
        claimed_trust_floor: "COUNTERPARTY_SIGNED".into(),
        expected_derived_floor: "AGENT_SIGNED".into(),
        expected_valid: false,
        expected_tampered: false,
        expected_failed_rules: vec!["REVOCATION".into(), "TRUST_FLOOR".into()],
        packet: revoked_packet,
        context: revoked_ctx,
        context_json: revoked_ctx_json,
    };

    // 9. Valid Audit Export ZIP
    let honest_report = verify_packet(&honest_packet, &honest_ctx);
    let (signer_pk, signer_sk) = seed_keypair("syntriass:aip:seed:audit_service_signer:v1");
    let signer_seed: [u8; 32] = signer_sk.try_into().expect("32 byte signer sk");
    let signer_pub: [u8; 32] = signer_pk.try_into().expect("32 byte signer pk");
    let valid_zip = build_zip(
        "tenant-enterprise-demo",
        &honest_packet,
        &honest_report,
        &signer_seed,
        &signer_pub,
    ).expect("build valid zip bundle");

    // 10. Tampered Audit Export ZIP (unzip, mutate evidence.json, rezip)
    let mut tampered_zip_cursor = Cursor::new(Vec::new());
    {
        let mut archive = zip::ZipArchive::new(Cursor::new(&valid_zip)).expect("read valid zip");
        let mut zw = zip::ZipWriter::new(&mut tampered_zip_cursor);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        for i in 0..archive.len() {
            let mut file = archive.by_index(i).expect("file entry");
            let name = file.name().to_string();
            let mut buf = Vec::new();
            use std::io::Read;
            file.read_to_end(&mut buf).expect("read file bytes");

            zw.start_file(&name, options).expect("start zip entry");
            if name == "evidence.json" {
                // Mutate evidence JSON inside zip archive
                let mut tampered_bytes = buf.clone();
                if let Ok(mut val) = serde_json::from_slice::<serde_json::Value>(&buf) {
                    if let Some(dec) = val.get_mut("decision") {
                        if let Some(obj) = dec.as_object_mut() {
                            obj.insert(
                                "summary".to_string(),
                                serde_json::Value::String(
                                    "Approve vendor payment INV-2026-0142 for $4,820,000.00 to Acme Industrial GmbH".into(),
                                ),
                            );
                        }
                    }
                    tampered_bytes = serde_json::to_vec_pretty(&val).unwrap_or(buf);
                }
                use std::io::Write;
                zw.write_all(&tampered_bytes).expect("write mutated evidence bytes");
            } else {
                use std::io::Write;
                zw.write_all(&buf).expect("write unchanged file bytes");
            }
        }
        zw.finish().expect("finish zip");
    }
    let tampered_zip = tampered_zip_cursor.into_inner();

    // Catalog index.json
    let index_val = serde_json::json!({
        "version": "1.0.0",
        "generated_at": 1781769600000u64,
        "fixtures": [
            {
                "id": honest_rec.id,
                "filename": honest_rec.filename,
                "context_filename": honest_rec.context_filename,
                "title": honest_rec.title,
                "category": honest_rec.category,
                "description": honest_rec.description,
                "claimed_trust_floor": honest_rec.claimed_trust_floor,
                "expected_derived_floor": honest_rec.expected_derived_floor,
                "expected_valid": honest_rec.expected_valid,
                "expected_tampered": honest_rec.expected_tampered,
                "expected_failed_rules": honest_rec.expected_failed_rules,
            },
            {
                "id": auth_rec.id,
                "filename": auth_rec.filename,
                "context_filename": auth_rec.context_filename,
                "title": auth_rec.title,
                "category": auth_rec.category,
                "description": auth_rec.description,
                "claimed_trust_floor": auth_rec.claimed_trust_floor,
                "expected_derived_floor": auth_rec.expected_derived_floor,
                "expected_valid": auth_rec.expected_valid,
                "expected_tampered": auth_rec.expected_tampered,
                "expected_failed_rules": auth_rec.expected_failed_rules,
            },
            {
                "id": agent_rec.id,
                "filename": agent_rec.filename,
                "context_filename": agent_rec.context_filename,
                "title": agent_rec.title,
                "category": agent_rec.category,
                "description": agent_rec.description,
                "claimed_trust_floor": agent_rec.claimed_trust_floor,
                "expected_derived_floor": agent_rec.expected_derived_floor,
                "expected_valid": agent_rec.expected_valid,
                "expected_tampered": agent_rec.expected_tampered,
                "expected_failed_rules": agent_rec.expected_failed_rules,
            },
            {
                "id": tampered_summary_rec.id,
                "filename": tampered_summary_rec.filename,
                "context_filename": tampered_summary_rec.context_filename,
                "title": tampered_summary_rec.title,
                "category": tampered_summary_rec.category,
                "description": tampered_summary_rec.description,
                "claimed_trust_floor": tampered_summary_rec.claimed_trust_floor,
                "expected_derived_floor": tampered_summary_rec.expected_derived_floor,
                "expected_valid": tampered_summary_rec.expected_valid,
                "expected_tampered": tampered_summary_rec.expected_tampered,
                "expected_failed_rules": tampered_summary_rec.expected_failed_rules,
            },
            {
                "id": tampered_hash_rec.id,
                "filename": tampered_hash_rec.filename,
                "context_filename": tampered_hash_rec.context_filename,
                "title": tampered_hash_rec.title,
                "category": tampered_hash_rec.category,
                "description": tampered_hash_rec.description,
                "claimed_trust_floor": tampered_hash_rec.claimed_trust_floor,
                "expected_derived_floor": tampered_hash_rec.expected_derived_floor,
                "expected_valid": tampered_hash_rec.expected_valid,
                "expected_tampered": tampered_hash_rec.expected_tampered,
                "expected_failed_rules": tampered_hash_rec.expected_failed_rules,
            },
            {
                "id": tampered_sig_rec.id,
                "filename": tampered_sig_rec.filename,
                "context_filename": tampered_sig_rec.context_filename,
                "title": tampered_sig_rec.title,
                "category": tampered_sig_rec.category,
                "description": tampered_sig_rec.description,
                "claimed_trust_floor": tampered_sig_rec.claimed_trust_floor,
                "expected_derived_floor": tampered_sig_rec.expected_derived_floor,
                "expected_valid": tampered_sig_rec.expected_valid,
                "expected_tampered": tampered_sig_rec.expected_tampered,
                "expected_failed_rules": tampered_sig_rec.expected_failed_rules,
            },
            {
                "id": scope_esc_rec.id,
                "filename": scope_esc_rec.filename,
                "context_filename": scope_esc_rec.context_filename,
                "title": scope_esc_rec.title,
                "category": scope_esc_rec.category,
                "description": scope_esc_rec.description,
                "claimed_trust_floor": scope_esc_rec.claimed_trust_floor,
                "expected_derived_floor": scope_esc_rec.expected_derived_floor,
                "expected_valid": scope_esc_rec.expected_valid,
                "expected_tampered": scope_esc_rec.expected_tampered,
                "expected_failed_rules": scope_esc_rec.expected_failed_rules,
            },
            {
                "id": revoked_rec.id,
                "filename": revoked_rec.filename,
                "context_filename": revoked_rec.context_filename,
                "title": revoked_rec.title,
                "category": revoked_rec.category,
                "description": revoked_rec.description,
                "claimed_trust_floor": revoked_rec.claimed_trust_floor,
                "expected_derived_floor": revoked_rec.expected_derived_floor,
                "expected_valid": revoked_rec.expected_valid,
                "expected_tampered": revoked_rec.expected_tampered,
                "expected_failed_rules": revoked_rec.expected_failed_rules,
            },
            {
                "id": "audit_bundle_valid",
                "filename": "audit_bundle_valid.zip",
                "context_filename": "honest_counterparty.context.json",
                "title": "Certified Audit Export Bundle",
                "category": "bundle",
                "format": "zip",
                "description": "Conforming 7-file ZIP archive signed by service key with valid manifest and file checksums.",
                "expected_valid": true,
                "expected_checks": [
                    "BUNDLE_STRUCTURE",
                    "MANIFEST_PARSE",
                    "FILE_HASHES",
                    "BUNDLE_HASH",
                    "BUNDLE_SIGNATURE",
                    "EVIDENCE_INTEGRITY",
                    "PACKET_VERIFICATION"
                ],
            },
            {
                "id": "audit_bundle_tampered",
                "filename": "audit_bundle_tampered.zip",
                "title": "Tampered Audit Export Bundle",
                "category": "bundle",
                "format": "zip",
                "description": "ZIP bundle with modified evidence.json. FILE_HASHES check detects content tampering.",
                "expected_valid": false,
                "expected_failed_checks": ["FILE_HASHES"],
            }
        ]
    });

    let index_json = serde_json::to_string_pretty(&index_val).unwrap_or_default();

    AllFixtures {
        honest_counterparty: honest_rec,
        authority_bound: auth_rec,
        agent_signed: agent_rec,
        tampered_summary: tampered_summary_rec,
        tampered_hash: tampered_hash_rec,
        tampered_signature: tampered_sig_rec,
        scope_escalation: scope_esc_rec,
        revoked_token: revoked_rec,
        valid_bundle_zip: valid_zip,
        tampered_bundle_zip: tampered_zip,
        index_json,
    }
}

pub fn self_verify_fixtures(fixtures: &AllFixtures) -> Result<(), String> {
    // 1. Honest Counterparty: valid == true, tampered == false, floor == CounterpartySigned
    let rep = verify_packet(&fixtures.honest_counterparty.packet, &fixtures.honest_counterparty.context);
    if !rep.valid || rep.tampered || rep.trust_floor != TrustFloor::CounterpartySigned {
        return Err(format!("honest_counterparty failed verification: valid={}, tampered={}, floor={:?}", rep.valid, rep.tampered, rep.trust_floor));
    }

    // 2. Authority Bound: valid == true, tampered == false, floor == AuthorityBound
    let rep = verify_packet(&fixtures.authority_bound.packet, &fixtures.authority_bound.context);
    if !rep.valid || rep.tampered || rep.trust_floor != TrustFloor::AuthorityBound {
        return Err(format!("authority_bound failed verification: valid={}, tampered={}, floor={:?}", rep.valid, rep.tampered, rep.trust_floor));
    }

    // 3. Agent Signed: valid == false (ROOT_TOKEN_SIGNATURE fails), tampered == false, floor == AgentSigned
    let rep = verify_packet(&fixtures.agent_signed.packet, &fixtures.agent_signed.context);
    if rep.valid || rep.tampered || rep.trust_floor != TrustFloor::AgentSigned {
        return Err(format!("agent_signed verification mismatch: valid={}, tampered={}, floor={:?}", rep.valid, rep.tampered, rep.trust_floor));
    }

    // 4. Tampered Summary: valid == false, tampered == true
    let rep = verify_packet(&fixtures.tampered_summary.packet, &fixtures.tampered_summary.context);
    if rep.valid || !rep.tampered {
        return Err(format!("tampered_summary not detected: valid={}, tampered={}", rep.valid, rep.tampered));
    }

    // 5. Tampered Hash: valid == false, tampered == true
    let rep = verify_packet(&fixtures.tampered_hash.packet, &fixtures.tampered_hash.context);
    if rep.valid || !rep.tampered {
        return Err(format!("tampered_hash not detected: valid={}, tampered={}", rep.valid, rep.tampered));
    }

    // 6. Tampered Signature: valid == false, tampered == true
    let rep = verify_packet(&fixtures.tampered_signature.packet, &fixtures.tampered_signature.context);
    if rep.valid || !rep.tampered {
        return Err(format!("tampered_signature not detected: valid={}, tampered={}", rep.valid, rep.tampered));
    }

    // 7. Scope Escalation: valid == false, tampered == true
    let rep = verify_packet(&fixtures.scope_escalation.packet, &fixtures.scope_escalation.context);
    if rep.valid || !rep.tampered {
        return Err(format!("scope_escalation not detected: valid={}, tampered={}", rep.valid, rep.tampered));
    }

    // 8. Revoked Token: valid == false, tampered == false (administrative status, not tampering)
    let rep = verify_packet(&fixtures.revoked_token.packet, &fixtures.revoked_token.context);
    if rep.valid || rep.tampered || rep.trust_floor != TrustFloor::AgentSigned {
        return Err(format!("revoked_token mismatch: valid={}, tampered={}, floor={:?}", rep.valid, rep.tampered, rep.trust_floor));
    }

    // 9. Valid ZIP bundle: overall == Pass
    let zip_rep = verify_zip(&fixtures.valid_bundle_zip, &fixtures.honest_counterparty.context);
    if zip_rep.overall != BundleStatus::Pass {
        return Err(format!("valid_bundle_zip failed verification: overall={:?}", zip_rep.overall));
    }

    // 10. Tampered ZIP bundle: overall == Fail
    let zip_rep = verify_zip(&fixtures.tampered_bundle_zip, &fixtures.honest_counterparty.context);
    if zip_rep.overall != BundleStatus::Fail {
        return Err(format!("tampered_bundle_zip not detected: overall={:?}", zip_rep.overall));
    }

    Ok(())
}
