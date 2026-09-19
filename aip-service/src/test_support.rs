//! Shared test fixtures: build a real, signed EvidencePacket and a matching
//! generate request, using only `aip-core` + `aip-protocol` primitives.
//!
//! Compiled under `#[cfg(test)]` only.

use std::collections::HashMap;

use aip_core::capability::{issue_scoped_token, scope_orchestrator, scope_submitter};
use aip_core::create_identity;
use aip_core::delegation::create_delegation;
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};
use aip_protocol::{
    verify_packet, ActionAttestation, AgentIdentitySummary, DecisionRecord, EvidencePacket,
    EvidencePacketBuilder, RootAuthority, TrustFloor, VerificationContext,
};
use aip_types::{Action, AlgorithmId, ProvenanceTriple, PublicKey, ScopeAction};

use crate::evidence::{ActionInput, DecisionInput, GenerateRequest, ProvenanceInput};

use std::sync::Arc;

/// Build an `AppState` for in-process router tests with the given store and
/// API keys. Uses a fresh service keypair and empty delegation/revocation logs.
pub fn test_app_state(
    store: Arc<dyn crate::store::EvidenceStore>,
    api_keys: crate::auth::ApiKeyStore,
) -> Arc<crate::AppState> {
    // Mirrors the production default (AUDIT B-7): a test that wants the
    // managed-signing endpoint must ask for it explicitly, so no test can
    // silently exercise a route real deployments do not serve.
    test_app_state_with(store, api_keys, crate::ManagedSigning::Refused)
}

/// As [`test_app_state`], with the managed-signing posture stated.
pub fn test_app_state_with(
    store: Arc<dyn crate::store::EvidenceStore>,
    api_keys: crate::auth::ApiKeyStore,
    managed_signing: crate::ManagedSigning,
) -> Arc<crate::AppState> {
    let kp = crate::keys::ServiceKey::generate();
    let encoding_key = kp.encoding_key();
    let decoding_key = kp.decoding_key();
    let mut p = std::env::temp_dir();
    p.push(format!("aip_test_logs_{}", uuid::Uuid::new_v4()));
    let log_path = p.to_str().unwrap().to_owned();
    Arc::new(crate::AppState {
        encoding_key,
        decoding_key,
        public_pem: kp.public_pem.clone(),
        fingerprint: kp.fingerprint.clone(),
        revocation_log_path: log_path.clone(),
        revocation_set: crate::revocation::load_revocation_set(&log_path),
        store,
        api_keys,
        signer: Arc::new(kp),
        managed_signing,
    })
}

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

/// A complete signed packet plus the issuer public keys (AIP-ID → hex) needed
/// to verify it. CFO principal → treasury orchestrator → payments agent.
pub fn sample_packet() -> (EvidencePacket, HashMap<String, String>) {
    let cfo_kp = generate_ed25519_keypair();
    let cfo_id = derive_aip_id(&cfo_kp.public_key, &prov("cfo"));
    let (orch_aid, orch_kp) = create_identity(prov("orch"), None).unwrap();
    let (agent_aid, agent_kp) = create_identity(prov("agent"), None).unwrap();

    let root_token = issue_scoped_token(
        &cfo_id,
        &cfo_kp.private_key,
        &orch_aid.id,
        scope_orchestrator(),
        Some(3_600_000),
    )
    .unwrap();
    let hop = create_delegation(
        &root_token,
        &orch_kp.private_key,
        &agent_aid.id,
        scope_submitter(),
    )
    .unwrap();

    let now = now_ms();
    let decision = DecisionRecord {
        decision_id: aip_core::capability::random_jti(),
        action_kind: ScopeAction::Standard(Action::Write),
        summary: "approve payment".into(),
        input_hash: sha256(b"invoice"),
        rationale_hash: sha256(b"ok"),
        decided_at: now,
    };
    let action = ActionAttestation::create(
        &agent_aid.id,
        &agent_kp.private_key,
        &decision.decision_id,
        ScopeAction::Standard(Action::Write),
        "POST /ledger/payments",
        sha256(b"payload"),
        now + 1,
    )
    .unwrap();

    let packet = EvidencePacketBuilder::new(
        AgentIdentitySummary {
            aip_id: agent_aid.id.clone(),
            public_key: PublicKey {
                algorithm: AlgorithmId::Ed25519,
                key_bytes: agent_kp.public_key.clone(),
            },
            provenance: agent_aid.provenance.clone(),
        },
        RootAuthority {
            principal_id: cfo_id.clone(),
            display_role: "CFO".into(),
            root_token,
        },
    )
    .delegation_chain(vec![hop])
    .decision(decision)
    .action(action)
    .claimed_trust_floor(TrustFloor::AuthorityBound)
    .build_and_sign(&agent_kp.private_key)
    .unwrap();

    // Sanity: the fixture must verify with these keys.
    let mut issuer_keys = HashMap::new();
    issuer_keys.insert(cfo_id.clone(), hex::encode(&cfo_kp.public_key));
    issuer_keys.insert(orch_aid.id.clone(), hex::encode(&orch_kp.public_key));

    let ctx = VerificationContext::new()
        .trust_issuer(&cfo_id, &cfo_kp.public_key)
        .trust_issuer(&orch_aid.id, &orch_kp.public_key);
    debug_assert!(verify_packet(&packet, &ctx).valid);

    (packet, issuer_keys)
}

/// A generate request whose authority tokens are pre-signed, plus the issuer
/// keys to verify the resulting packet. Mirrors `sample_packet` but exercises
/// the HTTP generate path (agent seed supplied in the request).
pub fn sample_generate_request() -> (GenerateRequest, HashMap<String, String>) {
    let cfo_kp = generate_ed25519_keypair();
    let cfo_id = derive_aip_id(&cfo_kp.public_key, &prov("cfo"));
    let (orch_aid, orch_kp) = create_identity(prov("orch"), None).unwrap();

    // Agent identity from a fixed seed so the request can carry the seed hex.
    let agent_kp = generate_ed25519_keypair();
    let agent_seed_hex = hex::encode(&agent_kp.private_key);
    let agent_prov = ProvenanceInput {
        model: "agent-model".into(),
        environment: "agent-env".into(),
        toolchain: "agent-tool".into(),
    };
    let agent_id = derive_aip_id(&agent_kp.public_key, &agent_prov.to_triple());

    let root_token = issue_scoped_token(
        &cfo_id,
        &cfo_kp.private_key,
        &orch_aid.id,
        scope_orchestrator(),
        Some(3_600_000),
    )
    .unwrap();
    let hop = create_delegation(
        &root_token,
        &orch_kp.private_key,
        &agent_id,
        scope_submitter(),
    )
    .unwrap();

    let req = GenerateRequest {
        agent_seed_hex,
        provenance: agent_prov,
        principal_id: cfo_id.clone(),
        principal_role: "CFO".into(),
        root_token,
        delegation_chain: vec![hop],
        decision: DecisionInput {
            action_kind: "write".into(),
            summary: "approve payment".into(),
            input: "invoice INV-1".into(),
            rationale: "3-way match ok".into(),
        },
        actions: vec![ActionInput {
            action_kind: "write".into(),
            description: "POST /ledger/payments".into(),
            payload: "{\"amount\":100}".into(),
        }],
        trace: None,
        receipt: None,
        claimed_trust_floor: Some(TrustFloor::AuthorityBound),
    };

    let mut issuer_keys = HashMap::new();
    issuer_keys.insert(cfo_id, hex::encode(&cfo_kp.public_key));
    issuer_keys.insert(orch_aid.id, hex::encode(&orch_kp.public_key));
    (req, issuer_keys)
}
