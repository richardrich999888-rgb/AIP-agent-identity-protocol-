//! Fixtures for the service's integration tests.
//!
//! `src/test_support.rs` is `#[cfg(test)]`, so it is invisible to an
//! integration test, which is a separate crate. Rather than widen that
//! module's visibility — a production-surface change made for a test's
//! convenience — the fixtures an integration test needs are built here from
//! the same public primitives.
//!
//! # Why the packet is built directly rather than via `generate_packet`
//!
//! `generate_packet` stamps `decided_at` and `performed_at` from the
//! service's own clock, so no generate request can produce a future-dated
//! packet. That is a property worth having, and it is asserted below — but it
//! also means the generate path cannot exercise R16's failing branch.
//!
//! The verify endpoint does not require the packet to have come from this
//! service. The documented production shape is the opposite: agents sign
//! client-side and the service is used for verify and ingest. So a packet
//! built here, dated where the test needs it, is the realistic input, not a
//! contrivance.

#![allow(dead_code)] // each test file uses a subset

use std::collections::HashMap;

use aip_core::capability::{issue_scoped_token, random_jti, scope_orchestrator, scope_submitter};
use aip_core::create_identity;
use aip_core::delegation::create_delegation;
use aip_crypto::sha256;
use aip_protocol::{
    ActionAttestation, AgentIdentitySummary, DecisionRecord, EvidencePacket, EvidencePacketBuilder,
    RootAuthority, TrustFloor,
};
use aip_types::{Action, AlgorithmId, ProvenanceTriple, PublicKey, ScopeAction};
use std::path::PathBuf;

use airon_aip::evidence::{ActionInput, DecisionInput, GenerateRequest, ProvenanceInput};

/// Unix milliseconds. Mirrors the service's own clock helper; the tests use
/// it to place fixtures relative to real time, because the property under
/// test is precisely that the service consults real time.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before the Unix epoch")
        .as_millis() as u64
}

/// A century, in milliseconds. Wide enough that a token issued now covers any
/// instant the tests date a packet at, so the authority-window rule (R10)
/// stays satisfied and R16 is the *only* rule that can object to the date.
/// Without this, a future-dated packet would fail for the wrong reason and
/// the test would pass while proving nothing about R16.
const CENTURY_MS: u64 = 100 * 365 * 24 * 60 * 60 * 1000;

fn prov(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(format!("model:{tag}").as_bytes()),
        environment_commitment: sha256(format!("env:{tag}").as_bytes()),
        toolchain_commitment: sha256(format!("tool:{tag}").as_bytes()),
    }
}

/// A fixture packet and everything a test needs to reason about its dates.
pub struct Fixture {
    pub packet: EvidencePacket,
    /// Issuer AIP-ID → Ed25519 public key (hex), as the verify API wants them.
    pub issuers: HashMap<String, String>,
    /// The instant the authority tokens were issued. This is the *earliest*
    /// instant at which the packet can legitimately verify: a verification
    /// bound before it would rightly object that the tokens did not yet
    /// exist. Tests compute their explicit verification instants from this
    /// rather than from a separate clock read, so no test depends on how much
    /// wall time elapses inside the fixture.
    pub issued_at_ms: u64,
    /// The instant the packet claims its decision was made.
    pub decided_at_ms: u64,
}

/// A complete, correctly signed CFO → orchestrator → agent packet whose
/// decision is dated `offset_ms` after its authority was issued.
///
/// Every field except the two activity timestamps is what an honest packet
/// carries. The authority tokens are issued at the real present — the public
/// issuance API stamps its own clock and offers no way to back-date, which is
/// correct — so `offset_ms` moves the *claimed activity* forward without
/// moving the authority. That is exactly the shape a future-dating agent
/// produces, and exactly what R16 exists to see.
///
/// # Boundary
///
/// `offset_ms` is unsigned on purpose. A negative offset would date the
/// decision before the authority that permits it, which R10
/// (`TEMPORAL_VALIDITY`) rejects — correctly, and for a reason that has
/// nothing to do with R16. A test wanting a packet older than the
/// verification instant should move the *verification* instant later
/// instead.
pub fn packet_dated(offset_ms: u64) -> Fixture {
    let (cfo_aid, cfo_kp) = create_identity(prov("cfo"), None).expect("cfo identity");
    let (orch_aid, orch_kp) = create_identity(prov("orch"), None).expect("orchestrator identity");
    let (agent_aid, agent_kp) = create_identity(prov("agent"), None).expect("agent identity");

    let root_token = issue_scoped_token(
        &cfo_aid.id,
        &cfo_kp.private_key,
        &orch_aid.id,
        scope_orchestrator(),
        Some(CENTURY_MS),
    )
    .expect("root token");
    let hop = create_delegation(
        &root_token,
        &orch_kp.private_key,
        &agent_aid.id,
        scope_submitter(),
    )
    .expect("delegation hop");

    // Dated from the hop, not from a fresh clock read: the hop is issued
    // after the root token, so this is the true earliest legitimate instant.
    let issued_at_ms = hop.issued_at.max(root_token.issued_at);
    let decided_at_ms = issued_at_ms + offset_ms;

    let decision = DecisionRecord {
        decision_id: random_jti(),
        action_kind: ScopeAction::Standard(Action::Write),
        summary: "approve payment".into(),
        input_hash: sha256(b"invoice INV-1"),
        rationale_hash: sha256(b"3-way match ok"),
        decided_at: decided_at_ms,
    };
    let action = ActionAttestation::create(
        &agent_aid.id,
        &agent_kp.private_key,
        &decision.decision_id,
        ScopeAction::Standard(Action::Write),
        "POST /ledger/payments",
        sha256(b"{\"amount\":100}"),
        // Equal timestamps are valid; a fixture for the present must not
        // depend on signing taking at least one millisecond.
        decided_at_ms,
    )
    .expect("action attestation");

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
            principal_id: cfo_aid.id.clone(),
            display_role: "CFO".into(),
            root_token,
        },
    )
    .delegation_chain(vec![hop])
    .decision(decision)
    .action(action)
    .claimed_trust_floor(TrustFloor::AuthorityBound)
    .build_and_sign(&agent_kp.private_key)
    .expect("seal packet");

    let issuers = HashMap::from([
        (cfo_aid.id, hex::encode(&cfo_kp.public_key)),
        (orch_aid.id, hex::encode(&orch_kp.public_key)),
    ]);
    Fixture {
        packet,
        issuers,
        issued_at_ms,
        decided_at_ms,
    }
}

/// A generate request whose authority tokens are pre-signed, plus the issuer
/// keys needed to verify the resulting packet.
///
/// Mirrors `src/test_support::sample_generate_request`, which is
/// `#[cfg(test)]` and therefore unreachable from here. It is deliberately a
/// second, independent fixture rather than a shared one: making the unit-test
/// fixture public would put test scaffolding on the crate's production
/// surface, which is a worse trade than forty duplicated lines of setup.
pub fn sample_generate_request() -> (GenerateRequest, HashMap<String, String>) {
    let (cfo_aid, cfo_kp) = create_identity(prov("cfo"), None).expect("cfo identity");
    let (orch_aid, orch_kp) = create_identity(prov("orch"), None).expect("orchestrator identity");
    let (agent_aid, agent_kp) = create_identity(prov("agent"), None).expect("agent identity");

    // The request carries the agent's seed, so the provenance the service
    // will hash must be the provenance the identity was derived from —
    // otherwise the derived AIP-ID would not match and the packet's
    // delegation hop would name the wrong subject.
    let agent_prov = ProvenanceInput {
        model: "model:agent".into(),
        environment: "env:agent".into(),
        toolchain: "tool:agent".into(),
    };
    debug_assert_eq!(
        agent_prov.to_triple(),
        agent_aid.provenance,
        "the fixture's provenance strings must hash to the identity's triple"
    );

    let root_token = issue_scoped_token(
        &cfo_aid.id,
        &cfo_kp.private_key,
        &orch_aid.id,
        scope_orchestrator(),
        Some(CENTURY_MS),
    )
    .expect("root token");
    let hop = create_delegation(
        &root_token,
        &orch_kp.private_key,
        &agent_aid.id,
        scope_submitter(),
    )
    .expect("delegation hop");

    let req = GenerateRequest {
        agent_seed_hex: hex::encode(&agent_kp.private_key),
        provenance: agent_prov,
        principal_id: cfo_aid.id.clone(),
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

    let issuers = HashMap::from([
        (cfo_aid.id, hex::encode(&cfo_kp.public_key)),
        (orch_aid.id, hex::encode(&orch_kp.public_key)),
    ]);
    (req, issuers)
}

// ── HTTP-level fixtures ───────────────────────────────────────────────────────

/// An `ApiKeyStore` holding one machine key with secret `secret`, for tenant
/// `tenant`.
///
/// Written to a file and loaded through `ApiKeyStore::load` — the production
/// path — because the in-crate `from_entries` constructor is `#[cfg(test)]`.
/// Going through the real loader is the better test anyway: it exercises the
/// format an operator actually writes.
pub fn api_key_store(secret: &str, tenant: &str) -> (airon_aip::auth::ApiKeyStore, PathBuf) {
    let mut path = std::env::temp_dir();
    path.push(format!("aip_it_keys_{}.json", uuid::Uuid::new_v4()));
    let digest = hex::encode(aip_crypto::sha256(secret.as_bytes()));
    std::fs::write(
        &path,
        serde_json::json!({
            "keys": [{
                "key_id": "k-test",
                "secret_sha256": digest,
                "tenant_id": tenant,
                "role": "machine",
            }]
        })
        .to_string(),
    )
    .expect("write api keys file");
    let store = airon_aip::auth::ApiKeyStore::load(path.to_str().expect("utf-8 path"));
    assert!(!store.is_empty(), "the fixture key file must load");
    (store, path)
}

/// Build an `AppState` for in-process router tests.
///
/// Constructed field by field from the crate's public API rather than by
/// exposing `src/test_support`, which is `#[cfg(test)]`. Same reasoning as
/// above: test scaffolding does not belong on the production surface, and
/// `AppState`'s fields are already public.
pub fn app_state(
    store: std::sync::Arc<dyn airon_aip::store::EvidenceStore>,
    api_keys: airon_aip::auth::ApiKeyStore,
    managed_signing: airon_aip::ManagedSigning,
) -> std::sync::Arc<airon_aip::AppState> {
    let kp = airon_aip::keys::ServiceKey::generate();
    let encoding_key = kp.encoding_key();
    let decoding_key = kp.decoding_key();
    let mut p = std::env::temp_dir();
    p.push(format!("aip_it_logs_{}", uuid::Uuid::new_v4()));
    let log_path = p.to_str().expect("utf-8 path").to_owned();

    std::sync::Arc::new(airon_aip::AppState {
        encoding_key,
        decoding_key,
        public_pem: kp.public_pem.clone(),
        fingerprint: kp.fingerprint.clone(),
        revocation_log_path: log_path.clone(),
        revocation_set: airon_aip::revocation::load_revocation_set(&log_path),
        store,
        artifacts: std::sync::Arc::new(airon_aip::artifacts::JsonlArtifactStore::in_memory()),
        api_keys,
        signer: std::sync::Arc::new(kp),
        metrics: std::sync::Arc::new(Default::default()),
        managed_signing,
    })
}

/// The JSON body of a generate request.
///
/// Built as JSON rather than by deriving `Serialize` on `GenerateRequest`:
/// that type is deliberately deserialize-only, and adding a `Serialize` impl
/// so a test could round-trip it would create a second, sanctioned way for a
/// private seed to be written out — which is the defect under test.
///
/// Returns the body and the seed it carries. `substitute_seed` replaces the
/// fixture's own seed with a distinctive value, for tests that need to search
/// a response for it; `None` keeps the real seed so generation succeeds.
pub fn generate_request_json(substitute_seed: Option<&str>) -> String {
    let (req, _) = sample_generate_request();
    let seed = substitute_seed.unwrap_or(&req.agent_seed_hex);
    serde_json::json!({
        "agent_seed_hex": seed,
        "provenance": {
            "model": req.provenance.model,
            "environment": req.provenance.environment,
            "toolchain": req.provenance.toolchain,
        },
        "principal_id": req.principal_id,
        "principal_role": req.principal_role,
        "root_token": req.root_token,
        "delegation_chain": req.delegation_chain,
        "decision": {
            "action_kind": req.decision.action_kind,
            "summary": req.decision.summary,
            "input": req.decision.input,
            "rationale": req.decision.rationale,
        },
        "actions": req.actions.iter().map(|a| serde_json::json!({
            "action_kind": a.action_kind,
            "description": a.description,
            "payload": a.payload,
        })).collect::<Vec<_>>(),
        "claimed_trust_floor": req.claimed_trust_floor,
    })
    .to_string()
}

// ── Replay fixtures ───────────────────────────────────────────────────────────

/// Two distinct packets that share a decision id, plus the issuer keys for
/// both.
///
/// This is what a replay actually looks like: same agent, same authority,
/// same decision, different packets. Two calls to [`packet_dated`] cannot
/// produce it — each draws a fresh decision id — so the pair is built from
/// one chain here.
pub fn replay_pair() -> (EvidencePacket, EvidencePacket, HashMap<String, String>) {
    let (cfo_aid, cfo_kp) = create_identity(prov("cfo"), None).expect("cfo identity");
    let (orch_aid, orch_kp) = create_identity(prov("orch"), None).expect("orchestrator identity");
    let (agent_aid, agent_kp) = create_identity(prov("agent"), None).expect("agent identity");

    let root_token = issue_scoped_token(
        &cfo_aid.id,
        &cfo_kp.private_key,
        &orch_aid.id,
        scope_orchestrator(),
        Some(CENTURY_MS),
    )
    .expect("root token");
    let hop = create_delegation(
        &root_token,
        &orch_kp.private_key,
        &agent_aid.id,
        scope_submitter(),
    )
    .expect("delegation hop");

    let at = hop.issued_at.max(root_token.issued_at);
    let decision_id = [0xD0u8; 16];

    // Two packets differing only in the action payload, so they have
    // different packet ids and different action ids while claiming the same
    // decision.
    let seal = |payload: &[u8], offset: u64| -> EvidencePacket {
        let decision = DecisionRecord {
            decision_id,
            action_kind: ScopeAction::Standard(Action::Write),
            summary: "approve payment".into(),
            input_hash: sha256(b"invoice INV-1"),
            rationale_hash: sha256(b"3-way match ok"),
            decided_at: at,
        };
        let action = ActionAttestation::create(
            &agent_aid.id,
            &agent_kp.private_key,
            &decision_id,
            ScopeAction::Standard(Action::Write),
            "POST /ledger/payments",
            sha256(payload),
            at + offset,
        )
        .expect("action attestation");
        EvidencePacketBuilder::new(
            AgentIdentitySummary {
                aip_id: agent_aid.id.clone(),
                public_key: PublicKey {
                    algorithm: AlgorithmId::Ed25519,
                    key_bytes: agent_kp.public_key.clone(),
                },
                provenance: agent_aid.provenance.clone(),
            },
            RootAuthority {
                principal_id: cfo_aid.id.clone(),
                display_role: "CFO".into(),
                root_token: root_token.clone(),
            },
        )
        .delegation_chain(vec![hop.clone()])
        .decision(decision)
        .action(action)
        .claimed_trust_floor(TrustFloor::AuthorityBound)
        .build_and_sign(&agent_kp.private_key)
        .expect("seal packet")
    };

    let first = seal(b"pay 1000", 1);
    let second = seal(b"pay 9999", 2);
    assert_ne!(
        first.packet_id, second.packet_id,
        "the pair must be two distinct packets, or the fixture proves nothing"
    );
    assert_eq!(first.decision.decision_id, second.decision.decision_id);

    let issuers = HashMap::from([
        (cfo_aid.id, hex::encode(&cfo_kp.public_key)),
        (orch_aid.id, hex::encode(&orch_kp.public_key)),
    ]);
    (first, second, issuers)
}
