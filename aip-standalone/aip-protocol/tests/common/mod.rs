//! Shared fixture for the bundle suites.
//!
//! Extracted from `bundle.rs` so `signer_anchored.rs` builds the same
//! bundle rather than a lookalike: a Phase B test that anchored a
//! differently-constructed packet would be testing its own fixture.

#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{Cursor, Read, Write};

use aip_core::capability::{issue_scoped_token, scope_orchestrator, scope_submitter};
use aip_core::create_identity;
use aip_core::delegation::create_delegation;
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};
use aip_protocol::{
    verify_packet, ActionAttestation, AgentIdentitySummary, DecisionRecord, EvidencePacket,
    EvidencePacketBuilder, RootAuthority, TrustFloor, VerificationContext, VerificationReport,
};
use aip_types::{Action, AlgorithmId, ProvenanceTriple, PublicKey, ScopeAction};

pub fn prov(tag: &str) -> ProvenanceTriple {
    ProvenanceTriple {
        model_commitment: sha256(format!("m:{tag}").as_bytes()),
        environment_commitment: sha256(format!("e:{tag}").as_bytes()),
        toolchain_commitment: sha256(format!("t:{tag}").as_bytes()),
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Returns (packet, report, trust ctx, signer_seed, signer_public).
pub fn fixture() -> (
    EvidencePacket,
    VerificationReport,
    VerificationContext,
    [u8; 32],
    [u8; 32],
) {
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
        summary: "Approve payment INV-9 for $1,000".into(),
        input_hash: sha256(b"inv-9"),
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

    let ctx = VerificationContext::new()
        .trust_issuer(&cfo_id, &cfo_kp.public_key)
        .trust_issuer(&orch_aid.id, &orch_kp.public_key);
    let report = verify_packet(&packet, &ctx);
    assert!(report.valid);

    // Service signer key (distinct from agent/principal).
    let signer = generate_ed25519_keypair();
    let seed: [u8; 32] = signer.private_key.clone().try_into().unwrap();
    let public: [u8; 32] = signer.public_key.clone().try_into().unwrap();

    // The returned context anchors the bundle signer, because this fixture
    // is the "verifier already trusts the publisher" case and `Pass` now
    // means exactly that. A verifier that has not anchored the signer gets
    // a warning instead, which is what `VerificationContext::new()` is for
    // in the tests below.
    let ctx = ctx.trust_bundle_signer("acme", &signer.public_key);

    (packet, report, ctx, seed, public)
}

/// Read a zip into a name→bytes map.
pub fn unzip(bytes: &[u8]) -> HashMap<String, Vec<u8>> {
    let mut a = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
    let mut m = HashMap::new();
    for i in 0..a.len() {
        let mut f = a.by_index(i).unwrap();
        let name = f.name().to_string();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        m.insert(name, buf);
    }
    m
}

/// Rebuild a zip from a name→bytes map (for crafting tampered bundles).
pub fn rezip(files: &HashMap<String, Vec<u8>>) -> Vec<u8> {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut zw = zip::ZipWriter::new(&mut cursor);
        let opts = zip::write::SimpleFileOptions::default();
        for (name, bytes) in files {
            zw.start_file(name, opts).unwrap();
            zw.write_all(bytes).unwrap();
        }
        zw.finish().unwrap();
    }
    cursor.into_inner()
}
