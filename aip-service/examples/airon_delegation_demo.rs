use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt, path::PathBuf};

use aip_core::{
    capability::{issue_scoped_token, scope_orchestrator, scope_submitter},
    create_identity,
    delegation::create_delegation_with_signer,
};
use aip_crypto::custody::InMemoryCustodian;
use aip_types::ProvenanceTriple;
use serde::Serialize;

const TENANT: &str = "airon-local-demo";
const TOKEN_TTL_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Serialize)]
struct TrustAnchor {
    tenant_id: String,
    agent_id: String,
    public_key_hex: String,
}

#[derive(Serialize)]
struct TrustFile {
    anchors: Vec<TrustAnchor>,
}

#[derive(Serialize)]
struct VerifyRequest {
    root_token: aip_types::ScopedToken,
    chain: Vec<aip_types::DelegationToken>,
}

fn write_new_private(path: &PathBuf, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let home = std::env::var("HOME")?;
    let out = match std::env::var_os("AIP_DEMO_OUT_DIR") {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(home).join(".local/share/airon-aip-demo"),
    };
    std::fs::create_dir_all(&out)?;

    let provenance = ProvenanceTriple {
        model_commitment: [1u8; 32],
        environment_commitment: [2u8; 32],
        toolchain_commitment: [3u8; 32],
    };

    // Generate three independent AIP identities in memory.
    let (authority, authority_keys) = create_identity(provenance.clone(), None)?;

    let (orchestrator, orchestrator_keys) = create_identity(provenance.clone(), None)?;

    let (submitter, _submitter_keys) = create_identity(provenance, None)?;

    // Authority grants the orchestrator its permitted scope.
    let root_token = issue_scoped_token(
        &authority.id,
        &authority_keys.private_key,
        &orchestrator.id,
        scope_orchestrator(),
        Some(TOKEN_TTL_MS),
    )?;

    // The orchestrator delegates a narrower scope to the submitter.
    let orchestrator_signer = InMemoryCustodian::new(
        &orchestrator_keys.private_key,
        &orchestrator_keys.public_key,
    )?;

    let delegation = create_delegation_with_signer(
        &root_token,
        &orchestrator_signer,
        &submitter.id,
        scope_submitter(),
    )
    .map_err(|e| format!("delegation signing failed: {e:?}"))?;

    // Only public keys are written to the institution trust configuration.
    let trust = TrustFile {
        anchors: vec![
            TrustAnchor {
                tenant_id: TENANT.into(),
                agent_id: authority.id.clone(),
                public_key_hex: hex::encode(&authority_keys.public_key),
            },
            TrustAnchor {
                tenant_id: TENANT.into(),
                agent_id: orchestrator.id.clone(),
                public_key_hex: hex::encode(&orchestrator_keys.public_key),
            },
        ],
    };

    let request = VerifyRequest {
        root_token,
        chain: vec![delegation],
    };

    let trust_path = out.join("agent-trust.json");
    let request_path = out.join("delegation-request.json");

    let trust_json = serde_json::to_vec_pretty(&trust)?;
    let request_json = serde_json::to_vec_pretty(&request)?;

    write_new_private(&trust_path, &trust_json)?;
    write_new_private(&request_path, &request_json)?;

    println!("AIRON AIP delegation demo generated.");
    println!("Tenant:             {TENANT}");
    println!("Authority AIP-ID:   {}", authority.id);
    println!("Orchestrator AIP-ID: {}", orchestrator.id);
    println!("Submitter AIP-ID:   {}", submitter.id);
    println!("Delegation depth:   1");
    println!("Authority anchors:  2");
    println!("Trust file:         {}", trust_path.display());
    println!("Request file:       {}", request_path.display());
    println!("Private keys:       kept in memory; not exported");

    Ok(())
}
