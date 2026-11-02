//! Operator-side adapters around existing AIP authorization and verification.
//! No signing configuration is accepted from monitored agent input.

use std::{collections::BTreeMap, io::Read, path::Path};

use aip_core::{capability::issue_scoped_token, execution_binding::collect_binding_for_pid};
use aip_crypto::{derive_aip_id, generate_ed25519_keypair, sha256};
use aip_mcp_gateway::assurance::{
    authorize_measured, check_authorization, evaluate_run, public_key, AllowedCall,
    AuthorityConfig, RunBundle, RunTrustConfig,
};
use aip_types::{CapabilityScope, ProvenanceTriple};
use serde::Deserialize;
use serde_json::{json, Value};

const MAX_INPUT: u64 = 16 * 1024 * 1024;

fn read_config<T: serde::de::DeserializeOwned>(path: &Path, private: bool) -> Result<T, String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| "cannot inspect configured file")?;
    if !metadata.is_file() || metadata.len() > MAX_INPUT {
        return Err("configuration must be a bounded regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let forbidden = if private { 0o077 } else { 0o022 };
        if metadata.permissions().mode() & forbidden != 0 {
            return Err(
                "configuration permissions permit unauthorized access or modification".into(),
            );
        }
    }
    let text = std::fs::read(path).map_err(|_| "cannot read configured file")?;
    serde_json::from_slice(&text).map_err(|_| "invalid configured JSON".into())
}

fn trust() -> Result<RunTrustConfig, String> {
    let path = std::env::var("AIP_RUN_TRUST_FILE").map_err(|_| "AIP_RUN_TRUST_FILE is required")?;
    let trust: RunTrustConfig = read_config(Path::new(&path), false)?;
    trust.validate()?;
    Ok(trust)
}

fn write_private(path: &Path, content: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| "refusing to replace provisioned file")?;
    file.write_all(content)
        .map_err(|_| "cannot write provisioned file")?;
    file.sync_all()
        .map_err(|_| "cannot sync provisioned file".into())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Init {
    directory: String,
    model_id: String,
    allowed_calls: Vec<AllowedCall>,
    observer_id: String,
    observer_public_key_hex: String,
}

fn initialize(input: &[u8]) -> Result<Value, String> {
    let request: Init = serde_json::from_slice(input).map_err(|_| "invalid provision request")?;
    if request.model_id.is_empty()
        || request.model_id.len() > 512
        || request.allowed_calls.is_empty()
        || request.allowed_calls.len() > 128
        || request.allowed_calls.iter().any(|call| {
            !call.arguments.is_object()
                || aip_authorize::tool_invoke_parameters(
                    &call.tool_id,
                    aip_mcp_gateway::parameter_commitment(&call.arguments),
                )
                .is_err()
        })
    {
        return Err(
            "provisioning requires a model and explicit bounded tool/resource policy".into(),
        );
    }
    let directory = Path::new(&request.directory);
    if !directory.is_absolute() {
        return Err("provisioning directory must be absolute".into());
    }
    if !directory.exists() {
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(directory)
            .map_err(|_| "cannot create protected provisioning directory")?;
    }
    let metadata = std::fs::symlink_metadata(directory)
        .map_err(|_| "cannot inspect provisioning directory")?;
    if !metadata.is_dir() {
        return Err("provisioning directory is not a directory".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("provisioning directory must be owner-only".into());
        }
    }
    let provenance = ProvenanceTriple {
        model_commitment: sha256(request.model_id.as_bytes()),
        environment_commitment: sha256(b"isolated-runtime-validation"),
        toolchain_commitment: sha256(env!("CARGO_PKG_VERSION").as_bytes()),
    };
    let agent = generate_ed25519_keypair();
    let issuer = generate_ed25519_keypair();
    let authority = generate_ed25519_keypair();
    let gateway = generate_ed25519_keypair();
    let reconciler = generate_ed25519_keypair();
    let agent_id = derive_aip_id(&agent.public_key, &provenance);
    let issuer_id = derive_aip_id(&issuer.public_key, &provenance);
    let authority_id = derive_aip_id(&authority.public_key, &provenance);
    let gateway_id = derive_aip_id(&gateway.public_key, &provenance);
    let reconciler_id = derive_aip_id(&reconciler.public_key, &provenance);
    let root = issue_scoped_token(
        &issuer_id,
        &issuer.private_key,
        &agent_id,
        CapabilityScope {
            allowed: vec![aip_authorize::tool_invoke_action()],
            denied: vec![],
        },
        Some(3_600_000),
    )
    .map_err(|_| "cannot issue independently signed root scope")?;
    let authority_key_path = directory.join("decision.key");
    let gateway_key_path = directory.join("gateway.key");
    let reconciler_key_path = directory.join("reconciler.key");
    let authority_path = directory.join("authority.json");
    let trust_path = directory.join("trust.json");
    let config = AuthorityConfig {
        decision_point_id: authority_id.clone(),
        decision_key_file: authority_key_path.to_string_lossy().into_owned(),
        decision_public_key_hex: hex::encode(&authority.public_key),
        agent_id: agent_id.clone(),
        agent_public_key_hex: hex::encode(&agent.public_key),
        issuer_keys: BTreeMap::from([(issuer_id, hex::encode(&issuer.public_key))]),
        root_token: root,
        delegation_chain: vec![],
        allowed_calls: request.allowed_calls,
        max_ttl_ms: 60_000,
        requested_ttl_ms: 30_000,
    };
    let trust = RunTrustConfig {
        agent_id: agent_id.clone(),
        agent_public_key_hex: hex::encode(&agent.public_key),
        decision_point_id: authority_id,
        decision_point_public_key_hex: hex::encode(&authority.public_key),
        gateway_id: gateway_id.clone(),
        gateway_key_version: 1,
        gateway_public_key_hex: hex::encode(&gateway.public_key),
        observer_id: request.observer_id,
        observer_key_version: 1,
        observer_public_key_hex: request.observer_public_key_hex,
        reconciler_id: reconciler_id.clone(),
        reconciler_key_version: 1,
        reconciler_public_key_hex: hex::encode(&reconciler.public_key),
        checkpoints: BTreeMap::new(),
        health_max_age_ms: 60_000,
        window_tolerance_ms: 0,
    };
    trust.validate()?;
    write_private(
        &authority_key_path,
        hex::encode(&authority.private_key).as_bytes(),
    )?;
    write_private(
        &gateway_key_path,
        hex::encode(&gateway.private_key).as_bytes(),
    )?;
    write_private(
        &reconciler_key_path,
        hex::encode(&reconciler.private_key).as_bytes(),
    )?;
    write_private(
        &directory.join("agent.key"),
        hex::encode(&agent.private_key).as_bytes(),
    )?;
    // The root issuer key is not needed by the runtime authority. Retaining
    // it only inside this owner-only directory supports an operator audit.
    write_private(
        &directory.join("issuer.key"),
        hex::encode(&issuer.private_key).as_bytes(),
    )?;
    write_private(
        &authority_path,
        &serde_json::to_vec_pretty(&config).map_err(|_| "authority serialization")?,
    )?;
    write_private(
        &trust_path,
        &serde_json::to_vec_pretty(&trust).map_err(|_| "trust serialization")?,
    )?;
    Ok(
        json!({"agent_id": agent_id, "agent_public_key_hex":hex::encode(&agent.public_key),
        "authority_config_path":authority_path,"run_trust_path":trust_path,
        "gateway_key_path":gateway_key_path,"gateway_id":gateway_id,
        "gateway_public_key_hex":hex::encode(&gateway.public_key),
        "decision_point_id":config.decision_point_id,
        "decision_point_public_key_hex":config.decision_public_key_hex,
        "reconciler_key_path":reconciler_key_path,"reconciler_id":reconciler_id,
        "reconciler_public_key_hex":hex::encode(&reconciler.public_key),
        "authority_scope":"operator-owned exact canonical tool/resource allowlist; fresh disposable validation keys"}),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Authorize {
    agent_id: String,
    process_id: u32,
    tool_id: String,
    arguments: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Check {
    expectation: aip_authorize::ExpectedExecution,
    agent_id: String,
    tool_id: String,
    arguments: Value,
    received_at_ms: u64,
}

fn run() -> Result<Value, String> {
    let mode = std::env::args()
        .nth(1)
        .ok_or("expected init-authority, authorize, check-authorization or evaluate")?;
    let mut input = Vec::new();
    std::io::stdin()
        .take(MAX_INPUT + 1)
        .read_to_end(&mut input)
        .map_err(|_| "cannot read bounded request")?;
    if input.len() as u64 > MAX_INPUT {
        return Err("request exceeds 16 MiB".into());
    }
    match mode.as_str() {
        "init-authority" => initialize(&input),
        "authorize" => {
            let path = std::env::var("AIP_AUTHORITY_CONFIG")
                .map_err(|_| "AIP_AUTHORITY_CONFIG required")?;
            let config: AuthorityConfig = read_config(Path::new(&path), true)?;
            let request: Authorize =
                serde_json::from_slice(&input).map_err(|_| "invalid authorization request")?;
            if request.agent_id != config.agent_id {
                return Err("agent is outside configured authority policy".into());
            }
            let metadata = std::fs::symlink_metadata(&config.decision_key_file)
                .map_err(|_| "cannot inspect authority key")?;
            if !metadata.is_file() || metadata.len() > 256 {
                return Err("authority key must be a bounded regular hex file".into());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err("authority key must be owner-only".into());
                }
            }
            let secret = std::fs::read_to_string(&config.decision_key_file)
                .map_err(|_| "cannot read authority key")?;
            let key = public_key(secret.trim()).map_err(|_| "authority key must be 32-byte hex")?;
            let binding = collect_binding_for_pid(&config.agent_id, request.process_id)
                .map_err(|e| format!("independent process binding failed: {e:?}"))?;
            let repeated = collect_binding_for_pid(&config.agent_id, request.process_id)
                .map_err(|e| format!("process ended during binding: {e:?}"))?;
            if !binding.same_execution(&repeated) {
                return Err("process instance or executable changed during binding".into());
            }
            let expectation = authorize_measured(
                &config,
                &key,
                repeated,
                &request.tool_id,
                &request.arguments,
            )?;
            Ok(
                json!({"expectation":expectation,"agent_public_key_hex":config.agent_public_key_hex}),
            )
        }
        "check-authorization" => {
            let request: Check =
                serde_json::from_slice(&input).map_err(|_| "invalid authorization check")?;
            check_authorization(
                &request.expectation,
                &trust()?,
                &request.agent_id,
                &request.tool_id,
                &request.arguments,
                request.received_at_ms,
            )?;
            Ok(json!({"authorized":true}))
        }
        "evaluate" | "evaluate-and-sign" => {
            let bundle: RunBundle =
                serde_json::from_slice(&input).map_err(|_| "invalid run bundle")?;
            let trust = trust()?;
            let evaluation = evaluate_run(&bundle, &trust)?;
            if mode == "evaluate" {
                return serde_json::to_value(evaluation)
                    .map_err(|_| "evaluation serialization".into());
            }
            let key_path = std::env::var("AIP_RECONCILER_KEY_FILE")
                .map_err(|_| "AIP_RECONCILER_KEY_FILE is required")?;
            let metadata = std::fs::symlink_metadata(&key_path)
                .map_err(|_| "cannot inspect reconciler key")?;
            if !metadata.is_file() || metadata.len() > 256 {
                return Err("reconciler key must be a bounded regular hex file".into());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err("reconciler key must be owner-only".into());
                }
            }
            let secret =
                std::fs::read_to_string(key_path).map_err(|_| "cannot read reconciler key")?;
            let key =
                public_key(secret.trim()).map_err(|_| "reconciler key must be 32-byte hex")?;
            let public = public_key(&trust.reconciler_public_key_hex)?;
            if aip_crypto::public_key_from_private(&key).map_err(|_| "invalid reconciler key")?
                != public
            {
                return Err("reconciler key does not match independently configured anchor".into());
            }
            let signer = aip_reconcile::ReconcilerSigner::new(
                &trust.reconciler_id,
                trust.reconciler_key_version,
                &key,
                &public,
            )
            .map_err(|_| "cannot initialize reconciler signer")?;
            let reconciliation = evaluation
                .reconciliation
                .as_ref()
                .ok_or("cannot sign without an evaluated authorization")?;
            let signed = signer
                .sign(reconciliation)
                .map_err(|_| "cannot sign recomputed reconciliation")?;
            Ok(json!({"evaluation":evaluation,"signed_reconciliation":signed}))
        }
        _ => Err("expected init-authority, authorize, check-authorization or evaluate".into()),
    }
}

fn main() {
    match run() {
        Ok(result) => println!("{result}"),
        Err(error) => {
            // Messages are fixed classifications, never raw model/tool input
            // or signing configuration.
            eprintln!("aip-execution-assurance: {error}");
            std::process::exit(1);
        }
    }
}
