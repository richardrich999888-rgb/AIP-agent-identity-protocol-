//! AIP CLI — Command-line tool for the Agent Identity Protocol.
//!
//! Commands:
//!   create-identity  Create a new agent identity
//!   sign             Sign a payload with a stored identity
//!   verify           Verify a signature
//!   challenge        Issue and verify a liveness challenge
//!   list             List stored identities
//!   simulate         Run multi-node verification simulation

use aip_core::nonce::NonceTracker;
use aip_core::runtime::bind_identity_to_runtime;
use aip_core::simulation::simulate_network_verification;
use aip_core::store::{IdentityStore, Persistence};
use aip_core::*;
use aip_crypto::*;
use aip_types::*;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// AIP CLI — Agent Identity Protocol command-line tool.
#[derive(Parser)]
#[command(name = "aip-cli", version, about = "Agent Identity Protocol CLI")]
struct Cli {
    /// Path to the identity store file.
    #[arg(long, default_value = "aip_store.json")]
    store: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new agent identity.
    CreateIdentity {
        /// Model name for provenance commitment.
        #[arg(long, default_value = "default-model")]
        model: String,
        /// Environment label.
        #[arg(long, default_value = "local")]
        env: String,
    },

    /// Sign a payload with a stored identity.
    Sign {
        /// AIP-ID of the signing agent (uses first identity if not specified).
        #[arg(long)]
        agent_id: Option<String>,
        /// Payload to sign.
        #[arg(long)]
        payload: String,
    },

    /// Verify a signature (provide JSON on stdin or via --signature-json).
    Verify {
        /// AIP-ID of the signer.
        #[arg(long)]
        agent_id: String,
        /// Signature JSON string.
        #[arg(long)]
        signature_json: String,
    },

    /// Issue a liveness challenge to a stored identity and verify response.
    Challenge {
        /// AIP-ID of the target agent to challenge.
        #[arg(long)]
        target_id: String,
    },

    /// List all stored identities.
    List,

    /// Run a multi-node verification simulation.
    Simulate {
        /// Number of agents to simulate.
        #[arg(long, default_value = "5")]
        agents: usize,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::CreateIdentity { model, env } => {
            cmd_create_identity(&cli.store, &model, &env);
        }
        Commands::Sign { agent_id, payload } => {
            cmd_sign(&cli.store, agent_id.as_deref(), &payload);
        }
        Commands::Verify {
            agent_id,
            signature_json,
        } => {
            cmd_verify(&cli.store, &agent_id, &signature_json);
        }
        Commands::Challenge { target_id } => {
            cmd_challenge(&cli.store, &target_id);
        }
        Commands::List => {
            cmd_list(&cli.store);
        }
        Commands::Simulate { agents } => {
            cmd_simulate(agents);
        }
    }
}

fn cmd_create_identity(store_path: &PathBuf, model: &str, env: &str) {
    let mut store = load_store(store_path);

    let provenance = ProvenanceTriple {
        model_commitment: sha256(model.as_bytes()),
        environment_commitment: sha256(env.as_bytes()),
        toolchain_commitment: sha256(b"aip-cli-v0.3.0"),
    };

    let (mut aid, kp) = create_identity(provenance, None).expect("Failed to create identity");
    let agent_id = aid.id.clone();

    // Activate immediately
    activate_identity(&mut aid).expect("Failed to activate");

    // Bind to runtime
    let binding = bind_identity_to_runtime(&agent_id);

    store.put_identity(aid, kp);
    store.save().expect("Failed to save store");

    println!("✓ Identity created and activated");
    println!("  AIP-ID:        {}", agent_id);
    println!("  Model:         {}", model);
    println!("  Environment:   {}", env);
    println!("  Status:        Active");
    println!("  Runtime hash:  {}", hex(&binding.runtime_hash));
    println!("  Stored in:     {}", store_path.display());
}

fn cmd_sign(store_path: &PathBuf, agent_id: Option<&str>, payload: &str) {
    let store = load_store(store_path);

    let id = match agent_id {
        Some(id) => id.to_string(),
        None => {
            let ids = store.list_identities();
            if ids.is_empty() {
                eprintln!("✗ No identities found. Run 'create-identity' first.");
                std::process::exit(1);
            }
            ids[0].to_string()
        }
    };

    let entry = match store.get_identity(&id) {
        Some(e) => e,
        None => {
            eprintln!("✗ Identity not found: {}", id);
            std::process::exit(1);
        }
    };

    let sig =
        sign_ed25519(&entry.keypair.private_key, &id, payload.as_bytes()).expect("Failed to sign");

    let sig_json = serde_json::to_string_pretty(&sig).expect("Failed to serialize");

    println!("✓ Payload signed by {}", id);
    println!("{}", sig_json);
}

fn cmd_verify(store_path: &PathBuf, agent_id: &str, signature_json: &str) {
    let store = load_store(store_path);

    let sig: Signature = match serde_json::from_str(signature_json) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("✗ Invalid signature JSON: {}", e);
            std::process::exit(1);
        }
    };

    let entry = match store.get_identity(agent_id) {
        Some(e) => e,
        None => {
            eprintln!("✗ Identity not found: {}", agent_id);
            std::process::exit(1);
        }
    };

    // Nonce/freshness check
    let mut tracker = NonceTracker::new();
    match tracker.validate_and_record(&sig) {
        Ok(()) => {}
        Err(AipError::SignatureExpired) => {
            eprintln!("✗ Signature expired (too old or too far in the future)");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("✗ Nonce check failed: {:?}", e);
            std::process::exit(1);
        }
    }

    match verify_ed25519(&entry.keypair.public_key, &sig) {
        Ok(true) => {
            println!("✓ Signature VALID");
            println!("  Signer:     {}", sig.signer_id);
            println!("  Timestamp:  {}", sig.timestamp);
            println!("  Payload:    {}", hex(&sig.payload_hash));
        }
        Ok(false) => {
            eprintln!("✗ Signature INVALID — cryptographic verification failed");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("✗ Verification error: {:?}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_challenge(store_path: &PathBuf, target_id: &str) {
    let store = load_store(store_path);

    let entry = match store.get_identity(target_id) {
        Some(e) => e,
        None => {
            eprintln!("✗ Identity not found: {}", target_id);
            std::process::exit(1);
        }
    };

    println!("Issuing liveness challenge to {}...", target_id);

    let challenge = issue_liveness_challenge("aip-cli", target_id);
    let response = respond_to_challenge(&challenge, &entry.keypair.private_key, target_id)
        .expect("Failed to create response");

    match verify_liveness(&challenge, &response, &entry.keypair.public_key) {
        Ok(true) => {
            println!("✓ Liveness challenge PASSED");
            println!("  Target:      {}", target_id);
            println!("  Response at: {} ms", response.responded_at);
            println!("  Proof:       {}", hex(&response.proof));
        }
        Ok(false) => {
            eprintln!("✗ Liveness challenge FAILED");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("✗ Liveness verification error: {:?}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_list(store_path: &PathBuf) {
    let store = load_store(store_path);
    let ids = store.list_identities();

    if ids.is_empty() {
        println!("No identities stored.");
        return;
    }

    println!("{} identities stored:\n", ids.len());
    for id in ids {
        let entry = store.get_identity(id).unwrap();
        println!("  ID:      {}", entry.aid.id);
        println!("  Status:  {:?}", entry.aid.status);
        println!("  Created: {} ms", entry.aid.created_at);
        println!("  Seq:     {}", entry.aid.sequence);
        println!();
    }
}

fn cmd_simulate(agent_count: usize) {
    println!(
        "Running multi-node verification simulation with {} agents...\n",
        agent_count
    );

    let result = simulate_network_verification(agent_count);

    for line in &result.log {
        println!("{}", line);
    }

    println!();
    println!("╔══════════════════════════════════════╗");
    println!("║     SIMULATION RESULTS               ║");
    println!("╠══════════════════════════════════════╣");
    println!(
        "║ Agents created:          {:>5}       ║",
        result.agents_created
    );
    println!(
        "║ Verifications passed:    {:>5}       ║",
        result.verifications_passed
    );
    println!(
        "║ Liveness passed:         {:>5}       ║",
        result.liveness_challenges_passed
    );
    println!(
        "║ Replays rejected:        {:>5}       ║",
        result.replay_attacks_rejected
    );
    println!(
        "║ Reputation votes:        {:>5}       ║",
        result.reputation_votes_cast
    );
    println!(
        "║ All passed:              {:>5}       ║",
        result.all_passed
    );
    println!("╚══════════════════════════════════════╝");

    if !result.all_passed {
        std::process::exit(1);
    }
}

/// The CLI is a development tool and its store is a development store: it
/// writes private keys to disk (owner-only, but in the clear). Production
/// deployments keep signing keys in a custodian — see
/// `aip_crypto::custody` and `docs/adr/ADR-KEY-CUSTODY.md`.
fn load_store(path: &PathBuf) -> IdentityStore {
    IdentityStore::with_file(path, Persistence::DevelopmentPlaintext).unwrap_or_else(|e| {
        eprintln!("Warning: Could not load store ({}), using empty store", e);
        IdentityStore::new()
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
