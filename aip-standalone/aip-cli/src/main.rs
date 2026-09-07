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
use aip_core::store::IdentityStore;
use aip_core::*;
use aip_crypto::*;
use aip_custody::{CustodyPolicy, FileCustodian, KeyCustody};
use aip_types::*;
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

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

    // The private key goes to its own custodian file before anything else. If
    // this fails the identity is not recorded at all — an entry in the store
    // with no key behind it is an identity nobody can ever speak for, and
    // silently creating one is worse than failing here.
    let key_file = key_path(store_path, &agent_id);
    if let Err(e) = aip_custody::ensure_secret_dir(&key_dir(store_path)) {
        eprintln!("✗ Could not prepare the key directory: {e}");
        std::process::exit(1);
    }
    let custodian = FileCustodian::create(&key_file, &agent_id, 0, &kp.private_key, &kp.public_key)
        .unwrap_or_else(|e| {
            eprintln!("✗ Could not store the signing key: {e}");
            std::process::exit(1);
        });

    store.put_public_identity(aid);
    store.save().expect("Failed to save store");

    println!("✓ Identity created and activated");
    println!("  AIP-ID:        {}", agent_id);
    println!("  Model:         {}", model);
    println!("  Environment:   {}", env);
    println!("  Status:        Active");
    println!("  Runtime hash:  {}", hex(&binding.runtime_hash));
    println!("  Stored in:     {}", store_path.display());
    println!("  Signing key:   {}", custodian.path().display());
    println!("  Custody:       {:?}", custodian.custody_class());
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

    if store.get_identity(&id).is_none() {
        eprintln!("✗ Identity not found: {}", id);
        std::process::exit(1);
    }

    let custodian = load_custodian(store_path, &id);
    let sig =
        aip_custody::sign_envelope(&custodian, &id, payload.as_bytes()).expect("Failed to sign");

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

    match verify_ed25519(entry.public_key(), &sig) {
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
    let custodian = load_custodian(store_path, target_id);
    let sig = aip_custody::sign_envelope(&custodian, target_id, &challenge.nonce)
        .expect("Failed to sign the challenge nonce");
    let response = assemble_liveness_response(&challenge, sig, target_id);

    match verify_liveness(&challenge, &response, entry.public_key()) {
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

/// Open the identity store, or exit.
///
/// This used to fall back to an empty in-memory store on any load error and
/// print a warning. That is the same defect class as `load_or_generate`: the
/// next `save()` would rewrite the file from the empty store and delete every
/// identity it held. A store that cannot be read is a stop condition, not a
/// warning.
fn load_store(path: &PathBuf) -> IdentityStore {
    IdentityStore::with_file(path).unwrap_or_else(|e| {
        eprintln!("✗ Could not open the identity store at {}", path.display());
        eprintln!("  {e}");
        eprintln!("  Refusing to continue with an empty store: saving one would");
        eprintln!("  overwrite the file and destroy the identities it holds.");
        std::process::exit(1);
    })
}

/// Where the private keys for `store_path` live: a sibling directory at mode
/// 0700, one `FileCustodian` file per identity.
///
/// Keys are deliberately *not* in the store file. The store holds public
/// identity documents and reputation records; key material is the custodian's,
/// with its own permissions and its own lifecycle.
fn key_dir(store_path: &Path) -> PathBuf {
    let mut dir = store_path.as_os_str().to_owned();
    dir.push(".keys");
    PathBuf::from(dir)
}

fn key_path(store_path: &Path, agent_id: &str) -> PathBuf {
    // AIP-IDs are base58 with a fixed prefix and contain no path separators
    // (validate_aip_id enforces the alphabet), so this cannot escape the
    // directory. Checked rather than assumed:
    if agent_id.contains('/') || agent_id.contains('\\') || agent_id.contains("..") {
        eprintln!("✗ Refusing to use {agent_id} as a file name");
        std::process::exit(1);
    }
    key_dir(store_path).join(format!("{agent_id}.key"))
}

/// Load the custodian for `agent_id`, or exit.
///
/// Checks the deployment's custody policy before returning: a custodian whose
/// class the policy does not admit is refused here rather than used and
/// regretted.
fn load_custodian(store_path: &Path, agent_id: &str) -> FileCustodian {
    let path = key_path(store_path, agent_id);
    let custodian = FileCustodian::load(&path).unwrap_or_else(|e| {
        eprintln!("✗ No usable signing key for {agent_id}");
        eprintln!("  {e}");
        std::process::exit(1);
    });
    if let Err(e) = aip_custody::admits(CustodyPolicy::from_env(), &custodian) {
        eprintln!("✗ {e}");
        std::process::exit(1);
    }
    custodian
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
