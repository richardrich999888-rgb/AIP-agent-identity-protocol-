use std::{fs, path::PathBuf, time::SystemTime};

use aip_core::passport::{canonical_passport_body_bytes, AgentPassport};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

#[derive(Debug, Parser)]
#[command(
    name = "airon-passport",
    version,
    about = "Verify AIP AgentPassport documents offline"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Verify an AgentPassport JSON document.
    Verify {
        /// Passport JSON file.
        file: PathBuf,
        /// Override current Unix time for deterministic tests.
        #[arg(long)]
        now: Option<u64>,
    },
}

fn main() {
    match run() {
        Ok(exit) => std::process::exit(exit),
        Err(error) => {
            eprintln!("airon-passport: {error}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<i32, String> {
    let cli = Cli::parse();
    match cli.command {
        Command::Verify { file, now } => verify_file(file, now),
    }
}

fn verify_file(file: PathBuf, now: Option<u64>) -> Result<i32, String> {
    let raw = fs::read_to_string(&file)
        .map_err(|e| format!("failed to read passport {}: {e}", file.display()))?;
    let passport: AgentPassport =
        serde_json::from_str(&raw).map_err(|e| format!("passport JSON parse failed: {e}"))?;

    match verify_passport(&passport, now.unwrap_or_else(now_unix_seconds)) {
        Ok(()) => {
            println!("PASS AgentPassport");
            println!("  passport_id: {}", passport.body.passport_id);
            println!("  agent_id: {}", passport.body.subject.agent_id);
            println!(
                "  capabilities: {}",
                passport.body.constraints.capabilities.join(",")
            );
            println!("  expires_at: {}", passport.body.constraints.expires_at);
            Ok(0)
        }
        Err(reason) => {
            eprintln!("TOXIC AgentPassport");
            eprintln!("  reason: {reason}");
            eprintln!("  passport_id: {}", passport.body.passport_id);
            eprintln!("  agent_id: {}", passport.body.subject.agent_id);
            Ok(2)
        }
    }
}

fn verify_passport(passport: &AgentPassport, now_unix_seconds: u64) -> Result<(), String> {
    if passport.header.alg != "Ed25519" {
        return Err(format!(
            "unsupported passport algorithm in Phase 1 verifier: {}",
            passport.header.alg
        ));
    }
    if passport.proof.pqc_signature.is_some() {
        return Err("PQC signature verification is not enabled in this Phase 1 verifier".into());
    }

    passport
        .structural_check()
        .map_err(|e| format!("structural check failed: {e}"))?;
    passport
        .temporal_check(now_unix_seconds)
        .map_err(|e| format!("temporal check failed: {e}"))?;

    let public_key_bytes = B64URL
        .decode(passport.body.issuer.classical_pubkey.as_bytes())
        .map_err(|e| format!("issuer public key decode failed: {e}"))?;
    let public_key: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| "issuer classical public key must be 32 bytes".to_owned())?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|e| format!("issuer public key parse failed: {e}"))?;

    let signature_bytes = B64URL
        .decode(passport.proof.signature.as_bytes())
        .map_err(|e| format!("passport signature decode failed: {e}"))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|e| format!("passport signature parse failed: {e}"))?;
    let body_bytes = canonical_passport_body_bytes(&passport.body)
        .map_err(|e| format!("canonical body encoding failed: {e}"))?;

    verifying_key
        .verify(&body_bytes, &signature)
        .map_err(|_| "passport Ed25519 signature mismatch".to_owned())
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
