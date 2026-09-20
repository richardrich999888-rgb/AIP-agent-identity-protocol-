//! `ot-provision` — key custody and policy signing for the governed gateway.
//!
//! The operator-side counterpart to the gateway binaries: it holds the pens.
//! Keys are generated into permission-enforced files (see
//! [`ot_mcp_gateway::keyring`] for what that does and does not protect
//! against), edges are signed with them, and rotation is one command instead
//! of a by-hand sweep across a policy file.
//!
//! ```text
//! # An officer's signing key. Prints the identity to put in `issuers`.
//! ot-provision keygen --out officer.key
//!
//! # Sign every edge the officer issues, authorising the key in the same step.
//! ot-provision sign-edges --key officer.key \
//!     --issuer did:syntriass:officer:OFF-1 --policy mission.json
//!
//! # Rotate: re-sign the officer's edges with a new key, authorise it,
//! # withdraw the old identity — atomically on the document.
//! ot-provision rotate-issuer --old-identity <hex> --new-key officer-2.key \
//!     --issuer did:syntriass:officer:OFF-1 --policy mission.json
//!
//! # A supervisor approval for one specific invocation, for
//! # `_meta.governance.supervisorCoSignature`.
//! ot-provision cosign --key supervisor.key --agent did:... --edge edge-1 \
//!     --tool send_command --params '{"command":"SAFE_MODE"}' \
//!     --expires 2026-08-27T12:05:00.000Z
//!
//! # The enrolment digest of a client certificate, for `agent.credentials`.
//! ot-provision cert-digest --cert agent.pem
//! ```

use clap::{Parser, Subcommand};
use ot_accountability_core::{canonical_json, sha256_hex};
use ot_mcp_gateway::keyring::{generate_key_file, load_key_file};
use ot_mcp_gateway::pem::parse_pem;
use ot_mcp_gateway::provision::{
    credential_digest_of_der, rotate_issuer, sign_policy_edges, write_policy_atomically,
};
use ot_mcp_gateway::trust::sign_cosignature;
use ot_pqc::CryptoSuite;
use serde_json::Value;

#[derive(Parser, Debug)]
#[command(
    name = "ot-provision",
    about = "Key custody and policy signing for the governed MCP gateway",
    long_about = None
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate a signing key into a permission-enforced key file.
    Keygen {
        /// Where to write the key. Refuses to overwrite.
        #[arg(long, value_name = "FILE")]
        out: String,
    },
    /// Print a key file's identity, for `issuers` or `coSignatories`.
    Identity {
        #[arg(long, value_name = "FILE")]
        key: String,
    },
    /// Sign every delegation edge an issuer DID grants, in place, and
    /// authorise the signing key in the policy's `issuers`.
    SignEdges {
        #[arg(long, value_name = "FILE")]
        key: String,
        /// The DID whose edges this key signs for.
        #[arg(long, value_name = "DID")]
        issuer: String,
        #[arg(long, value_name = "FILE")]
        policy: String,
    },
    /// Rotate an issuer's key: re-sign its edges with the new key, authorise
    /// it, and withdraw the old identity — one atomic edit of the document.
    RotateIssuer {
        /// The 64-hex identity being withdrawn.
        #[arg(long, value_name = "HEX")]
        old_identity: String,
        /// The replacement key file.
        #[arg(long, value_name = "FILE")]
        new_key: String,
        #[arg(long, value_name = "DID")]
        issuer: String,
        #[arg(long, value_name = "FILE")]
        policy: String,
    },
    /// Produce a supervisor co-signature approving one specific invocation.
    Cosign {
        #[arg(long, value_name = "FILE")]
        key: String,
        /// The agent whose call is being approved.
        #[arg(long, value_name = "DID")]
        agent: String,
        /// The delegation edge the tool is held under.
        #[arg(long, value_name = "ID")]
        edge: String,
        #[arg(long, value_name = "NAME")]
        tool: String,
        /// The exact arguments being approved, as JSON. The approval binds to
        /// their digest: different arguments, invalid approval.
        #[arg(long, value_name = "JSON")]
        params: String,
        /// ISO-8601 UTC expiry. Keep it short — minutes, not days: an
        /// approval is for a call that is about to happen.
        #[arg(long, value_name = "TIMESTAMP")]
        expires: String,
    },
    /// Print the enrolment digest of a PEM client certificate, for
    /// `agent.credentials` with method `MUTUAL_TLS`.
    CertDigest {
        #[arg(long, value_name = "FILE")]
        cert: String,
    },
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(why) => {
            eprintln!("ot-provision: {why}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    match Args::parse().command {
        Command::Keygen { out } => {
            let identity = generate_key_file(&out, CryptoSuite::X25519MlKem1024MlDsa87)?;
            eprintln!("ot-provision: wrote {out} (owner-only). Software custody: hold production keys in an HSM.");
            println!("{identity}");
        }
        Command::Identity { key } => {
            println!("{}", load_key_file(&key)?.verifying_key().identity_hex());
        }
        Command::SignEdges {
            key,
            issuer,
            policy,
        } => {
            let signer = load_key_file(&key)?;
            let mut document = read_policy(&policy)?;
            let signed = sign_policy_edges(&mut document, &issuer, &signer)?;
            write_policy_atomically(&policy, &document)?;
            eprintln!(
                "ot-provision: signed {signed} edge(s) for {issuer}; key {}… authorised in `issuers`",
                &signer.verifying_key().identity_hex()[..12],
            );
        }
        Command::RotateIssuer {
            old_identity,
            new_key,
            issuer,
            policy,
        } => {
            let signer = load_key_file(&new_key)?;
            let mut document = read_policy(&policy)?;
            let resigned = rotate_issuer(&mut document, &issuer, &old_identity, &signer)?;
            write_policy_atomically(&policy, &document)?;
            eprintln!(
                "ot-provision: rotated {issuer}: {resigned} edge(s) re-signed by {}…, {}… withdrawn",
                &signer.verifying_key().identity_hex()[..12],
                &old_identity[..old_identity.len().min(12)],
            );
        }
        Command::Cosign {
            key,
            agent,
            edge,
            tool,
            params,
            expires,
        } => {
            let signer = load_key_file(&key)?;
            let params: Value = serde_json::from_str(&params)
                .map_err(|e| format!("--params is not valid JSON: {e}"))?;
            let digest = sha256_hex(&canonical_json(&params));
            println!(
                "{}",
                sign_cosignature(&agent, &edge, &tool, &digest, &expires, &signer)?
            );
        }
        Command::CertDigest { cert } => {
            let pem = std::fs::read(&cert).map_err(|e| format!("cannot read {cert}: {e}"))?;
            let ders = parse_pem(&pem, "CERTIFICATE");
            let der = ders.first().ok_or(format!("no certificate in {cert}"))?;
            println!("{}", credential_digest_of_der(der));
        }
    }
    Ok(())
}

fn read_policy(path: &str) -> Result<Value, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("{path} is not valid JSON: {e}"))
}
