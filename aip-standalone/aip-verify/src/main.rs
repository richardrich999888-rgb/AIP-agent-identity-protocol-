//! `aip-verify` — offline EvidencePacket verifier for auditors.
//!
//! Verification is a pure function of the packet plus the trust roots the
//! verifier supplies. With no trust roots, the integrity self-checks
//! (canonical hash + agent signature) still run, so an auditor can detect
//! tampering before establishing trust in issuer keys.
//!
//! Examples:
//!   aip-verify evidence.json
//!   aip-verify evidence.json --report
//!   aip-verify evidence.json --json
//!   aip-verify evidence.json --trust aip1PRINCIPAL=<hex> --trust aip1ISSUER=<hex>
//!   aip-verify evidence.json --counterparty ledger.bank=<hex> --receipt-data receipt.bin

use std::collections::HashMap;
use std::process::ExitCode;

use clap::Parser;

use aip_protocol::{verify_packet, EvidencePacket, VerificationContext};

#[derive(Parser, Debug)]
#[command(
    name = "aip-verify",
    about = "Offline verifier for AIP EvidencePackets",
    version
)]
struct Cli {
    /// Path to the EvidencePacket JSON file.
    packet: String,

    /// Trusted issuer key, repeatable: `--trust <aip_id>=<pubkey_hex>`.
    #[arg(long = "trust", value_name = "AIP_ID=HEX")]
    trust: Vec<String>,

    /// Trusted counterparty key, repeatable: `--counterparty <id>=<pubkey_hex>`.
    #[arg(long = "counterparty", value_name = "ID=HEX")]
    counterparty: Vec<String>,

    /// Revoked JTI (16-byte hex), repeatable.
    #[arg(long = "revoked", value_name = "JTI_HEX")]
    revoked: Vec<String>,

    /// File whose bytes must hash to the packet's trace_hash.
    #[arg(long = "trace-data", value_name = "FILE")]
    trace_data: Option<String>,

    /// File whose bytes must hash to the packet's receipt_hash.
    #[arg(long = "receipt-data", value_name = "FILE")]
    receipt_data: Option<String>,

    /// Print the full per-rule report (human readable).
    #[arg(long)]
    report: bool,

    /// Print the VerificationReport as JSON (machine readable).
    #[arg(long)]
    json: bool,
}

fn parse_kv(pairs: &[String], what: &str) -> Result<HashMap<String, Vec<u8>>, String> {
    let mut map = HashMap::new();
    for pair in pairs {
        let (id, hex_str) = pair
            .split_once('=')
            .ok_or_else(|| format!("--{what} expects ID=HEX, got '{pair}'"))?;
        let key =
            hex::decode(hex_str.trim()).map_err(|e| format!("--{what} {id}: invalid hex: {e}"))?;
        map.insert(id.trim().to_string(), key);
    }
    Ok(map)
}

fn run(cli: &Cli) -> Result<bool, String> {
    let raw = std::fs::read_to_string(&cli.packet)
        .map_err(|e| format!("cannot read {}: {e}", cli.packet))?;
    let packet = EvidencePacket::from_json(&raw)
        .map_err(|e| format!("{} is not a valid EvidencePacket: {e}", cli.packet))?;

    let mut ctx = VerificationContext::new();
    ctx.issuer_public_keys = parse_kv(&cli.trust, "trust")?;
    ctx.counterparty_public_keys = parse_kv(&cli.counterparty, "counterparty")?;
    for jti_hex in &cli.revoked {
        let bytes =
            hex::decode(jti_hex.trim()).map_err(|e| format!("--revoked: invalid hex: {e}"))?;
        if bytes.len() != 16 {
            return Err(format!(
                "--revoked: JTI must be 16 bytes, got {}",
                bytes.len()
            ));
        }
        let mut jti = [0u8; 16];
        jti.copy_from_slice(&bytes);
        ctx.revoked_jtis.insert(jti);
    }
    if let Some(path) = &cli.trace_data {
        ctx.trace_data = Some(std::fs::read(path).map_err(|e| format!("trace-data: {e}"))?);
    }
    if let Some(path) = &cli.receipt_data {
        ctx.receipt_data = Some(std::fs::read(path).map_err(|e| format!("receipt-data: {e}"))?);
    }

    let report = verify_packet(&packet, &ctx);

    if cli.json {
        println!(
            "{}",
            report
                .to_json()
                .map_err(|e| format!("serialize report: {e}"))?
        );
        return Ok(report.valid);
    }

    println!("packet_id:   {}", report.packet_id);
    println!("agent_id:    {}", report.agent_id);
    println!("valid:       {}", report.valid);
    println!("trust_floor: {:?}", report.trust_floor);
    println!("tampered:    {}", report.tampered);
    if cli.trust.is_empty() {
        println!(
            "note:        no --trust keys supplied; authority rules cannot pass. \
             Integrity (hash + agent signature) is still checked."
        );
    }

    if cli.report {
        println!("\nrules:");
        for c in &report.checks {
            println!(
                "  [{}] {:<20} {}",
                if c.pass { "PASS" } else { "FAIL" },
                c.rule,
                c.detail
            );
        }
    } else if !report.valid {
        println!("\nfailed rules:");
        for c in report.failures() {
            println!("  [FAIL] {:<20} {}", c.rule, c.detail);
        }
    }

    Ok(report.valid)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(2), // parsed + verified, but INVALID
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1) // could not parse/verify at all
        }
    }
}
