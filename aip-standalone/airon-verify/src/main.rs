use airon_verify::{
    encode_hex, read_keyring, read_packet, read_receipt_payload, verify_packet, ReceiptDigestInput,
    VerifyError,
};
use clap::Parser;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "airon-verify",
    version,
    about = "Verify AIRON EvidencePacket non-repudiation chains"
)]
struct Cli {
    /// EvidencePacket JSON file.
    #[arg(long)]
    packet: PathBuf,

    /// Verification keyring JSON containing assembler, agent, trace, receipt, and counterparty keys.
    #[arg(long)]
    keyring: PathBuf,

    /// External receipt digest as 32-byte hex. Must equal receipt_binding.receipt_hash.
    #[arg(long)]
    receipt_digest_hex: Option<String>,

    /// External receipt payload file. SHA-256(payload) must equal receipt_binding.receipt_hash.
    #[arg(long)]
    receipt_payload: Option<PathBuf>,

    /// Write the verification report JSON to this path.
    #[arg(long)]
    report: Option<PathBuf>,

    /// Print only JSON report output.
    #[arg(long)]
    json: bool,
}

fn main() {
    match run() {
        Ok(exit) => std::process::exit(exit),
        Err(error) => {
            eprintln!("airon-verify: {error}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<i32, VerifyError> {
    let cli = Cli::parse();
    let packet = read_packet(&cli.packet)?;
    let keyring = read_keyring(&cli.keyring)?;
    let receipt_digest = receipt_digest_input(&cli)?.expected_digest()?;
    let report = verify_packet(&packet, &keyring, Some(receipt_digest));
    let report_json = serde_json::to_string_pretty(&report)
        .map_err(|e| VerifyError::Json(format!("failed to serialize report: {e}")))?;

    if let Some(path) = &cli.report {
        fs::write(path, &report_json).map_err(|e| {
            VerifyError::Io(format!("failed to write report {}: {e}", path.display()))
        })?;
    }

    if cli.json {
        println!("{report_json}");
    } else if report.toxic {
        eprintln!("TOXIC EvidencePacket");
        eprintln!("  decision_id: {}", report.decision_id_hex);
        eprintln!("  packet_digest: {}", report.packet_digest_hex);
        for check in &report.checks {
            if matches!(check.status, airon_verify::CheckStatus::Fail) {
                eprintln!("  FAIL {}: {}", check.name, check.detail);
            }
        }
    } else {
        println!("PASS EvidencePacket");
        println!("  decision_id: {}", report.decision_id_hex);
        println!("  packet_digest: {}", report.packet_digest_hex);
        println!(
            "  trust_floor: {} ({})",
            report.trust_floor, report.trust_floor_label
        );
        println!("  receipt_digest: {}", encode_hex(&receipt_digest));
    }

    Ok(if report.toxic { 2 } else { 0 })
}

fn receipt_digest_input(cli: &Cli) -> Result<ReceiptDigestInput, VerifyError> {
    match (&cli.receipt_digest_hex, &cli.receipt_payload) {
        (Some(_), Some(_)) => Err(VerifyError::InvalidInput(
            "provide either --receipt-digest-hex or --receipt-payload, not both".into(),
        )),
        (Some(hex), None) => Ok(ReceiptDigestInput::Hex(hex.clone())),
        (None, Some(path)) => Ok(ReceiptDigestInput::Payload(read_receipt_payload(path)?)),
        (None, None) => Err(VerifyError::InvalidInput(
            "external receipt evidence required: pass --receipt-digest-hex or --receipt-payload"
                .into(),
        )),
    }
}
