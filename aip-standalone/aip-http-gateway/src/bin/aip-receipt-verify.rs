//! `aip-receipt-verify` — check a gateway's receipt stream offline.
//!
//! This is the auditor's half of B10. The gateway issues; this verifies, with
//! nothing but the receipt file and the gateway's published public key. No
//! call to the gateway, no call to us.
//!
//! Exit status is `0` when every receipt verified, `1` when any did not, and
//! `2` on bad arguments. A file with no receipts in it is **not** a pass: an
//! empty stream and a verified stream are different statements, and only one
//! of them says anything.

use std::process::ExitCode;

use aip_airi::{verify_tool_receipt, GatewayTrustAnchors, SignedToolReceipt};

const USAGE: &str = "\
aip-receipt-verify — verify a gateway receipt stream offline

USAGE:
    aip-receipt-verify --receipts <FILE> --gateway-id <ID> --key-version <N>
                       --pubkey <FILE> [--agent-pubkey <FILE>]

    --pubkey        hex ed25519 public key the gateway publishes
    --agent-pubkey  the agent's key, when known. Supplying it makes the
                    verifier refuse a receipt signed by the agent's own key,
                    which is a gateway that is not independent of what it
                    receipts.

Exit 0 if every receipt verified, 1 if any did not. An empty file exits 1.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("aip-receipt-verify: {message}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn val(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}

fn read_hex(path: &str) -> Result<Vec<u8>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let text = text.trim();
    if !text.len().is_multiple_of(2) || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{path} is not hex"));
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn run(args: &[String]) -> Result<ExitCode, String> {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return Ok(ExitCode::SUCCESS);
    }
    let receipts_path = val(args, "--receipts").ok_or("--receipts is required")?;
    let gateway_id = val(args, "--gateway-id").ok_or("--gateway-id is required")?;
    let key_version: u32 = val(args, "--key-version")
        .ok_or("--key-version is required")?
        .parse()
        .map_err(|e| format!("--key-version: {e}"))?;
    let pubkey = read_hex(&val(args, "--pubkey").ok_or("--pubkey is required")?)?;
    let agent_pubkey = match val(args, "--agent-pubkey") {
        Some(path) => Some(read_hex(&path)?),
        None => None,
    };

    let text = std::fs::read_to_string(&receipts_path)
        .map_err(|e| format!("cannot read {receipts_path}: {e}"))?;
    let anchors = GatewayTrustAnchors::new().trust(&gateway_id, key_version, &pubkey);

    let mut verified = 0usize;
    let mut failed = 0usize;
    println!(
        "{:<4} {:<26} {:<24} {:<10} parameter commitment",
        "#", "tool", "agent", "disposition"
    );
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let n = i + 1;
        let signed: SignedToolReceipt = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                println!("{n:<4} MALFORMED — {e}");
                failed += 1;
                continue;
            }
        };
        match verify_tool_receipt(&signed, &anchors, agent_pubkey.as_deref()) {
            Ok(v) => {
                let r = v.receipt();
                println!(
                    "{n:<4} {:<26} {:<24} {:<10} {}",
                    r.tool_id,
                    r.agent_id,
                    format!("{:?}", r.disposition),
                    hex(&r.parameter_commitment)
                );
                verified += 1;
            }
            Err(e) => {
                println!("{n:<4} REFUSED — {e:?}");
                failed += 1;
            }
        }
    }

    if verified == 0 && failed == 0 {
        // An empty stream is not a clean bill of health.
        println!("\nNO RECEIPTS in {receipts_path} — an empty stream verifies nothing");
        return Ok(ExitCode::from(1));
    }
    println!("\n{verified} verified, {failed} refused");
    Ok(if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
