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

use aip_protocol::bundle::{verify_zip, BundleStatus};
use aip_protocol::{
    verify_packet, verify_revocation_list, EvidencePacket, RevocationEvidence,
    RevocationListAnchors, SignedRevocationList, VerificationContext,
};

#[derive(Parser, Debug)]
#[command(
    name = "aip-verify",
    about = "Offline verifier for AIP EvidencePackets",
    version
)]
struct Cli {
    /// Path to an EvidencePacket JSON file OR an audit-export bundle (.zip).
    packet: String,

    /// Trusted issuer key, repeatable: `--trust <aip_id>=<pubkey_hex>`.
    #[arg(long = "trust", value_name = "AIP_ID=HEX")]
    trust: Vec<String>,

    /// Trusted audit-export bundle signer, repeatable:
    /// `--trust-bundle-signer <pubkey_hex>`.
    ///
    /// Without one, a bundle's signature is checked only against the key the
    /// bundle itself names, which establishes internal consistency and not
    /// who produced it (AUDIT B-4). Bundle verification then reports WARNING
    /// rather than PASS.
    #[arg(long = "trust-bundle-signer", value_name = "HEX")]
    trust_bundle_signer: Vec<String>,

    /// Trusted counterparty key, repeatable: `--counterparty <id>=<pubkey_hex>`.
    #[arg(long = "counterparty", value_name = "ID=HEX")]
    counterparty: Vec<String>,

    /// Revoked JTI (16-byte hex), repeatable.
    ///
    /// A bare identifier carries no issuer, issue time or expiry. Supplying
    /// one lets the verifier fail a packet, but a pass records that the
    /// answer rests on what the operator typed. Prefer `--revocations`.
    #[arg(long = "revoked", value_name = "JTI_HEX")]
    revoked: Vec<String>,

    /// Signed revocation list (JSON), from the authority that maintains it.
    ///
    /// Verified under `--trust-revocation-issuer` and placed in time against
    /// `--at`/`--now`. A list outside its validity window leaves the
    /// REVOCATION rule NOT EVALUATED — never a pass.
    #[arg(long = "revocations", value_name = "FILE")]
    revocations: Option<String>,

    /// Trusted revocation-list issuer, repeatable:
    /// `--trust-revocation-issuer <issuer_id>:<key_version>=<pubkey_hex>`.
    #[arg(long = "trust-revocation-issuer", value_name = "ID:VER=HEX")]
    trust_revocation_issuer: Vec<String>,

    /// Refuse an authority root that the acting agent issued to itself.
    ///
    /// Off by default, because some deployments are legitimately their own
    /// principal. A regulated entity — where the point is that something
    /// other than the agent decided — sets this. Without it, a self-issued
    /// root still passes but the report says so.
    #[arg(long = "require-independent-authority")]
    require_independent_authority: bool,

    /// File whose bytes must hash to the packet's trace_hash.
    #[arg(long = "trace-data", value_name = "FILE")]
    trace_data: Option<String>,

    /// File whose bytes must hash to the packet's receipt_hash.
    #[arg(long = "receipt-data", value_name = "FILE")]
    receipt_data: Option<String>,

    /// Verify as of this Unix-ms instant: refuse anything in the packet
    /// dated after it. Without `--at` or `--now`, the verifier applies no
    /// temporal bound and says so in the report.
    #[arg(long = "at", value_name = "UNIX_MS", conflicts_with = "now")]
    at: Option<u64>,

    /// Verify as of this machine's clock. Equivalent to `--at <now>`;
    /// separate so that reading a clock is always an explicit choice.
    #[arg(long)]
    now: bool,

    /// Allow timestamps up to this many ms ahead of the verification time,
    /// to absorb declared clock skew. Requires `--at` or `--now`.
    #[arg(long = "future-tolerance", value_name = "MS", default_value_t = 0)]
    future_tolerance: u64,

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

fn build_ctx(cli: &Cli) -> Result<VerificationContext, String> {
    let mut ctx = VerificationContext::new();
    ctx.issuer_public_keys = parse_kv(&cli.trust, "trust")?;
    for hex_key in &cli.trust_bundle_signer {
        let bytes = hex::decode(hex_key.trim())
            .map_err(|e| format!("--trust-bundle-signer: invalid hex: {e}"))?;
        // Rejected here rather than dropped silently by the context builder:
        // a caller who mistyped an anchor must be told, not left believing a
        // bundle was attributed when no anchor was installed.
        let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            format!(
                "--trust-bundle-signer: Ed25519 keys are 32 bytes, got {}",
                bytes.len()
            )
        })?;
        ctx.trusted_bundle_signers.insert(key);
    }
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
    ctx.independent_authority_required = cli.require_independent_authority;
    if let Some(path) = &cli.trace_data {
        ctx.trace_data = Some(std::fs::read(path).map_err(|e| format!("trace-data: {e}"))?);
    }
    if let Some(path) = &cli.receipt_data {
        ctx.receipt_data = Some(std::fs::read(path).map_err(|e| format!("receipt-data: {e}"))?);
    }
    ctx.verification_time_ms = match (cli.at, cli.now) {
        (Some(ms), _) => Some(ms),
        (None, true) => Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| format!("--now: {e}"))?
                .as_millis() as u64,
        ),
        (None, false) => None,
    };
    ctx.future_tolerance_ms = cli.future_tolerance;
    if ctx.verification_time_ms.is_none() && cli.future_tolerance != 0 {
        return Err("--future-tolerance requires --at or --now".into());
    }
    // The revocation list is placed in time, so it needs the same instant the
    // rest of the verification uses. A caller who supplies a list but no
    // instant is told to choose one rather than being given a pass that
    // silently assumed the list was current.
    if let Some(path) = &cli.revocations {
        let Some(now) = ctx.verification_time_ms else {
            return Err(
                "--revocations requires --at or --now: a revocation list is only \
                 meaningful relative to an instant, and this verifier will not \
                 assume one"
                    .into(),
            );
        };
        let raw = std::fs::read_to_string(path).map_err(|e| format!("--revocations: {e}"))?;
        let signed = SignedRevocationList::from_json(&raw)
            .map_err(|e| format!("--revocations: not a signed revocation list: {e}"))?;
        let anchors = parse_revocation_anchors(&cli.trust_revocation_issuer)?;
        // A list that fails to verify is carried into the report as the
        // reason the rule could not be evaluated, not discarded. An operator
        // who supplied a stale or unanchored list must see that in the
        // report, not merely in a warning they may have scrolled past.
        ctx.revocation_evidence = Some(match verify_revocation_list(&signed, &anchors, now) {
            Ok(list) => RevocationEvidence::Fresh(Box::new(list)),
            Err(defect) => RevocationEvidence::Unusable(defect),
        });
    } else if !cli.trust_revocation_issuer.is_empty() {
        return Err("--trust-revocation-issuer without --revocations has nothing to check".into());
    }
    Ok(ctx)
}

/// Parse `--trust-revocation-issuer ID:VERSION=HEX` pairs.
///
/// The key version is part of the anchor because a list names the version it
/// was signed under; an operator who rotates the issuer key must be able to
/// say which version they are trusting, and an old list must not silently
/// verify against a new key.
fn parse_revocation_anchors(pairs: &[String]) -> Result<RevocationListAnchors, String> {
    let mut anchors = RevocationListAnchors::new();
    for pair in pairs {
        let (id_ver, hex_str) = pair.split_once('=').ok_or_else(|| {
            format!("--trust-revocation-issuer expects ID:VERSION=HEX, got '{pair}'")
        })?;
        let (id, ver) = id_ver.rsplit_once(':').ok_or_else(|| {
            format!("--trust-revocation-issuer expects ID:VERSION=HEX, got '{pair}'")
        })?;
        let version: u32 = ver.trim().parse().map_err(|_| {
            format!("--trust-revocation-issuer {id}: key version '{ver}' is not a number")
        })?;
        let key = hex::decode(hex_str.trim())
            .map_err(|e| format!("--trust-revocation-issuer {id}: invalid hex: {e}"))?;
        anchors = anchors.trust(id.trim(), version, &key);
    }
    Ok(anchors)
}

fn is_zip(bytes: &[u8]) -> bool {
    bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06")
}

/// Verify an audit-export bundle. Returns true unless any check FAILed.
fn run_bundle(cli: &Cli, bytes: &[u8]) -> Result<bool, String> {
    let ctx = build_ctx(cli)?;
    let v = verify_zip(bytes, &ctx);

    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&v).map_err(|e| format!("serialize: {e}"))?
        );
        return Ok(v.overall != BundleStatus::Fail);
    }

    println!("bundle:      {}", cli.packet);
    println!("bundle_id:   {}", v.bundle_id);
    println!("packet_id:   {}", v.packet_id);
    println!("signer_fp:   {}", v.signer_fingerprint);
    println!("result:      {:?}", v.overall);
    if cli.trust.is_empty() {
        println!(
            "note:        no --trust keys supplied; the authority chain is not \
             verified (WARNING). Bundle integrity + signature are still checked."
        );
    }
    if cli.trust_bundle_signer.is_empty() {
        println!(
            "note:        no --trust-bundle-signer supplied; the signature was \
             checked against the key the bundle names, which does not \
             establish who produced it (WARNING)."
        );
    }
    if cli.report || v.overall != BundleStatus::Pass {
        println!("\nchecks:");
        for c in &v.checks {
            println!("  [{:?}] {:<20} {}", c.status, c.name, c.detail);
        }
    }
    Ok(v.overall != BundleStatus::Fail)
}

fn run(cli: &Cli) -> Result<bool, String> {
    let bytes =
        std::fs::read(&cli.packet).map_err(|e| format!("cannot read {}: {e}", cli.packet))?;

    // An audit-export bundle (.zip) is verified end to end; otherwise treat the
    // input as a bare EvidencePacket JSON.
    if is_zip(&bytes) || cli.packet.ends_with(".zip") {
        return run_bundle(cli, &bytes);
    }

    let raw = String::from_utf8(bytes)
        .map_err(|_| format!("{} is neither a zip bundle nor UTF-8 JSON", cli.packet))?;
    let packet = EvidencePacket::from_json(&raw)
        .map_err(|e| format!("{} is not a valid EvidencePacket: {e}", cli.packet))?;

    let ctx = build_ctx(cli)?;
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
                "  [{}] {:<24} {}",
                if !c.evaluated {
                    "  - "
                } else if c.pass {
                    "PASS"
                } else {
                    "FAIL"
                },
                c.rule,
                c.detail
            );
        }
        for c in report.not_evaluated() {
            println!("\nnote: {} was NOT evaluated — {}", c.rule, c.detail);
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
