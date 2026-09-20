//! `aip-route-map` — sign and inspect an institution's route map.
//!
//! The gateway refuses to run on a map it cannot verify, so the institution
//! needs a way to produce one. This is that tool, and it is deliberately
//! separate from the gateway binary: the signing key belongs to the
//! institution's infrastructure owner, not to the host the gateway runs on.
//!
//! ```text
//!   routes.json  ──sign──▶  route-map.json  ──▶  the gateway verifies it
//!   (a list)     (institution key)  (signed)      (issuer public key only)
//! ```
//!
//! `sign` refuses a map that is not well formed — unsorted, duplicated, or
//! carrying two routes that could name one request — **before** signing it,
//! so a map that exists is a map the gateway will accept. Catching an overlap
//! at deploy time rather than at startup is the difference between a
//!deploy-time mistake and an outage.
//!
//! `verify` is what an auditor runs: it takes the published public key and the
//! map, and says whether the institution signed exactly these routes.

use std::process::ExitCode;

use aip_crypto::sign_ed25519;
use aip_http_gateway::{RouteEntry, RouteMap, RouteMapAnchors, ROUTE_MAP_VERSION};
use aip_types::{AlgorithmId, Signature};

const USAGE: &str = "\
aip-route-map — sign and verify an institution's HTTP route map

USAGE:
    aip-route-map sign   --routes <FILE> --map-id <ID> --issuer-id <ID>
                         --revision <N> --valid-from-ms <MS>
                         --key <FILE> --out <FILE>
    aip-route-map verify --map <FILE> --issuer-id <ID> --pubkey <FILE>
    aip-route-map keygen --out-private <FILE> --out-public <FILE>

    --routes   JSON array of {\"tool_id\",\"method\",\"path\"}; order does not
               matter, the tool sorts them into the one canonical order
    --key      hex ed25519 PRIVATE key of the institution
    --pubkey   hex ed25519 public key of the institution

`sign` refuses a map that is not well formed before signing it, so a map that
exists is one the gateway will accept.

`keygen` is for a lab or a bootstrap only. A production institution key lives
in an HSM and never exists as a file; see `aip-hsm`.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("aip-route-map: {message}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn val(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}

fn need(args: &[String], flag: &str) -> Result<String, String> {
    val(args, flag).ok_or_else(|| format!("{flag} is required"))
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
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return Ok(ExitCode::SUCCESS);
    }
    match args[0].as_str() {
        "sign" => sign(args),
        "verify" => verify(args),
        "keygen" => keygen(args),
        other => Err(format!("unknown command {other:?}")),
    }
}

fn sign(args: &[String]) -> Result<ExitCode, String> {
    let routes_path = need(args, "--routes")?;
    let out_path = need(args, "--out")?;
    let issuer_id = need(args, "--issuer-id")?;
    let key = read_hex(&need(args, "--key")?)?;
    let revision: u64 = need(args, "--revision")?
        .parse()
        .map_err(|e| format!("--revision: {e}"))?;
    let valid_from_ms: u64 = need(args, "--valid-from-ms")?
        .parse()
        .map_err(|e| format!("--valid-from-ms: {e}"))?;

    let mut routes: Vec<RouteEntry> = serde_json::from_str(
        &std::fs::read_to_string(&routes_path)
            .map_err(|e| format!("cannot read {routes_path}: {e}"))?,
    )
    .map_err(|e| format!("{routes_path} is not a route list: {e}"))?;
    // One canonical order, chosen here so an operator's file order cannot
    // change the signed bytes.
    routes.sort_by(|a, b| (&a.method, &a.path).cmp(&(&b.method, &b.path)));

    let mut map = RouteMap {
        version: ROUTE_MAP_VERSION,
        map_id: need(args, "--map-id")?,
        issuer_id: issuer_id.clone(),
        revision,
        valid_from_ms,
        routes,
        signature: Signature {
            algorithm: AlgorithmId::Ed25519,
            signer_id: issuer_id.clone(),
            timestamp: 0,
            nonce: [0u8; 16],
            payload_hash: [0u8; 32],
            signature_bytes: Vec::new(),
        },
    };

    // Refuse before signing: a signed map that the gateway will reject at
    // startup is worse than no map, because it is discovered in production.
    map.check_well_formed()
        .map_err(|e| format!("refusing to sign a map that is not well formed: {e:?}"))?;

    let preimage = map.signing_preimage();
    map.signature =
        sign_ed25519(&key, &issuer_id, &preimage).map_err(|e| format!("signing failed: {e:?}"))?;

    std::fs::write(
        &out_path,
        serde_json::to_string_pretty(&map).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("cannot write {out_path}: {e}"))?;

    eprintln!(
        "aip-route-map: signed {} routes as {} revision {} by {issuer_id} -> {out_path}",
        map.routes.len(),
        map.map_id,
        map.revision
    );
    Ok(ExitCode::SUCCESS)
}

fn verify(args: &[String]) -> Result<ExitCode, String> {
    let map_path = need(args, "--map")?;
    let issuer_id = need(args, "--issuer-id")?;
    let key = read_hex(&need(args, "--pubkey")?)?;

    let map: RouteMap = serde_json::from_str(
        &std::fs::read_to_string(&map_path).map_err(|e| format!("cannot read {map_path}: {e}"))?,
    )
    .map_err(|e| format!("{map_path} is not a route map: {e}"))?;

    match map.verify(&RouteMapAnchors::new().trust(&issuer_id, &key)) {
        Ok(()) => {
            println!(
                "VERIFIED  {} revision {} — {} routes signed by {issuer_id}",
                map.map_id,
                map.revision,
                map.routes.len()
            );
            for r in &map.routes {
                println!("  {:<7} {:<32} {}", r.method, r.path, r.tool_id);
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            println!("REFUSED   {map_path} does not verify under {issuer_id}: {e:?}");
            Ok(ExitCode::from(1))
        }
    }
}

/// Generate an Ed25519 keypair as two hex files.
///
/// Deliberately blunt about what this is for: a key written to a file is a key
/// that can be copied. A production institution or gateway key is generated
/// inside an HSM and is non-extractable (`aip-hsm`); this exists so a lab, a
/// test rig or a first bootstrap does not need one.
fn keygen(args: &[String]) -> Result<ExitCode, String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let private_path = need(args, "--out-private")?;
    let public_path = need(args, "--out-public")?;
    let kp = aip_crypto::generate_ed25519_keypair();

    // 0600 at creation, not chmod afterwards: a private key must never exist
    // world-readable, not even for the instant between the two calls.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&private_path)
        .map_err(|e| format!("cannot create {private_path}: {e}"))?;
    writeln!(file, "{}", hex(&kp.private_key)).map_err(|e| e.to_string())?;

    std::fs::write(&public_path, format!("{}\n", hex(&kp.public_key)))
        .map_err(|e| format!("cannot write {public_path}: {e}"))?;

    eprintln!(
        "aip-route-map: wrote {private_path} (0600) and {public_path}. \
         A file-backed key is a copyable key; production keys belong in an HSM."
    );
    Ok(ExitCode::SUCCESS)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
