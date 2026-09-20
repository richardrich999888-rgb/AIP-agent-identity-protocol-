//! `aip-hsm` — commission and check a PKCS#11-held signing key (R16).
//!
//! ```text
//! aip-hsm provision  --module <path> --token <label> --key <label> [--pin-file <path>]
//! aip-hsm public-key --module <path> --token <label> --key <label> [--pin-file <path>]
//! aip-hsm self-test  --module <path> --token <label> --key <label> [--pin-file <path>]
//! ```
//!
//! The PIN comes from `--pin-file` (owner-readable only) or, failing that,
//! the `AIP_PKCS11_PIN` environment variable. It is never an argument:
//! arguments are visible to every process on the host.
//!
//! `self-test` opens the custodian — which finds the key, refuses a weak
//! policy, and proves the pair — then signs and verifies one envelope with
//! the workspace's ordinary verifier and prints the backend. It is what an
//! operator runs after a firmware update, a token replacement, or a change
//! of PIN, and what a commissioning record attaches.

use std::path::PathBuf;
use std::process::ExitCode;

use aip_crypto::custody::Custodian;
use aip_hsm::{provision_ed25519, PinSource, Pkcs11Config, Pkcs11Custodian};

const PIN_ENV: &str = "AIP_PKCS11_PIN";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("provision") => config(&args[1..]).and_then(do_provision),
        Some("public-key") => config(&args[1..]).and_then(do_public_key),
        Some("self-test") => config(&args[1..]).and_then(do_self_test),
        _ => Err(usage()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::FAILURE
        }
    }
}

fn usage() -> String {
    "usage:\n  aip-hsm provision  --module <path> --token <label> --key <label> [--pin-file <path>]\n  \
     aip-hsm public-key --module <path> --token <label> --key <label> [--pin-file <path>]\n  \
     aip-hsm self-test  --module <path> --token <label> --key <label> [--pin-file <path>]\n\
     The PIN is read from --pin-file (mode 0600) or the AIP_PKCS11_PIN environment variable."
        .to_string()
}

/// Flag parsing without a dependency. Every flag takes a value; an unknown
/// flag is an error rather than ignored, because a misspelt `--token` that
/// silently falls back to a default is how the wrong token gets used.
fn config(args: &[String]) -> Result<Pkcs11Config, String> {
    let mut module = None;
    let mut token = None;
    let mut key = None;
    let mut pin_file = None;
    let mut i = 0;
    while i < args.len() {
        let value = args
            .get(i + 1)
            .ok_or_else(|| format!("{} needs a value", args[i]))?;
        match args[i].as_str() {
            "--module" => module = Some(PathBuf::from(value)),
            "--token" => token = Some(value.clone()),
            "--key" => key = Some(value.clone()),
            "--pin-file" => pin_file = Some(PathBuf::from(value)),
            other => return Err(format!("unknown flag {other}\n{}", usage())),
        }
        i += 2;
    }
    let cfg = Pkcs11Config {
        module: module.ok_or("--module is required")?,
        token_label: token.ok_or("--token is required")?,
        key_label: key.ok_or("--key is required")?,
        pin: match pin_file {
            Some(p) => PinSource::File(p),
            None => PinSource::Env(PIN_ENV.to_string()),
        },
    };
    cfg.validate().map_err(|e| e.to_string())?;
    Ok(cfg)
}

fn do_provision(cfg: Pkcs11Config) -> Result<(), String> {
    let p = provision_ed25519(&cfg).map_err(|e| e.to_string())?;
    println!(
        "provisioned Ed25519 key `{}` on token `{}`",
        cfg.key_label, cfg.token_label
    );
    println!("policy: CKA_SENSITIVE=true CKA_EXTRACTABLE=false CKA_TOKEN=true");
    println!("public_key_hex: {}", hex(&p.public_key));
    Ok(())
}

fn do_public_key(cfg: Pkcs11Config) -> Result<(), String> {
    let c = Pkcs11Custodian::open(&cfg).map_err(|e| e.to_string())?;
    println!("{}", hex(c.public_key()));
    Ok(())
}

fn do_self_test(cfg: Pkcs11Config) -> Result<(), String> {
    let c = Pkcs11Custodian::open(&cfg).map_err(|e| e.to_string())?;
    let signer_id = format!("self-test:{}", cfg.key_label);
    let payload = b"aip-hsm self-test";
    let sig = c.sign(&signer_id, payload).map_err(|e| e.to_string())?;
    let ok = aip_crypto::verify_ed25519(c.public_key(), &sig).map_err(|e| format!("{e:?}"))?;
    if !ok {
        return Err(
            "the signature the module produced did not verify under the public key it \
                    reports; do not use this token"
                .into(),
        );
    }
    println!(
        "backend: {:?} (production: {})",
        c.backend(),
        c.backend().is_production()
    );
    println!("token: {}  key: {}", c.token_label(), c.key_label());
    println!("public_key_hex: {}", hex(c.public_key()));
    println!("policy: sensitive, not extractable (read back from the module)");
    println!("pair: proven at open");
    println!("envelope: signed and verified with aip_crypto::verify_ed25519");
    Ok(())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
