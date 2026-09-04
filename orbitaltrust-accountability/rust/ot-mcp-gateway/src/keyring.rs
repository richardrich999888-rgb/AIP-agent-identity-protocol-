//! Software custody for signing keys.
//!
//! # What this is, and is not
//!
//! This is the honest floor for key custody: a seed file that only its owner
//! can read, refused outright when its permissions say otherwise, with the
//! key's identity stored alongside so silent corruption is caught rather
//! than yielding a different key. It is deliberately **not** an HSM. A
//! production deployment holding officer or supervisor keys should implement
//! [`AttestationSigner`](crate::trust::AttestationSigner) over its HSM or
//! KMS and never let the seed touch a filesystem; this module exists so that
//! until then, the keys are at least held the way SSH holds its private
//! keys, instead of as constants in a tool.
//!
//! # Why the seed and not the expanded key
//!
//! ML-DSA private keys are seed-derived: 32 bytes expand deterministically
//! into the full signing key. Storing the seed keeps the file small, makes
//! the format suite-portable, and means the stored `identityHex` is a real
//! integrity check — a flipped bit in the seed derives a key whose identity
//! no longer matches, and loading fails loudly instead of signing as a
//! stranger.
//!
//! # No passphrase encryption, on purpose
//!
//! The workspace carries no password-hardening KDF (argon2, scrypt), and
//! deriving an AES key from a passphrase with a fast hash would be security
//! theatre — brute-forceable at billions of guesses a second while looking
//! encrypted. Rather than ship that, the file is plaintext under strict
//! permissions, and the module says so. Disk encryption and HSMs are the
//! real answers at the two ends of the deployment spectrum.

use ot_pqc::{CryptoSuite, SignatureKeyPair};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// The key-file format identifier.
pub const KEY_FILE_STANDARD: &str = "OT-SIGNING-KEY-v1";

/// The on-disk shape.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct KeyFile {
    standard: String,
    /// The suite label, e.g. `X25519-MLKEM1024-MLDSA87`.
    suite: String,
    /// The 32-byte seed, hex.
    seed_hex: String,
    /// The derived verifying key's identity, for integrity checking.
    identity_hex: String,
}

/// Generates a fresh signing key and writes it to `path`.
///
/// Refuses to overwrite: a key file is an identity, and clobbering one on a
/// typo'd path should be impossible rather than recoverable. The file is
/// created with owner-only permissions before the seed is written, so there
/// is no window in which it exists world-readable.
///
/// Returns the new key's identity, for enrolment in a policy.
pub fn generate_key_file(path: impl AsRef<Path>, suite: CryptoSuite) -> Result<String, String> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| format!("OS entropy unavailable: {e}"))?;
    let pair =
        SignatureKeyPair::from_seed(suite, &seed).map_err(|e| format!("cannot derive key: {e}"))?;
    let identity = pair.verifying_key().identity_hex();

    let contents = serde_json::to_string_pretty(&KeyFile {
        standard: KEY_FILE_STANDARD.to_string(),
        suite: suite.as_str().to_string(),
        seed_hex: hex(&seed),
        identity_hex: identity.clone(),
    })
    .map_err(|e| format!("cannot serialize key file: {e}"))?;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path.as_ref())
        .map_err(|e| format!("cannot create {}: {e}", path.as_ref().display()))?;
    use std::io::Write;
    file.write_all(contents.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("cannot write {}: {e}", path.as_ref().display()))?;
    Ok(identity)
}

/// Loads a signing key, enforcing custody.
///
/// Refuses a file that group or world can read — the same rule SSH applies,
/// for the same reason: a key anyone else on the host can copy is not a
/// credential, and continuing would let the deployment believe it has one.
/// Refuses a seed whose derived identity does not match the stored one, so
/// corruption or tampering fails loudly instead of signing as a stranger.
pub fn load_key_file(path: impl AsRef<Path>) -> Result<SignatureKeyPair, String> {
    let path = path.as_ref();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map_err(|e| format!("cannot stat {}: {e}", path.display()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(format!(
                "refusing {}: permissions {:o} allow group/other access — a signing key \
                 anyone else on the host can read is not a credential (chmod 600 to fix)",
                path.display(),
                mode & 0o777,
            ));
        }
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let parsed: KeyFile = serde_json::from_str(&text)
        .map_err(|e| format!("{} is not a key file: {e}", path.display()))?;
    if parsed.standard != KEY_FILE_STANDARD {
        return Err(format!(
            "{}: unknown key-file standard {:?}",
            path.display(),
            parsed.standard
        ));
    }
    let suite = CryptoSuite::from_str(&parsed.suite)
        .ok_or_else(|| format!("{}: unknown suite {:?}", path.display(), parsed.suite))?;
    let seed: [u8; 32] = unhex(&parsed.seed_hex)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| format!("{}: seed is not 32 hex-encoded bytes", path.display()))?;
    let pair =
        SignatureKeyPair::from_seed(suite, &seed).map_err(|e| format!("cannot derive key: {e}"))?;
    if pair.verifying_key().identity_hex() != parsed.identity_hex {
        return Err(format!(
            "{}: seed derives a key whose identity does not match the stored one — \
             the file is corrupted or tampered with",
            path.display(),
        ));
    }
    Ok(pair)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUITE: CryptoSuite = CryptoSuite::X25519MlKem1024MlDsa87;

    #[test]
    fn a_generated_key_round_trips_and_keeps_its_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("officer.key");
        let identity = generate_key_file(&path, SUITE).unwrap();
        assert_eq!(identity.len(), 64);
        let loaded = load_key_file(&path).unwrap();
        assert_eq!(loaded.verifying_key().identity_hex(), identity);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "key file was not created owner-only");
        }
    }

    #[test]
    fn generation_refuses_to_overwrite_an_existing_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("officer.key");
        generate_key_file(&path, SUITE).unwrap();
        assert!(
            generate_key_file(&path, SUITE).is_err(),
            "an existing key was clobbered"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_key_file_others_can_read_is_refused_not_used() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("officer.key");
        generate_key_file(&path, SUITE).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = load_key_file(&path).unwrap_err();
        assert!(err.contains("group/other"), "{err}");
        // Fixing the permissions fixes the load — nothing was destroyed.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_key_file(&path).is_ok());
    }

    #[test]
    fn a_tampered_seed_fails_loudly_rather_than_signing_as_a_stranger() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("officer.key");
        generate_key_file(&path, SUITE).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        // Flip one nibble of the seed; every other field stays intact.
        let seed = value["seedHex"].as_str().unwrap().to_string();
        let flipped = if seed.starts_with('0') { "1" } else { "0" };
        value["seedHex"] = serde_json::json!(format!("{flipped}{}", &seed[1..]));
        std::fs::write(&path, serde_json::to_string(&value).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let err = load_key_file(&path).unwrap_err();
        assert!(err.contains("does not match"), "{err}");
    }

    #[test]
    fn garbage_and_wrong_standards_are_refused_with_a_reason() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.key");
        for contents in [
            "not json at all",
            r#"{"standard":"SOMETHING-ELSE","suite":"X25519-MLKEM1024-MLDSA87","seedHex":"00","identityHex":"00"}"#,
        ] {
            std::fs::write(&path, contents).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            assert!(load_key_file(&path).is_err(), "accepted {contents:?}");
        }
    }
}
