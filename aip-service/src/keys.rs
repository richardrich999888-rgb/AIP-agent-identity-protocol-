//! Ed25519 keypair management.
//!
//! Key lifecycle:
//!   1. On startup, look for a seed file at `AIP_KEY_PATH`.
//!   2. If found, load the 32-byte seed (base64-encoded) and reconstruct the keypair.
//!   3. If not found, generate a new keypair and persist the seed.
//!
//! The seed file is chmod 600 on Unix.  The private key is NEVER logged.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

// ── DER/PEM helpers ───────────────────────────────────────────────────────────
//
// We construct PKCS#8 (private) and SPKI (public) DER manually.
// The structures are fixed-size for Ed25519, so no ASN.1 library is needed.
// Both structures are defined in RFC 8410.
//
// PKCS#8 PrivateKeyInfo (48 bytes total):
//   SEQUENCE (46) {
//     INTEGER 0                        -- version = v1
//     SEQUENCE { OID 1.3.101.112 }    -- AlgorithmIdentifier for Ed25519
//     OCTET STRING (34) {
//       OCTET STRING (32) { seed }    -- Ed25519PrivateKey
//     }
//   }
//
// SPKI SubjectPublicKeyInfo (44 bytes total):
//   SEQUENCE (42) {
//     SEQUENCE { OID 1.3.101.112 }    -- AlgorithmIdentifier for Ed25519
//     BIT STRING (33) { 0x00, pubkey }
//   }

fn seed_to_pkcs8_der(seed: &[u8; 32]) -> [u8; 48] {
    let mut der = [0u8; 48];
    der[..16].copy_from_slice(&[
        0x30, 0x2e, // SEQUENCE, length 46
        0x02, 0x01, 0x00, // INTEGER 0  (version = v1)
        0x30, 0x05, // SEQUENCE, length 5
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
        0x04, 0x22, // OCTET STRING, length 34
        0x04, 0x20, // OCTET STRING, length 32
    ]);
    der[16..].copy_from_slice(seed);
    der
}

fn pubkey_to_spki_der(pubkey: &[u8; 32]) -> [u8; 44] {
    let mut der = [0u8; 44];
    der[..12].copy_from_slice(&[
        0x30, 0x2a, // SEQUENCE, length 42
        0x30, 0x05, // SEQUENCE, length 5
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
        0x03, 0x21, // BIT STRING, length 33
        0x00, // 0 unused bits
    ]);
    der[12..].copy_from_slice(pubkey);
    der
}

fn der_to_pem(der: &[u8], label: &str) -> String {
    // Base64 encode then wrap at 64 characters per PEM spec (RFC 7468)
    let b64 = B64.encode(der);
    let wrapped = b64
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN {label}-----\n{wrapped}\n-----END {label}-----\n")
}

// ── KeyPair ───────────────────────────────────────────────────────────────────

pub struct KeyPair {
    /// 32-byte Ed25519 seed — NEVER printed or logged.
    seed: [u8; 32],

    /// PKCS#8 PEM — passed to jsonwebtoken::EncodingKey::from_ed_pem.
    pub private_pem: String,

    /// SPKI PEM — passed to jsonwebtoken::DecodingKey::from_ed_pem
    /// and returned from GET /v1/identity/public-key.
    pub public_pem: String,

    /// SHA-256 of the raw 32-byte public key, hex-encoded.
    /// Included in every issued token response so callers can identify which key signed it.
    pub fingerprint: String,
}

impl KeyPair {
    fn from_seed(seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key: VerifyingKey = signing_key.verifying_key();

        let private_pem = der_to_pem(&seed_to_pkcs8_der(&seed), "PRIVATE KEY");
        let public_pem = der_to_pem(&pubkey_to_spki_der(verifying_key.as_bytes()), "PUBLIC KEY");
        let fingerprint = hex::encode(Sha256::digest(verifying_key.as_bytes()));

        KeyPair {
            seed,
            private_pem,
            public_pem,
            fingerprint,
        }
    }

    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let seed: [u8; 32] = *signing_key.as_bytes();
        Self::from_seed(seed)
    }

    /// The 32-byte Ed25519 seed (private). Used to sign audit-export manifests.
    /// Never logged or serialized outside the chmod-600 seed file.
    pub fn signing_seed(&self) -> [u8; 32] {
        self.seed
    }

    /// The 32-byte Ed25519 public key.
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        SigningKey::from_bytes(&self.seed)
            .verifying_key()
            .to_bytes()
    }

    pub fn load_or_generate(key_path: &str) -> Self {
        let path = Path::new(key_path);

        if path.exists() {
            match Self::load_from_file(key_path) {
                Ok(kp) => {
                    // Log fingerprint (safe — public information)
                    tracing::info!(
                        key_path,
                        fingerprint = %kp.fingerprint,
                        "Loaded Ed25519 keypair from disk"
                    );
                    return kp;
                }
                Err(e) => {
                    tracing::warn!(
                        key_path,
                        error = %e,
                        "Failed to load key file — generating new keypair"
                    );
                }
            }
        }

        let kp = Self::generate();
        match kp.save_to_file(key_path) {
            Ok(()) => tracing::info!(
                key_path,
                fingerprint = %kp.fingerprint,
                "Generated new Ed25519 keypair and persisted to disk"
            ),
            Err(e) => tracing::error!(
                key_path,
                error = %e,
                "Could not persist key to disk — key is ephemeral this session"
            ),
        }
        kp
    }

    fn load_from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let raw = fs::read_to_string(path)?;
        let seed_bytes = B64.decode(raw.trim())?;
        let seed: [u8; 32] = seed_bytes
            .try_into()
            .map_err(|_| "seed file must contain exactly 32 bytes (base64-encoded)")?;
        Ok(Self::from_seed(seed))
    }

    pub fn save_to_file(&self, path: &str) -> std::io::Result<()> {
        // Persist only the 32-byte seed, base64-encoded.
        // We intentionally do NOT write the PEM (it is re-derived on every load).
        fs::write(path, B64.encode(self.seed))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(path, perms)?;
        }
        Ok(())
    }
}
