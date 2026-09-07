//! Ed25519 key management for the service.
//!
//! # Key lifecycle
//!
//! 1. On startup, look for a key file at `AIP_KEY_PATH`.
//! 2. If `AIP_KEY_PASSPHRASE` is set, the file is a
//!    [`WrappedFileCustodian`] key — Argon2id + XChaCha20-Poly1305, mode
//!    0600. This is the production posture.
//! 3. If it is not set, the file is the legacy base64 seed: **plaintext on
//!    disk**, classified [`Backend::PlaintextFile`], and refused by a
//!    production policy.
//! 4. A key is generated only when the file **does not exist**. Every other
//!    condition is fatal.
//!
//! # What was wrong before, and why it mattered
//!
//! The previous entry point was `load_or_generate`, which on *any* load error
//! — a transient read failure, a truncated file, a bad mode — logged a warning
//! and **generated a new key**. That silently rotates the service identity.
//! Every JWT already issued becomes unverifiable, every client pinning the old
//! public key breaks, and every audit-export bundle signed under the old key
//! can no longer be traced to a key the service will admit to. The service
//! would come up looking healthy while having destroyed its own identity.
//!
//! It also, on a failed *write*, logged an error and continued with an
//! **ephemeral** key: tokens issued for the life of that process stopped
//! verifying the moment it restarted.
//!
//! [`ServiceKey::load_or_create`] replaces both. Generation is reachable from
//! exactly one condition — the file does not exist — and every other outcome
//! is an error the caller must handle. Fail closed.
//!
//! The legacy seed file was also written and *then* `chmod`-ed, leaving it
//! world-readable for the interval between the two syscalls. It is now created
//! with the mode already set, and its permissions are verified on every load.
//!
//! # What this custody is, exactly
//!
//! Under a passphrase: [`Backend::WrappedFile`] — the key is encrypted at rest
//! and the passphrase is the protection. Not hardware-backed and not
//! non-exportable; anyone who can read this process's memory has the decrypted
//! key, and the passphrase has to come from somewhere the process can reach.
//!
//! Without one: [`Backend::PlaintextFile`] — protected by file permission
//! only. `root`, anything running as the service uid, and anyone holding the
//! disk or a backup have it. `is_production()` is false for that backend, so a
//! production policy refuses to start on it.
//!
//! One export path remains and is not closable here: `jsonwebtoken` builds its
//! `EncodingKey` from a PKCS#8 PEM, so the private key must be materialised in
//! that form to issue JWTs at all. It is confined to this module — the PEM is
//! no longer a public field — and handed out only as an opaque `EncodingKey`,
//! which does not give the bytes back. That is a real reduction in exposure and
//! it is not the same as non-exportability; calling it that would be a lie.
//!
//! The private key is never logged. The fingerprint is public and is.

use aip_crypto::custody::{
    Backend, CustodyError, InMemoryCustodian, RawSigner, WrappedFileCustodian,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::{fmt, fs, path::Path};

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

// ── ServiceKey ────────────────────────────────────────────────────────────────

/// The service's Ed25519 signing key.
///
/// Holds the key material privately and exposes only operations: an opaque
/// `EncodingKey` for JWT issuance, the public PEM and fingerprint, and
/// [`RawSigner::sign_raw`] for audit-export manifests. There is no accessor
/// that returns the key.
pub struct ServiceKey {
    /// 32-byte Ed25519 seed — never printed, logged, or returned.
    seed: [u8; 32],

    /// PKCS#8 PEM. Private: it is the seed in another encoding, and a public
    /// `String` field is exactly how key material ends up in a log line or a
    /// debug response. Reachable only as an opaque [`Self::encoding_key`].
    private_pem: String,

    /// SPKI PEM — served from `GET /v1/identity/public-key`.
    pub public_pem: String,

    /// SHA-256 of the raw 32-byte public key, hex-encoded. Public information;
    /// included in every issued token response so callers can identify which
    /// key signed it.
    pub fingerprint: String,

    /// Raw public key bytes.
    public_key: [u8; 32],

    /// How this key is actually protected. Set from how it was obtained, not
    /// from how it was intended to be obtained.
    backend: Backend,
}

impl ServiceKey {
    fn from_seed(seed: [u8; 32], backend: Backend) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key: VerifyingKey = signing_key.verifying_key();

        let private_pem = der_to_pem(&seed_to_pkcs8_der(&seed), "PRIVATE KEY");
        let public_pem = der_to_pem(&pubkey_to_spki_der(verifying_key.as_bytes()), "PUBLIC KEY");
        let fingerprint = hex::encode(Sha256::digest(verifying_key.as_bytes()));

        ServiceKey {
            seed,
            private_pem,
            public_pem,
            fingerprint,
            public_key: verifying_key.to_bytes(),
            backend,
        }
    }

    /// Generate an ephemeral key that is never written anywhere.
    ///
    /// [`Backend::DevelopmentInMemory`], because that is what it is: a key in
    /// this process's memory with no file behind it. `is_production()` is
    /// false, which is why the startup path does not use it.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self::from_seed(*signing_key.as_bytes(), Backend::DevelopmentInMemory)
    }

    /// An opaque JWT encoding key.
    ///
    /// The one place the private PEM is consumed. `EncodingKey` does not hand
    /// the key material back, so callers get the ability to sign a JWT without
    /// getting the key.
    pub fn encoding_key(&self) -> jsonwebtoken::EncodingKey {
        jsonwebtoken::EncodingKey::from_ed_pem(self.private_pem.as_bytes())
            .expect("a PEM this module generated must be valid")
    }

    /// The matching JWT decoding key. Public material.
    pub fn decoding_key(&self) -> jsonwebtoken::DecodingKey {
        jsonwebtoken::DecodingKey::from_ed_pem(self.public_pem.as_bytes())
            .expect("a PEM this module generated must be valid")
    }

    /// The 32-byte Ed25519 public key.
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.public_key
    }

    /// How this key is protected, as it actually is.
    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// Load the service key, creating one **only if the file does not exist**.
    ///
    /// Every other condition is an error:
    ///
    /// | condition | outcome |
    /// |---|---|
    /// | file absent | generate, create at mode 0600, return |
    /// | file present, permissions wrong | `Err` — never loaded, never replaced |
    /// | file present, unreadable | `Err` — **never** regenerated |
    /// | file present, malformed | `Err` — **never** regenerated |
    /// | wrong passphrase | `Err` — indistinguishable from an altered file, and treated as one |
    /// | file absent, cannot be created | `Err` — no ephemeral fallback |
    ///
    /// The rows that say "never regenerated" are the whole point. A service
    /// that mints a new identity because it could not read its old one has
    /// destroyed every signature it ever made, and reported success.
    ///
    /// `passphrase` selects the backend: `Some` uses the wrapped-file
    /// custodian, `None` the legacy plaintext seed.
    pub fn load_or_create(key_path: &str, passphrase: Option<&[u8]>) -> Result<Self, CustodyError> {
        match passphrase {
            Some(pp) => Self::load_or_create_wrapped(key_path, pp),
            None => Self::load_or_create_plaintext(key_path),
        }
    }

    fn load_or_create_wrapped(key_path: &str, passphrase: &[u8]) -> Result<Self, CustodyError> {
        let path = Path::new(key_path);
        // `create` refuses to overwrite, so absence is the only path to a new
        // key and a race with another starting process loses safely.
        let custodian = if path.exists() {
            WrappedFileCustodian::open(path, passphrase)?
        } else {
            let c = WrappedFileCustodian::create(path, passphrase)?;
            tracing::info!(key_path, "Generated a new wrapped Ed25519 service key");
            c
        };

        // The custodian holds the key and will not surrender it. The service
        // needs the seed in PKCS#8 PEM form because that is the only thing
        // `jsonwebtoken` accepts, so it comes back through the one named
        // export path in aip-crypto rather than through an accessor every
        // caller would inherit.
        let seed = aip_crypto::custody::wrapped_file_seed(path, passphrase)?;
        let key = Self::from_seed(seed, Backend::WrappedFile);
        debug_assert_eq!(key.public_key.as_slice(), custodian.public_key());
        tracing::info!(
            key_path,
            fingerprint = %key.fingerprint,
            backend = ?Backend::WrappedFile,
            "Loaded wrapped Ed25519 service key"
        );
        Ok(key)
    }

    fn load_or_create_plaintext(key_path: &str) -> Result<Self, CustodyError> {
        let path = Path::new(key_path);

        if !path.exists() {
            let signing_key = SigningKey::generate(&mut OsRng);
            let seed = *signing_key.as_bytes();
            aip_crypto::custody::create_owner_only(path, B64.encode(seed).as_bytes())?;
            let key = Self::from_seed(seed, Backend::PlaintextFile);
            tracing::warn!(
                key_path,
                fingerprint = %key.fingerprint,
                "Generated a new PLAINTEXT Ed25519 service key. Set AIP_KEY_PASSPHRASE \
                 for a wrapped key; a production policy refuses this backend."
            );
            return Ok(key);
        }

        aip_crypto::custody::check_secret_file(path)?;
        let raw = fs::read_to_string(path).map_err(|e| CustodyError::Io(e.to_string()))?;
        let seed_bytes = B64
            .decode(raw.trim())
            .map_err(|e| CustodyError::Malformed(format!("seed file is not valid base64: {e}")))?;
        let seed: [u8; 32] = seed_bytes
            .try_into()
            .map_err(|_| CustodyError::Malformed("seed file must be exactly 32 bytes".into()))?;

        let key = Self::from_seed(seed, Backend::PlaintextFile);
        tracing::info!(
            key_path,
            fingerprint = %key.fingerprint,
            backend = ?Backend::PlaintextFile,
            "Loaded plaintext Ed25519 service key"
        );
        Ok(key)
    }
}

impl RawSigner for ServiceKey {
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn sign_raw(&self, message: &[u8]) -> Result<[u8; 64], CustodyError> {
        aip_crypto::sign_ed25519_raw(&self.seed, message).map_err(CustodyError::Crypto)
    }
}

/// Redacted: the seed and the private PEM are the same secret in two encodings,
/// and neither appears here.
impl fmt::Debug for ServiceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceKey")
            .field("fingerprint", &self.fingerprint)
            .field("backend", &self.backend)
            .field("seed", &"<redacted 32 bytes>")
            .field("private_pem", &"<redacted>")
            .finish()
    }
}

/// A development key with no file behind it, for tests.
pub fn development_key() -> ServiceKey {
    ServiceKey::generate()
}

/// An in-memory custodian over a service key, for tests that need one.
#[allow(dead_code)]
pub(crate) fn in_memory_custodian(key: &ServiceKey) -> InMemoryCustodian {
    InMemoryCustodian::new(&key.seed, &key.public_key).expect("service key must be valid")
}
