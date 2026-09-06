//! Ed25519 keypair management — custody of the service's signing identity.
//!
//! Key lifecycle:
//!   1. On startup, look for a seed file at `AIP_KEY_PATH`.
//!   2. If it exists, load the 32-byte seed (base64) and reconstruct the keypair.
//!      Any failure here is returned to the caller, which must refuse to start.
//!   3. If and only if it does not exist, create one, exclusively, mode 0600.
//!
//! The private key is never logged.
//!
//! # Why loading fails closed (AUDIT B-6)
//!
//! `load_or_generate` previously treated *any* load failure — a truncated
//! file, a permissions error, a wrong-length seed — as licence to generate a
//! fresh keypair and carry on. That silently rotates the service's identity.
//! The damage is not limited to the restart:
//!
//! - Every JWT the service previously issued stops verifying, with no signal
//!   distinguishing "key rotated by accident" from "token forged".
//! - Every audit-export manifest signed under the old key is now signed by a
//!   key the service no longer advertises. An auditor holding an old bundle
//!   cannot tell a legitimate historical signature from a fabricated one.
//! - The rotation is announced at WARN level, in a log line that a running
//!   service emits once and nobody reads.
//!
//! A signing identity is not a cache. If the configured key cannot be read,
//! the correct behaviour is to refuse to serve, and to say what is wrong.
//!
//! # Why creation is exclusive and mode-checked (AUDIT B-5)
//!
//! `save_to_file` wrote the seed with `fs::write` and then chmod'd it to
//! 0600. Between those two calls the private key sits on disk at whatever the
//! process umask allows — commonly 0644. A local reader that wins that race
//! obtains the service's signing key. Creation is therefore done with
//! `O_CREAT | O_EXCL` and the mode supplied at open time, so the file never
//! exists with permissions wider than 0600. `O_EXCL` also removes the second
//! half of the problem: this code can no longer overwrite an existing key.
//!
//! Loading applies the same standard in reverse: a seed file readable by
//! group or other is refused rather than used, because a key that other local
//! accounts can read is not a key that identifies this service.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

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

    /// A fresh keypair, held only in memory.
    ///
    /// Not the production bootstrap path — that is [`KeyPair::load_or_create`],
    /// which persists the seed and refuses to invent one over a key that
    /// already exists. This exists for tests and for callers that genuinely
    /// want an ephemeral identity.
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

    /// Load the keypair at `key_path`, creating one only if the file does not
    /// exist. Every other outcome is an error the caller must act on.
    ///
    /// This replaces the former `load_or_generate`, whose fallback to
    /// generation on *any* failure is AUDIT B-6. The distinction this method
    /// draws is the whole point: "there is no key yet" is a first-run
    /// condition; "there is a key and I could not read it" is an incident.
    pub fn load_or_create(key_path: &str) -> Result<Self, KeyError> {
        match Self::load(key_path) {
            Ok(kp) => {
                // The fingerprint is a hash of the public key: safe to log,
                // and the only way an operator can confirm which identity the
                // service came up as.
                tracing::info!(
                    key_path,
                    fingerprint = %kp.fingerprint,
                    "loaded Ed25519 signing key from disk"
                );
                Ok(kp)
            }
            Err(KeyError::Absent { .. }) => {
                let kp = Self::create_new(key_path)?;
                tracing::info!(
                    key_path,
                    fingerprint = %kp.fingerprint,
                    "no signing key present; created one"
                );
                Ok(kp)
            }
            // Unreadable, malformed, or world-readable: fail closed. Never
            // generate over a key that exists but could not be used.
            Err(e) => Err(e),
        }
    }

    /// Read and validate the seed file. Fails rather than substituting.
    pub fn load(key_path: &str) -> Result<Self, KeyError> {
        let path = PathBuf::from(key_path);
        let raw = match fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(KeyError::Absent { path }),
            Err(source) => return Err(KeyError::Unreadable { path, source }),
        };

        // Permissions are checked after the read succeeds so that a genuine
        // I/O error is reported as one, but before the bytes are used for
        // anything: a seed other local accounts can read does not identify
        // this service, whatever it decodes to.
        check_seed_permissions(&path)?;

        let decoded = B64.decode(raw.trim()).map_err(|e| KeyError::Malformed {
            path: path.clone(),
            reason: format!("seed file is not valid base64: {e}"),
        })?;
        let len = decoded.len();
        let seed: [u8; 32] = decoded.try_into().map_err(|_| KeyError::Malformed {
            path: path.clone(),
            reason: format!("seed must decode to exactly 32 bytes, got {len}"),
        })?;
        Ok(Self::from_seed(seed))
    }

    /// Create a new keypair and persist the seed, failing if a key is already
    /// there.
    ///
    /// The file is created with `O_CREAT | O_EXCL` and mode 0600 supplied at
    /// open time, so it never exists with wider permissions and this call can
    /// never overwrite an existing key (AUDIT B-5).
    pub fn create_new(key_path: &str) -> Result<Self, KeyError> {
        let path = PathBuf::from(key_path);
        let kp = Self::generate();
        write_new_seed_file(&path, &B64.encode(kp.seed))?;
        Ok(kp)
    }
}

// ── Seed file I/O ─────────────────────────────────────────────────────────────

/// Bits that must be clear on a seed file: any group or other permission.
#[cfg(unix)]
const FORBIDDEN_MODE_BITS: u32 = 0o077;

/// Refuse a seed file that group or other can reach.
///
/// Non-Unix targets have no equivalent bit to check; the function is a no-op
/// there rather than pretending to a guarantee it cannot make.
#[cfg(unix)]
fn check_seed_permissions(path: &Path) -> Result<(), KeyError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)
        .map_err(|source| KeyError::Unreadable {
            path: path.to_path_buf(),
            source,
        })?
        .permissions()
        .mode()
        & 0o777;
    if mode & FORBIDDEN_MODE_BITS != 0 {
        return Err(KeyError::Permissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_seed_permissions(_path: &Path) -> Result<(), KeyError> {
    Ok(())
}

/// Write `contents` to `path`, which must not already exist, at mode 0600.
///
/// Deliberately not a write-to-temp-and-rename: the payload is 44 bytes of
/// base64, far below any sector or page boundary, so a torn write is not a
/// realistic failure mode — whereas a stale temp file left by a crashed
/// process is, and it would block every subsequent start. If a partial file
/// somehow appeared, the next start fails closed on a malformed seed, which
/// is the outcome an operator should see.
fn write_new_seed_file(path: &Path, contents: &str) -> Result<(), KeyError> {
    use std::io::Write;

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // The mode is applied by the kernel at creation, so the file is never
        // observable with wider permissions (AUDIT B-5).
        opts.mode(0o600);
    }

    let mut file = opts.open(path).map_err(|source| {
        if source.kind() == io::ErrorKind::AlreadyExists {
            KeyError::AlreadyExists {
                path: path.to_path_buf(),
            }
        } else {
            KeyError::NotWritable {
                path: path.to_path_buf(),
                source,
            }
        }
    })?;
    file.write_all(contents.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|source| KeyError::NotWritable {
            path: path.to_path_buf(),
            source,
        })
}

// ── Errors ────────────────────────────────────────────────────────────────────

/// Why the service could not obtain its signing identity.
///
/// Every variant except [`KeyError::Absent`] is a refusal: the caller must
/// stop, not substitute a fresh key. `Absent` is separated out because it is
/// the only condition under which creating a key is correct.
#[derive(Debug)]
pub enum KeyError {
    /// No file at the configured path. The one recoverable case.
    Absent { path: PathBuf },
    /// The file exists but could not be read.
    Unreadable { path: PathBuf, source: io::Error },
    /// The file was read but does not contain a 32-byte base64 seed.
    Malformed { path: PathBuf, reason: String },
    /// The file is readable by group or other.
    Permissions { path: PathBuf, mode: u32 },
    /// A key already exists where one was to be created.
    AlreadyExists { path: PathBuf },
    /// The new key could not be written.
    NotWritable { path: PathBuf, source: io::Error },
}

impl fmt::Display for KeyError {
    /// Messages name the path and the remedy: this text is what an operator
    /// sees when the service refuses to start, and it is the only thing
    /// standing between them and a wrong guess about what happened.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::Absent { path } => {
                write!(f, "no signing key at {}", path.display())
            }
            KeyError::Unreadable { path, source } => write!(
                f,
                "signing key at {} exists but could not be read ({source}). \
                 Refusing to start: generating a new key here would silently \
                 rotate this service's identity and invalidate every token \
                 and audit bundle it has already signed.",
                path.display()
            ),
            KeyError::Malformed { path, reason } => write!(
                f,
                "signing key at {} is not a valid seed: {reason}. Refusing to \
                 start: restore the key from backup, or move it aside to have \
                 a new identity created deliberately.",
                path.display()
            ),
            KeyError::Permissions { path, mode } => write!(
                f,
                "signing key at {} has mode {mode:04o}; group and other must \
                 have no access. Run: chmod 600 {}",
                path.display(),
                path.display()
            ),
            KeyError::AlreadyExists { path } => write!(
                f,
                "a signing key already exists at {}; refusing to overwrite it",
                path.display()
            ),
            KeyError::NotWritable { path, source } => write!(
                f,
                "could not write a new signing key to {}: {source}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for KeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            KeyError::Unreadable { source, .. } | KeyError::NotWritable { source, .. } => {
                Some(source)
            }
            _ => None,
        }
    }
}
