//! Private-key custody — Phase A.
//!
//! A [`Custodian`] holds a signing key and signs with it. It does not hand
//! it back. That is the whole of the idea, and everything below follows
//! from it: a production backend has no method that returns key material,
//! so a caller cannot leak what it cannot obtain.
//!
//! ```text
//!   Custodian
//!     ├── DevelopmentInMemory   key in memory, never written, not production
//!     └── WrappedFile           Argon2id + XChaCha20-Poly1305, mode 0600
//!         (future: TPM, HSM, KMS — added with their implementations,
//!          never as an empty variant that reads like a capability)
//! ```
//!
//! # Custody is not attestation
//!
//! A protected key establishes **who signed**. It establishes nothing
//! about whether what was signed is true. These stay separate everywhere:
//!
//! ```text
//! hardware-backed key ≠ hardware-attested execution ≠ physical-effect proof
//! ```
//!
//! Nothing here licenses a stronger statement about an observation, and no
//! evidence-strength decision anywhere consults which backend signed.
//!
//! # One set of semantics
//!
//! Every backend produces a [`Signature`] through the same
//! [`sign_ed25519`] envelope, so a verifier cannot tell which backend
//! signed and does not need to. Custody changes where a key lives, never
//! what a signature means.
//!
//! See `docs/adr/ADR-KEY-CUSTODY.md` for the backend comparison and for
//! what this decision deliberately does not settle.

use std::path::{Path, PathBuf};

use aip_types::{AipError, Signature};
use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::sign_ed25519;

/// Which mechanism is holding the key.
///
/// Named rather than boolean so a log line, a report or a test says what
/// it actually is. `is_production` is the question callers ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// Key material in this process's memory, never written anywhere.
    /// Tests and development. Losing the process loses the key.
    DevelopmentInMemory,
    /// A passphrase-wrapped file: Argon2id derives the key-encryption key,
    /// XChaCha20-Poly1305 wraps the signing key, the file is mode 0600.
    WrappedFile,
}

impl Backend {
    /// May a production deployment rely on this?
    ///
    /// The point of the question is that a development backend must not be
    /// mistakable for a production one — not that this crate enforces a
    /// policy it cannot see. Callers that have a production/development
    /// distinction ask this and refuse.
    pub fn is_production(self) -> bool {
        match self {
            Backend::DevelopmentInMemory => false,
            Backend::WrappedFile => true,
        }
    }
}

#[derive(Debug)]
pub enum CustodyError {
    /// The file is not a wrapped key, or is of a version this build does
    /// not implement. Named, never guessed at.
    Malformed(String),
    UnsupportedVersion(u16),
    /// The passphrase did not open it, or the file was altered. These are
    /// deliberately one error: an AEAD cannot distinguish them, and
    /// pretending otherwise would invent information.
    CannotOpen,
    Io(String),
    Crypto(AipError),
    /// A key of the wrong length reached a constructor.
    InvalidKeyLength(usize),
}

impl std::fmt::Display for CustodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CustodyError::Malformed(e) => write!(f, "not a wrapped key: {e}"),
            CustodyError::UnsupportedVersion(v) => {
                write!(f, "wrapped-key format version {v} is not implemented here")
            }
            CustodyError::CannotOpen => write!(
                f,
                "the key could not be opened: wrong passphrase, or the file was altered"
            ),
            CustodyError::Io(e) => write!(f, "io: {e}"),
            CustodyError::Crypto(e) => write!(f, "crypto: {e:?}"),
            CustodyError::InvalidKeyLength(n) => {
                write!(f, "a signing key must be 32 bytes, got {n}")
            }
        }
    }
}

impl std::error::Error for CustodyError {}

/// Holds a signing key and signs with it.
///
/// There is no `private_key()`, and adding one would defeat the purpose:
/// a caller cannot leak what it cannot obtain. Backends that could
/// technically expose the bytes still do not, so that code written against
/// this trait keeps working when a non-exportable backend replaces a
/// software one.
pub trait Custodian: std::fmt::Debug + Send + Sync {
    fn public_key(&self) -> &[u8];
    fn sign(&self, signer_id: &str, payload: &[u8]) -> Result<Signature, CustodyError>;
    fn backend(&self) -> Backend;
}

// ─── Development ───

/// Key material in memory. Wiped on drop, written nowhere, and it says it
/// is not production when asked.
pub struct InMemoryCustodian {
    private_key: Zeroizing<Vec<u8>>,
    public_key: Vec<u8>,
}

impl std::fmt::Debug for InMemoryCustodian {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryCustodian")
            .field("backend", &Backend::DevelopmentInMemory)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

impl InMemoryCustodian {
    pub fn new(private_key: &[u8], public_key: &[u8]) -> Result<Self, CustodyError> {
        if private_key.len() != 32 {
            return Err(CustodyError::InvalidKeyLength(private_key.len()));
        }
        Ok(Self {
            private_key: Zeroizing::new(private_key.to_vec()),
            public_key: public_key.to_vec(),
        })
    }

    /// A fresh key that exists only in this process.
    pub fn generate() -> Self {
        let kp = crate::generate_ed25519_keypair();
        Self {
            private_key: Zeroizing::new(kp.private_key),
            public_key: kp.public_key,
        }
    }
}

impl Custodian for InMemoryCustodian {
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    fn sign(&self, signer_id: &str, payload: &[u8]) -> Result<Signature, CustodyError> {
        sign_ed25519(&self.private_key, signer_id, payload).map_err(CustodyError::Crypto)
    }
    fn backend(&self) -> Backend {
        Backend::DevelopmentInMemory
    }
}

// ─── Wrapped file ───

const MAGIC: &[u8; 8] = b"AIPWKEY\x00";
const WRAPPED_KEY_VERSION: u16 = 1;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 24;

/// A signing key wrapped under a passphrase, on disk.
///
/// The file is `magic ‖ version ‖ salt ‖ nonce ‖ ciphertext`, and the
/// header is the AEAD's associated data, so swapping a salt or a version
/// between files fails to open rather than opening something else.
///
/// The decrypted key lives in a `Zeroizing` buffer for the life of the
/// custodian and is never returned. An attacker who can read this
/// process's memory has it anyway — that is what a hardware backend would
/// address, and it is not implemented.
pub struct WrappedFileCustodian {
    path: PathBuf,
    private_key: Zeroizing<Vec<u8>>,
    public_key: Vec<u8>,
}

impl std::fmt::Debug for WrappedFileCustodian {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WrappedFileCustodian")
            .field("backend", &Backend::WrappedFile)
            .field("path", &self.path)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

fn kek(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, CustodyError> {
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(passphrase, salt, out.as_mut())
        .map_err(|e| CustodyError::Malformed(format!("key derivation: {e}")))?;
    Ok(out)
}

/// `magic ‖ version` — bound as associated data so a header cannot be
/// edited without the open failing.
fn header(salt: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut h = Vec::with_capacity(MAGIC.len() + 2 + SALT_LEN + NONCE_LEN);
    h.extend_from_slice(MAGIC);
    h.extend_from_slice(&WRAPPED_KEY_VERSION.to_be_bytes());
    h.extend_from_slice(salt);
    h.extend_from_slice(nonce);
    h
}

impl WrappedFileCustodian {
    /// Generate a key and wrap it at `path`. The key is never returned.
    ///
    /// Refuses to overwrite: replacing a key is [`rotate`](Self::rotate),
    /// which is a deliberate act, and silently clobbering one would make
    /// every signature it ever made unverifiable by accident.
    pub fn create(path: impl AsRef<Path>, passphrase: &[u8]) -> Result<Self, CustodyError> {
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            return Err(CustodyError::Io(format!(
                "{} already holds a key; use rotate to replace it",
                path.display()
            )));
        }
        let kp = crate::generate_ed25519_keypair();
        Self::write(&path, passphrase, &kp.private_key, &kp.public_key)?;
        Ok(Self {
            path,
            private_key: Zeroizing::new(kp.private_key),
            public_key: kp.public_key,
        })
    }

    /// Replace the key at `path` with a fresh one.
    ///
    /// The previous key is gone afterwards. Signatures it made remain
    /// verifiable by anyone holding its public key — verification does not
    /// consult custody — so rotation is not retroactive and is not meant
    /// to be.
    pub fn rotate(path: impl AsRef<Path>, passphrase: &[u8]) -> Result<Self, CustodyError> {
        let path = path.as_ref().to_path_buf();
        let kp = crate::generate_ed25519_keypair();
        Self::write(&path, passphrase, &kp.private_key, &kp.public_key)?;
        Ok(Self {
            path,
            private_key: Zeroizing::new(kp.private_key),
            public_key: kp.public_key,
        })
    }

    /// Wrap an existing key. For enrolling a key generated elsewhere; a
    /// key generated here never needs it.
    pub fn adopt(
        path: impl AsRef<Path>,
        passphrase: &[u8],
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<Self, CustodyError> {
        if private_key.len() != 32 {
            return Err(CustodyError::InvalidKeyLength(private_key.len()));
        }
        let path = path.as_ref().to_path_buf();
        Self::write(&path, passphrase, private_key, public_key)?;
        Ok(Self {
            path,
            private_key: Zeroizing::new(private_key.to_vec()),
            public_key: public_key.to_vec(),
        })
    }

    /// Open a wrapped key. A wrong passphrase and an altered file are the
    /// same error, because the AEAD cannot tell them apart and inventing a
    /// distinction would be inventing information.
    pub fn open(path: impl AsRef<Path>, passphrase: &[u8]) -> Result<Self, CustodyError> {
        let path = path.as_ref().to_path_buf();
        let bytes = std::fs::read(&path).map_err(|e| CustodyError::Io(e.to_string()))?;
        let min = MAGIC.len() + 2 + SALT_LEN + NONCE_LEN;
        if bytes.len() < min {
            return Err(CustodyError::Malformed("file is too short".into()));
        }
        if &bytes[..MAGIC.len()] != MAGIC {
            return Err(CustodyError::Malformed("wrong magic".into()));
        }
        let version = u16::from_be_bytes([bytes[MAGIC.len()], bytes[MAGIC.len() + 1]]);
        if version != WRAPPED_KEY_VERSION {
            return Err(CustodyError::UnsupportedVersion(version));
        }
        let salt_at = MAGIC.len() + 2;
        let nonce_at = salt_at + SALT_LEN;
        let ct_at = nonce_at + NONCE_LEN;
        let salt = &bytes[salt_at..nonce_at];
        let nonce = &bytes[nonce_at..ct_at];
        let ciphertext = &bytes[ct_at..];

        let key = kek(passphrase, salt)?;
        let aead = XChaCha20Poly1305::new(key.as_ref().into());
        let plain = aead
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &header(salt, nonce),
                },
            )
            .map_err(|_| CustodyError::CannotOpen)?;
        let plain = Zeroizing::new(plain);
        if plain.len() != 64 {
            return Err(CustodyError::Malformed(
                "wrapped payload is not a keypair".into(),
            ));
        }
        Ok(Self {
            path,
            private_key: Zeroizing::new(plain[..32].to_vec()),
            public_key: plain[32..].to_vec(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn write(
        path: &Path,
        passphrase: &[u8],
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<(), CustodyError> {
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        let mut plain = Zeroizing::new(Vec::with_capacity(64));
        plain.extend_from_slice(private_key);
        plain.extend_from_slice(public_key);

        let key = kek(passphrase, &salt)?;
        let aead = XChaCha20Poly1305::new(key.as_ref().into());
        let ciphertext = aead
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: &header(&salt, &nonce),
                },
            )
            .map_err(|e| CustodyError::Malformed(format!("wrap: {e}")))?;

        let mut out = header(&salt, &nonce);
        out.extend_from_slice(&ciphertext);

        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| CustodyError::Io(e.to_string()))?;
            }
        }
        // Written to a temporary file with restrictive permissions set
        // before any bytes land, then renamed: a reader never sees a
        // partly-written key, and never sees one at mode 644 even briefly.
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &out).map_err(|e| CustodyError::Io(e.to_string()))?;
        restrict(&tmp)?;
        std::fs::rename(&tmp, path).map_err(|e| CustodyError::Io(e.to_string()))?;
        restrict(path)?;
        Ok(())
    }
}

/// Owner-only. Best effort on platforms without Unix permissions, where
/// the caller is told by [`Backend`] what it is relying on.
fn restrict(path: &Path) -> Result<(), CustodyError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)
            .map_err(|e| CustodyError::Io(e.to_string()))?
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms).map_err(|e| CustodyError::Io(e.to_string()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

impl Custodian for WrappedFileCustodian {
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    fn sign(&self, signer_id: &str, payload: &[u8]) -> Result<Signature, CustodyError> {
        sign_ed25519(&self.private_key, signer_id, payload).map_err(CustodyError::Crypto)
    }
    fn backend(&self) -> Backend {
        Backend::WrappedFile
    }
}
