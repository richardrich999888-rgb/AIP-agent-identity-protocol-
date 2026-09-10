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
    /// Key material on disk in the clear, protected only by file
    /// permission.
    ///
    /// **Not production**, and named rather than left unnamed so that the
    /// places that still do this cannot be mistaken for the places that do
    /// not. It exists because `aip-service` persists a base64 seed in this
    /// shape and its deployed key files must keep loading; a deployment
    /// that wants a production custody posture supplies a passphrase and
    /// gets [`Backend::WrappedFile`] instead.
    ///
    /// This is not a capability claim for an unimplemented backend — it
    /// names something the repository actually does today, so that a policy
    /// check can refuse it.
    PlaintextFile,
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
            // Plaintext on the disk. Anyone holding the volume, a snapshot
            // or a backup has the key, and no passphrase stands in the way.
            Backend::PlaintextFile => false,
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
        check_secret_file(&path)?;
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
        // Written to a temporary file whose mode is set *by the open call*,
        // before any bytes land, then renamed: a reader never sees a
        // partly-written key, and never sees one at mode 644 even briefly.
        //
        // The mode must come from `OpenOptions::mode`, not from a `chmod`
        // after the write. `fs::write` creates at `0o666 & !umask`, so a
        // write-then-restrict sequence leaves the key world-readable for the
        // interval between the two syscalls — and a reader only has to win
        // that race once. The temp name carries the process id so two
        // processes writing at once do not collide on it.
        let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
        write_owner_only_file(&tmp, &out)?;
        if let Err(e) = std::fs::rename(&tmp, path) {
            // Leave no readable remnant of a failed write.
            let _ = std::fs::remove_file(&tmp);
            return Err(CustodyError::Io(e.to_string()));
        }
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

// ─── Permission discipline ───

/// Create `path` with mode 0600 applied by the open call, and write `bytes`.
///
/// The mode must be set at creation. `fs::write` creates at `0o666 & !umask`
/// and a following `chmod` closes the window only *after* the bytes are on
/// disk; a reader only has to win that race once. On a platform without Unix
/// permissions this falls back to a plain write, and [`Backend`] is what tells
/// the caller what it is relying on.
pub fn write_owner_only_file(path: &Path, bytes: &[u8]) -> Result<(), CustodyError> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| CustodyError::Io(e.to_string()))?;
        f.write_all(bytes)
            .and_then(|()| f.sync_all())
            .map_err(|e| CustodyError::Io(e.to_string()))
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes).map_err(|e| CustodyError::Io(e.to_string()))
    }
}

/// Refuse a key file that is not a regular file, owner-only, in a directory
/// nobody else can write.
///
/// Fail closed, and it is worth being precise about what this adds to a file
/// that is already encrypted. The passphrase is the primary protection; these
/// checks are what keep an attacker from *getting* the ciphertext to attack
/// offline, and from replacing it:
///
/// - **Mode.** A wrapped key at 0644 is an Argon2id target any local user can
///   copy and grind at their leisure. Encryption raises the cost of an offline
///   attack; it does not make handing over the ciphertext free.
/// - **Regular file.** A symlink's own mode is meaningless (always 0777), so
///   checking a target's mode through a link proves nothing about the link,
///   which can be repointed.
/// - **Parent directory.** A 0600 key in a group-writable directory can be
///   unlinked and replaced with the attacker's own wrapped key under a
///   passphrase they chose. That is a substitution attack, and it is worse
///   than disclosure because the system keeps working and signs with their
///   key. The sticky bit is the kernel's own exception — only an owner may
///   remove a file from such a directory — so `/tmp` and its like are accepted.
pub fn check_secret_file(path: &Path) -> Result<(), CustodyError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let meta = std::fs::symlink_metadata(path).map_err(|e| CustodyError::Io(e.to_string()))?;
        if !meta.file_type().is_file() {
            return Err(CustodyError::Malformed(
                "not a regular file: a symlink, directory or device cannot carry \
                 enforceable key permissions"
                    .into(),
            ));
        }
        let mode = meta.permissions().mode() & 0o7777;
        // 0o077 = any read, write or execute bit for group or other.
        if mode & 0o077 != 0 {
            return Err(CustodyError::Malformed(format!(
                "{} has mode {mode:o}; group and other must have no access. \
                 Run: chmod 600 {}",
                path.display(),
                path.display()
            )));
        }

        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            if let Ok(dm) = std::fs::metadata(parent) {
                let dmode = dm.permissions().mode() & 0o7777;
                if dmode & 0o022 != 0 && dmode & 0o1000 == 0 {
                    return Err(CustodyError::Malformed(format!(
                        "{} has mode {dmode:o}; another user could replace the key \
                         inside it. Run: chmod 700 {}",
                        parent.display(),
                        parent.display()
                    )));
                }
            }
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

// ─── Raw signing ───

/// A custodian that will also produce a bare Ed25519 signature over exact
/// bytes, outside the [`Signature`] envelope.
///
/// Deliberately **separate from [`Custodian`]**, and implemented only by the
/// two general-purpose backends. Some things a signer must sign are not AIP
/// signature envelopes — an audit-export bundle manifest is signed as a
/// detached 64-byte signature so it can be checked offline with nothing but
/// the public key and the bytes.
///
/// It is a separate trait because `sign(&[u8]) -> [u8; 64]` is a raw-signing
/// oracle: whoever holds one can obtain that key's signature over *any* bytes,
/// including bytes that are a valid preimage for some other protocol in this
/// workspace. Widening `Custodian` would hand that oracle to every key holder
/// that implements it — including the collector, whose only signing surface
/// should stay the batch attestation it constructs itself. So the two capabilities
/// stay apart, and a type opts in to the wider one.
///
/// `CollectorKey` deliberately does **not** implement this.
pub trait RawSigner: Send + Sync {
    /// The public key a verifier anchors. Safe to publish.
    fn public_key(&self) -> &[u8];

    /// Sign `message` exactly, returning the detached Ed25519 signature.
    fn sign_raw(&self, message: &[u8]) -> Result<[u8; 64], CustodyError>;
}

impl RawSigner for InMemoryCustodian {
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    fn sign_raw(&self, message: &[u8]) -> Result<[u8; 64], CustodyError> {
        crate::sign_ed25519_raw(&self.private_key, message).map_err(CustodyError::Crypto)
    }
}

impl RawSigner for WrappedFileCustodian {
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    fn sign_raw(&self, message: &[u8]) -> Result<[u8; 64], CustodyError> {
        crate::sign_ed25519_raw(&self.private_key, message).map_err(CustodyError::Crypto)
    }
}

/// Create `path` exclusively at mode 0600 and write `bytes`.
///
/// `create_new(true)` is `O_EXCL`: the existence check and the creation are one
/// syscall, so no other process can win a race and have its file silently
/// replaced. Fails if anything is already there — overwriting a key file
/// destroys an identity.
///
/// For key material a caller stores in its own format. Callers holding a
/// wrapped key use [`WrappedFileCustodian`] instead.
pub fn create_owner_only(path: &Path, bytes: &[u8]) -> Result<(), CustodyError> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|e| CustodyError::Io(e.to_string()))?;
        }
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| CustodyError::Io(e.to_string()))?;
        f.write_all(bytes)
            .and_then(|()| f.sync_all())
            .map_err(|e| CustodyError::Io(e.to_string()))
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes).map_err(|e| CustodyError::Io(e.to_string()))
    }
}

/// Recover the raw signing seed from a wrapped key file.
///
/// **A named export path, and the only one.** [`Custodian`] has no
/// `private_key()` and [`WrappedFileCustodian`] will not surrender its key;
/// this function exists because `jsonwebtoken` builds its `EncodingKey` from a
/// PKCS#8 PEM, so a service issuing JWTs must materialise the key in that form
/// or not issue JWTs at all.
///
/// It is a free function with an unmistakable name rather than a method,
/// precisely so that every use of it is visible at the call site and greppable
/// in review. Do not reach for it for anything a [`Custodian`] can already do.
pub fn wrapped_file_seed(path: &Path, passphrase: &[u8]) -> Result<[u8; 32], CustodyError> {
    let custodian = WrappedFileCustodian::open(path, passphrase)?;
    custodian
        .private_key
        .as_slice()
        .try_into()
        .map_err(|_| CustodyError::InvalidKeyLength(custodian.private_key.len()))
}
