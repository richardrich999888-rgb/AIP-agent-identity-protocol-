//! The OS-protected file custodian.
//!
//! # What this actually protects against, precisely
//!
//! The key is a file the operating system protects by permission. Created
//! with `O_EXCL` at mode `0600`, refused on load if group or other can reach
//! it, and refused if the directory holding it is writable by anyone else.
//!
//! That defends against:
//!
//! - another local user reading the key,
//! - another local user replacing the key (via a writable parent directory),
//! - a permissive `umask` at creation time,
//! - an accidental overwrite of an existing identity.
//!
//! It does **not** defend against: `root`, any process running as the same
//! uid, memory disclosure of this process, possession of the disk or of a
//! backup, or an offline attacker. A file permission is enforced by a running
//! kernel against local users; it is not a hardware boundary and this class is
//! not named as though it were. Nothing here is tamper-proof,
//! hardware-secured, or non-exportable — the bytes are on the disk in the
//! clear, and anyone who is `root` or who holds the volume has them.
//!
//! Key material is not zeroized on drop. Memory disclosure is outside what
//! [`CustodyClass::OsProtectedFile`] claims, and a `Vec<u8>` that has been
//! reallocated cannot be reliably wiped anyway; claiming otherwise would be
//! the sort of thing this module exists to stop.
//!
//! # Why not a passphrase-wrapped file
//!
//! A passphrase moves the secret, it does not remove it. An unattended edge
//! collector that must sign after an unsupervised reboot has to hold the
//! passphrase somewhere the same process can read — so the wrapped file plus
//! the stored passphrase is exactly as strong as the unwrapped file, with an
//! added appearance of protection. Where a human is present to type it, that
//! is a real gain; that deployment is not this one. See
//! `docs/architecture/KEY_CUSTODY_INVENTORY.md` §2 option B.
//!
//! # On-disk format
//!
//! A fixed binary layout, written and parsed by hand:
//!
//! ```text
//! offset  size  field
//! 0       8     magic "AIPKEY" + format version u16 LE
//! 8       4     key_version u32 LE
//! 12      2     key_id length u16 LE
//! 14      n     key_id (UTF-8)
//! 14+n    32    private key
//! 46+n    32    public key
//! ```
//!
//! Total length is exactly `78 + n`; a file of any other length is malformed.
//!
//! No `serde`, and no type in this module derives `Serialize`. The invariant
//! is "never *casually* serialized": this encoding is a deliberate, reviewed
//! act at one call site, which is the opposite of a derive that will follow a
//! struct into any JSON response someone later writes.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::custodian::{KeyCustody, SigningCustodian};
use crate::error::CustodyError;
use crate::policy::CustodyClass;

/// File magic. Byte 6..8 is the format version, so a future layout change is
/// a parse refusal rather than a misread of the wrong bytes as a key.
const MAGIC: [u8; 6] = *b"AIPKEY";
const FORMAT_VERSION: u16 = 1;

const KEY_LEN: usize = 32;
const HEADER_LEN: usize = 14;

/// A probe message used to check that the stored public key really is the one
/// belonging to the stored private key.
///
/// Ed25519 signing is deterministic (RFC 8032 §5.1.6), so this check is
/// deterministic too: the same file always produces the same probe signature
/// and therefore the same verdict. Domain-separated so the probe signature can
/// never be replayed as a signature over anything the system treats as real.
const PROBE: &[u8] = b"aip.custody.file.selfcheck.v1";

/// A signer whose key lives in an OS-protected file.
pub struct FileCustodian {
    key_id: String,
    key_version: u32,
    private_key: Vec<u8>,
    public_key: Vec<u8>,
    path: PathBuf,
}

impl FileCustodian {
    /// Load an existing key. **Never creates one.**
    ///
    /// Splitting load from create is the whole point: a load that silently
    /// generates on failure — the `load_or_generate` shape — turns a transient
    /// read error into a permanent identity change, and every signature ever
    /// made under the old key becomes unverifiable against the new one. Absence
    /// is reported as [`CustodyError::Absent`] so a caller that genuinely wants
    /// first-run provisioning must ask for it explicitly.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, CustodyError> {
        let path = path.as_ref();
        check_secret_file_permissions(path)?;

        let mut bytes = Vec::new();
        fs::File::open(path)
            .and_then(|mut f| f.read_to_end(&mut bytes))
            .map_err(|source| CustodyError::Unreadable {
                path: path.to_path_buf(),
                source,
            })?;

        Self::decode(path, &bytes)
    }

    /// Create a key file, failing if anything already exists at `path`.
    ///
    /// `create_new(true)` is `O_EXCL`: the existence check and the creation are
    /// one atomic syscall, so there is no window in which another process can
    /// win the race and have its key silently overwritten. `mode(0o600)` sets
    /// the permission at creation, not afterwards — a create-then-`chmod`
    /// leaves the key world-readable for the interval between the two calls.
    pub fn create(
        path: impl AsRef<Path>,
        key_id: &str,
        key_version: u32,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<Self, CustodyError> {
        let path = path.as_ref();
        require_unix(path)?;
        check_parent_directory(path)?;

        if private_key.len() != KEY_LEN || public_key.len() != KEY_LEN {
            return Err(CustodyError::Malformed {
                path: path.to_path_buf(),
                reason: format!(
                    "expected {KEY_LEN}-byte keys, got {} and {}",
                    private_key.len(),
                    public_key.len()
                ),
            });
        }
        if key_id.is_empty() || key_id.len() > u16::MAX as usize {
            return Err(CustodyError::Malformed {
                path: path.to_path_buf(),
                reason: format!("key_id length {} is out of range", key_id.len()),
            });
        }

        let encoded = encode(key_id, key_version, private_key, public_key);
        create_secret_file(path, &encoded)?;

        Ok(Self {
            key_id: key_id.to_owned(),
            key_version,
            private_key: private_key.to_vec(),
            public_key: public_key.to_vec(),
            path: path.to_path_buf(),
        })
    }

    /// Generate a fresh key and create its file.
    ///
    /// Correct only on first provisioning. It fails with
    /// [`CustodyError::AlreadyExists`] rather than replacing an identity.
    pub fn generate(
        path: impl AsRef<Path>,
        key_id: &str,
        key_version: u32,
    ) -> Result<Self, CustodyError> {
        let kp = aip_crypto::generate_ed25519_keypair();
        Self::create(path, key_id, key_version, &kp.private_key, &kp.public_key)
    }

    /// Load the key, creating one **only if the file does not exist**.
    ///
    /// This is the first-run provisioning path, and the distinction from
    /// `load_or_generate` is the security property: creation is reachable from
    /// exactly one error — [`CustodyError::Absent`]. An unreadable file, a bad
    /// mode, a malformed file and a mismatched key pair all propagate. Those
    /// are the conditions under which generating a replacement would destroy
    /// an identity that still exists, and under which a `load_or_generate`
    /// shape does exactly that.
    pub fn load_or_create(
        path: impl AsRef<Path>,
        key_id: &str,
        key_version: u32,
    ) -> Result<Self, CustodyError> {
        let path = path.as_ref();
        match Self::load(path) {
            Err(CustodyError::Absent { .. }) => Self::generate(path, key_id, key_version),
            other => other,
        }
    }

    /// The file this custodian's key was loaded from. A path, never contents.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Parse the on-disk layout. Every length is checked before it is used.
    fn decode(path: &Path, bytes: &[u8]) -> Result<Self, CustodyError> {
        let malformed = |reason: String| CustodyError::Malformed {
            path: path.to_path_buf(),
            reason,
        };

        if bytes.len() < HEADER_LEN {
            return Err(malformed(format!(
                "file is {} bytes; the header alone is {HEADER_LEN}",
                bytes.len()
            )));
        }
        if bytes[0..6] != MAGIC {
            return Err(malformed("not an AIP key file (bad magic)".to_string()));
        }
        let format_version = u16::from_le_bytes([bytes[6], bytes[7]]);
        if format_version != FORMAT_VERSION {
            return Err(malformed(format!(
                "key file format version {format_version}; this build reads \
                 version {FORMAT_VERSION} only"
            )));
        }
        let key_version = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let id_len = u16::from_le_bytes([bytes[12], bytes[13]]) as usize;

        // Exact length: a trailing byte means the file is not what this build
        // wrote, and a short file means it was truncated. Both are refusals,
        // because "read as much as parses" is how a truncated key becomes a
        // silently different identity.
        let expected = HEADER_LEN + id_len + 2 * KEY_LEN;
        if bytes.len() != expected {
            return Err(malformed(format!(
                "file is {} bytes; a key with a {id_len}-byte id is exactly \
                 {expected}",
                bytes.len()
            )));
        }
        if id_len == 0 {
            return Err(malformed("empty key id".to_string()));
        }

        let key_id = std::str::from_utf8(&bytes[HEADER_LEN..HEADER_LEN + id_len])
            .map_err(|e| malformed(format!("key id is not UTF-8: {e}")))?
            .to_owned();

        let priv_at = HEADER_LEN + id_len;
        let private_key = bytes[priv_at..priv_at + KEY_LEN].to_vec();
        let public_key = bytes[priv_at + KEY_LEN..priv_at + 2 * KEY_LEN].to_vec();

        // Self-consistency: sign a fixed probe with the stored private key and
        // verify it with the stored public key. If they are not a pair, this
        // custodian would emit signatures that no verifier anchored on the
        // stored public key could ever accept — a failure that would otherwise
        // surface far away, at the relying party, as an unexplained rejection.
        let probe = aip_crypto::sign_ed25519_raw(&private_key, PROBE)
            .map_err(|e| malformed(format!("stored private key is unusable: {e:?}")))?;
        if !aip_crypto::verify_ed25519_raw(&public_key, PROBE, &probe) {
            return Err(malformed(
                "the stored public key does not correspond to the stored \
                 private key"
                    .to_string(),
            ));
        }

        Ok(Self {
            key_id,
            key_version,
            private_key,
            public_key,
            path: path.to_path_buf(),
        })
    }
}

/// Serialize the fixed layout. The only place key bytes are written out.
fn encode(key_id: &str, key_version: u32, private_key: &[u8], public_key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + key_id.len() + 2 * KEY_LEN);
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&key_version.to_le_bytes());
    out.extend_from_slice(&(key_id.len() as u16).to_le_bytes());
    out.extend_from_slice(key_id.as_bytes());
    out.extend_from_slice(private_key);
    out.extend_from_slice(public_key);
    out
}

/// Refuse on any platform where the permission model this class names is not
/// the one actually being enforced.
///
/// Fail closed. A Windows build silently producing a file with no mode would
/// report `OsProtectedFile` custody it does not have, and a class that lies is
/// worse than a class that is missing.
fn require_unix(path: &Path) -> Result<(), CustodyError> {
    #[cfg(unix)]
    {
        let _ = path;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        Err(CustodyError::Malformed {
            path: path.to_path_buf(),
            reason: "OS-protected file custody is implemented for Unix \
                     permission semantics only; this platform has none, and \
                     this backend will not claim protection it cannot enforce"
                .to_string(),
        })
    }
}

/// Refuse a key whose own mode lets group or other reach it.
fn check_mode(path: &Path, meta: &fs::Metadata) -> Result<(), CustodyError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o7777;
        // 0o077 = any read, write or execute bit for group or other.
        if mode & 0o077 != 0 {
            return Err(CustodyError::Permissions {
                path: path.to_path_buf(),
                mode,
            });
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (path, meta);
        require_unix(path)
    }
}

/// Refuse a key whose directory lets another user replace it.
///
/// A mode-0600 key in a group-writable directory is not protected: another
/// user cannot read it, but can unlink it and put their own key in its place,
/// which is a stronger attack than reading. The sticky bit (`0o1000`) is the
/// exception the kernel itself makes — in a sticky directory only the owner
/// may remove a file — so a sticky world-writable directory such as `/tmp` is
/// accepted, and a plain one is not.
fn check_parent_directory(path: &Path) -> Result<(), CustodyError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
        let Some(parent) = parent else {
            return Ok(());
        };
        let meta = match fs::metadata(parent) {
            Ok(m) => m,
            // A missing directory is the caller's to create; it is not a
            // permission finding, and create() will report it as NotWritable.
            Err(_) => return Ok(()),
        };
        let mode = meta.permissions().mode() & 0o7777;
        if mode & 0o022 != 0 && mode & 0o1000 == 0 {
            return Err(CustodyError::Permissions {
                path: parent.to_path_buf(),
                mode,
            });
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        require_unix(path)
    }
}

impl KeyCustody for FileCustodian {
    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn key_version(&self) -> u32 {
        self.key_version
    }
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    fn custody_class(&self) -> CustodyClass {
        CustodyClass::OsProtectedFile
    }
}

impl SigningCustodian for FileCustodian {
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], CustodyError> {
        aip_crypto::sign_ed25519_raw(&self.private_key, message)
            .map_err(|e| CustodyError::SigningFailed(format!("{e:?}")))
    }
}

/// Redacted: a custodian must not print what it holds, in any format.
impl std::fmt::Debug for FileCustodian {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileCustodian")
            .field("key_id", &self.key_id)
            .field("key_version", &self.key_version)
            .field("path", &self.path)
            .field("custody_class", &CustodyClass::OsProtectedFile)
            .field(
                "private_key",
                &format_args!("<redacted {} bytes>", self.private_key.len()),
            )
            .finish()
    }
}

/// Atomically replace `path` with `bytes`, at mode 0600.
///
/// For files that carry secret material but are rewritten rather than created
/// once — a development identity store, for example. [`FileCustodian::create`]
/// is `O_EXCL` because a key file must never be replaced; this is the deliberate
/// counterpart for the case where replacement is the point.
///
/// Two properties, both load-bearing:
///
/// - **The mode is set at creation.** The temporary file is opened with
///   `mode(0o600)`, so the content is never momentarily world-readable. A
///   write-then-`chmod` leaves exactly that window, and a reader only has to
///   win a race once.
/// - **The replacement is atomic.** Content is written to a temporary file in
///   the same directory and `rename`d over the target, which is atomic within a
///   filesystem. A crash mid-write therefore leaves the previous file intact
///   rather than a truncated one — and a truncated store of identities is
///   indistinguishable from a store from which identities were deleted.
///
/// The temporary file carries the process id so two processes writing at once
/// do not collide on it; the `rename` still makes one of them the loser, which
/// is the correct outcome for a last-writer-wins file.
pub fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<(), CustodyError> {
    require_unix(path)?;
    check_parent_directory(path)?;

    // An existing symlink would have rename() replace the link, not the file
    // it points at — but a subsequent load through the same path would then
    // read the new file, so the risk is a stale target elsewhere rather than a
    // redirect. Refuse anyway: a key-bearing path that is not a regular file
    // has no honest permission story.
    match fs::symlink_metadata(path) {
        Ok(m) if !m.file_type().is_file() => {
            return Err(CustodyError::Malformed {
                path: path.to_path_buf(),
                reason: "not a regular file (a symlink, directory or device \
                         cannot carry enforceable key permissions)"
                    .to_string(),
            });
        }
        _ => {}
    }

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
        let not_writable = |source: std::io::Error| CustodyError::NotWritable {
            path: path.to_path_buf(),
            source,
        };

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(not_writable)?;

        let written = file
            .write_all(bytes)
            .and_then(|()| file.sync_all())
            .and_then(|()| fs::rename(&tmp, path));

        if let Err(e) = written {
            // Leave no readable remnant of a failed write.
            let _ = fs::remove_file(&tmp);
            return Err(not_writable(e));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = bytes;
        require_unix(path)
    }
}

/// Create `dir` if absent, at mode 0700, and refuse it if anyone else can
/// write to it.
///
/// A key file at mode 0600 inside a group-writable directory is not protected:
/// another user cannot read the key, but can unlink it and leave their own in
/// its place — a substitution attack, which is worse than disclosure because
/// the system keeps working and signs with the attacker's key. The directory
/// permission is therefore part of the custody claim, not an operational nicety.
///
/// The mode is set by `DirBuilder::mode`, at creation, so there is no interval
/// during which the directory is world-writable. An existing directory is
/// checked rather than corrected: silently `chmod`-ing a directory the operator
/// created is a surprising action, and refusing tells them what is wrong.
pub fn ensure_secret_dir(dir: &Path) -> Result<(), CustodyError> {
    require_unix(dir)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

        if !dir.exists() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(|source| CustodyError::NotWritable {
                    path: dir.to_path_buf(),
                    source,
                })?;
        }

        let meta = fs::metadata(dir).map_err(|source| CustodyError::Unreadable {
            path: dir.to_path_buf(),
            source,
        })?;
        if !meta.is_dir() {
            return Err(CustodyError::Malformed {
                path: dir.to_path_buf(),
                reason: "expected a directory".to_string(),
            });
        }
        let mode = meta.permissions().mode() & 0o7777;
        // Sticky (0o1000) is the kernel's own exception: only an owner may
        // remove a file from such a directory, so substitution is blocked.
        if mode & 0o022 != 0 && mode & 0o1000 == 0 {
            return Err(CustodyError::Permissions {
                path: dir.to_path_buf(),
                mode,
            });
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        require_unix(dir)
    }
}

/// Verify that `path` is a regular file whose permissions make it a secret.
///
/// The single implementation of the rule, so a caller that stores key material
/// in its own format — the service's base64 seed file, for instance — enforces
/// exactly what [`FileCustodian::load`] enforces rather than a second, drifting
/// approximation.
///
/// Checks, in order: the path exists ([`CustodyError::Absent`] if not, which is
/// the one recoverable condition); it is a regular file, not a symlink,
/// directory or device; its directory is not writable by anyone else; and its
/// own mode grants nothing to group or other.
pub fn check_secret_file_permissions(path: &Path) -> Result<(), CustodyError> {
    require_unix(path)?;

    // symlink_metadata, not metadata: a symlink's own mode is meaningless
    // (always 0777), so checking the target's mode through a link would pass
    // while the link itself could be repointed at another file.
    let link_meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(CustodyError::Absent {
                path: path.to_path_buf(),
            });
        }
        Err(source) => {
            return Err(CustodyError::Unreadable {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if !link_meta.file_type().is_file() {
        return Err(CustodyError::Malformed {
            path: path.to_path_buf(),
            reason: "not a regular file (a symlink, directory or device cannot \
                     carry enforceable key permissions)"
                .to_string(),
        });
    }

    check_parent_directory(path)?;
    check_mode(path, &link_meta)
}

/// Create `path` exclusively, at mode 0600, and write `bytes` to it.
///
/// `create_new(true)` is `O_EXCL`: existence check and creation are one
/// syscall, so no other process can win a race and have its file silently
/// replaced. `mode(0o600)` applies the permission at creation — a
/// create-then-`chmod` leaves the content world-readable for the interval
/// between the two calls, and a reader only has to win that race once.
///
/// Fails with [`CustodyError::AlreadyExists`] if anything is already there.
/// That refusal is the point: overwriting a key file destroys an identity.
pub fn create_secret_file(path: &Path, bytes: &[u8]) -> Result<(), CustodyError> {
    require_unix(path)?;
    check_parent_directory(path)?;

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|source| {
                if source.kind() == std::io::ErrorKind::AlreadyExists {
                    CustodyError::AlreadyExists {
                        path: path.to_path_buf(),
                    }
                } else {
                    CustodyError::NotWritable {
                        path: path.to_path_buf(),
                        source,
                    }
                }
            })?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|source| CustodyError::NotWritable {
                path: path.to_path_buf(),
                source,
            })
    }
    #[cfg(not(unix))]
    {
        let _ = bytes;
        require_unix(path)
    }
}
