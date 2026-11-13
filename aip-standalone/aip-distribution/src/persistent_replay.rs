//! Durable, bounded request replay journal for Unix hosts.
//!
//! The journal detects accidental corruption and serializes local writers. Its
//! unkeyed digest is not an authenticity mechanism, and restoring an older
//! journal remains possible without an independently trusted checkpoint.

use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::fd::AsRawFd,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

pub const REPLAY_JOURNAL_VERSION: u16 = 1;
pub const REPLAY_RETENTION_MS: u64 = 24 * 60 * 60 * 1000;
pub const MAX_DURABLE_REPLAY_IDS: usize = 131_072;
pub const MAX_DURABLE_REPLAY_IDS_PER_PEER: usize = 4096;
pub const MAX_REPLAY_JOURNAL_BYTES: u64 = 8 * 1024 * 1024;
const JOURNAL_DOMAIN: &[u8] = b"AIP/DISTRIBUTION/REPLAY_JOURNAL/v1\0";
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayEntry {
    peer_id: String,
    request_id: [u8; 16],
    expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalState {
    version: u16,
    entries: Vec<ReplayEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalEnvelope {
    state: JournalState,
    digest_sha256: String,
}

/// Holds an exclusive lock for its lifetime. Open this once per process and
/// call `record` only after transport peer identity and application admission
/// have succeeded. The durable record is synced before `record` returns.
pub struct PersistentReplayGuard {
    path: PathBuf,
    _lock: File,
    state: JournalState,
    seen: HashSet<(PeerId, [u8; 16])>,
    poisoned: bool,
}

impl PersistentReplayGuard {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "replay journal parent must be a real directory",
            ));
        }
        let name = path.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "replay journal path must name a file",
            )
        })?;
        let lock_path = sibling_with_suffix(parent, name, ".lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(lock_path)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "another process holds the replay journal lock",
            ));
        }

        let state = match read_state(&path) {
            Ok(state) => state,
            Err(error) if error.kind() == io::ErrorKind::NotFound => JournalState {
                version: REPLAY_JOURNAL_VERSION,
                entries: Vec::new(),
            },
            Err(error) => return Err(error),
        };
        validate_state(&state)?;
        let mut seen = HashSet::with_capacity(state.entries.len());
        for entry in &state.entries {
            let peer_id = entry.peer_id.parse::<PeerId>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "replay journal contains malformed PeerId",
                )
            })?;
            if !seen.insert((peer_id, entry.request_id)) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "replay journal contains duplicate request IDs",
                ));
            }
        }
        Ok(Self {
            path,
            _lock: lock,
            state,
            seen,
            poisoned: false,
        })
    }

    /// Record an ID for the fixed 24-hour retention window. At capacity, the
    /// operation fails closed until entries expire; it never evicts live IDs.
    pub fn record(&mut self, peer: PeerId, request_id: [u8; 16], now_ms: u64) -> io::Result<()> {
        if self.poisoned {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "replay journal is poisoned after a persistence failure",
            ));
        }
        if request_id == [0; 16] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero request ID is invalid",
            ));
        }
        let key = (peer, request_id);
        let mut next = self.state.clone();
        next.entries.retain(|entry| entry.expires_at_ms >= now_ms);
        let live_for_peer = next
            .entries
            .iter()
            .filter(|entry| entry.peer_id == peer.to_string())
            .count();
        if self.seen.contains(&key)
            && next
                .entries
                .iter()
                .any(|entry| entry.peer_id == peer.to_string() && entry.request_id == request_id)
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "request ID replay",
            ));
        }
        if next.entries.len() >= MAX_DURABLE_REPLAY_IDS
            || live_for_peer >= MAX_DURABLE_REPLAY_IDS_PER_PEER
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "durable replay journal is at capacity",
            ));
        }
        let expires_at_ms = now_ms
            .checked_add(REPLAY_RETENTION_MS)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "replay expiry overflow"))?;
        next.entries.push(ReplayEntry {
            peer_id: peer.to_string(),
            request_id,
            expires_at_ms,
        });
        if let Err(error) = self.persist(&next) {
            self.poisoned = true;
            return Err(error);
        }
        self.state = next;
        self.rebuild_index()?;
        Ok(())
    }

    pub fn retained_ids(&self) -> usize {
        self.state.entries.len()
    }

    fn persist(&self, state: &JournalState) -> io::Result<()> {
        let envelope = JournalEnvelope {
            state: state.clone(),
            digest_sha256: state_digest(state)?,
        };
        let bytes = serde_json::to_vec(&envelope)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if bytes.len() as u64 > MAX_REPLAY_JOURNAL_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "replay journal exceeds byte limit",
            ));
        }
        let parent = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let name = self.path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid journal filename")
        })?;
        let (temporary_path, mut temporary) = create_temporary(parent, name)?;
        let write_result = (|| {
            temporary.write_all(&bytes)?;
            temporary.sync_all()?;
            fs::rename(&temporary_path, &self.path)?;
            File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temporary_path);
        }
        write_result
    }

    fn rebuild_index(&mut self) -> io::Result<()> {
        self.seen.clear();
        for entry in &self.state.entries {
            let peer = entry.peer_id.parse::<PeerId>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "malformed PeerId in replay state",
                )
            })?;
            self.seen.insert((peer, entry.request_id));
        }
        Ok(())
    }
}

fn validate_state(state: &JournalState) -> io::Result<()> {
    if state.version != REPLAY_JOURNAL_VERSION || state.entries.len() > MAX_DURABLE_REPLAY_IDS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported or oversized replay journal",
        ));
    }
    Ok(())
}

fn state_digest(state: &JournalState) -> io::Result<String> {
    let bytes = serde_json::to_vec(state)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut input = JOURNAL_DOMAIN.to_vec();
    input.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    input.extend_from_slice(&bytes);
    Ok(hex::encode(aip_crypto::sha256(&input)))
}

fn read_state(path: &Path) -> io::Result<JournalState> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_REPLAY_JOURNAL_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "replay journal is not a bounded regular file",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_REPLAY_JOURNAL_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_REPLAY_JOURNAL_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "replay journal exceeds byte limit",
        ));
    }
    let envelope: JournalEnvelope = serde_json::from_slice(&bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("malformed replay journal: {error}"),
        )
    })?;
    if envelope.digest_sha256 != state_digest(&envelope.state)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "replay journal digest mismatch",
        ));
    }
    validate_state(&envelope.state)?;
    Ok(envelope.state)
}

fn sibling_with_suffix(parent: &Path, name: &std::ffi::OsStr, suffix: &str) -> PathBuf {
    let mut value = OsString::from(name);
    value.push(suffix);
    parent.join(value)
}

fn create_temporary(parent: &Path, name: &std::ffi::OsStr) -> io::Result<(PathBuf, File)> {
    for _ in 0..16 {
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut suffix = OsString::from(".tmp-");
        suffix.push(std::process::id().to_string());
        suffix.push("-");
        suffix.push(counter.to_string());
        let path = sibling_with_suffix(parent, name, &suffix.to_string_lossy());
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "unable to allocate replay-journal temporary file",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_directory() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("aip-replay-journal-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn replay_is_rejected_after_reopen_and_entries_expire_at_policy_boundary() {
        let root = temp_directory();
        let path = root.join("journal.json");
        let peer = identity::Keypair::generate_ed25519().public().to_peer_id();
        let id = [7; 16];
        {
            let mut guard = PersistentReplayGuard::open(&path).unwrap();
            guard.record(peer, id, 100).unwrap();
        }
        let mut reopened = PersistentReplayGuard::open(&path).unwrap();
        assert_eq!(
            reopened.record(peer, id, 101).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        reopened
            .record(peer, id, 100 + REPLAY_RETENTION_MS + 1)
            .unwrap();
        assert_eq!(reopened.retained_ids(), 1);
        drop(reopened);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn journal_corruption_fails_closed_and_single_writer_is_enforced() {
        let root = temp_directory();
        let path = root.join("journal.json");
        let first = PersistentReplayGuard::open(&path).unwrap();
        let second_open = PersistentReplayGuard::open(&path);
        assert!(matches!(second_open, Err(ref error) if error.kind() == io::ErrorKind::WouldBlock));
        drop(first);
        fs::write(
            &path,
            br#"{"state":{"version":1,"entries":[]},"digest_sha256":"00"}"#,
        )
        .unwrap();
        let corrupt_open = PersistentReplayGuard::open(&path);
        assert!(
            matches!(corrupt_open, Err(ref error) if error.kind() == io::ErrorKind::InvalidData)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn persistence_failure_poisons_guard() {
        let root = temp_directory();
        let path = root.join("journal.json");
        let mut guard = PersistentReplayGuard::open(&path).unwrap();
        fs::remove_dir_all(&root).unwrap();
        let peer = identity::Keypair::generate_ed25519().public().to_peer_id();
        assert!(guard.record(peer, [4; 16], 1).is_err());
        assert_eq!(
            guard.record(peer, [5; 16], 2).unwrap_err().kind(),
            io::ErrorKind::Other
        );
    }
}
