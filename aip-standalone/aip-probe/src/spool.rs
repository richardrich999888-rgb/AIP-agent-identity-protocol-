//! Private, bounded, crash-recoverable queue for unsigned observation batches.
//!
//! Enqueue commits the exact payload with file and directory fsync before the
//! sender may see it. Acknowledgement is a separate durable operation. A crash
//! between the collector commit and that operation deliberately replays the
//! batch; the collector must return its original receipt, not attest it again.
//! Capacity, corruption and IO errors are fatal to collection. They are never
//! translated into a dropped queue entry or a claim of uninterrupted coverage.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use aip_crypto::sha256;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SpoolContext {
    version: u8,
    probe_id: String,
    collector_noise_pubkey: [u8; 32],
}

/// Queue accounting is independent of surviving payload filenames. The
/// expected pending interval is (acknowledged_through, next_enqueue).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SpoolPosition {
    version: u8,
    acknowledged_through: u64,
    next_enqueue: u64,
}

impl SpoolPosition {
    fn initial() -> Self {
        Self {
            version: 1,
            acknowledged_through: 0,
            next_enqueue: 1,
        }
    }
    fn validate(self) -> Result<(), String> {
        if self.version != 1
            || self.next_enqueue == 0
            || self.acknowledged_through >= self.next_enqueue
        {
            return Err("invalid spool checkpoint position".into());
        }
        Ok(())
    }
    fn checksum(self) -> [u8; 32] {
        let mut bytes = b"AIP/PROBE-SPOOL-POSITION/v1".to_vec();
        bytes.push(self.version);
        bytes.extend_from_slice(&self.acknowledged_through.to_be_bytes());
        bytes.extend_from_slice(&self.next_enqueue.to_be_bytes());
        sha256(&bytes)
    }
    fn can_follow(self, previous: Self) -> bool {
        self == previous
            || (self.acknowledged_through == previous.acknowledged_through
                && previous.next_enqueue.checked_add(1) == Some(self.next_enqueue))
            || (self.next_enqueue == previous.next_enqueue
                && previous.acknowledged_through.checked_add(1) == Some(self.acknowledged_through))
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckedPosition {
    position: SpoolPosition,
    checksum: [u8; 32],
}

/// Leaves headroom for JSON framing of the byte array inside the 4 MiB
/// authenticated transport limit. An oversized batch must stop collection;
/// it must not remain forever at the head of an unsendable queue.
pub const MAX_PAYLOAD_BYTES: usize = 1_048_000;

#[derive(Clone, Debug)]
pub struct SpoolEntry {
    pub bytes: Vec<u8>,
    seq: u64,
    digest: [u8; 32],
}

#[derive(Clone, Debug)]
struct StoredEntry {
    path: PathBuf,
    digest: [u8; 32],
    len: u64,
}

/// A process-exclusive spool. Share this value under a mutex between a sensor
/// producer and a transport worker; do not hold the mutex during network IO.
#[derive(Debug)]
pub struct DurableSpool {
    dir: PathBuf,
    _lock: File,
    pending: BTreeMap<u64, StoredEntry>,
    position: SpoolPosition,
    bytes: u64,
    max_bytes: u64,
    max_batches: usize,
    failed: bool,
}

impl DurableSpool {
    /// Production opener: queued customer observations may only be delivered
    /// under the probe identity and collector pin that owned this spool.
    /// Changing that context requires draining/exporting the old spool first;
    /// it is never silently migrated to a different recipient.
    pub fn open_bound(
        dir: &Path,
        max_bytes: u64,
        max_batches: usize,
        probe_id: &str,
        collector_noise_pubkey: &[u8; 32],
    ) -> Result<Self, String> {
        let spool = Self::open(dir, max_bytes, max_batches)?;
        let context = SpoolContext {
            version: 1,
            probe_id: probe_id.into(),
            collector_noise_pubkey: *collector_noise_pubkey,
        };
        let path = dir.join(".context");
        if path.exists() {
            if read_context(&path)? != context {
                return Err(
                    "spool belongs to another probe or collector key; retained, no replay".into(),
                );
            }
        } else {
            if spool.position != SpoolPosition::initial() || !spool.is_empty() {
                return Err("cannot bind an existing used spool without its recipient context; retained, no replay".into());
            }
            let staging = dir.join(".context.staging");
            let bytes =
                serde_json::to_vec(&context).map_err(|e| format!("encode spool context: {e}"))?;
            let mut options = private_options();
            options.write(true).create_new(true);
            let mut file = options
                .open(&staging)
                .map_err(|e| io_error("create spool context", &staging, e))?;
            file.write_all(&bytes)
                .map_err(|e| io_error("write spool context", &staging, e))?;
            file.sync_all()
                .map_err(|e| io_error("flush spool context", &staging, e))?;
            std::fs::hard_link(&staging, &path)
                .map_err(|e| io_error("commit spool context", &path, e))?;
            sync_dir(dir)?;
            std::fs::remove_file(&staging)
                .map_err(|e| io_error("remove context staging", &staging, e))?;
            sync_dir(dir)?;
        }
        Ok(spool)
    }
    pub fn open(dir: &Path, max_bytes: u64, max_batches: usize) -> Result<Self, String> {
        if max_bytes == 0 || max_batches == 0 {
            return Err("spool byte and batch limits must be positive".into());
        }
        if !dir.is_absolute() {
            return Err("spool directory must be absolute".into());
        }
        match std::fs::symlink_metadata(dir) {
            Ok(_) => validate_private(dir, true)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut builder = std::fs::DirBuilder::new();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    builder.mode(0o700);
                }
                builder
                    .create(dir)
                    .map_err(|e| io_error("create spool", dir, e))?;
                sync_dir(dir.parent().ok_or("spool directory has no parent")?)?;
            }
            Err(e) => return Err(io_error("inspect spool", dir, e)),
        }
        validate_private(dir, true)?;
        let lock_path = dir.join(".lock");
        let previously_locked = std::fs::symlink_metadata(&lock_path).is_ok();
        let mut options = private_options();
        options.read(true).write(true).create(true);
        let lock = options
            .open(&lock_path)
            .map_err(|e| io_error("open spool lock", &lock_path, e))?;
        validate_private(&lock_path, false)?;
        lock.try_lock()
            .map_err(|e| format!("spool is already in use or cannot be locked: {e}"))?;
        sync_dir(dir)?;

        // One serialized operation can leave one acknowledged payload or one
        // uncheckpointed enqueue, plus staging links. Bound enumeration before
        // allocating metadata for a corrupt oversized spool.
        let member_limit = max_batches
            .checked_mul(2)
            .and_then(|n| n.checked_add(8))
            .ok_or("spool batch limit is too large")?;
        let mut members = Vec::new();
        for entry in std::fs::read_dir(dir).map_err(|e| io_error("list spool", dir, e))? {
            if members.len() >= member_limit {
                return Err(
                    "existing spool exceeds batch enumeration limit; retained, no replay".into(),
                );
            }
            let entry = entry.map_err(|e| io_error("list spool entry", dir, e))?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "non-UTF8 spool entry")?;
            members.push((name, entry.path()));
        }
        let has_data = members
            .iter()
            .any(|(name, _)| !matches!(name.as_str(), ".lock" | ".position" | ".position.staging"));
        let (mut position, staged_checkpoint) = load_position(dir, previously_locked, has_data)?;
        let expected_count = position.next_enqueue - position.acknowledged_through - 1;
        if expected_count > max_batches as u64 {
            return Err("checkpoint declares more pending batches than configured capacity; retained, no replay".into());
        }

        let mut files = BTreeMap::<u64, StoredEntry>::new();
        for (name, path) in members {
            if matches!(name.as_str(), ".lock" | ".position" | ".position.staging") {
                continue;
            }
            if name == ".context" {
                read_context(&path)?;
                continue;
            }
            if name == ".context.staging" {
                let context = read_context(&path)?;
                let final_path = dir.join(".context");
                match std::fs::hard_link(&path, &final_path) {
                    Ok(()) => sync_dir(dir)?,
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        if read_context(&final_path)? != context {
                            return Err("conflicting spool contexts".into());
                        }
                    }
                    Err(e) => return Err(io_error("recover spool context", &final_path, e)),
                }
                std::fs::remove_file(&path)
                    .map_err(|e| io_error("remove context staging", &path, e))?;
                sync_dir(dir)?;
                continue;
            }
            let (seq, digest, staging) = parse_name(&name)?;
            let bytes = read_payload(&path)?;
            if sha256(&bytes) != digest {
                return Err(format!(
                    "spool corruption at {}; retained, no replay",
                    path.display()
                ));
            }
            let final_path = dir.join(entry_name(seq, &digest, false));
            if staging {
                match std::fs::hard_link(&path, &final_path) {
                    Ok(()) => sync_dir(dir)?,
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        if read_payload(&final_path)? != bytes {
                            return Err("conflicting recovered spool entry".into());
                        }
                    }
                    Err(e) => return Err(io_error("recover spool entry", &path, e)),
                }
                std::fs::remove_file(&path)
                    .map_err(|e| io_error("remove committed staging entry", &path, e))?;
                sync_dir(dir)?;
            }
            if let Some(existing) = files.get(&seq) {
                if existing.digest != digest {
                    return Err("conflicting spool sequence numbers".into());
                }
            } else {
                files.insert(
                    seq,
                    StoredEntry {
                        path: final_path,
                        digest,
                        len: bytes.len() as u64,
                    },
                );
            }
        }

        // Every expected record must exist, including the oldest, newest, or
        // the only record. Surviving filenames never define the expected range.
        let mut expected = position.acknowledged_through + 1;
        for (&seq, _) in files.range(expected..position.next_enqueue) {
            if seq != expected {
                return Err("spool checkpoint pending sequence gap; retained, no replay".into());
            }
            expected += 1;
        }
        if expected != position.next_enqueue {
            return Err("spool checkpoint pending sequence gap; retained, no replay".into());
        }
        if files.keys().any(|&seq| seq > position.next_enqueue) {
            return Err(
                "spool has an unexpected enqueue beyond its checkpoint; retained, no replay".into(),
            );
        }
        let orphan = files.contains_key(&position.next_enqueue);
        if orphan && staged_checkpoint {
            return Err("spool has both a staged checkpoint and an unaccounted enqueue; retained, no replay".into());
        }
        if orphan {
            // Payload commit precedes its checkpoint. At most this one exact
            // next entry can be rolled forward after a crash.
            position.next_enqueue = position
                .next_enqueue
                .checked_add(1)
                .ok_or("spool sequence exhausted")?;
        }
        let mut pending = BTreeMap::new();
        let mut acknowledged = Vec::new();
        let mut bytes = 0u64;
        for (seq, entry) in files {
            if seq <= position.acknowledged_through {
                acknowledged.push(entry.path);
            } else {
                bytes = bytes
                    .checked_add(entry.len)
                    .ok_or("spool byte count overflow")?;
                pending.insert(seq, entry);
            }
        }
        if bytes > max_bytes || pending.len() > max_batches {
            return Err("existing spool exceeds configured limits; retained, no replay".into());
        }
        if staged_checkpoint {
            commit_position_staging(dir)?;
        }
        if orphan {
            write_position(dir, position)?;
        }
        // An ACK checkpoint is durable BEFORE payload deletion. These are the
        // only files recovery may remove without contacting the collector.
        for path in acknowledged {
            std::fs::remove_file(&path)
                .map_err(|e| io_error("remove acknowledged recovery entry", &path, e))?;
        }
        sync_dir(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            _lock: lock,
            pending,
            position,
            bytes,
            max_bytes,
            max_batches,
            failed: false,
        })
    }

    pub fn enqueue(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.ensure_healthy()?;
        let result = self.enqueue_inner(bytes);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn enqueue_inner(&mut self, bytes: &[u8]) -> Result<(), String> {
        if bytes.is_empty() || bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(format!(
                "spool payload must contain 1..={MAX_PAYLOAD_BYTES} bytes"
            ));
        }
        let total = self
            .bytes
            .checked_add(bytes.len() as u64)
            .ok_or("spool size overflow")?;
        if total > self.max_bytes || self.pending.len() >= self.max_batches {
            return Err(
                "spool capacity exhausted; retained all pending evidence, collection must stop"
                    .into(),
            );
        }
        let seq = self.position.next_enqueue;
        let next_seq = seq.checked_add(1).ok_or("spool sequence exhausted")?;
        let digest = sha256(bytes);
        let staging = self.dir.join(entry_name(seq, &digest, true));
        let final_path = self.dir.join(entry_name(seq, &digest, false));
        let mut options = private_options();
        options.write(true).create_new(true);
        let mut file = options
            .open(&staging)
            .map_err(|e| io_error("create spool entry", &staging, e))?;
        file.write_all(bytes)
            .map_err(|e| io_error("write spool entry", &staging, e))?;
        file.sync_all()
            .map_err(|e| io_error("flush spool entry", &staging, e))?;
        std::fs::hard_link(&staging, &final_path)
            .map_err(|e| io_error("commit spool entry", &final_path, e))?;
        sync_dir(&self.dir)?;
        std::fs::remove_file(&staging)
            .map_err(|e| io_error("remove spool staging entry", &staging, e))?;
        sync_dir(&self.dir)?;
        let position = SpoolPosition {
            next_enqueue: next_seq,
            ..self.position
        };
        write_position(&self.dir, position)?;
        self.pending.insert(
            seq,
            StoredEntry {
                path: final_path,
                digest,
                len: bytes.len() as u64,
            },
        );
        self.position = position;
        self.bytes = total;
        Ok(())
    }

    pub fn front(&self) -> Result<Option<SpoolEntry>, String> {
        self.ensure_healthy()?;
        let Some((&seq, entry)) = self.pending.first_key_value() else {
            return Ok(None);
        };
        let bytes = read_payload(&entry.path)?;
        if bytes.len() as u64 != entry.len || sha256(&bytes) != entry.digest {
            return Err("spool payload changed or is corrupt; retained, no replay".into());
        }
        Ok(Some(SpoolEntry {
            bytes,
            seq,
            digest: entry.digest,
        }))
    }

    /// Call only after the pinned, authenticated collector acknowledges this
    /// exact front payload. An ACK from another entry cannot delete anything.
    pub fn acknowledge(&mut self, entry: &SpoolEntry) -> Result<(), String> {
        self.ensure_healthy()?;
        let result = self.acknowledge_inner(entry);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn acknowledge_inner(&mut self, entry: &SpoolEntry) -> Result<(), String> {
        let Some((&seq, stored)) = self.pending.first_key_value() else {
            return Err("acknowledgement for empty spool".into());
        };
        if seq != entry.seq || stored.digest != entry.digest || sha256(&entry.bytes) != entry.digest
        {
            return Err("acknowledgement does not match the pending front entry".into());
        }
        // Do not erase a file that changed after it was sent, even when an
        // otherwise genuine ACK arrived. Preserve it for investigation.
        if read_payload(&stored.path)? != entry.bytes {
            return Err("spool entry changed before acknowledgement".into());
        }
        let position = SpoolPosition {
            acknowledged_through: seq,
            ..self.position
        };
        write_position(&self.dir, position)?;
        self.position = position;
        std::fs::remove_file(&stored.path)
            .map_err(|e| io_error("remove acknowledged entry", &stored.path, e))?;
        sync_dir(&self.dir)?;
        self.bytes -= stored.len;
        self.pending.remove(&seq);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
    pub fn pending_bytes(&self) -> u64 {
        self.bytes
    }
    fn ensure_healthy(&self) -> Result<(), String> {
        if self.failed {
            Err("spool failed; collection must stop and restart requires recovery".into())
        } else {
            Ok(())
        }
    }
}

fn read_position(path: &Path) -> Result<SpoolPosition, String> {
    let bytes = read_payload(path)?;
    if bytes.len() > 4096 {
        return Err("oversized spool checkpoint".into());
    }
    let checked: CheckedPosition = serde_json::from_slice(&bytes)
        .map_err(|e| format!("invalid or torn spool checkpoint: {e}"))?;
    checked.position.validate()?;
    if checked.checksum != checked.position.checksum() {
        return Err("spool checkpoint checksum mismatch; retained, no replay".into());
    }
    Ok(checked.position)
}

fn load_position(
    dir: &Path,
    previously_locked: bool,
    has_data: bool,
) -> Result<(SpoolPosition, bool), String> {
    let path = dir.join(".position");
    let staging = dir.join(".position.staging");
    let read_optional = |path: &Path| match std::fs::symlink_metadata(path) {
        Ok(_) => read_position(path).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_error("inspect spool checkpoint", path, e)),
    };
    let committed = read_optional(&path)?;
    let staged = read_optional(&staging)?;
    match (committed, staged) {
        (Some(previous), Some(next)) if next.can_follow(previous) => Ok((next, true)),
        (Some(_), Some(_)) => Err(
            "spool checkpoint staging is not one legal adjacent operation; retained, no replay"
                .into(),
        ),
        (Some(position), None) => Ok((position, false)),
        (None, Some(position)) if !has_data && position == SpoolPosition::initial() => {
            Ok((position, true))
        }
        (None, None) if !previously_locked && !has_data => {
            let position = SpoolPosition::initial();
            write_position(dir, position)?;
            Ok((position, false))
        }
        _ => Err("spool checkpoint missing from an existing queue; retained, no replay".into()),
    }
}

fn write_position(dir: &Path, position: SpoolPosition) -> Result<(), String> {
    position.validate()?;
    let bytes = serde_json::to_vec(&CheckedPosition {
        position,
        checksum: position.checksum(),
    })
    .map_err(|e| format!("encode spool checkpoint: {e}"))?;
    let staging = dir.join(".position.staging");
    let mut options = private_options();
    options.write(true).create_new(true);
    let mut file = options
        .open(&staging)
        .map_err(|e| io_error("create spool checkpoint", &staging, e))?;
    file.write_all(&bytes)
        .map_err(|e| io_error("write spool checkpoint", &staging, e))?;
    file.sync_all()
        .map_err(|e| io_error("flush spool checkpoint", &staging, e))?;
    commit_position_staging(dir)
}

fn commit_position_staging(dir: &Path) -> Result<(), String> {
    let staging = dir.join(".position.staging");
    std::fs::rename(&staging, dir.join(".position"))
        .map_err(|e| io_error("commit spool checkpoint", &staging, e))?;
    sync_dir(dir)
}

fn read_context(path: &Path) -> Result<SpoolContext, String> {
    let bytes = read_payload(path)?;
    let context: SpoolContext =
        serde_json::from_slice(&bytes).map_err(|e| format!("invalid spool context: {e}"))?;
    if context.version != 1 || context.probe_id.is_empty() {
        return Err("unsupported or empty spool context".into());
    }
    Ok(context)
}

fn entry_name(seq: u64, digest: &[u8; 32], staging: bool) -> String {
    format!(
        "{seq:020}-{}.{}",
        hex::encode(digest),
        if staging { "staging" } else { "batch" }
    )
}

fn parse_name(name: &str) -> Result<(u64, [u8; 32], bool), String> {
    let (stem, suffix) = name.rsplit_once('.').ok_or("unexpected spool entry")?;
    let staging = match suffix {
        "staging" => true,
        "batch" => false,
        _ => return Err("unexpected spool entry".into()),
    };
    let (seq, digest) = stem.split_once('-').ok_or("malformed spool entry")?;
    let seq: u64 = seq.parse().map_err(|_| "malformed spool sequence")?;
    let digest: [u8; 32] = hex::decode(digest)
        .map_err(|_| "malformed spool hash")?
        .try_into()
        .map_err(|_| "malformed spool hash")?;
    if seq == 0 || name != entry_name(seq, &digest, staging) {
        return Err("noncanonical spool entry".into());
    }
    Ok((seq, digest, staging))
}

fn read_payload(path: &Path) -> Result<Vec<u8>, String> {
    validate_private(path, false)?;
    let mut options = private_options();
    options.read(true);
    let file = options
        .open(path)
        .map_err(|e| io_error("open spool payload", path, e))?;
    let mut bytes = Vec::new();
    file.take((MAX_PAYLOAD_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| io_error("read spool payload", path, e))?;
    if bytes.is_empty() || bytes.len() > MAX_PAYLOAD_BYTES {
        return Err("empty or oversized spool payload".into());
    }
    Ok(bytes)
}

fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options
}

fn validate_private(path: &Path, directory: bool) -> Result<(), String> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|e| io_error("inspect spool entry", path, e))?;
    if metadata.file_type().is_symlink()
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
    {
        return Err(format!(
            "spool path is not a regular {}: {}",
            if directory { "directory" } else { "file" },
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no arguments and no side effects.
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
            return Err(format!(
                "spool path must be owner-only and owned by the current user: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn sync_dir(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|e| io_error("flush spool directory", path, e))
}

fn io_error(action: &str, path: &Path, error: std::io::Error) -> String {
    format!("{action} {}: {error}", path.display())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static ID: AtomicU64 = AtomicU64::new(0);
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!(
                "aip-spool-{}-{}",
                std::process::id(),
                ID.fetch_add(1, Ordering::Relaxed)
            )))
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn restart_replays_original_bytes_in_order_until_durable_ack() {
        let dir = Temp::new();
        let original =
            b"{\"probe_run_id\":[9],\"claimed_from_ms\":100, \"payload\":\"original\"}\n";
        {
            let mut q = DurableSpool::open(&dir.0, 1024, 8).unwrap();
            q.enqueue(original).unwrap();
            q.enqueue(b"second").unwrap();
        }
        {
            let mut q = DurableSpool::open(&dir.0, 1024, 8).unwrap();
            let e = q.front().unwrap().unwrap();
            assert_eq!(e.bytes, original);
            q.acknowledge(&e).unwrap();
        }
        let mut q = DurableSpool::open(&dir.0, 1024, 8).unwrap();
        assert_eq!(q.len(), 1);
        assert_eq!(q.pending_bytes(), 6);
        let e = q.front().unwrap().unwrap();
        assert_eq!(e.bytes, b"second");
        q.acknowledge(&e).unwrap();
        drop(q);
        assert!(DurableSpool::open(&dir.0, 1024, 8).unwrap().is_empty());
    }

    #[test]
    fn full_spool_preserves_every_pending_entry_and_poison_stops_collection() {
        let dir = Temp::new();
        let mut q = DurableSpool::open(&dir.0, 5, 2).unwrap();
        q.enqueue(b"12345").unwrap();
        assert!(q.enqueue(b"6").unwrap_err().contains("capacity"));
        assert!(q.enqueue(b"x").unwrap_err().contains("failed"));
        drop(q);
        let q = DurableSpool::open(&dir.0, 5, 2).unwrap();
        assert_eq!(q.front().unwrap().unwrap().bytes, b"12345");
    }

    #[test]
    fn batch_count_limit_is_independent_of_byte_capacity() {
        let dir = Temp::new();
        let mut q = DurableSpool::open(&dir.0, 1000, 1).unwrap();
        q.enqueue(b"a").unwrap();
        assert!(q.enqueue(b"b").is_err());
        assert_eq!(q.pending_bytes(), 1);
    }

    #[test]
    fn torn_or_mutated_payload_is_retained_and_refuses_startup() {
        let dir = Temp::new();
        let mut q = DurableSpool::open(&dir.0, 1000, 2).unwrap();
        q.enqueue(b"original").unwrap();
        let path = q.pending.first_key_value().unwrap().1.path.clone();
        std::fs::write(&path, b"modified").unwrap();
        assert!(q.front().is_err());
        drop(q);
        assert!(DurableSpool::open(&dir.0, 1000, 2)
            .unwrap_err()
            .contains("corruption"));
        assert!(path.exists());
    }

    #[test]
    fn complete_staging_file_recovers_after_crash_before_directory_commit() {
        let dir = Temp::new();
        let q = DurableSpool::open(&dir.0, 1000, 2).unwrap();
        let bytes = b"complete staging";
        let path = dir.0.join(entry_name(1, &sha256(bytes), true));
        let mut opt = private_options();
        opt.write(true).create_new(true);
        let mut f = opt.open(path).unwrap();
        f.write_all(bytes).unwrap();
        f.sync_all().unwrap();
        drop(q);
        let q = DurableSpool::open(&dir.0, 1000, 2).unwrap();
        assert_eq!(q.front().unwrap().unwrap().bytes, bytes);
    }

    #[test]
    fn crash_after_link_before_unlink_recovers_once() {
        let dir = Temp::new();
        let mut q = DurableSpool::open(&dir.0, 1000, 2).unwrap();
        q.enqueue(b"once").unwrap();
        let (&seq, stored) = q.pending.first_key_value().unwrap();
        std::fs::hard_link(
            &stored.path,
            dir.0.join(entry_name(seq, &stored.digest, true)),
        )
        .unwrap();
        drop(q);
        let q = DurableSpool::open(&dir.0, 1000, 2).unwrap();
        assert_eq!(q.len(), 1);
        assert_eq!(q.pending_bytes(), 4);
    }

    #[test]
    fn unrelated_ack_and_modified_sent_bytes_cannot_remove_the_front() {
        let dir = Temp::new();
        let mut q = DurableSpool::open(&dir.0, 1000, 2).unwrap();
        q.enqueue(b"saved").unwrap();
        let mut e = q.front().unwrap().unwrap();
        e.bytes = b"tampered".to_vec();
        assert!(q.acknowledge(&e).is_err());
        assert_eq!(q.len(), 1);
        drop(q);
        let q = DurableSpool::open(&dir.0, 1000, 2).unwrap();
        assert_eq!(q.front().unwrap().unwrap().bytes, b"saved");
    }

    #[test]
    fn simultaneous_process_owners_are_refused() {
        let dir = Temp::new();
        let _q = DurableSpool::open(&dir.0, 1000, 2).unwrap();
        assert!(DurableSpool::open(&dir.0, 1000, 2).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_and_public_permissions_are_refused() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = Temp::new();
        let link = Temp::new();
        let mut q = DurableSpool::open(&dir.0, 1000, 2).unwrap();
        q.enqueue(b"private").unwrap();
        symlink(&dir.0, &link.0).unwrap();
        assert!(DurableSpool::open(&link.0, 1000, 2).is_err());
        std::fs::remove_file(&link.0).unwrap();
        let path = q.pending.first_key_value().unwrap().1.path.clone();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(q.front().is_err());
    }

    #[test]
    fn recipient_or_probe_change_refuses_replay_without_deleting_evidence() {
        let dir = Temp::new();
        let mut q = DurableSpool::open_bound(&dir.0, 1000, 2, "customer-a", &[1; 32]).unwrap();
        q.enqueue(b"customer a evidence").unwrap();
        drop(q);
        assert!(DurableSpool::open_bound(&dir.0, 1000, 2, "customer-b", &[1; 32]).is_err());
        assert!(DurableSpool::open_bound(&dir.0, 1000, 2, "customer-a", &[2; 32]).is_err());
        let q = DurableSpool::open_bound(&dir.0, 1000, 2, "customer-a", &[1; 32]).unwrap();
        assert_eq!(q.front().unwrap().unwrap().bytes, b"customer a evidence");
    }

    #[test]
    fn oversized_payload_fails_before_creating_an_unsendable_entry() {
        let dir = Temp::new();
        let mut q = DurableSpool::open(&dir.0, 10_000_000, 2).unwrap();
        assert!(q.enqueue(&vec![1; MAX_PAYLOAD_BYTES + 1]).is_err());
        assert!(q.is_empty());
    }

    #[test]
    fn an_interior_missing_entry_is_not_treated_as_an_acknowledgement() {
        let dir = Temp::new();
        let mut q = DurableSpool::open(&dir.0, 1000, 5).unwrap();
        for payload in [b"first".as_slice(), b"second", b"third"] {
            q.enqueue(payload).unwrap();
        }
        let missing = q.pending.get(&2).unwrap().path.clone();
        std::fs::remove_file(missing).unwrap();
        drop(q);
        assert!(DurableSpool::open(&dir.0, 1000, 5)
            .unwrap_err()
            .contains("sequence gap"));
        assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 4); // lock, checkpoint, two preserved records
    }

    #[test]
    fn torn_staging_file_is_retained_instead_of_silently_discarded() {
        let dir = Temp::new();
        let q = DurableSpool::open(&dir.0, 1000, 2).unwrap();
        let complete = b"original complete batch";
        let path = dir.0.join(entry_name(1, &sha256(complete), true));
        let mut options = private_options();
        options.write(true).create_new(true);
        options.open(&path).unwrap().write_all(b"partial").unwrap();
        drop(q);
        assert!(DurableSpool::open(&dir.0, 1000, 2)
            .unwrap_err()
            .contains("corruption"));
        assert_eq!(std::fs::read(path).unwrap(), b"partial");
    }

    fn staged_position(dir: &Path, position: SpoolPosition) {
        let bytes = serde_json::to_vec(&CheckedPosition {
            position,
            checksum: position.checksum(),
        })
        .unwrap();
        let mut options = private_options();
        options.write(true).create_new(true);
        let mut file = options.open(dir.join(".position.staging")).unwrap();
        file.write_all(&bytes).unwrap();
        file.sync_all().unwrap();
    }

    fn orphan_payload(dir: &Path, seq: u64, payload: &[u8], staging: bool) -> PathBuf {
        let path = dir.join(entry_name(seq, &sha256(payload), staging));
        let mut options = private_options();
        options.write(true).create_new(true);
        let mut file = options.open(&path).unwrap();
        file.write_all(payload).unwrap();
        file.sync_all().unwrap();
        path
    }

    #[test]
    fn missing_first_last_sole_or_all_pending_records_refuses_without_rebasing_checkpoint() {
        for (count, removed) in [(3, vec![1]), (3, vec![3]), (3, vec![1, 2, 3]), (1, vec![1])] {
            let dir = Temp::new();
            let mut q = DurableSpool::open(&dir.0, 1000, 5).unwrap();
            for _ in 0..count {
                q.enqueue(b"original").unwrap();
            }
            let checkpoint = std::fs::read(dir.0.join(".position")).unwrap();
            for seq in removed {
                std::fs::remove_file(&q.pending.get(&seq).unwrap().path).unwrap();
            }
            drop(q);
            assert!(DurableSpool::open(&dir.0, 1000, 5)
                .unwrap_err()
                .contains("checkpoint pending sequence gap"));
            assert_eq!(checkpoint, std::fs::read(dir.0.join(".position")).unwrap());
        }
    }

    #[test]
    fn missing_checkpoint_refuses_even_when_existing_queue_is_empty_and_unbound() {
        for bound in [false, true] {
            for empty in [false, true] {
                let dir = Temp::new();
                let mut q = if bound {
                    DurableSpool::open_bound(&dir.0, 1000, 5, "probe", &[1; 32]).unwrap()
                } else {
                    DurableSpool::open(&dir.0, 1000, 5).unwrap()
                };
                q.enqueue(b"original").unwrap();
                if empty {
                    let entry = q.front().unwrap().unwrap();
                    q.acknowledge(&entry).unwrap();
                }
                drop(q);
                std::fs::remove_file(dir.0.join(".position")).unwrap();
                assert!(DurableSpool::open(&dir.0, 1000, 5)
                    .unwrap_err()
                    .contains("checkpoint missing"));
                assert!(!dir.0.join(".position").exists());
            }
        }
    }

    #[test]
    fn exact_next_complete_enqueue_recovers_before_tail_checkpoint_commit() {
        for staging in [false, true] {
            let dir = Temp::new();
            let q = DurableSpool::open(&dir.0, 1000, 5).unwrap();
            orphan_payload(&dir.0, 1, b"original next entry", staging);
            drop(q);
            let q = DurableSpool::open(&dir.0, 1000, 5).unwrap();
            assert_eq!(q.front().unwrap().unwrap().bytes, b"original next entry");
            assert_eq!(q.position.next_enqueue, 2);
            drop(q);
            assert_eq!(
                read_position(&dir.0.join(".position"))
                    .unwrap()
                    .next_enqueue,
                2
            );
        }
    }

    #[test]
    fn enqueue_checkpoint_staging_requires_its_complete_payload() {
        for present in [false, true] {
            let dir = Temp::new();
            let q = DurableSpool::open(&dir.0, 1000, 5).unwrap();
            staged_position(
                &dir.0,
                SpoolPosition {
                    next_enqueue: 2,
                    ..q.position
                },
            );
            if present {
                orphan_payload(&dir.0, 1, b"persisted before tail", false);
            }
            drop(q);
            if present {
                let q = DurableSpool::open(&dir.0, 1000, 5).unwrap();
                assert_eq!(q.position.next_enqueue, 2);
                assert_eq!(q.front().unwrap().unwrap().bytes, b"persisted before tail");
                assert!(!dir.0.join(".position.staging").exists());
            } else {
                assert!(DurableSpool::open(&dir.0, 1000, 5)
                    .unwrap_err()
                    .contains("sequence gap"));
                assert_eq!(
                    read_position(&dir.0.join(".position")).unwrap(),
                    SpoolPosition::initial()
                );
                assert!(dir.0.join(".position.staging").exists());
            }
        }
    }

    #[test]
    fn durable_ack_checkpoint_precedes_cleanup_and_recovery_keeps_the_remaining_entry() {
        for staged in [false, true] {
            let dir = Temp::new();
            let mut q = DurableSpool::open(&dir.0, 1000, 5).unwrap();
            q.enqueue(b"collector acknowledged").unwrap();
            q.enqueue(b"still pending").unwrap();
            let acknowledged_path = q.pending.get(&1).unwrap().path.clone();
            let position = SpoolPosition {
                acknowledged_through: 1,
                ..q.position
            };
            if staged {
                staged_position(&dir.0, position);
            } else {
                write_position(&dir.0, position).unwrap();
            }
            drop(q); // crash before unlink
            let q = DurableSpool::open(&dir.0, 1000, 5).unwrap();
            assert_eq!(q.position, position);
            assert_eq!(q.len(), 1);
            assert_eq!(q.front().unwrap().unwrap().bytes, b"still pending");
            assert!(!acknowledged_path.exists());
        }
    }

    #[test]
    fn empty_queue_retains_monotonic_enqueue_and_ack_counters_across_restart() {
        let dir = Temp::new();
        let mut q = DurableSpool::open(&dir.0, 1000, 5).unwrap();
        for _ in 0..2 {
            q.enqueue(b"acked").unwrap();
            let e = q.front().unwrap().unwrap();
            q.acknowledge(&e).unwrap();
        }
        assert!(q.is_empty());
        drop(q);
        let mut q = DurableSpool::open(&dir.0, 1000, 5).unwrap();
        assert_eq!(q.position.acknowledged_through, 2);
        assert_eq!(q.position.next_enqueue, 3);
        q.enqueue(b"next after restart").unwrap();
        assert_eq!(q.front().unwrap().unwrap().seq, 3);
    }

    #[test]
    fn torn_bad_checksum_and_nonadjacent_checkpoint_staging_are_preserved_and_refused() {
        for variant in 0..3 {
            let dir = Temp::new();
            let q = DurableSpool::open(&dir.0, 1000, 5).unwrap();
            let staging = dir.0.join(".position.staging");
            match variant {
                0 => {
                    let mut options = private_options();
                    options.write(true).create_new(true);
                    options
                        .open(&staging)
                        .unwrap()
                        .write_all(b"{partial")
                        .unwrap();
                }
                1 => {
                    staged_position(&dir.0, q.position);
                    let mut value: serde_json::Value =
                        serde_json::from_slice(&std::fs::read(&staging).unwrap()).unwrap();
                    value["checksum"][0] =
                        serde_json::json!((q.position.checksum()[0] as u64 + 1) % 256);
                    std::fs::write(&staging, serde_json::to_vec(&value).unwrap()).unwrap();
                }
                _ => staged_position(
                    &dir.0,
                    SpoolPosition {
                        next_enqueue: 9,
                        ..q.position
                    },
                ),
            }
            let bytes = std::fs::read(&staging).unwrap();
            drop(q);
            assert!(DurableSpool::open(&dir.0, 1000, 5).is_err());
            assert_eq!(bytes, std::fs::read(&staging).unwrap());
            assert_eq!(
                read_position(&dir.0.join(".position")).unwrap(),
                SpoolPosition::initial()
            );
        }
    }

    #[test]
    fn orphan_cannot_hide_a_missing_old_pending_entry_or_more_than_one_uncommitted_enqueue() {
        for missing_old in [false, true] {
            let dir = Temp::new();
            let mut q = DurableSpool::open(&dir.0, 1000, 5).unwrap();
            if missing_old {
                q.enqueue(b"old first").unwrap();
                q.enqueue(b"old last").unwrap();
                std::fs::remove_file(&q.pending.get(&1).unwrap().path).unwrap();
                orphan_payload(&dir.0, 3, b"new orphan", false);
            } else {
                orphan_payload(&dir.0, 1, b"first orphan", false);
                orphan_payload(&dir.0, 2, b"impossible second orphan", false);
            }
            let checkpoint = std::fs::read(dir.0.join(".position")).unwrap();
            drop(q);
            assert!(DurableSpool::open(&dir.0, 1000, 5).is_err());
            assert_eq!(checkpoint, std::fs::read(dir.0.join(".position")).unwrap());
        }
    }

    #[test]
    fn failed_ack_checkpoint_commit_never_unlinks_the_pending_evidence() {
        let dir = Temp::new();
        let mut q = DurableSpool::open(&dir.0, 1000, 5).unwrap();
        q.enqueue(b"original").unwrap();
        let e = q.front().unwrap().unwrap();
        let path = q.pending.get(&1).unwrap().path.clone();
        let mut options = private_options();
        options.write(true).create_new(true);
        options
            .open(dir.0.join(".position.staging"))
            .unwrap()
            .write_all(b"torn prior write")
            .unwrap();
        assert!(q.acknowledge(&e).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
        assert_eq!(
            read_position(&dir.0.join(".position"))
                .unwrap()
                .acknowledged_through,
            0
        );
    }

    #[test]
    fn complete_initial_checkpoint_staging_recovers_only_an_empty_initialization() {
        let dir = Temp::new();
        let q = DurableSpool::open(&dir.0, 1000, 5).unwrap();
        drop(q);
        std::fs::remove_file(dir.0.join(".position")).unwrap();
        staged_position(&dir.0, SpoolPosition::initial());
        let q = DurableSpool::open(&dir.0, 1000, 5).unwrap();
        assert_eq!(q.position, SpoolPosition::initial());
        assert!(!dir.0.join(".position.staging").exists());
    }

    #[test]
    fn staged_ack_cannot_hide_a_missing_other_pending_record_or_erase_its_leftover() {
        let dir = Temp::new();
        let mut q = DurableSpool::open(&dir.0, 1000, 5).unwrap();
        q.enqueue(b"ack received").unwrap();
        q.enqueue(b"still pending").unwrap();
        let acknowledged = q.pending.get(&1).unwrap().path.clone();
        std::fs::remove_file(&q.pending.get(&2).unwrap().path).unwrap();
        staged_position(
            &dir.0,
            SpoolPosition {
                acknowledged_through: 1,
                ..q.position
            },
        );
        drop(q);
        assert!(DurableSpool::open(&dir.0, 1000, 5)
            .unwrap_err()
            .contains("sequence gap"));
        assert_eq!(std::fs::read(acknowledged).unwrap(), b"ack received");
        assert_eq!(
            read_position(&dir.0.join(".position"))
                .unwrap()
                .acknowledged_through,
            0
        );
        assert!(dir.0.join(".position.staging").exists());
    }

    #[test]
    fn corrupt_committed_checkpoint_never_reinitializes_from_surviving_payloads() {
        for torn in [false, true] {
            let dir = Temp::new();
            let mut q = DurableSpool::open(&dir.0, 1000, 5).unwrap();
            q.enqueue(b"original").unwrap();
            let payload = q.pending.get(&1).unwrap().path.clone();
            drop(q);
            let checkpoint = dir.0.join(".position");
            let bytes = if torn {
                b"{torn".to_vec()
            } else {
                let mut value: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&checkpoint).unwrap()).unwrap();
                value["position"]["next_enqueue"] = serde_json::json!(3);
                serde_json::to_vec(&value).unwrap()
            };
            std::fs::write(&checkpoint, &bytes).unwrap();
            assert!(DurableSpool::open(&dir.0, 1000, 5).is_err());
            assert_eq!(std::fs::read(&checkpoint).unwrap(), bytes);
            assert_eq!(std::fs::read(payload).unwrap(), b"original");
        }
    }

    #[test]
    fn drained_used_spool_cannot_silently_rebind_after_context_loss() {
        let dir = Temp::new();
        let mut q = DurableSpool::open_bound(&dir.0, 1000, 5, "customer-a", &[1; 32]).unwrap();
        q.enqueue(b"original").unwrap();
        let e = q.front().unwrap().unwrap();
        q.acknowledge(&e).unwrap();
        drop(q);
        std::fs::remove_file(dir.0.join(".context")).unwrap();
        assert!(
            DurableSpool::open_bound(&dir.0, 1000, 5, "customer-b", &[2; 32])
                .unwrap_err()
                .contains("recipient context")
        );
        assert!(!dir.0.join(".context").exists());
    }
}
