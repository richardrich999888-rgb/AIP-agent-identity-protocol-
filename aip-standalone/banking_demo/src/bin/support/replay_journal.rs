//! Persistent replay journal. The software key/checkpoint are development-only.
use aip_protocol::{verification::ObservedHistory, EvidencePacket};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

type HmacSha256 = Hmac<Sha256>;
const VERSION: u8 = 2;
const RECORD_DOMAIN: &[u8] = b"AIRON-EVIDENCE-JOURNAL-RECORD-V2\0";
const CHECKPOINT_DOMAIN: &[u8] = b"AIRON-EVIDENCE-JOURNAL-CHECKPOINT-V1\0";
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Serialize, Deserialize)]
struct Record {
    version: u8,
    sequence: u64,
    previous_hash: String,
    packet_id: String,
    decision_id: String,
    action_ids: Vec<String>,
    mac: String,
}
#[derive(Serialize)]
struct UnsignedRecord<'a> {
    version: u8,
    sequence: u64,
    previous_hash: &'a str,
    packet_id: &'a str,
    decision_id: &'a str,
    action_ids: &'a [String],
}
#[derive(Serialize, Deserialize)]
struct Checkpoint {
    version: u8,
    sequence: u64,
    head_hash: String,
    mac: String,
}
#[derive(Serialize)]
struct UnsignedCheckpoint<'a> {
    version: u8,
    sequence: u64,
    head_hash: &'a str,
}

/// Hardware implementations can replace this with an external monotonic store.
trait CheckpointProvider {
    fn read(&self) -> Result<Option<(u64, String)>, String>;
    fn advance(&self, seq: u64, hash: &str) -> Result<(), String>;
}
/// Development-only: an attacker who can replace both checkpoint and journal key can roll back.
struct SoftwareCheckpoint {
    path: PathBuf,
    key: Vec<u8>,
}
impl CheckpointProvider for SoftwareCheckpoint {
    fn read(&self) -> Result<Option<(u64, String)>, String> {
        if !self.path.exists() {
            return Ok(None);
        }
        let mut f = open_read_nofollow(&self.path).map_err(|e| format!("Open checkpoint: {e}"))?;
        let mut b = Vec::new();
        f.read_to_end(&mut b)
            .map_err(|e| format!("Read checkpoint: {e}"))?;
        let cp: Checkpoint =
            serde_json::from_slice(&b).map_err(|e| format!("Invalid checkpoint: {e}"))?;
        if cp.version != 1 || !lower_hex(&cp.head_hash, 32) || !lower_hex(&cp.mac, 32) {
            return Err("Malformed or unsupported replay checkpoint".into());
        }
        let expected = checkpoint_mac(&self.key, cp.sequence, &cp.head_hash)?;
        if !ct_eq(&hex::decode(cp.mac).unwrap_or_default(), &expected) {
            return Err("Replay checkpoint authentication failed".into());
        }
        Ok(Some((cp.sequence, cp.head_hash)))
    }
    fn advance(&self, seq: u64, hash: &str) -> Result<(), String> {
        let cp = Checkpoint {
            version: 1,
            sequence: seq,
            head_hash: hash.into(),
            mac: hex::encode(checkpoint_mac(&self.key, seq, hash)?),
        };
        atomic_write(
            &self.path,
            &serde_json::to_vec(&cp).map_err(|e| e.to_string())?,
        )
        .map_err(|e| format!("Persist replay checkpoint: {e}"))
    }
}

struct Lock(File);
impl Drop for Lock {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            libc::flock(std::os::fd::AsRawFd::as_raw_fd(&self.0), libc::LOCK_UN);
        }
    }
}
pub(super) struct ReplayStore {
    pub(super) history: ObservedHistory,
    file: File,
    pub(super) path: PathBuf,
    _lock: Lock,
    key: Vec<u8>,
    seq: u64,
    head: String,
    checkpoint: SoftwareCheckpoint,
    poisoned: bool,
}

impl ReplayStore {
    pub(super) fn open() -> Result<Self, String> {
        let path = match std::env::var_os("AIRON_EVIDENCE_JOURNAL") {
            Some(v) => PathBuf::from(v),
            None => PathBuf::from(
                std::env::var_os("HOME")
                    .ok_or("HOME is not set; configure AIRON_EVIDENCE_JOURNAL")?,
            )
            .join(".local/share/airon-native/replay-history.jsonl"),
        };
        Self::open_path(path)
    }
    pub(super) fn open_path(path: PathBuf) -> Result<Self, String> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        private_dirs(parent).map_err(|e| format!("Create journal directory: {e}"))?;
        let lock_file = open_private(&sibling(&path, ".lock"), true)
            .map_err(|e| format!("Open journal lock: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            if unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err(format!("Replay journal already locked: {}", path.display()));
            }
        }
        #[cfg(not(unix))]
        {
            return Err("Exclusive journal locks are unsupported on this platform".into());
        }
        let lock = Lock(lock_file);
        let key_path = sibling(&path, ".key");
        let key = load_key(&key_path).map_err(|e| format!("Load journal integrity key: {e}"))?;
        let file = open_private(&path, true).map_err(|e| format!("Open replay journal: {e}"))?;
        let checkpoint = SoftwareCheckpoint {
            path: sibling(&path, ".checkpoint"),
            key: key.clone(),
        };
        let mut bytes = Vec::new();
        file.try_clone()
            .map_err(|e| e.to_string())?
            .read_to_end(&mut bytes)
            .map_err(|e| format!("Read journal: {e}"))?;
        let (history, seq, head, good_len) = load(&bytes, &key)?;
        match checkpoint.read()? {
            Some((n, h)) if n == seq && h == head => (),
            Some((n, _)) if n > seq => {
                return Err("Replay journal is older than trusted checkpoint".into())
            }
            Some(_) => return Err("Replay journal and checkpoint are inconsistent".into()),
            None if seq != 0 => {
                return Err(
                    "Missing checkpoint for non-empty journal; refusing unsafe bootstrap".into(),
                )
            }
            None => checkpoint.advance(0, ZERO_HASH)?,
        }
        if good_len < bytes.len() {
            let f = file.try_clone().map_err(|e| e.to_string())?;
            f.set_len(good_len as u64)
                .map_err(|e| format!("Recover incomplete final record: {e}"))?;
            f.sync_all()
                .map_err(|e| format!("Sync recovered journal: {e}"))?;
            File::open(parent)
                .and_then(|d| d.sync_all())
                .map_err(|e| format!("Sync journal directory after recovery: {e}"))?;
        } else if !bytes.is_empty() && !bytes.ends_with(b"\n") {
            let mut f = file.try_clone().map_err(|e| e.to_string())?;
            f.seek(SeekFrom::End(0))
                .and_then(|_| f.write_all(b"\n"))
                .and_then(|_| f.sync_all())
                .map_err(|e| format!("Terminate recovered complete record: {e}"))?;
        }
        Ok(Self {
            history,
            file,
            path,
            _lock: lock,
            key,
            seq,
            head,
            checkpoint,
            poisoned: false,
        })
    }
    pub(super) fn record(&mut self, packet: &EvidencePacket) -> Result<(), String> {
        if self.poisoned {
            return Err("Replay journal is fail-stopped after a prior persistence error".into());
        }
        let packet_id = hex::encode(packet.packet_id);
        let decision_id = hex::encode(packet.decision.decision_id);
        let action_ids: Vec<_> = packet
            .actions
            .iter()
            .map(|a| hex::encode(a.action_id))
            .collect();
        let seq = self
            .seq
            .checked_add(1)
            .ok_or("Replay journal sequence exhausted")?;
        let unsigned = UnsignedRecord {
            version: VERSION,
            sequence: seq,
            previous_hash: &self.head,
            packet_id: &packet_id,
            decision_id: &decision_id,
            action_ids: &action_ids,
        };
        let mut mac = HmacSha256::new_from_slice(&self.key).map_err(|e| e.to_string())?;
        mac.update(RECORD_DOMAIN);
        mac.update(&serde_json::to_vec(&unsigned).map_err(|e| e.to_string())?);
        let record = Record {
            version: VERSION,
            sequence: seq,
            previous_hash: self.head.clone(),
            packet_id: packet_id.clone(),
            decision_id: decision_id.clone(),
            action_ids: action_ids.clone(),
            mac: hex::encode(mac.finalize().into_bytes()),
        };
        let encoded = serde_json::to_vec(&record).map_err(|e| e.to_string())?;
        let next = hex::encode(Sha256::digest(&encoded));
        self.poisoned = true;
        self.file
            .seek(SeekFrom::End(0))
            .map_err(|e| e.to_string())?;
        self.file
            .write_all(&encoded)
            .and_then(|_| self.file.write_all(b"\n"))
            .map_err(|e| format!("Append journal: {e}"))?;
        self.file
            .sync_all()
            .map_err(|e| format!("Sync journal: {e}"))?;
        File::open(self.path.parent().unwrap_or(Path::new(".")))
            .and_then(|d| d.sync_all())
            .map_err(|e| format!("Sync journal directory: {e}"))?;
        self.checkpoint.advance(seq, &next)?; // failure is reported; restart detects mismatch and fails closed
        self.seq = seq;
        self.head = next;
        self.history
            .decisions
            .insert(packet.decision.decision_id, packet.packet_id);
        for action in &packet.actions {
            self.history
                .actions
                .insert(action.action_id, packet.packet_id);
        }
        self.poisoned = false;
        Ok(())
    }
}

fn load(bytes: &[u8], key: &[u8]) -> Result<(ObservedHistory, u64, String, usize), String> {
    let mut history = ObservedHistory::new();
    let mut seq = 0;
    let mut head = ZERO_HASH.to_owned();
    let mut off = 0;
    let mut good = 0;
    while off < bytes.len() {
        let end = bytes[off..]
            .iter()
            .position(|b| *b == b'\n')
            .map(|n| off + n);
        let terminated = end.is_some();
        let stop = end.unwrap_or(bytes.len());
        let line = &bytes[off..stop];
        if line.is_empty() {
            return Err(format!("Empty journal line at byte {off}"));
        }
        let rec = match parse(line, key, seq + 1, &head) {
            Ok(r) => r,
            Err(e) if !terminated => {
                let _ = e;
                break;
            }
            Err(e) => return Err(format!("Corrupt journal record at byte {off}: {e}")),
        };
        seq = rec.sequence;
        head = hex::encode(Sha256::digest(line));
        let packet = id(&rec.packet_id, seq)?;
        let decision = id(&rec.decision_id, seq)?;
        if history.decisions.insert(decision, packet).is_some() {
            return Err(format!("Duplicate decision ID in record {seq}"));
        }
        for a in rec.action_ids {
            if history.actions.insert(id(&a, seq)?, packet).is_some() {
                return Err(format!("Duplicate action ID in record {seq}"));
            }
        }
        off = end.map(|n| n + 1).unwrap_or(stop);
        good = off;
    }
    Ok((history, seq, head, good))
}
fn parse(line: &[u8], key: &[u8], seq: u64, prev: &str) -> Result<Record, String> {
    let r: Record = serde_json::from_slice(line).map_err(|e| e.to_string())?;
    if serde_json::to_vec(&r).map_err(|e| e.to_string())? != line {
        return Err("non-canonical JSON".into());
    }
    if r.version != VERSION {
        return Err(format!("unsupported journal version {}", r.version));
    }
    if r.sequence != seq || r.previous_hash != prev {
        return Err("sequence or preceding-record hash mismatch".into());
    }
    for s in std::iter::once(&r.packet_id)
        .chain(std::iter::once(&r.decision_id))
        .chain(r.action_ids.iter())
    {
        if !lower_hex(s, 16) {
            return Err("invalid ID".into());
        }
    }
    if !lower_hex(&r.mac, 32) {
        return Err("invalid MAC encoding".into());
    }
    let unsigned = UnsignedRecord {
        version: r.version,
        sequence: r.sequence,
        previous_hash: &r.previous_hash,
        packet_id: &r.packet_id,
        decision_id: &r.decision_id,
        action_ids: &r.action_ids,
    };
    let mut mac = HmacSha256::new_from_slice(key).map_err(|e| e.to_string())?;
    mac.update(RECORD_DOMAIN);
    mac.update(&serde_json::to_vec(&unsigned).map_err(|e| e.to_string())?);
    if !ct_eq(
        &hex::decode(&r.mac).unwrap_or_default(),
        &mac.finalize().into_bytes(),
    ) {
        return Err("record authentication failed".into());
    }
    Ok(r)
}
fn checkpoint_mac(key: &[u8], seq: u64, hash: &str) -> Result<Vec<u8>, String> {
    let mut m = HmacSha256::new_from_slice(key).map_err(|e| e.to_string())?;
    m.update(CHECKPOINT_DOMAIN);
    m.update(
        &serde_json::to_vec(&UnsignedCheckpoint {
            version: 1,
            sequence: seq,
            head_hash: hash,
        })
        .map_err(|e| e.to_string())?,
    );
    Ok(m.finalize().into_bytes().to_vec())
}
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |x, (a, b)| x | (a ^ b)) == 0
}
fn lower_hex(s: &str, n: usize) -> bool {
    s.len() == 2 * n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn id(s: &str, line: u64) -> Result<[u8; 16], String> {
    hex::decode(s)
        .map_err(|e| format!("Invalid ID in record {line}: {e}"))?
        .try_into()
        .map_err(|_| format!("ID must be 16 bytes in record {line}"))
}
fn sibling(p: &Path, s: &str) -> PathBuf {
    let mut x = p.as_os_str().to_os_string();
    x.push(s);
    PathBuf::from(x)
}
#[cfg(unix)]
fn open_private(p: &Path, create: bool) -> std::io::Result<File> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut o = OpenOptions::new();
    o.read(true)
        .write(true)
        .create(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let f = o.open(p)?;
    if !f.metadata()?.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    f.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(f)
}
#[cfg(not(unix))]
fn open_private(_: &Path, _: bool) -> std::io::Result<File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "secure no-follow file handling unavailable",
    ))
}
#[cfg(unix)]
fn open_read_nofollow(p: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)
}
#[cfg(not(unix))]
fn open_read_nofollow(_: &Path) -> std::io::Result<File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "no-follow checkpoint read unavailable",
    ))
}
#[cfg(unix)]
fn private_dirs(p: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let mut missing = Vec::new();
    let mut cur = p;
    while !cur.exists() {
        missing.push(cur.to_path_buf());
        cur = cur.parent().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "no existing ancestor")
        })?;
    }
    for d in missing.into_iter().rev() {
        match fs::DirBuilder::new().mode(0o700).create(d) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
#[cfg(not(unix))]
fn private_dirs(p: &Path) -> std::io::Result<()> {
    fs::create_dir_all(p)
}
fn atomic_write(p: &Path, b: &[u8]) -> std::io::Result<()> {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(std::io::Error::other)?
        .as_nanos();
    let tmp = sibling(p, &format!(".tmp-{}-{nonce}", std::process::id()));
    #[cfg(unix)]
    let mut f = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)?
    };
    #[cfg(not(unix))]
    let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
    f.write_all(b)?;
    f.sync_all()?;
    fs::rename(&tmp, p)?;
    File::open(p.parent().unwrap_or(Path::new(".")))?.sync_all()
}
#[cfg(unix)]
fn load_key(p: &Path) -> std::io::Result<Vec<u8>> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    match OpenOptions::new()
        .write(true)
        .read(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)
    {
        Ok(mut f) => {
            let mut k = vec![0; 32];
            File::open("/dev/urandom")?.read_exact(&mut k)?;
            f.write_all(&k)?;
            f.sync_all()?;
            File::open(p.parent().unwrap_or(Path::new(".")))?.sync_all()?;
            Ok(k)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let mut f = open_read_nofollow(p)?;
            if !f.metadata()?.file_type().is_file() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "integrity key is not a regular file",
                ));
            }
            f.set_permissions(fs::Permissions::from_mode(0o600))?;
            let mut k = Vec::new();
            f.read_to_end(&mut k)?;
            if k.len() != 32 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "integrity key must be 32 bytes",
                ));
            }
            Ok(k)
        }
        Err(e) => Err(e),
    }
}
#[cfg(not(unix))]
fn load_key(_: &Path) -> std::io::Result<Vec<u8>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "software key creation unavailable",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn make_record(seq: u64, prev: &str, key: &[u8]) -> Vec<u8> {
        let packet_id = "01".repeat(16);
        let decision_id = format!("{:02x}", seq + 1).repeat(16);
        let action_ids = Vec::new();
        let unsigned = UnsignedRecord {
            version: VERSION,
            sequence: seq,
            previous_hash: prev,
            packet_id: &packet_id,
            decision_id: &decision_id,
            action_ids: &action_ids,
        };
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(RECORD_DOMAIN);
        mac.update(&serde_json::to_vec(&unsigned).unwrap());
        serde_json::to_vec(&Record {
            version: VERSION,
            sequence: seq,
            previous_hash: prev.into(),
            packet_id,
            decision_id,
            action_ids,
            mac: hex::encode(mac.finalize().into_bytes()),
        })
        .unwrap()
    }
    fn dir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "airon-journal-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&p).unwrap();
        p
    }
    #[test]
    fn lock_and_private_permissions() {
        let d = dir();
        let p = d.join("x.jsonl");
        let a = ReplayStore::open_path(p.clone()).unwrap();
        assert!(ReplayStore::open_path(p.clone()).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(d.join("x.jsonl.key"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        drop(a);
        assert!(ReplayStore::open_path(p).is_ok());
        fs::remove_dir_all(d).unwrap();
    }
    #[test]
    fn newly_created_journal_directories_are_private() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let d = dir();
            let parent = d.join("private").join("nested");
            let store = ReplayStore::open_path(parent.join("journal")).unwrap();
            assert_eq!(
                fs::metadata(&parent).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(parent.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            drop(store);
            fs::remove_dir_all(d).unwrap();
        }
    }
    #[test]
    fn symlink_journal_refused() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let d = dir();
            let real = d.join("real");
            File::create(&real).unwrap();
            let link = d.join("link");
            symlink(&real, &link).unwrap();
            assert!(ReplayStore::open_path(link).is_err());
            fs::remove_dir_all(d).unwrap();
        }
    }
    #[test]
    fn modified_deleted_reordered_and_bad_version_records_rejected() {
        let k = [7u8; 32];
        let line = make_record(1, ZERO_HASH, &k);
        assert!(parse(&line, &k, 1, ZERO_HASH).is_ok());
        let mut changed_record: Record = serde_json::from_slice(&line).unwrap();
        changed_record.packet_id.replace_range(0..2, "ff");
        let changed = serde_json::to_vec(&changed_record).unwrap();
        assert!(parse(&changed, &k, 1, ZERO_HASH).is_err());
        let head = hex::encode(Sha256::digest(&line));
        let second = make_record(2, &head, &k);
        let mut chain = line.clone();
        chain.push(b'\n');
        chain.extend_from_slice(&second);
        chain.push(b'\n');
        assert_eq!(load(&chain, &k).unwrap().1, 2);
        let mut deleted = second.clone();
        deleted.push(b'\n');
        assert!(load(&deleted, &k).is_err());
        let mut reordered = second.clone();
        reordered.push(b'\n');
        reordered.extend_from_slice(&line);
        reordered.push(b'\n');
        assert!(load(&reordered, &k).is_err());
        let mut bad: Record = serde_json::from_slice(&line).unwrap();
        bad.version = 1;
        assert!(parse(&serde_json::to_vec(&bad).unwrap(), &k, 1, ZERO_HASH).is_err());
        bad.version = VERSION;
        bad.packet_id = "xyz".into();
        assert!(parse(&serde_json::to_vec(&bad).unwrap(), &k, 1, ZERO_HASH).is_err());
    }
    #[test]
    fn incomplete_final_record_recovers_but_middle_corruption_and_empty_lines_fail() {
        let key = [3u8; 32];
        let (h, s, head, n) = load(b"", &key).unwrap();
        assert_eq!(s, 0);
        assert_eq!(n, 0);
        let _ = h;
        let _ = head;
        assert!(load(b"\n", &key).is_err());
        assert!(load(b"bad\n", &key).is_err());
        assert_eq!(load(b"partial", &key).unwrap().3, 0);
    }
    #[test]
    fn store_recovers_truncated_tail_and_durably_terminates_valid_unterminated_record() {
        let d = dir();
        let path = d.join("journal");
        let evidence = banking_demo::generate_banking_evidence().unwrap();
        let mut store = ReplayStore::open_path(path.clone()).unwrap();
        store.record(&evidence.packet).unwrap();
        drop(store);
        let complete = fs::read(&path).unwrap();
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{\"interrupted\":")
            .unwrap();
        let store = ReplayStore::open_path(path.clone()).unwrap();
        drop(store);
        assert_eq!(fs::read(&path).unwrap(), complete);

        let mut without_newline = complete.clone();
        assert_eq!(without_newline.pop(), Some(b'\n'));
        fs::write(&path, without_newline).unwrap();
        let store = ReplayStore::open_path(path.clone()).unwrap();
        drop(store);
        assert_eq!(fs::read(&path).unwrap(), complete);
        fs::remove_dir_all(d).unwrap();
    }
    #[test]
    fn checkpoint_detects_rollback_and_inconsistency() {
        let d = dir();
        let cp = SoftwareCheckpoint {
            path: d.join("c"),
            key: vec![9; 32],
        };
        cp.advance(2, &"ab".repeat(32)).unwrap();
        assert_eq!(cp.read().unwrap().unwrap().0, 2);
        let mut b = fs::read(&cp.path).unwrap();
        b[20] ^= 1;
        fs::write(&cp.path, b).unwrap();
        assert!(cp.read().is_err());
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn checkpoint_ahead_of_journal_is_rejected() {
        let d = dir();
        let path = d.join("journal");
        let store = ReplayStore::open_path(path.clone()).unwrap();
        let cp = SoftwareCheckpoint {
            path: sibling(&path, ".checkpoint"),
            key: store.key.clone(),
        };
        cp.advance(1, &"ab".repeat(32)).unwrap();
        drop(store);
        assert!(ReplayStore::open_path(path)
            .err()
            .unwrap()
            .contains("older than trusted checkpoint"));
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn checkpoint_rolled_back_behind_journal_is_rejected() {
        let d = dir();
        let path = d.join("journal");
        let mut store = ReplayStore::open_path(path.clone()).unwrap();
        let evidence = banking_demo::generate_banking_evidence().unwrap();
        store.record(&evidence.packet).unwrap();
        let cp = SoftwareCheckpoint {
            path: sibling(&path, ".checkpoint"),
            key: store.key.clone(),
        };
        cp.advance(0, ZERO_HASH).unwrap();
        drop(store);
        assert!(ReplayStore::open_path(path)
            .err()
            .unwrap()
            .contains("inconsistent"));
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn second_process_cannot_open_locked_journal() {
        if let Some(path) = std::env::var_os("AIRON_LOCK_HELPER_PATH") {
            assert!(ReplayStore::open_path(path.into()).is_err());
            return;
        }
        let d = dir();
        let path = d.join("journal");
        let store = ReplayStore::open_path(path.clone()).unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("replay_journal::tests::second_process_cannot_open_locked_journal")
            .arg("--nocapture")
            .env("AIRON_LOCK_HELPER_PATH", &path)
            .status()
            .unwrap();
        assert!(status.success());
        drop(store);
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn checkpoint_persistence_failure_is_reported_before_success() {
        let d = dir();
        let path = d.join("journal");
        let mut store = ReplayStore::open_path(path.clone()).unwrap();
        fs::remove_file(sibling(&path, ".checkpoint")).unwrap();
        fs::create_dir(sibling(&path, ".checkpoint")).unwrap();
        let evidence = banking_demo::generate_banking_evidence().unwrap();
        assert!(store.record(&evidence.packet).is_err());
        assert!(store
            .record(&evidence.packet)
            .unwrap_err()
            .contains("fail-stopped"));
        fs::remove_dir_all(d).unwrap();
    }
}
