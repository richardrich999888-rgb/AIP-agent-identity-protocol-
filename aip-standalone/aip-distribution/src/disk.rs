#![cfg(unix)]

//! Unix disk-backed receiver. File access is relative to an opened directory
//! descriptor and uses `O_NOFOLLOW`; the caller must protect the directory's
//! parent from hostile replacement.

use super::{
    parse_manifest, verify_chunk, verify_export_bytes, verify_manifest, DistributionError, Result,
    TransferChunk, TransferManifest, MAX_MANIFEST_JSON_BYTES, MAX_TRANSFER_BYTES,
};
use aip_crypto::sha256;
use aip_package::VerifiedPackage;
use serde::{Deserialize, Serialize};
use std::{
    ffi::CString,
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    os::fd::{AsRawFd, FromRawFd},
    os::unix::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
};

pub const MAX_JOURNAL_BYTES: usize = 4 * 1024 * 1024;
const JOURNAL_VERSION: u16 = 1;
const MANIFEST_FILE: &str = "manifest.json";
const DATA_FILE: &str = "chunks.bin";
const JOURNAL_FILE: &str = "journal.json";
const JOURNAL_TEMP: &str = "journal.tmp";
const MANIFEST_TEMP: &str = "manifest.tmp";
const LOCK_FILE: &str = "writer.lock";
const MAX_CHUNKS: u64 = MAX_TRANSFER_BYTES / super::CHUNK_SIZE as u64 + 1;
const MAX_PROOF_DEPTH: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u16,
    transfer_id: String,
    entries: Vec<JournalEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalEntry {
    index: u32,
    proof: Vec<String>,
}

/// A sequential durable receiver. It writes only proof-checked chunks. The
/// selected directory is a partial-data location, never an extraction path.
pub struct DiskTransferReceiver {
    directory: PathBuf,
    dir: File,
    data: File,
    _lock: File,
    manifest: TransferManifest,
    entries: Vec<JournalEntry>,
}

impl DiskTransferReceiver {
    /// Create a new transfer directory. The path must not already exist; no
    /// existing transfer data is overwritten.
    pub fn create(
        partial_directory: impl AsRef<Path>,
        manifest: TransferManifest,
        trusted_publisher_id: &str,
        trusted_publisher_key: &[u8],
    ) -> Result<Self> {
        verify_manifest(&manifest, trusted_publisher_id, trusted_publisher_key)?;
        validate_storage_size(&manifest)?;
        let directory = checked_path(partial_directory.as_ref(), false)?;
        let dir = create_directory(&directory)?;

        let manifest_bytes = serde_json::to_vec(&manifest)
            .map_err(|e| DistributionError::Invalid(format!("serialize manifest: {e}")))?;
        atomic_write(&dir, MANIFEST_TEMP, MANIFEST_FILE, &manifest_bytes)?;

        let data = open_at(
            &dir,
            DATA_FILE,
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
            0o600,
        )?;
        data.set_len(manifest.export_len)
            .map_err(|e| io_error("size chunk store", e))?;
        data.sync_all()
            .map_err(|e| io_error("sync chunk store", e))?;

        let entries = Vec::new();
        write_journal(&dir, &manifest.transfer_id, &entries)?;
        let lock = open_at(
            &dir,
            LOCK_FILE,
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
            0o600,
        )?;
        lock_writer(&lock)?;
        sync_directory(&dir)?;
        Ok(Self {
            directory,
            dir,
            data,
            _lock: lock,
            manifest,
            entries,
        })
    }

    /// Reopen an existing transfer, verify its external signer, lock it
    /// against concurrent writers, and recheck every journaled chunk.
    pub fn resume(
        partial_directory: impl AsRef<Path>,
        trusted_publisher_id: &str,
        trusted_publisher_key: &[u8],
    ) -> Result<Self> {
        let directory = checked_path(partial_directory.as_ref(), true)?;
        let dir = open_directory(&directory)?;
        let lock = open_existing_at(&dir, LOCK_FILE, true)?;
        lock_writer(&lock)?;
        check_directory_entries(&dir, true)?;

        // A stale temp can only be an interrupted atomic journal update. The
        // installed journal remains authoritative; chunks themselves are
        // independently reverified below.
        if entry_exists(&dir, JOURNAL_TEMP)? {
            unlink_at(&dir, JOURNAL_TEMP)?;
            sync_directory(&dir)?;
        }
        let manifest_bytes = read_bounded_at(&dir, MANIFEST_FILE, MAX_MANIFEST_JSON_BYTES)?;
        let manifest = parse_manifest(&manifest_bytes)?;
        verify_manifest(&manifest, trusted_publisher_id, trusted_publisher_key)?;
        validate_storage_size(&manifest)?;

        let journal_bytes = read_bounded_at(&dir, JOURNAL_FILE, MAX_JOURNAL_BYTES)?;
        let journal: Journal = serde_json::from_slice(&journal_bytes)
            .map_err(|e| DistributionError::Invalid(format!("malformed transfer journal: {e}")))?;
        if journal.version != JOURNAL_VERSION || journal.transfer_id != manifest.transfer_id {
            return Err(DistributionError::Invalid(
                "journal version or transfer ID mismatch".into(),
            ));
        }
        if journal.entries.len() as u64 > u64::from(manifest.chunk_count) {
            return Err(DistributionError::Invalid(
                "journal contains too many chunks".into(),
            ));
        }

        let data = open_existing_at(&dir, DATA_FILE, true)?;
        let metadata = data
            .metadata()
            .map_err(|e| io_error("stat chunk store", e))?;
        if !metadata.is_file() || metadata.len() != manifest.export_len {
            return Err(DistributionError::Invalid(
                "chunk store has an unexpected type or length".into(),
            ));
        }

        let mut expected = 0u32;
        for entry in &journal.entries {
            if entry.index != expected || entry.proof.len() > MAX_PROOF_DEPTH {
                return Err(DistributionError::Invalid(
                    "journal indexes or proof bounds are invalid".into(),
                ));
            }
            let chunk = read_chunk(
                &manifest,
                &mut {
                    data.try_clone()
                        .map_err(|e| io_error("clone chunk store", e))?
                },
                entry,
            )?;
            verify_chunk(&manifest, &chunk)?;
            expected = expected
                .checked_add(1)
                .ok_or_else(|| DistributionError::Invalid("chunk index overflow".into()))?;
        }

        Ok(Self {
            directory,
            dir,
            data,
            _lock: lock,
            manifest,
            entries: journal.entries,
        })
    }

    /// Verify proof and exact length before writing. Data reaches the journal
    /// only after `sync_data()` succeeds.
    pub fn accept(&mut self, chunk: TransferChunk) -> Result<()> {
        let next = u32::try_from(self.entries.len())
            .map_err(|_| DistributionError::Invalid("chunk index overflow".into()))?;
        if chunk.index != next || chunk.proof.len() > MAX_PROOF_DEPTH {
            return Err(DistributionError::Invalid(
                "duplicate, missing, reordered, or oversized-proof chunk".into(),
            ));
        }
        verify_chunk(&self.manifest, &chunk)?;
        let offset = u64::from(chunk.index)
            .checked_mul(u64::from(self.manifest.chunk_size))
            .ok_or_else(|| DistributionError::Invalid("chunk offset overflow".into()))?;
        let end = offset
            .checked_add(u64::try_from(chunk.bytes.len()).map_err(|_| {
                DistributionError::Invalid("chunk length conversion overflow".into())
            })?)
            .ok_or_else(|| DistributionError::Invalid("chunk end overflow".into()))?;
        if end > self.manifest.export_len || self.entries.len() as u64 >= MAX_CHUNKS {
            return Err(DistributionError::Invalid(
                "transfer exceeds configured bounds".into(),
            ));
        }
        self.data
            .seek(SeekFrom::Start(offset))
            .map_err(|e| io_error("seek chunk store", e))?;
        write_chunk_bytes(&mut self.data, &chunk.bytes)
            .map_err(|e| io_error("write verified chunk", e))?;
        self.data
            .sync_data()
            .map_err(|e| io_error("sync verified chunk", e))?;

        let mut candidate = self.entries.clone();
        candidate.push(JournalEntry {
            index: chunk.index,
            proof: chunk.proof,
        });
        write_journal(&self.dir, &self.manifest.transfer_id, &candidate)?;
        self.entries = candidate;
        Ok(())
    }

    pub fn completed_chunks(&self) -> usize {
        self.entries.len()
    }

    pub fn transfer_id(&self) -> &str {
        &self.manifest.transfer_id
    }

    /// Re-read and verify every persisted chunk, reconstruct the exact export,
    /// and expose payload only after existing package verification succeeds.
    pub fn finalize(
        mut self,
        package_publisher_id: &str,
        package_publisher_key: &[u8],
        independently_verified_aibom_digest: &str,
    ) -> Result<VerifiedPackage> {
        if self.entries.len() != self.manifest.chunk_count as usize {
            return Err(DistributionError::Invalid("incomplete transfer".into()));
        }
        let capacity = usize::try_from(self.manifest.export_len)
            .map_err(|_| DistributionError::Invalid("export allocation overflow".into()))?;
        let mut export = Vec::new();
        export.try_reserve_exact(capacity).map_err(|e| {
            DistributionError::Invalid(format!("cannot reserve export buffer: {e}"))
        })?;
        for entry in &self.entries {
            let chunk = read_chunk(&self.manifest, &mut self.data, entry)?;
            verify_chunk(&self.manifest, &chunk)?;
            export.extend_from_slice(&chunk.bytes);
        }
        if u64::try_from(export.len()).ok() != Some(self.manifest.export_len)
            || hex::encode(sha256(&export)) != self.manifest.export_sha256
        {
            return Err(DistributionError::Invalid(
                "assembled export digest mismatch".into(),
            ));
        }
        verify_export_bytes(
            &self.manifest,
            package_publisher_id,
            package_publisher_key,
            independently_verified_aibom_digest,
            &export,
        )
    }

    /// Exposes the directory selected by the caller for diagnostics only.
    pub fn partial_directory(&self) -> &Path {
        &self.directory
    }
}

fn validate_storage_size(manifest: &TransferManifest) -> Result<()> {
    if manifest.export_len > MAX_TRANSFER_BYTES
        || u64::from(manifest.chunk_count) > MAX_CHUNKS
        || manifest.chunk_count == 0
    {
        return Err(DistributionError::Invalid(
            "transfer exceeds disk storage limits".into(),
        ));
    }
    Ok(())
}

fn checked_path(path: &Path, must_exist: bool) -> Result<PathBuf> {
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(DistributionError::Invalid(
            "parent-directory traversal is not allowed in storage path".into(),
        ));
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| io_error("read current directory", e))?
            .join(path)
    };
    let mut cursor = PathBuf::from("/");
    let components: Vec<_> = absolute
        .components()
        .filter(|c| !matches!(c, Component::RootDir | Component::CurDir))
        .collect();
    for (i, component) in components.iter().enumerate() {
        cursor.push(component.as_os_str());
        match fs::symlink_metadata(&cursor) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(DistributionError::Invalid(format!(
                    "symlinked storage path component: {}",
                    cursor.display()
                )))
            }
            Ok(meta) if i + 1 < components.len() && !meta.is_dir() => {
                return Err(DistributionError::Invalid(
                    "storage path parent is not a directory".into(),
                ))
            }
            Ok(_) => {}
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    && !must_exist
                    && i + 1 == components.len() => {}
            Err(e) => return Err(io_error("inspect storage path", e)),
        }
    }
    if must_exist {
        let meta = fs::symlink_metadata(&absolute)
            .map_err(|e| io_error("inspect storage directory", e))?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(DistributionError::Invalid(
                "storage path is not a real directory".into(),
            ));
        }
    } else if absolute.exists() {
        return Err(DistributionError::Invalid(
            "partial-transfer directory already exists".into(),
        ));
    }
    Ok(absolute)
}

fn c_name(name: &str) -> Result<CString> {
    CString::new(name).map_err(|_| DistributionError::Invalid("invalid internal file name".into()))
}
fn open_root_directory() -> Result<File> {
    let root = c_name("/")?;
    // SAFETY: valid NUL-terminated root path; ownership transfers to File.
    let fd = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io_error(
            "open filesystem root",
            std::io::Error::last_os_error(),
        ));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn open_child_directory(parent: &File, name: &std::ffi::OsStr) -> Result<File> {
    let name = CString::new(name.as_bytes())
        .map_err(|_| DistributionError::Invalid("NUL in storage path".into()))?;
    // SAFETY: a live parent directory descriptor and O_NOFOLLOW protect each path component.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io_error(
            "open storage path component",
            std::io::Error::last_os_error(),
        ));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn open_directory(path: &Path) -> Result<File> {
    let mut current = open_root_directory()?;
    for component in path.components() {
        if let Component::Normal(name) = component {
            current = open_child_directory(&current, name)?;
        }
    }
    Ok(current)
}
fn create_directory(path: &Path) -> Result<File> {
    let parent_path = path
        .parent()
        .ok_or_else(|| DistributionError::Invalid("storage directory has no parent".into()))?;
    let name = path.file_name().ok_or_else(|| {
        DistributionError::Invalid("storage directory has no final component".into())
    })?;
    let parent = open_directory(parent_path)?;
    let name_c = CString::new(name.as_bytes())
        .map_err(|_| DistributionError::Invalid("NUL in storage directory name".into()))?;
    // SAFETY: mkdirat creates only the requested final component under the open parent.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name_c.as_ptr(), 0o700) } != 0 {
        return Err(io_error(
            "create partial-transfer directory",
            std::io::Error::last_os_error(),
        ));
    }
    sync_directory(&parent)?;
    open_child_directory(&parent, name)
}
fn open_at(dir: &File, name: &str, flags: i32, mode: u32) -> Result<File> {
    let name = c_name(name)?;
    // SAFETY: dir fd is live and name is a NUL-terminated single internal path component.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode as libc::mode_t,
        )
    };
    if fd < 0 {
        return Err(io_error(
            "open transfer file",
            std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: fd is newly returned and ownership transfers to File.
    let file = unsafe { File::from_raw_fd(fd) };
    if !file
        .metadata()
        .map_err(|e| io_error("stat transfer file", e))?
        .is_file()
    {
        return Err(DistributionError::Invalid(
            "transfer storage entry is not a regular file".into(),
        ));
    }
    Ok(file)
}
fn open_existing_at(dir: &File, name: &str, writable: bool) -> Result<File> {
    open_at(
        dir,
        name,
        if writable {
            libc::O_RDWR
        } else {
            libc::O_RDONLY
        },
        0,
    )
}
fn lock_writer(lock: &File) -> Result<()> {
    // SAFETY: flock operates on this valid open file descriptor.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io_error(
            "lock transfer directory",
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}
fn sync_directory(dir: &File) -> Result<()> {
    dir.sync_all()
        .map_err(|e| io_error("sync transfer directory", e))
}
fn unlink_at(dir: &File, name: &str) -> Result<()> {
    let name = c_name(name)?;
    // SAFETY: valid directory descriptor and fixed internal name.
    if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(io_error(
            "remove stale journal temp",
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}
fn entry_exists(dir: &File, name: &str) -> Result<bool> {
    let name = c_name(name)?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: stat is writable; AT_SYMLINK_NOFOLLOW makes the type check meaningful.
    let rc = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(false);
        }
        return Err(io_error("inspect transfer entry", error));
    }
    // SAFETY: successful fstatat initialized stat.
    let stat = unsafe { stat.assume_init() };
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(DistributionError::Invalid(
            "unexpected non-regular transfer entry".into(),
        ));
    }
    Ok(true)
}
fn read_bounded_at(dir: &File, name: &str, limit: usize) -> Result<Vec<u8>> {
    let file = open_existing_at(dir, name, false)?;
    let len = file
        .metadata()
        .map_err(|e| io_error("stat transfer metadata", e))?
        .len();
    if len > limit as u64 {
        return Err(DistributionError::Invalid(
            "transfer metadata exceeds configured limit".into(),
        ));
    }
    let mut bytes = Vec::with_capacity(len as usize);
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| io_error("read transfer metadata", e))?;
    if bytes.len() > limit {
        return Err(DistributionError::Invalid(
            "transfer metadata exceeds configured limit".into(),
        ));
    }
    Ok(bytes)
}
fn atomic_write(dir: &File, temp: &str, target: &str, bytes: &[u8]) -> Result<()> {
    if entry_exists(dir, temp)? {
        unlink_at(dir, temp)?;
    }
    let mut file = open_at(
        dir,
        temp,
        libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY,
        0o600,
    )?;
    file.write_all(bytes)
        .map_err(|e| io_error("write atomic metadata", e))?;
    file.sync_all()
        .map_err(|e| io_error("sync atomic metadata", e))?;
    let ctemp = c_name(temp)?;
    let ctarget = c_name(target)?;
    // SAFETY: both names are fixed components relative to the same open directory.
    if unsafe {
        libc::renameat(
            dir.as_raw_fd(),
            ctemp.as_ptr(),
            dir.as_raw_fd(),
            ctarget.as_ptr(),
        )
    } != 0
    {
        return Err(io_error(
            "install atomic metadata",
            std::io::Error::last_os_error(),
        ));
    }
    sync_directory(dir)
}
fn write_journal(dir: &File, transfer_id: &str, entries: &[JournalEntry]) -> Result<()> {
    let bytes = serde_json::to_vec(&Journal {
        version: JOURNAL_VERSION,
        transfer_id: transfer_id.into(),
        entries: entries.to_vec(),
    })
    .map_err(|e| DistributionError::Invalid(format!("serialize journal: {e}")))?;
    if bytes.len() > MAX_JOURNAL_BYTES {
        return Err(DistributionError::Invalid(
            "transfer journal exceeds configured limit".into(),
        ));
    }
    atomic_write(dir, JOURNAL_TEMP, JOURNAL_FILE, &bytes)
}
fn check_directory_entries(dir: &File, allow_journal_temp: bool) -> Result<()> {
    let allowed = [
        MANIFEST_FILE,
        DATA_FILE,
        JOURNAL_FILE,
        LOCK_FILE,
        JOURNAL_TEMP,
    ];
    // Enumerate relative to the pinned directory fd so a replaced path cannot
    // redirect the check. Each entry is classified with fstatat(NO FOLLOW).
    // SAFETY: dup returns a separately owned descriptor for fdopendir.
    let duplicate = unsafe { libc::dup(dir.as_raw_fd()) };
    if duplicate < 0 {
        return Err(io_error(
            "duplicate transfer directory handle",
            std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: fdopendir takes ownership of duplicate on success.
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        // SAFETY: fdopendir failed; duplicate remains ours.
        unsafe {
            libc::close(duplicate);
        }
        return Err(io_error(
            "list transfer directory",
            std::io::Error::last_os_error(),
        ));
    }
    let result = (|| {
        loop {
            // SAFETY: stream is live until closed below.
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                break;
            }
            // SAFETY: d_name is NUL terminated in the returned dirent.
            let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }
                .to_str()
                .map_err(|_| DistributionError::Invalid("non-UTF8 transfer filename".into()))?;
            if name == "." || name == ".." {
                continue;
            }
            if !allowed.contains(&name) || (name == JOURNAL_TEMP && !allow_journal_temp) {
                return Err(DistributionError::Invalid(format!(
                    "unexpected transfer file: {name}"
                )));
            }
            if !entry_exists(dir, name)? {
                return Err(DistributionError::Invalid(format!(
                    "unexpected transfer file type: {name}"
                )));
            }
        }
        Ok(())
    })();
    // SAFETY: closes DIR and its owned duplicate descriptor.
    if unsafe { libc::closedir(stream) } != 0 {
        return Err(io_error(
            "close transfer directory listing",
            std::io::Error::last_os_error(),
        ));
    }
    result
}
fn read_chunk(
    manifest: &TransferManifest,
    data: &mut File,
    entry: &JournalEntry,
) -> Result<TransferChunk> {
    let offset = u64::from(entry.index)
        .checked_mul(u64::from(manifest.chunk_size))
        .ok_or_else(|| DistributionError::Invalid("chunk offset overflow".into()))?;
    let remain = manifest
        .export_len
        .checked_sub(offset)
        .ok_or_else(|| DistributionError::Invalid("chunk offset beyond transfer".into()))?;
    let len = usize::try_from(remain.min(u64::from(manifest.chunk_size)))
        .map_err(|_| DistributionError::Invalid("chunk length overflow".into()))?;
    let mut bytes = vec![0; len];
    data.seek(SeekFrom::Start(offset))
        .map_err(|e| io_error("seek persisted chunk", e))?;
    data.read_exact(&mut bytes)
        .map_err(|e| io_error("read persisted chunk", e))?;
    Ok(TransferChunk {
        index: entry.index,
        bytes,
        proof: entry.proof.clone(),
    })
}
fn io_error(action: &str, error: std::io::Error) -> DistributionError {
    DistributionError::Invalid(format!("{action}: {error}"))
}

fn write_chunk_bytes<W: Write>(writer: &mut W, bytes: &[u8]) -> std::io::Result<()> {
    writer.write_all(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct PartialFailure(usize);
    impl Write for PartialFailure {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.0 == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "simulated disk full",
                ));
            }
            let written = self.0.min(bytes.len());
            self.0 -= written;
            Ok(written)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn partial_chunk_write_error_is_propagated() {
        let mut writer = PartialFailure(2);
        let error = write_chunk_bytes(&mut writer, b"chunk").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::WriteZero);
    }
}

#[cfg(not(unix))]
pub struct DiskTransferReceiver;

#[cfg(not(unix))]
impl DiskTransferReceiver {
    pub fn create<P: AsRef<Path>>(_: P, _: TransferManifest, _: &str, _: &[u8]) -> Result<Self> {
        Err(DistributionError::Invalid("disk receiver is unavailable on this platform; secure no-follow file operations are not implemented".into()))
    }
    pub fn resume<P: AsRef<Path>>(_: P, _: &str, _: &[u8]) -> Result<Self> {
        Err(DistributionError::Invalid("disk receiver is unavailable on this platform; secure no-follow file operations are not implemented".into()))
    }
    pub fn accept(&mut self, _: TransferChunk) -> Result<()> {
        Err(DistributionError::Invalid(
            "disk receiver is unavailable on this platform".into(),
        ))
    }
    pub fn completed_chunks(&self) -> usize {
        0
    }
    pub fn transfer_id(&self) -> &str {
        ""
    }
    pub fn finalize(self, _: &str, _: &[u8], _: &str) -> Result<VerifiedPackage> {
        Err(DistributionError::Invalid(
            "disk receiver is unavailable on this platform".into(),
        ))
    }
    pub fn partial_directory(&self) -> &Path {
        Path::new("")
    }
}
