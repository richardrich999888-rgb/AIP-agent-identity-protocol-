//! Linux descriptor-relative package staging.
//!
//! The installation root must already exist and be administrator-controlled.
//! Every path component is opened with O_NOFOLLOW. The installation root
//! and its ancestors must be administrator-controlled.

use crate::{
    sign_persistent_install_inventory, verify_persistent_install_inventory, InstallError,
    InstalledExecutable, PersistentInstallInventory, PersistentInventoryFile,
    SignedPersistentInstallInventory,
};
use aip_crypto::{custody::Custodian, sha256};
use aip_package::VerifiedPackage;
use rand::RngCore;
use std::{
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    path::{Component, Path, PathBuf},
};

const DIRECTORY_MODE: libc::mode_t = 0o700;
const DATA_MODE: libc::mode_t = 0o644;
const EXECUTABLE_MODE: libc::mode_t = 0o755;

const INSTALL_LOCK_FILENAME: &str = ".aip-install.lock";

/// Holds an advisory installation lock until this descriptor is dropped.
/// The lock file is persistent and must never be unlinked during normal use.
struct InstallationLock {
    _fd: OwnedFd,
}

fn acquire_installation_lock(
    root_fd: &OwnedFd,
    exclusive: bool,
) -> Result<InstallationLock, InstallError> {
    let lock_name = c_name(INSTALL_LOCK_FILENAME)?;
    let fd = unsafe {
        libc::openat(
            root_fd.as_raw_fd(),
            lock_name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0o600 as libc::mode_t,
        )
    };

    if fd < 0 {
        return Err(io_error("open installation lock"));
    }

    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };

    if unsafe { libc::fstat(fd.as_raw_fd(), &mut metadata) } < 0 {
        return Err(io_error("inspect installation lock"));
    }

    if (metadata.st_mode & libc::S_IFMT) != libc::S_IFREG
        || (metadata.st_mode & 0o777) != 0o600
        || metadata.st_nlink != 1
    {
        return Err(InstallError::InvalidField("installation_lock_file"));
    }

    let operation = if exclusive {
        libc::LOCK_EX
    } else {
        libc::LOCK_SH
    };

    loop {
        if unsafe { libc::flock(fd.as_raw_fd(), operation) } == 0 {
            break;
        }

        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(InstallError::Io(format!(
                "acquire installation lock: {error}"
            )));
        }
    }

    Ok(InstallationLock { _fd: fd })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InstalledFileDigest {
    path: String,
    sha256: [u8; 32],
    executable: bool,
}

fn duplicate_fd(fd: &OwnedFd) -> Result<OwnedFd, InstallError> {
    let duplicate = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };

    if duplicate < 0 {
        return Err(io_error("duplicate directory descriptor"));
    }

    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

/// Remove a private staging tree through its pinned root directory descriptor.
/// Linux procfs provides the descriptor-relative path; remove_dir_all does not
/// follow symlinks encountered inside the tree.
fn cleanup_stage(root: &OwnedFd, stage_name: &str) {
    let path = PathBuf::from(format!("/proc/self/fd/{}/{}", root.as_raw_fd(), stage_name));

    let _ = std::fs::remove_dir_all(path);
}

struct StageCleanup {
    root_fd: OwnedFd,
    stage_name: String,
    armed: bool,
}

impl Drop for StageCleanup {
    fn drop(&mut self) {
        if self.armed {
            cleanup_stage(&self.root_fd, &self.stage_name);
        }
    }
}

pub struct StagedPackage {
    root_fd: OwnedFd,
    stage_name: String,
    executables: Vec<InstalledExecutable>,
    files: Vec<InstalledFileDigest>,
    package_name: String,
    package_version: String,
    publisher_id: String,
    archive_sha256: [u8; 32],
    manifest_sha256: [u8; 32],
    aibom_manifest_sha256: [u8; 32],
}

/// Canonical digest of the relative-path inventory that staging writes for a
/// publisher-verified package. A staged receipt can bind to this digest; it
/// is not evidence that the package was activated or executed.
pub fn expected_staged_artifact_digest(package: &VerifiedPackage) -> [u8; 32] {
    let mut files: Vec<_> = package.files().iter().collect();
    files.sort_by(|left, right| left.path().cmp(right.path()));
    let mut bytes = b"AIP/INSTALL/STAGED_INVENTORY/v1\0".to_vec();
    bytes.extend_from_slice(&(files.len() as u64).to_be_bytes());
    for file in files {
        bytes.extend_from_slice(&(file.path().len() as u32).to_be_bytes());
        bytes.extend_from_slice(file.path().as_bytes());
        bytes.extend_from_slice(&sha256(file.contents()));
        bytes.push(u8::from(file.is_executable()));
    }
    sha256(&bytes)
}

impl Drop for StagedPackage {
    fn drop(&mut self) {
        cleanup_stage(&self.root_fd, &self.stage_name);
    }
}

impl StagedPackage {
    /// Private staging directory name, relative to the installation root.
    pub fn stage_name(&self) -> &str {
        &self.stage_name
    }

    /// Domain-separated digest of the exact relative paths, file hashes and
    /// executable bits recorded while the verified package was staged. This
    /// binds a staging claim to its staged inventory; it is not an install or
    /// execution attestation.
    pub fn staged_artifact_digest(&self) -> [u8; 32] {
        let mut files: Vec<_> = self.files.iter().collect();
        files.sort_by(|left, right| left.path.cmp(&right.path));
        let mut bytes = b"AIP/INSTALL/STAGED_INVENTORY/v1\0".to_vec();
        bytes.extend_from_slice(&(files.len() as u64).to_be_bytes());
        for file in files {
            bytes.extend_from_slice(&(file.path.len() as u32).to_be_bytes());
            bytes.extend_from_slice(file.path.as_bytes());
            bytes.extend_from_slice(&file.sha256);
            bytes.push(u8::from(file.executable));
        }
        sha256(&bytes)
    }

    /// Executable paths and hashes re-read from staged files.
    pub fn executables(&self) -> &[InstalledExecutable] {
        &self.executables
    }

    /// Borrow the installation-root descriptor for descriptor-relative
    /// activation operations. The descriptor remains owned by this object.
    pub fn root_directory(&self) -> BorrowedFd<'_> {
        self.root_fd.as_fd()
    }
}

fn parse_sha256_hex(value: &str) -> Result<[u8; 32], InstallError> {
    if value.len() != 64 {
        return Err(InstallError::InvalidField("aibom_manifest_sha256"));
    }

    let mut digest = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(chunk)
            .map_err(|_| InstallError::InvalidField("aibom_manifest_sha256"))?;
        digest[index] = u8::from_str_radix(pair, 16)
            .map_err(|_| InstallError::InvalidField("aibom_manifest_sha256"))?;
    }

    Ok(digest)
}

fn io_error(context: &str) -> InstallError {
    InstallError::Io(format!("{context}: {}", std::io::Error::last_os_error()))
}

fn c_name(value: &str) -> Result<CString, InstallError> {
    CString::new(value.as_bytes())
        .map_err(|_| InstallError::InvalidExecutablePath(value.to_string()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EntryIdentity {
    device: libc::dev_t,
    inode: libc::ino_t,
}

fn identity_from_stat(metadata: &libc::stat) -> EntryIdentity {
    EntryIdentity {
        device: metadata.st_dev,
        inode: metadata.st_ino,
    }
}

fn stat_entry_at(parent: &OwnedFd, name: &CString) -> std::io::Result<libc::stat> {
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            &mut metadata,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };

    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(metadata)
}

fn descriptor_matches_identity(fd: &OwnedFd, expected: EntryIdentity) -> std::io::Result<bool> {
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };

    if unsafe { libc::fstat(fd.as_raw_fd(), &mut metadata) } < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(identity_from_stat(&metadata) == expected)
}

fn open_regular_file_at(parent: &OwnedFd, name: &CString) -> std::io::Result<OwnedFd> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };

    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn open_directory_at(parent: &OwnedFd, name: &CString) -> std::io::Result<OwnedFd> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };

    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn create_directory_at(parent: &OwnedFd, name: &CString) -> Result<(), InstallError> {
    let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), DIRECTORY_MODE) };

    if result < 0 {
        return Err(io_error("create staging directory"));
    }

    Ok(())
}

fn open_or_create_directory(parent: &OwnedFd, component: &str) -> Result<OwnedFd, InstallError> {
    let name = c_name(component)?;

    match open_directory_at(parent, &name) {
        Ok(fd) => Ok(fd),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
            create_directory_at(parent, &name)?;
            open_directory_at(parent, &name)
                .map_err(|e| InstallError::Io(format!("open created directory: {e}")))
        }
        Err(error) => Err(InstallError::Io(format!(
            "open package directory component {component}: {error}"
        ))),
    }
}

fn open_install_root(root: &Path) -> Result<OwnedFd, InstallError> {
    if !root.is_absolute() {
        return Err(InstallError::InvalidField("installation_root"));
    }

    let slash = CString::new("/").expect("static path is valid");
    let fd = unsafe {
        libc::open(
            slash.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };

    if fd < 0 {
        return Err(io_error("open filesystem root"));
    }

    let mut current = unsafe { OwnedFd::from_raw_fd(fd) };

    for component in root.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                let name = CString::new(name.as_bytes())
                    .map_err(|_| InstallError::InvalidField("installation_root"))?;

                current = open_directory_at(&current, &name).map_err(|e| {
                    InstallError::Io(format!("open installation-root component: {e}"))
                })?;
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(InstallError::InvalidField("installation_root"));
            }
        }
    }

    Ok(current)
}

fn validate_relative_path(path: &str) -> Result<Vec<&str>, InstallError> {
    if path.is_empty() || path.starts_with('/') || path.contains('\\') {
        return Err(InstallError::InvalidExecutablePath(path.to_string()));
    }

    let components: Vec<&str> = path.split('/').collect();

    if components.iter().any(|part| {
        part.is_empty() || *part == "." || *part == ".." || part.as_bytes().contains(&0)
    }) {
        return Err(InstallError::InvalidExecutablePath(path.to_string()));
    }

    Ok(components)
}

fn open_or_create_staging_file(parent: &OwnedFd, name: &CString) -> Result<File, InstallError> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };

    if fd < 0 {
        return Err(io_error("create staging file"));
    }

    Ok(File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
}

fn write_verified_file(
    parent: &OwnedFd,
    name: &CString,
    contents: &[u8],
    executable: bool,
) -> Result<[u8; 32], InstallError> {
    let expected_hash = sha256(contents);
    let mut file = open_or_create_staging_file(parent, name)?;

    file.write_all(contents)
        .map_err(|e| InstallError::Io(format!("write staged file: {e}")))?;

    let mode = if executable {
        EXECUTABLE_MODE
    } else {
        DATA_MODE
    };

    if unsafe { libc::fchmod(file.as_raw_fd(), mode) } < 0 {
        return Err(io_error("set staged file permissions"));
    }

    file.sync_all()
        .map_err(|e| InstallError::Io(format!("sync staged file: {e}")))?;

    drop(file);

    // Reopen through the already-open parent directory descriptor.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };

    if fd < 0 {
        return Err(io_error("reopen staged file"));
    }

    let mut reopened = File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    let mut actual_contents = Vec::with_capacity(contents.len());

    reopened
        .read_to_end(&mut actual_contents)
        .map_err(|e| InstallError::Io(format!("read staged file: {e}")))?;

    let actual_hash = sha256(&actual_contents);

    if actual_contents.len() != contents.len() || actual_hash != expected_hash {
        return Err(InstallError::DigestMismatch);
    }

    Ok(actual_hash)
}

fn sync_directory(directory: &OwnedFd) -> Result<(), InstallError> {
    if unsafe { libc::fsync(directory.as_raw_fd()) } < 0 {
        return Err(io_error("sync staging directory"));
    }

    Ok(())
}

/// Write an authenticated package into a new private staging directory.
///
/// No archive extraction takes place here: only files from `VerifiedPackage`
/// are accepted. Every file is created exclusively and reopened for hashing.
///
/// The returned object is not yet an active installation.
pub fn stage_verified_package(
    installation_root: &Path,
    package: &VerifiedPackage,
) -> Result<StagedPackage, InstallError> {
    let manifest = package.manifest();
    let aibom_manifest_sha256 = parse_sha256_hex(&manifest.aibom_manifest_sha256)?;
    let root_fd = open_install_root(installation_root)?;

    let mut random = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut random);

    let mut suffix = String::with_capacity(32);
    for byte in random {
        use std::fmt::Write as _;
        write!(&mut suffix, "{byte:02x}").expect("writing to String cannot fail");
    }

    let stage_name = format!(".aip-stage-{suffix}");
    let stage_c_name = c_name(&stage_name)?;

    create_directory_at(&root_fd, &stage_c_name)?;

    // If descriptor duplication fails, remove the directory immediately:
    // the cleanup guard cannot own the root descriptor until duplication works.
    let cleanup_root_fd = match duplicate_fd(&root_fd) {
        Ok(fd) => fd,
        Err(error) => {
            cleanup_stage(&root_fd, &stage_name);
            return Err(error);
        }
    };

    let mut cleanup = StageCleanup {
        root_fd: cleanup_root_fd,
        stage_name: stage_name.clone(),
        armed: true,
    };

    let stage_fd = open_directory_at(&root_fd, &stage_c_name)
        .map_err(|e| InstallError::Io(format!("open staging directory: {e}")))?;

    let mut executables = Vec::new();
    let mut files = Vec::new();

    for package_file in package.files() {
        let components = validate_relative_path(package_file.path())?;

        let mut current_directory = unsafe {
            // Duplicate the staging directory descriptor so traversal owns
            // its descriptor independently.
            let fd = libc::fcntl(stage_fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0);
            if fd < 0 {
                return Err(io_error("duplicate staging directory descriptor"));
            }
            OwnedFd::from_raw_fd(fd)
        };

        for component in &components[..components.len() - 1] {
            current_directory = open_or_create_directory(&current_directory, component)?;
        }

        let filename = c_name(components[components.len() - 1])?;

        let digest = write_verified_file(
            &current_directory,
            &filename,
            package_file.contents(),
            package_file.is_executable(),
        )?;

        sync_directory(&current_directory)?;

        files.push(InstalledFileDigest {
            path: package_file.path().to_string(),
            sha256: digest,
            executable: package_file.is_executable(),
        });

        if package_file.is_executable() {
            executables.push(InstalledExecutable {
                path: package_file.path().to_string(),
                sha256: digest,
            });
        }
    }

    executables.sort_by(|a, b| a.path.cmp(&b.path));
    files.sort_by(|a, b| a.path.cmp(&b.path));

    sync_directory(&stage_fd)?;
    sync_directory(&root_fd)?;

    let staged = StagedPackage {
        root_fd,
        stage_name,
        executables,
        files,
        package_name: manifest.name.clone(),
        package_version: manifest.version.clone(),
        publisher_id: manifest.publisher_id.clone(),
        archive_sha256: *package.archive_sha256(),
        manifest_sha256: *package.manifest_sha256(),
        aibom_manifest_sha256,
    };

    // The staged object now owns the staging directory lifecycle.
    // Disarm the failure guard, then let its duplicated descriptor close.
    cleanup.armed = false;
    drop(cleanup);

    Ok(staged)
}

/// A release that has been published and selected as the current installation.
///
/// Dropping this value does not remove the release from disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivatedPackage {
    release_name: String,
    executables: Vec<InstalledExecutable>,
    files: Vec<InstalledFileDigest>,
    package_name: String,
    package_version: String,
    publisher_id: String,
    archive_sha256: [u8; 32],
    manifest_sha256: [u8; 32],
    aibom_manifest_sha256: [u8; 32],
}

impl ActivatedPackage {
    /// Release directory name relative to the installation root.
    pub fn release_name(&self) -> &str {
        &self.release_name
    }

    /// Executable paths and hashes verified during staging.
    pub fn executables(&self) -> &[InstalledExecutable] {
        &self.executables
    }

    pub fn package_name(&self) -> &str {
        &self.package_name
    }

    pub fn package_version(&self) -> &str {
        &self.package_version
    }

    pub fn publisher_id(&self) -> &str {
        &self.publisher_id
    }

    pub fn archive_sha256(&self) -> &[u8; 32] {
        &self.archive_sha256
    }

    pub fn manifest_sha256(&self) -> &[u8; 32] {
        &self.manifest_sha256
    }

    pub fn aibom_manifest_sha256(&self) -> &[u8; 32] {
        &self.aibom_manifest_sha256
    }
}

/// Re-open every declared package file in the published release and verify
/// its type, expected permissions, and digest without following symlinks.
fn verify_release_inventory(
    root_fd: &OwnedFd,
    release_name: &str,
    files: &[InstalledFileDigest],
) -> Result<(), InstallError> {
    let release_c_name = c_name(release_name)?;
    let release_fd = open_directory_at(root_fd, &release_c_name)
        .map_err(|e| InstallError::Io(format!("open published release: {e}")))?;

    verify_release_inventory_at(&release_fd, files)
}

/// Verify package files relative to an already-open release directory.
///
/// Keeping the directory descriptor pinned prevents a release-name replacement
/// between inventory authentication and package-file verification.
fn verify_release_inventory_at(
    release_fd: &OwnedFd,
    files: &[InstalledFileDigest],
) -> Result<(), InstallError> {
    for entry in files {
        let components = validate_relative_path(&entry.path)?;
        let mut directory = duplicate_fd(release_fd)?;

        for component in &components[..components.len() - 1] {
            let name = c_name(component)?;
            directory = open_directory_at(&directory, &name).map_err(|e| {
                InstallError::Io(format!("open release path component {component}: {e}"))
            })?;
        }

        let filename = c_name(components[components.len() - 1])?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                filename.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };

        if fd < 0 {
            return Err(io_error("open published package file"));
        }

        let mut file = File::from(unsafe { OwnedFd::from_raw_fd(fd) });
        let mut metadata: libc::stat = unsafe { std::mem::zeroed() };

        if unsafe { libc::fstat(file.as_raw_fd(), &mut metadata) } < 0 {
            return Err(io_error("inspect published package file"));
        }

        if (metadata.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(InstallError::InvalidExecutablePath(entry.path.clone()));
        }

        let expected_mode = if entry.executable {
            EXECUTABLE_MODE
        } else {
            DATA_MODE
        };

        if (metadata.st_mode & 0o777) != expected_mode {
            return Err(InstallError::DigestMismatch);
        }

        let mut contents = Vec::new();
        file.read_to_end(&mut contents).map_err(|e| {
            InstallError::Io(format!("read published package file {}: {e}", entry.path))
        })?;

        if sha256(&contents) != entry.sha256 {
            return Err(InstallError::DigestMismatch);
        }
    }

    Ok(())
}

/// Read-only audit of the currently selected activated package.
pub fn audit_activated_package(
    installation_root: &Path,
    activated: &ActivatedPackage,
) -> Result<(), InstallError> {
    let root_fd = open_install_root(installation_root)?;
    let _installation_lock = acquire_installation_lock(&root_fd, false)?;
    let current_name = c_name("current")?;
    let current_fd = unsafe {
        libc::openat(
            root_fd.as_raw_fd(),
            current_name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };

    if current_fd < 0 {
        return Err(io_error("open current release pointer"));
    }

    let mut current_file = File::from(unsafe { OwnedFd::from_raw_fd(current_fd) });
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };

    if unsafe { libc::fstat(current_file.as_raw_fd(), &mut metadata) } < 0 {
        return Err(io_error("inspect current release pointer"));
    }

    if (metadata.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(InstallError::InvalidField("current_release_pointer"));
    }

    let mut pointer = String::new();
    current_file
        .read_to_string(&mut pointer)
        .map_err(|e| InstallError::Io(format!("read current release pointer: {e}")))?;

    if pointer != format!("{}\n", activated.release_name) {
        return Err(InstallError::DigestMismatch);
    }

    verify_release_inventory(&root_fd, &activated.release_name, &activated.files)
}

const INVENTORY_FILENAME: &str = ".aip-inventory.json";
const MAX_INVENTORY_BYTES: u64 = 1024 * 1024;
const INVENTORY_MODE: libc::mode_t = 0o600;

fn random_hex_16() -> String {
    let mut random = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut random);

    let mut suffix = String::with_capacity(32);
    for byte in random {
        use std::fmt::Write as _;
        write!(&mut suffix, "{byte:02x}").expect("writing to String cannot fail");
    }
    suffix
}

fn unix_time_ms() -> Result<u64, InstallError> {
    let value = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| InstallError::Io(format!("system clock before Unix epoch: {error}")))?
        .as_millis();
    u64::try_from(value).map_err(|_| InstallError::InvalidField("installed_at_ms"))
}

fn write_signed_inventory_to_stage(
    staged: &StagedPackage,
    installer_id: &str,
    custodian: &dyn Custodian,
    installation_id: [u8; 16],
    release_name: &str,
) -> Result<(), InstallError> {
    let inventory = PersistentInstallInventory {
        version: crate::INSTALL_INVENTORY_VERSION,
        installation_id,
        installer_id: installer_id.to_string(),
        release_name: release_name.to_string(),
        package_name: staged.package_name.clone(),
        package_version: staged.package_version.clone(),
        publisher_id: staged.publisher_id.clone(),
        archive_sha256: staged.archive_sha256,
        manifest_sha256: staged.manifest_sha256,
        aibom_manifest_sha256: staged.aibom_manifest_sha256,
        installed_at_ms: unix_time_ms()?,
        files: staged
            .files
            .iter()
            .map(|file| PersistentInventoryFile {
                path: file.path.clone(),
                sha256: file.sha256,
                executable: file.executable,
            })
            .collect(),
    };

    let signed = sign_persistent_install_inventory(inventory, custodian)?;
    let bytes = serde_json::to_vec(&signed)
        .map_err(|error| InstallError::Io(format!("serialize signed inventory: {error}")))?;

    if bytes.len() as u64 > MAX_INVENTORY_BYTES {
        return Err(InstallError::InvalidField("inventory_size"));
    }

    let stage_c_name = c_name(&staged.stage_name)?;
    let stage_fd = open_directory_at(&staged.root_fd, &stage_c_name).map_err(|error| {
        InstallError::Io(format!("open staging directory for inventory: {error}"))
    })?;
    let inventory_c_name = c_name(INVENTORY_FILENAME)?;

    let fd = unsafe {
        libc::openat(
            stage_fd.as_raw_fd(),
            inventory_c_name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            INVENTORY_MODE,
        )
    };
    if fd < 0 {
        return Err(io_error("create persistent inventory"));
    }

    let mut file = File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    file.write_all(&bytes)
        .map_err(|error| InstallError::Io(format!("write persistent inventory: {error}")))?;
    if unsafe { libc::fchmod(file.as_raw_fd(), INVENTORY_MODE) } < 0 {
        return Err(io_error("set persistent inventory permissions"));
    }
    file.sync_all()
        .map_err(|error| InstallError::Io(format!("sync persistent inventory: {error}")))?;
    sync_directory(&stage_fd)?;
    Ok(())
}

fn read_signed_inventory(
    release_fd: &OwnedFd,
) -> Result<SignedPersistentInstallInventory, InstallError> {
    let name = c_name(INVENTORY_FILENAME)?;
    let fd = unsafe {
        libc::openat(
            release_fd.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(io_error("open persistent inventory"));
    }

    let file = File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(file.as_raw_fd(), &mut metadata) } < 0 {
        return Err(io_error("inspect persistent inventory"));
    }
    if (metadata.st_mode & libc::S_IFMT) != libc::S_IFREG
        || (metadata.st_mode & 0o777) != INVENTORY_MODE
        || metadata.st_size < 0
        || metadata.st_size as u64 > MAX_INVENTORY_BYTES
    {
        return Err(InstallError::InvalidField("persistent_inventory_file"));
    }

    let mut bytes = Vec::with_capacity(metadata.st_size as usize);
    file.take(MAX_INVENTORY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| InstallError::Io(format!("read persistent inventory: {error}")))?;
    if bytes.len() as u64 > MAX_INVENTORY_BYTES {
        return Err(InstallError::InvalidField("inventory_size"));
    }

    serde_json::from_slice(&bytes)
        .map_err(|error| InstallError::Io(format!("parse persistent inventory: {error}")))
}

/// Activate a package while persisting its signed inventory before publication.
/// The inventory is stored inside the release directory and is not part of the
/// package-file digest list, avoiding a self-referential hash.
pub fn activate_staged_package_with_inventory(
    staged: StagedPackage,
    installer_id: &str,
    custodian: &dyn Custodian,
) -> Result<ActivatedPackage, InstallError> {
    if installer_id.trim().is_empty() || installer_id.len() > 256 {
        return Err(InstallError::InvalidField("installer_id"));
    }

    let _installation_lock = acquire_installation_lock(&staged.root_fd, true)?;

    let release_name = format!("release-{}", random_hex_16());
    let mut installation_id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut installation_id);

    write_signed_inventory_to_stage(
        &staged,
        installer_id,
        custodian,
        installation_id,
        &release_name,
    )?;

    activate_staged_package_named(staged, release_name)
}

fn load_current_inventory(
    root_fd: &OwnedFd,
    trusted_installer_public_key: &[u8],
) -> Result<(String, PersistentInstallInventory), InstallError> {
    let (release_name, inventory, _) =
        load_current_inventory_with_identity(root_fd, trusted_installer_public_key)?;
    Ok((release_name, inventory))
}

fn load_current_inventory_with_identity(
    root_fd: &OwnedFd,
    trusted_installer_public_key: &[u8],
) -> Result<(String, PersistentInstallInventory, EntryIdentity), InstallError> {
    let current_name = c_name("current")?;
    let current_fd = unsafe {
        libc::openat(
            root_fd.as_raw_fd(),
            current_name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };

    if current_fd < 0 {
        return Err(io_error("open current release pointer"));
    }

    let mut current_file = File::from(unsafe { OwnedFd::from_raw_fd(current_fd) });
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };

    if unsafe { libc::fstat(current_file.as_raw_fd(), &mut metadata) } < 0 {
        return Err(io_error("inspect current release pointer"));
    }

    if (metadata.st_mode & libc::S_IFMT) != libc::S_IFREG
        || metadata.st_size < 0
        || metadata.st_size > 256
    {
        return Err(InstallError::InvalidField("current_release_pointer"));
    }

    let mut pointer = String::new();
    current_file
        .read_to_string(&mut pointer)
        .map_err(|error| InstallError::Io(format!("read current release pointer: {error}")))?;

    let release_name = pointer
        .strip_suffix('\n')
        .ok_or(InstallError::InvalidField("current_release_pointer"))?;

    if !release_name.starts_with("release-")
        || release_name.len() != "release-".len() + 32
        || !release_name["release-".len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(InstallError::InvalidField("current_release_pointer"));
    }

    let release_c_name = c_name(release_name)?;
    let release_fd = open_directory_at(root_fd, &release_c_name)
        .map_err(|error| InstallError::Io(format!("open current release: {error}")))?;

    let signed = read_signed_inventory(&release_fd)?;
    let inventory = verify_persistent_install_inventory(&signed, trusted_installer_public_key)?;

    if inventory.release_name != release_name {
        return Err(InstallError::DigestMismatch);
    }

    Ok((
        release_name.to_string(),
        inventory.clone(),
        identity_from_stat(&metadata),
    ))
}

/// Upgrade an existing installation while preserving its authenticated
/// installation identity. The previous release is retained for rollback.
///
/// The trusted public key must be supplied independently by the caller.
/// An absent or unauthenticated current inventory causes the upgrade to fail.
pub fn upgrade_staged_package_with_inventory(
    staged: StagedPackage,
    installer_id: &str,
    custodian: &dyn Custodian,
    trusted_installer_public_key: &[u8],
) -> Result<ActivatedPackage, InstallError> {
    if installer_id.trim().is_empty() || installer_id.len() > 256 {
        return Err(InstallError::InvalidField("installer_id"));
    }

    // Preserve the existing trust anchor across the upgrade.
    if custodian.public_key() != trusted_installer_public_key {
        return Err(InstallError::InvalidSignature);
    }

    let _installation_lock = acquire_installation_lock(&staged.root_fd, true)?;

    let (_, current_inventory) =
        load_current_inventory(&staged.root_fd, trusted_installer_public_key)?;

    if current_inventory.installer_id != installer_id {
        return Err(InstallError::SignerMismatch);
    }

    let installation_id = current_inventory.installation_id;
    let release_name = format!("release-{}", random_hex_16());

    write_signed_inventory_to_stage(
        &staged,
        installer_id,
        custodian,
        installation_id,
        &release_name,
    )?;

    activate_staged_package_named(staged, release_name)
}

/// Classification of an entry discovered during read-only installation recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryEntryKind {
    ValidCurrentRelease,
    PublishedInactiveRelease,
    IncompleteStaging,
    OrphanTemporaryPointer,
    UnexpectedFilesystemEntry,
    InvalidOrUnauthenticatedRelease,
    InvalidCurrentPointer,
    CurrentPointerChangedDuringScan,
}

/// One filesystem entry observed by the recovery scanner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryEntry {
    pub name: String,
    pub kind: RecoveryEntryKind,
    pub detail: Option<String>,
}

/// Read-only snapshot of recoverable installation state.
///
/// This report does not establish that an earlier fsync completed before a
/// crash. It reports only the state observable during this scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryReport {
    pub current_release: Option<String>,
    pub entries: Vec<RecoveryEntry>,
}

fn is_valid_release_name(name: &str) -> bool {
    name.strip_prefix("release-").is_some_and(|suffix| {
        suffix.len() == 32 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn inspect_published_release(
    release_fd: &OwnedFd,
    release_name: &str,
    trusted_installer_public_key: &[u8],
) -> Result<PersistentInstallInventory, InstallError> {
    if !is_valid_release_name(release_name) {
        return Err(InstallError::InvalidField("release_name"));
    }

    let signed = read_signed_inventory(release_fd)?;
    let inventory = verify_persistent_install_inventory(&signed, trusted_installer_public_key)?;

    if inventory.release_name != release_name {
        return Err(InstallError::DigestMismatch);
    }

    let files: Vec<InstalledFileDigest> = inventory
        .files
        .iter()
        .map(|file| InstalledFileDigest {
            path: file.path.clone(),
            sha256: file.sha256,
            executable: file.executable,
        })
        .collect();

    verify_release_inventory_at(release_fd, &files)?;
    Ok(inventory.clone())
}

/// Inspect installation state after startup without changing the filesystem.
///
/// The trusted public key must be supplied independently by the caller.
/// Invalid entries are reported rather than repaired or deleted.
pub fn inspect_installation_recovery(
    installation_root: &Path,
    trusted_installer_public_key: &[u8],
) -> Result<RecoveryReport, InstallError> {
    inspect_installation_recovery_with_hook(installation_root, trusted_installer_public_key, |_| {})
}

fn inspect_installation_recovery_with_hook<F>(
    installation_root: &Path,
    trusted_installer_public_key: &[u8],
    mut after_entry_stat: F,
) -> Result<RecoveryReport, InstallError>
where
    F: FnMut(&str),
{
    let root_fd = open_install_root(installation_root)?;
    let _installation_lock = acquire_installation_lock(&root_fd, false)?;

    let current_name = c_name("current")?;
    let observe_current_pointer = || {
        stat_entry_at(&root_fd, &current_name)
            .map(|metadata| {
                (
                    identity_from_stat(&metadata),
                    metadata.st_mode & libc::S_IFMT,
                )
            })
            .map_err(|error| error.raw_os_error())
    };

    // Observe the directory entry independently of pointer authentication.
    // This also tracks invalid, symlinked, and initially missing pointers.
    let initial_pointer_observation = observe_current_pointer();

    let current_result =
        load_current_inventory_with_identity(&root_fd, trusted_installer_public_key);
    let current_release = current_result
        .as_ref()
        .ok()
        .map(|(release_name, _, _)| release_name.clone());

    let mut entries = Vec::new();

    if let Err(error) = &current_result {
        entries.push(RecoveryEntry {
            name: "current".to_string(),
            kind: RecoveryEntryKind::InvalidCurrentPointer,
            detail: Some(format!("{error:?}")),
        });
    }

    let root_path = PathBuf::from(format!("/proc/self/fd/{}", root_fd.as_raw_fd()));
    let directory_entries = std::fs::read_dir(root_path)
        .map_err(|error| InstallError::Io(format!("enumerate installation root: {error}")))?;

    for directory_entry in directory_entries {
        let directory_entry = directory_entry
            .map_err(|error| InstallError::Io(format!("read installation entry: {error}")))?;

        let Some(name) = directory_entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };

        let is_stage = name.starts_with(".aip-stage-");
        let is_temp_pointer = name.starts_with(".aip-current-");
        let is_release = name.starts_with("release-");

        if !is_stage && !is_temp_pointer && !is_release {
            continue;
        }

        if is_release && !is_valid_release_name(&name) {
            entries.push(RecoveryEntry {
                name,
                kind: RecoveryEntryKind::InvalidOrUnauthenticatedRelease,
                detail: Some("release directory name is malformed".to_string()),
            });
            continue;
        }

        let entry_name = c_name(&name)?;
        let observed = match stat_entry_at(&root_fd, &entry_name) {
            Ok(metadata) => metadata,
            Err(error) => {
                let kind = if is_release {
                    RecoveryEntryKind::InvalidOrUnauthenticatedRelease
                } else {
                    RecoveryEntryKind::UnexpectedFilesystemEntry
                };
                entries.push(RecoveryEntry {
                    name,
                    kind,
                    detail: Some(format!("entry disappeared or changed during scan: {error}")),
                });
                continue;
            }
        };

        let expected_identity = identity_from_stat(&observed);

        // Internal synchronization point used by deterministic race tests.
        // Production callers use the public no-op hook.
        after_entry_stat(&name);

        if is_stage {
            let classification = open_directory_at(&root_fd, &entry_name).and_then(|fd| {
                if !descriptor_matches_identity(&fd, expected_identity)? {
                    return Ok(false);
                }
                Ok(true)
            });

            let (kind, detail) = match classification {
                Ok(true) => (
                    RecoveryEntryKind::IncompleteStaging,
                    "staging directory requires explicit operator review",
                ),
                Ok(false) => (
                    RecoveryEntryKind::UnexpectedFilesystemEntry,
                    "staging entry changed identity during scan",
                ),
                Err(error) => (
                    RecoveryEntryKind::UnexpectedFilesystemEntry,
                    if error.raw_os_error() == Some(libc::ELOOP) {
                        "staging-prefixed entry is a symlink"
                    } else {
                        "staging-prefixed entry is not a stable directory"
                    },
                ),
            };

            entries.push(RecoveryEntry {
                name,
                kind,
                detail: Some(detail.to_string()),
            });
            continue;
        }

        if is_temp_pointer {
            let classification = open_regular_file_at(&root_fd, &entry_name).and_then(|fd| {
                let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(fd.as_raw_fd(), &mut metadata) } < 0 {
                    return Err(std::io::Error::last_os_error());
                }

                let same_identity = identity_from_stat(&metadata) == expected_identity;
                let regular = (metadata.st_mode & libc::S_IFMT) == libc::S_IFREG;
                Ok(same_identity && regular)
            });

            let (kind, detail) = match classification {
                Ok(true) => (
                    RecoveryEntryKind::OrphanTemporaryPointer,
                    "temporary pointer requires explicit operator review",
                ),
                Ok(false) => (
                    RecoveryEntryKind::UnexpectedFilesystemEntry,
                    "temporary pointer changed identity or is not a regular file",
                ),
                Err(_) => (
                    RecoveryEntryKind::UnexpectedFilesystemEntry,
                    "temporary-pointer-prefixed entry is not a stable regular file",
                ),
            };

            entries.push(RecoveryEntry {
                name,
                kind,
                detail: Some(detail.to_string()),
            });
            continue;
        }

        let release_fd = match open_directory_at(&root_fd, &entry_name) {
            Ok(fd) => fd,
            Err(error) => {
                entries.push(RecoveryEntry {
                    name,
                    kind: RecoveryEntryKind::InvalidOrUnauthenticatedRelease,
                    detail: Some(format!("release is not a stable directory: {error}")),
                });
                continue;
            }
        };

        match descriptor_matches_identity(&release_fd, expected_identity) {
            Ok(true) => {}
            Ok(false) => {
                entries.push(RecoveryEntry {
                    name,
                    kind: RecoveryEntryKind::InvalidOrUnauthenticatedRelease,
                    detail: Some("release directory changed identity during scan".to_string()),
                });
                continue;
            }
            Err(error) => {
                entries.push(RecoveryEntry {
                    name,
                    kind: RecoveryEntryKind::InvalidOrUnauthenticatedRelease,
                    detail: Some(format!("verify release directory identity: {error}")),
                });
                continue;
            }
        }

        // Continue using the same pinned release descriptor whose identity
        // was checked against the directory entry observed during enumeration.
        match inspect_published_release(&release_fd, &name, trusted_installer_public_key) {
            Ok(_) => {
                let is_current = current_release.as_deref() == Some(name.as_str());
                entries.push(RecoveryEntry {
                    name,
                    kind: if is_current {
                        RecoveryEntryKind::ValidCurrentRelease
                    } else {
                        RecoveryEntryKind::PublishedInactiveRelease
                    },
                    detail: None,
                });
            }
            Err(error) => entries.push(RecoveryEntry {
                name,
                kind: RecoveryEntryKind::InvalidOrUnauthenticatedRelease,
                detail: Some(format!("{error:?}")),
            }),
        }
    }

    let final_pointer_observation = observe_current_pointer();
    let pointer_changed = initial_pointer_observation != final_pointer_observation;

    let current_release = if pointer_changed {
        if let Some(initial_release) = current_release.as_deref() {
            for entry in &mut entries {
                if entry.name == initial_release
                    && entry.kind == RecoveryEntryKind::ValidCurrentRelease
                {
                    entry.kind = RecoveryEntryKind::PublishedInactiveRelease;
                    entry.detail = Some(
                        "release was current at scan start; current pointer changed during scan"
                            .to_string(),
                    );
                }
            }
        }

        entries.push(RecoveryEntry {
            name: "current".to_string(),
            kind: RecoveryEntryKind::CurrentPointerChangedDuringScan,
            detail: Some(
                "current pointer identity changed or disappeared during recovery scan".to_string(),
            ),
        });
        None
    } else {
        current_release
    };

    entries.sort_by(|left, right| left.name.cmp(&right.name));

    Ok(RecoveryReport {
        current_release,
        entries,
    })
}

/// Audit the current installation using only persistent on-disk state.
/// The caller must supply an independently trusted installer public key.
pub fn audit_persistent_installation(
    installation_root: &Path,
    trusted_installer_public_key: &[u8],
) -> Result<PersistentInstallInventory, InstallError> {
    let root_fd = open_install_root(installation_root)?;
    let _installation_lock = acquire_installation_lock(&root_fd, false)?;
    let (release_name, inventory) = load_current_inventory(&root_fd, trusted_installer_public_key)?;

    let files: Vec<InstalledFileDigest> = inventory
        .files
        .iter()
        .map(|file| InstalledFileDigest {
            path: file.path.clone(),
            sha256: file.sha256,
            executable: file.executable,
        })
        .collect();

    verify_release_inventory(&root_fd, &release_name, &files)?;
    Ok(inventory)
}

/// Roll back to an explicitly selected, previously published release.
///
/// Both the current and target inventories must authenticate with the
/// independently trusted installer key. The target's installation identity
/// and installer identity must match the current installation. All target
/// files are verified before the current pointer is atomically replaced.
pub fn rollback_to_release(
    installation_root: &Path,
    target_release_name: &str,
    trusted_installer_public_key: &[u8],
) -> Result<PersistentInstallInventory, InstallError> {
    let suffix = target_release_name
        .strip_prefix("release-")
        .filter(|suffix| suffix.len() == 32 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or(InstallError::InvalidField("release_name"))?;

    let root_fd = open_install_root(installation_root)?;
    let _installation_lock = acquire_installation_lock(&root_fd, true)?;

    let (current_release_name, current_inventory) =
        load_current_inventory(&root_fd, trusted_installer_public_key)?;

    let target_c_name = c_name(target_release_name)?;
    let target_fd = open_directory_at(&root_fd, &target_c_name)
        .map_err(|error| InstallError::Io(format!("open rollback target release: {error}")))?;

    let signed_target = read_signed_inventory(&target_fd)?;
    let target_inventory =
        verify_persistent_install_inventory(&signed_target, trusted_installer_public_key)?;

    if target_inventory.release_name != target_release_name {
        return Err(InstallError::DigestMismatch);
    }

    if target_inventory.installation_id != current_inventory.installation_id {
        return Err(InstallError::InvalidField("installation_id"));
    }

    if target_inventory.installer_id != current_inventory.installer_id {
        return Err(InstallError::SignerMismatch);
    }

    let target_files: Vec<InstalledFileDigest> = target_inventory
        .files
        .iter()
        .map(|file| InstalledFileDigest {
            path: file.path.clone(),
            sha256: file.sha256,
            executable: file.executable,
        })
        .collect();

    verify_release_inventory(&root_fd, target_release_name, &target_files)?;

    if current_release_name != target_release_name {
        switch_current_pointer(&root_fd, target_release_name)?;
    }

    let _ = suffix;
    Ok(target_inventory.clone())
}

/// Publish a staged package as a uniquely named release, then atomically
/// replace the installation root's `current` pointer.
///
/// The pointer is a regular file containing the release directory name.
/// A failed pointer update can leave an inactive release directory behind;
/// it is intentionally not deleted because the failure may occur after the
/// release has become durable.
pub fn activate_staged_package(staged: StagedPackage) -> Result<ActivatedPackage, InstallError> {
    let _installation_lock = acquire_installation_lock(&staged.root_fd, true)?;
    let release_name = format!("release-{}", random_hex_16());
    activate_staged_package_named(staged, release_name)
}

/// Publish and durably synchronize a staged release without changing
/// the current installation pointer.
fn publish_staged_release(staged: &StagedPackage, release_name: &str) -> Result<(), InstallError> {
    let release_c_name = c_name(release_name)?;
    let stage_c_name = c_name(&staged.stage_name)?;

    // Never replace an existing release directory.
    let rename_result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            staged.root_fd.as_raw_fd(),
            stage_c_name.as_ptr(),
            staged.root_fd.as_raw_fd(),
            release_c_name.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };

    if rename_result < 0 {
        return Err(io_error("publish release directory"));
    }

    // Verify the published files before considering the release durable.
    verify_release_inventory(&staged.root_fd, release_name, &staged.files)?;

    // Persist the release directory entry before any pointer replacement.
    sync_directory(&staged.root_fd)?;

    Ok(())
}

/// Stages at which pointer switching can be interrupted in tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PointerSwitchStage {
    CreateTemporaryPointer,
    WritePointer,
    SyncPointer,
    RenamePointer,
    SyncInstallationRoot,
}

/// Atomically switch the installation's current release pointer.
fn switch_current_pointer(root_fd: &OwnedFd, release_name: &str) -> Result<(), InstallError> {
    switch_current_pointer_with_hook(root_fd, release_name, |_| Ok(()))
}

/// Internal implementation with a per-call fault-injection hook.
///
/// Production passes a no-op hook. Tests can inject deterministic failures
/// without global mutable state or interference between parallel tests.
fn switch_current_pointer_with_hook<F>(
    root_fd: &OwnedFd,
    release_name: &str,
    mut hook: F,
) -> Result<(), InstallError>
where
    F: FnMut(PointerSwitchStage) -> Result<(), InstallError>,
{
    let suffix = release_name
        .strip_prefix("release-")
        .filter(|suffix| suffix.len() == 32 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or(InstallError::InvalidField("release_name"))?;

    let pointer_name = format!(".aip-current-{suffix}");
    let pointer_c_name = c_name(&pointer_name)?;
    let current_c_name = c_name("current")?;

    hook(PointerSwitchStage::CreateTemporaryPointer)?;

    let pointer_fd = unsafe {
        libc::openat(
            root_fd.as_raw_fd(),
            pointer_c_name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600 as libc::mode_t,
        )
    };

    if pointer_fd < 0 {
        return Err(io_error("create temporary current pointer"));
    }

    let pointer_result = (|| -> Result<(), InstallError> {
        let mut pointer_file = File::from(unsafe { OwnedFd::from_raw_fd(pointer_fd) });

        hook(PointerSwitchStage::WritePointer)?;
        pointer_file
            .write_all(format!("{release_name}\n").as_bytes())
            .map_err(|error| InstallError::Io(format!("write current pointer: {error}")))?;

        hook(PointerSwitchStage::SyncPointer)?;
        pointer_file
            .sync_all()
            .map_err(|error| InstallError::Io(format!("sync current pointer: {error}")))?;

        hook(PointerSwitchStage::RenamePointer)?;
        let rename_pointer = unsafe {
            libc::renameat(
                root_fd.as_raw_fd(),
                pointer_c_name.as_ptr(),
                root_fd.as_raw_fd(),
                current_c_name.as_ptr(),
            )
        };

        if rename_pointer < 0 {
            return Err(io_error("atomically replace current pointer"));
        }

        hook(PointerSwitchStage::SyncInstallationRoot).map_err(|error| {
            InstallError::Io(format!(
                "current pointer was replaced, but installation-root durability is uncertain: {error:?}"
            ))
        })?;

        sync_directory(root_fd).map_err(|error| {
            InstallError::Io(format!(
                "current pointer was replaced, but installation-root durability is uncertain: {error:?}"
            ))
        })?;

        Ok(())
    })();

    if pointer_result.is_err() {
        unsafe {
            libc::unlinkat(root_fd.as_raw_fd(), pointer_c_name.as_ptr(), 0);
        }
    }

    pointer_result
}

fn activate_staged_package_named(
    staged: StagedPackage,
    release_name: String,
) -> Result<ActivatedPackage, InstallError> {
    publish_staged_release(&staged, &release_name)?;

    switch_current_pointer(&staged.root_fd, &release_name)?;

    Ok(ActivatedPackage {
        release_name,
        executables: staged.executables.clone(),
        files: staged.files.clone(),
        package_name: staged.package_name.clone(),
        package_version: staged.package_version.clone(),
        publisher_id: staged.publisher_id.clone(),
        archive_sha256: staged.archive_sha256,
        manifest_sha256: staged.manifest_sha256,
        aibom_manifest_sha256: staged.aibom_manifest_sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aip_crypto::custody::{Custodian, InMemoryCustodian};
    use aip_package::{build_package_v2, sign_package, verify_package_contents, PackageFile};
    use rand::RngCore;
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
        path::PathBuf,
    };

    const AIBOM_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn temporary_path(label: &str) -> PathBuf {
        let mut random = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut random);

        std::env::temp_dir().join(format!(
            "aip-install-{label}-{}-{:016x}",
            std::process::id(),
            u64::from_le_bytes(random),
        ))
    }

    fn verified_package_with_executables(
        files: Vec<PackageFile>,
        executable_paths: Vec<String>,
    ) -> VerifiedPackage {
        let package = build_package_v2(
            "test-agent",
            "1.0.0",
            "publisher-test",
            AIBOM_DIGEST,
            files,
            executable_paths,
        )
        .expect("test package should build");

        let publisher = InMemoryCustodian::generate();
        let signature = sign_package(&package, &publisher).expect("package should sign");

        verify_package_contents(&package, &signature, publisher.public_key(), AIBOM_DIGEST)
            .expect("signed package should verify")
    }

    fn verified_package(files: Vec<PackageFile>) -> VerifiedPackage {
        verified_package_with_executables(files, vec!["bin/agent".into()])
    }

    fn normal_package() -> VerifiedPackage {
        verified_package(vec![
            PackageFile {
                path: "bin/agent".into(),
                contents: b"#!/bin/sh\nprintf 'AIP agent\\n'\n".to_vec(),
            },
            PackageFile {
                path: "config/runtime.json".into(),
                contents: br#"{"runtime":"linux"}"#.to_vec(),
            },
        ])
    }

    #[test]
    fn stages_authenticated_files_with_declared_permissions_and_cleans_on_drop() {
        let root = temporary_path("stage");
        fs::create_dir(&root).expect("create installation root");

        let package = normal_package();
        let staged = stage_verified_package(&root, &package).expect("stage verified package");

        let stage_path = root.join(staged.stage_name());

        let executable = stage_path.join("bin/agent");
        let data = stage_path.join("config/runtime.json");

        assert_eq!(
            fs::read(&executable).expect("read staged executable"),
            b"#!/bin/sh\nprintf 'AIP agent\\n'\n"
        );
        assert_eq!(
            fs::read(&data).expect("read staged data"),
            br#"{"runtime":"linux"}"#
        );

        let executable_mode = fs::metadata(&executable)
            .expect("executable metadata")
            .permissions()
            .mode()
            & 0o777;
        let data_mode = fs::metadata(&data)
            .expect("data metadata")
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(executable_mode, EXECUTABLE_MODE);
        assert_eq!(data_mode, DATA_MODE);

        assert_eq!(staged.executables().len(), 1);
        assert_eq!(staged.executables()[0].path, "bin/agent");
        assert_eq!(
            staged.executables()[0].sha256,
            sha256(&fs::read(&executable).unwrap())
        );

        drop(staged);

        assert!(
            !stage_path.exists(),
            "dropping an unactivated stage should remove its directory"
        );

        fs::remove_dir_all(&root).expect("remove test root");
    }

    #[test]
    fn rejects_symlink_installation_root() {
        let base = temporary_path("symlink");
        fs::create_dir(&base).expect("create test base");

        let real_root = base.join("real-root");
        let linked_root = base.join("linked-root");

        fs::create_dir(&real_root).expect("create real root");
        symlink(&real_root, &linked_root).expect("create root symlink");

        let package = normal_package();

        assert!(
            stage_verified_package(&linked_root, &package).is_err(),
            "installer must reject a symlink in the installation-root path"
        );

        assert_eq!(
            fs::read_dir(&real_root).unwrap().count(),
            0,
            "rejected root must remain untouched"
        );

        fs::remove_dir_all(&base).expect("remove test base");
    }

    #[test]
    fn failed_staging_removes_partial_tree() {
        let root = temporary_path("failure");
        fs::create_dir(&root).expect("create installation root");

        // The first file creates "collision" as a regular file. The second
        // path requires that same component to be a directory.
        let package = verified_package_with_executables(
            vec![
                PackageFile {
                    path: "collision".into(),
                    contents: b"first".to_vec(),
                },
                PackageFile {
                    path: "collision/child".into(),
                    contents: b"second".to_vec(),
                },
            ],
            Vec::new(),
        );

        let result = stage_verified_package(&root, &package);

        assert!(result.is_err(), "conflicting paths must fail staging");
        assert_eq!(
            fs::read_dir(&root).unwrap().count(),
            0,
            "failed staging must not leave a partial staging directory"
        );

        fs::remove_dir_all(&root).expect("remove test root");
    }

    #[test]
    fn activated_package_produces_verifiable_signed_install_receipt() {
        let root = temporary_path("activation-receipt");
        fs::create_dir(&root).expect("create installation root");

        let package = normal_package();
        let staged = stage_verified_package(&root, &package).expect("stage verified package");
        let activated = activate_staged_package(staged).expect("activate staged package");

        let signer = InMemoryCustodian::generate();
        let signed = crate::create_signed_install_receipt(&activated, "installer-test", &signer)
            .expect("create signed install receipt");

        let receipt = crate::verify_install_receipt(&signed, signer.public_key())
            .expect("verify signed install receipt");

        assert_eq!(receipt.package_name, "test-agent");
        assert_eq!(receipt.package_version, "1.0.0");
        assert_eq!(receipt.publisher_id, "publisher-test");
        assert_eq!(receipt.archive_sha256, *package.archive_sha256());
        assert_eq!(receipt.manifest_sha256, *package.manifest_sha256());
        assert_eq!(receipt.aibom_manifest_sha256, [0xaa; 32]);
        assert_eq!(receipt.executables, activated.executables());
        assert!(receipt.installed_at_ms > 0);
        assert_ne!(receipt.installation_id, [0; 16]);

        fs::remove_dir_all(&root).expect("remove test root");
    }

    #[test]
    fn activation_rejects_modified_published_executable() {
        let root = temporary_path("activation-tamper");
        fs::create_dir(&root).expect("create installation root");

        let package = normal_package();
        let staged = stage_verified_package(&root, &package).expect("stage verified package");

        let stage_path = root.join(staged.stage_name());
        fs::write(stage_path.join("bin/agent"), b"tampered executable")
            .expect("modify staged executable");

        let result = activate_staged_package(staged);

        assert_eq!(result, Err(InstallError::DigestMismatch));
        assert!(
            !root.join("current").exists(),
            "tampered release must never become current"
        );

        assert!(
            fs::read_dir(&root)
                .unwrap()
                .filter_map(Result::ok)
                .any(|entry| entry.file_name().to_string_lossy().starts_with("release-")),
            "published release should remain available for inspection"
        );

        fs::remove_dir_all(&root).expect("remove test root");
    }

    #[test]
    fn activation_rejects_modified_published_data_file() {
        let root = temporary_path("activation-data-tamper");
        fs::create_dir(&root).expect("create installation root");

        let package = normal_package();
        let staged = stage_verified_package(&root, &package).expect("stage verified package");

        let stage_path = root.join(staged.stage_name());
        fs::write(
            stage_path.join("config/runtime.json"),
            br#"{"runtime":"tampered"}"#,
        )
        .expect("modify staged data file");

        let result = activate_staged_package(staged);

        assert_eq!(result, Err(InstallError::DigestMismatch));
        assert!(
            !root.join("current").exists(),
            "modified data file must prevent activation"
        );

        assert!(
            fs::read_dir(&root)
                .unwrap()
                .filter_map(Result::ok)
                .any(|entry| entry.file_name().to_string_lossy().starts_with("release-")),
            "published release should remain available for inspection"
        );

        fs::remove_dir_all(&root).expect("remove test root");
    }

    #[test]
    fn audit_accepts_unchanged_activated_package() {
        let root = temporary_path("audit-clean");
        fs::create_dir(&root).expect("create installation root");

        let package = normal_package();
        let staged = stage_verified_package(&root, &package).expect("stage package");
        let activated = activate_staged_package(staged).expect("activate package");

        audit_activated_package(&root, &activated).expect("clean audit should pass");

        fs::remove_dir_all(&root).expect("remove test root");
    }

    #[test]
    fn audit_rejects_modified_activated_data_file() {
        let root = temporary_path("audit-modified");
        fs::create_dir(&root).expect("create installation root");

        let package = normal_package();
        let staged = stage_verified_package(&root, &package).expect("stage package");
        let activated = activate_staged_package(staged).expect("activate package");

        fs::write(
            root.join(activated.release_name())
                .join("config/runtime.json"),
            br#"{"runtime":"tampered"}"#,
        )
        .expect("modify data file");

        assert_eq!(
            audit_activated_package(&root, &activated),
            Err(InstallError::DigestMismatch)
        );

        fs::remove_dir_all(&root).expect("remove test root");
    }

    #[test]
    fn audit_rejects_missing_activated_file() {
        let root = temporary_path("audit-missing");
        fs::create_dir(&root).expect("create installation root");

        let package = normal_package();
        let staged = stage_verified_package(&root, &package).expect("stage package");
        let activated = activate_staged_package(staged).expect("activate package");

        fs::remove_file(
            root.join(activated.release_name())
                .join("config/runtime.json"),
        )
        .expect("remove data file");

        assert!(audit_activated_package(&root, &activated).is_err());

        fs::remove_dir_all(&root).expect("remove test root");
    }

    #[test]
    fn audit_rejects_symlink_substituted_for_activated_file() {
        let root = temporary_path("audit-symlink");
        fs::create_dir(&root).expect("create installation root");

        let package = normal_package();
        let staged = stage_verified_package(&root, &package).expect("stage package");
        let activated = activate_staged_package(staged).expect("activate package");

        let data_file = root
            .join(activated.release_name())
            .join("config/runtime.json");
        fs::remove_file(&data_file).expect("remove original data file");
        symlink("/etc/passwd", &data_file).expect("substitute symlink");

        assert!(audit_activated_package(&root, &activated).is_err());

        fs::remove_dir_all(&root).expect("remove test root");
    }

    #[test]
    fn persistent_inventory_survives_dropping_activation_handle() {
        let root = temporary_path("persistent-restart");
        fs::create_dir(&root).expect("create installation root");

        let package = normal_package();
        let staged = stage_verified_package(&root, &package).expect("stage package");
        let custodian = InMemoryCustodian::generate();
        let trusted_key = custodian.public_key().to_vec();

        let activated =
            activate_staged_package_with_inventory(staged, "installer-test", &custodian)
                .expect("activate with persistent inventory");

        let release_name = activated.release_name().to_string();
        let inventory_path = root.join(&release_name).join(INVENTORY_FILENAME);

        assert!(inventory_path.is_file(), "signed inventory should exist");
        assert_eq!(
            fs::metadata(&inventory_path)
                .expect("inventory metadata")
                .permissions()
                .mode()
                & 0o777,
            INVENTORY_MODE
        );

        drop(activated);

        let inventory = audit_persistent_installation(&root, &trusted_key)
            .expect("persistent audit should work without ActivatedPackage");

        assert_eq!(inventory.installer_id, "installer-test");
        assert_eq!(inventory.release_name, release_name);
        assert_eq!(inventory.package_name, "test-agent");
        assert_eq!(inventory.package_version, "1.0.0");
        assert_eq!(inventory.publisher_id, "publisher-test");
        assert_eq!(inventory.files.len(), 2);

        fs::remove_dir_all(&root).expect("remove test root");
    }

    #[test]
    fn rollback_restores_previous_release_and_preserves_identity() {
        let root = temporary_path("rollback-success");
        fs::create_dir(&root).expect("create installation root");

        let custodian = InMemoryCustodian::generate();
        let trusted_key = custodian.public_key().to_vec();

        let first_stage =
            stage_verified_package(&root, &normal_package()).expect("stage first package");
        let first =
            activate_staged_package_with_inventory(first_stage, "installer-test", &custodian)
                .expect("activate first installation");

        let first_release = first.release_name().to_string();
        let original_inventory =
            audit_persistent_installation(&root, &trusted_key).expect("audit first install");

        let upgrade_stage =
            stage_verified_package(&root, &normal_package()).expect("stage upgrade");
        let upgraded = upgrade_staged_package_with_inventory(
            upgrade_stage,
            "installer-test",
            &custodian,
            &trusted_key,
        )
        .expect("upgrade installation");

        assert_ne!(upgraded.release_name(), first_release);

        let rolled_back =
            rollback_to_release(&root, &first_release, &trusted_key).expect("rollback");

        assert_eq!(rolled_back.release_name, first_release);
        assert_eq!(
            rolled_back.installation_id,
            original_inventory.installation_id
        );
        assert_eq!(
            fs::read_to_string(root.join("current")).expect("read current pointer"),
            format!("{first_release}\n")
        );

        let audited =
            audit_persistent_installation(&root, &trusted_key).expect("audit rolled-back release");
        assert_eq!(audited.release_name, first_release);
        assert_eq!(audited.installation_id, original_inventory.installation_id);

        fs::remove_dir_all(&root).expect("remove test root");
    }

    #[test]
    fn rollback_rejects_target_signed_by_untrusted_key_without_switching_current() {
        let root = temporary_path("rollback-wrong-key");
        let foreign_root = temporary_path("rollback-wrong-key-foreign");
        fs::create_dir(&root).expect("create installation root");
        fs::create_dir(&foreign_root).expect("create foreign root");

        let trusted_custodian = InMemoryCustodian::generate();
        let trusted_key = trusted_custodian.public_key().to_vec();

        let first_stage =
            stage_verified_package(&root, &normal_package()).expect("stage first package");
        activate_staged_package_with_inventory(first_stage, "installer-test", &trusted_custodian)
            .expect("activate trusted installation");

        let original_pointer =
            fs::read_to_string(root.join("current")).expect("read current pointer");

        let wrong_custodian = InMemoryCustodian::generate();
        let foreign_stage = stage_verified_package(&foreign_root, &normal_package())
            .expect("stage foreign package");
        let foreign = activate_staged_package_with_inventory(
            foreign_stage,
            "installer-test",
            &wrong_custodian,
        )
        .expect("activate foreign release");

        let target_release = foreign.release_name().to_string();
        drop(foreign);

        fs::rename(
            foreign_root.join(&target_release),
            root.join(&target_release),
        )
        .expect("move foreign release into installation root");

        assert_eq!(
            rollback_to_release(&root, &target_release, &trusted_key).unwrap_err(),
            InstallError::InvalidSignature
        );
        assert_eq!(
            fs::read_to_string(root.join("current")).expect("read current pointer"),
            original_pointer
        );

        fs::remove_dir_all(&root).expect("remove test root");
        fs::remove_dir_all(&foreign_root).expect("remove foreign root");
    }

    #[test]
    fn rollback_rejects_modified_target_file_without_switching_current() {
        let root = temporary_path("rollback-file-tamper");
        fs::create_dir(&root).expect("create installation root");

        let custodian = InMemoryCustodian::generate();
        let trusted_key = custodian.public_key().to_vec();

        let first_stage =
            stage_verified_package(&root, &normal_package()).expect("stage first package");
        let first =
            activate_staged_package_with_inventory(first_stage, "installer-test", &custodian)
                .expect("activate first installation");
        let target_release = first.release_name().to_string();

        let upgrade_stage =
            stage_verified_package(&root, &normal_package()).expect("stage upgrade");
        upgrade_staged_package_with_inventory(
            upgrade_stage,
            "installer-test",
            &custodian,
            &trusted_key,
        )
        .expect("upgrade installation");

        let original_pointer =
            fs::read_to_string(root.join("current")).expect("read current pointer");

        fs::write(
            root.join(&target_release).join("config/runtime.json"),
            br#"{"runtime":"tampered"}"#,
        )
        .expect("tamper with rollback target");

        assert_eq!(
            rollback_to_release(&root, &target_release, &trusted_key).unwrap_err(),
            InstallError::DigestMismatch
        );
        assert_eq!(
            fs::read_to_string(root.join("current")).expect("read current pointer"),
            original_pointer
        );

        fs::remove_dir_all(&root).expect("remove test root");
    }

    #[test]
    fn rollback_rejects_release_from_different_installation() {
        let root = temporary_path("rollback-foreign-identity");
        let foreign_root = temporary_path("rollback-foreign-identity-source");
        fs::create_dir(&root).expect("create installation root");
        fs::create_dir(&foreign_root).expect("create foreign root");

        let custodian = InMemoryCustodian::generate();
        let trusted_key = custodian.public_key().to_vec();

        let first_stage =
            stage_verified_package(&root, &normal_package()).expect("stage first package");
        activate_staged_package_with_inventory(first_stage, "installer-test", &custodian)
            .expect("activate installation");

        let original_pointer =
            fs::read_to_string(root.join("current")).expect("read current pointer");

        let foreign_stage = stage_verified_package(&foreign_root, &normal_package())
            .expect("stage foreign package");
        let foreign =
            activate_staged_package_with_inventory(foreign_stage, "installer-test", &custodian)
                .expect("activate foreign installation");

        let target_release = foreign.release_name().to_string();
        drop(foreign);

        fs::rename(
            foreign_root.join(&target_release),
            root.join(&target_release),
        )
        .expect("move foreign release into installation root");

        assert_eq!(
            rollback_to_release(&root, &target_release, &trusted_key).unwrap_err(),
            InstallError::InvalidField("installation_id")
        );
        assert_eq!(
            fs::read_to_string(root.join("current")).expect("read current pointer"),
            original_pointer
        );

        fs::remove_dir_all(&root).expect("remove test root");
        fs::remove_dir_all(&foreign_root).expect("remove foreign root");
    }

    #[test]
    fn interrupted_after_release_publication_keeps_previous_release_active() {
        let root = temporary_path("interrupted-after-publication");
        fs::create_dir(&root).expect("create installation root");

        let custodian = InMemoryCustodian::generate();
        let trusted_key = custodian.public_key().to_vec();

        // Establish a valid first installation.
        let first_stage =
            stage_verified_package(&root, &normal_package()).expect("stage first package");
        let first =
            activate_staged_package_with_inventory(first_stage, "installer-test", &custodian)
                .expect("activate first installation");

        let first_release = first.release_name().to_string();
        let first_inventory =
            audit_persistent_installation(&root, &trusted_key).expect("audit first installation");
        let installation_id = first_inventory.installation_id;
        let original_pointer =
            fs::read_to_string(root.join("current")).expect("read original current pointer");

        // Prepare and publish a second signed release, but deliberately do
        // not switch the current pointer. This models interruption at the
        // publication-to-activation boundary.
        let second_stage =
            stage_verified_package(&root, &normal_package()).expect("stage second package");
        let second_release = format!("release-{}", random_hex_16());

        write_signed_inventory_to_stage(
            &second_stage,
            "installer-test",
            &custodian,
            installation_id,
            &second_release,
        )
        .expect("write second release inventory");

        publish_staged_release(&second_stage, &second_release).expect("publish second release");

        drop(second_stage);

        // The old installation remains active and auditable.
        assert_eq!(
            fs::read_to_string(root.join("current")).expect("read current pointer"),
            original_pointer
        );
        assert_eq!(original_pointer, format!("{first_release}\n"));

        let audited = audit_persistent_installation(&root, &trusted_key)
            .expect("audit still-active first release");
        assert_eq!(audited.release_name, first_release);
        assert_eq!(audited.installation_id, installation_id);

        // The newly published release remains on disk, independently
        // signed, but is not selected as current.
        assert!(
            root.join(&second_release).is_dir(),
            "published release must survive dropping the staged handle"
        );
        assert_ne!(second_release, first_release);

        let root_fd = open_install_root(&root).expect("open installation root");
        let release_c_name = c_name(&second_release).expect("validate release name");
        let release_fd =
            open_directory_at(&root_fd, &release_c_name).expect("open published release");
        let signed_inventory =
            read_signed_inventory(&release_fd).expect("read published inventory");
        verify_persistent_install_inventory(&signed_inventory, &trusted_key)
            .expect("verify published inventory signature");

        assert_eq!(signed_inventory.inventory.release_name, second_release);
        assert_eq!(signed_inventory.inventory.installation_id, installation_id);
        assert_eq!(signed_inventory.inventory.installer_id, "installer-test");

        fs::remove_dir_all(&root).expect("remove test root");
    }

    #[test]
    fn upgrade_preserves_installation_identity_and_previous_release() {
        let root = temporary_path("upgrade-identity");
        fs::create_dir(&root).expect("create installation root");

        let custodian = InMemoryCustodian::generate();
        let trusted_key = custodian.public_key().to_vec();

        let first_stage =
            stage_verified_package(&root, &normal_package()).expect("stage first package");
        let first =
            activate_staged_package_with_inventory(first_stage, "installer-test", &custodian)
                .expect("activate first installation");

        let first_release = first.release_name().to_string();
        let first_inventory =
            audit_persistent_installation(&root, &trusted_key).expect("audit first installation");
        let installation_id = first_inventory.installation_id;

        let upgrade_stage =
            stage_verified_package(&root, &normal_package()).expect("stage upgrade package");
        let upgraded = upgrade_staged_package_with_inventory(
            upgrade_stage,
            "installer-test",
            &custodian,
            &trusted_key,
        )
        .expect("upgrade installation");

        let upgraded_release = upgraded.release_name().to_string();
        assert_ne!(upgraded_release, first_release);
        assert!(
            root.join(&first_release).is_dir(),
            "previous release must remain"
        );

        let upgraded_inventory = audit_persistent_installation(&root, &trusted_key)
            .expect("audit upgraded installation");

        assert_eq!(upgraded_inventory.installation_id, installation_id);
        assert_eq!(upgraded_inventory.release_name, upgraded_release);
        assert_eq!(upgraded_inventory.installer_id, "installer-test");

        fs::remove_dir_all(&root).expect("remove test root");
    }

    #[test]
    fn upgrade_rejects_untrusted_signing_key_without_switching_current() {
        let root = temporary_path("upgrade-wrong-key");
        fs::create_dir(&root).expect("create installation root");

        let trusted_custodian = InMemoryCustodian::generate();
        let trusted_key = trusted_custodian.public_key().to_vec();

        let first_stage =
            stage_verified_package(&root, &normal_package()).expect("stage first package");
        let first = activate_staged_package_with_inventory(
            first_stage,
            "installer-test",
            &trusted_custodian,
        )
        .expect("activate first installation");

        let original_pointer =
            fs::read_to_string(root.join("current")).expect("read original pointer");

        let upgrade_stage =
            stage_verified_package(&root, &normal_package()).expect("stage upgrade package");
        let wrong_custodian = InMemoryCustodian::generate();

        assert_eq!(
            upgrade_staged_package_with_inventory(
                upgrade_stage,
                "installer-test",
                &wrong_custodian,
                &trusted_key,
            )
            .unwrap_err(),
            InstallError::InvalidSignature
        );

        assert_eq!(
            fs::read_to_string(root.join("current")).expect("read current pointer"),
            original_pointer
        );
        assert!(root.join(first.release_name()).is_dir());

        fs::remove_dir_all(&root).expect("remove test root");
    }

    #[test]
    fn upgrade_rejects_installer_id_change_without_switching_current() {
        let root = temporary_path("upgrade-installer-mismatch");
        fs::create_dir(&root).expect("create installation root");

        let custodian = InMemoryCustodian::generate();
        let trusted_key = custodian.public_key().to_vec();

        let first_stage =
            stage_verified_package(&root, &normal_package()).expect("stage first package");
        let first =
            activate_staged_package_with_inventory(first_stage, "installer-test", &custodian)
                .expect("activate first installation");

        let original_pointer =
            fs::read_to_string(root.join("current")).expect("read original pointer");

        let upgrade_stage =
            stage_verified_package(&root, &normal_package()).expect("stage upgrade package");

        assert_eq!(
            upgrade_staged_package_with_inventory(
                upgrade_stage,
                "different-installer",
                &custodian,
                &trusted_key,
            )
            .unwrap_err(),
            InstallError::SignerMismatch
        );

        assert_eq!(
            fs::read_to_string(root.join("current")).expect("read current pointer"),
            original_pointer
        );
        assert!(root.join(first.release_name()).is_dir());

        fs::remove_dir_all(&root).expect("remove test root");
    }

    #[test]
    fn upgrade_rejects_missing_current_inventory_without_resetting_identity() {
        let root = temporary_path("upgrade-missing-inventory");
        fs::create_dir(&root).expect("create installation root");

        let custodian = InMemoryCustodian::generate();
        let trusted_key = custodian.public_key().to_vec();

        let first_stage =
            stage_verified_package(&root, &normal_package()).expect("stage first package");
        let first =
            activate_staged_package_with_inventory(first_stage, "installer-test", &custodian)
                .expect("activate first installation");

        let original_pointer =
            fs::read_to_string(root.join("current")).expect("read original pointer");

        fs::remove_file(root.join(first.release_name()).join(INVENTORY_FILENAME))
            .expect("remove current inventory");

        let upgrade_stage =
            stage_verified_package(&root, &normal_package()).expect("stage upgrade package");

        assert!(
            upgrade_staged_package_with_inventory(
                upgrade_stage,
                "installer-test",
                &custodian,
                &trusted_key,
            )
            .is_err(),
            "upgrade must fail when the current authenticated inventory is missing"
        );

        assert_eq!(
            fs::read_to_string(root.join("current")).expect("read current pointer"),
            original_pointer
        );

        fs::remove_dir_all(&root).expect("remove test root");
    }

    #[test]
    fn persistent_inventory_rejects_wrong_trusted_key() {
        let root = temporary_path("persistent-wrong-key");
        fs::create_dir(&root).expect("create installation root");

        let package = normal_package();
        let staged = stage_verified_package(&root, &package).expect("stage package");
        let custodian = InMemoryCustodian::generate();
        let wrong_custodian = InMemoryCustodian::generate();

        let _activated =
            activate_staged_package_with_inventory(staged, "installer-test", &custodian)
                .expect("activate with persistent inventory");

        assert_eq!(
            audit_persistent_installation(&root, wrong_custodian.public_key()),
            Err(InstallError::InvalidSignature)
        );

        fs::remove_dir_all(&root).expect("remove test root");
    }

    #[test]
    fn persistent_inventory_rejects_modified_inventory() {
        let root = temporary_path("persistent-tamper");
        fs::create_dir(&root).expect("create installation root");

        let package = normal_package();
        let staged = stage_verified_package(&root, &package).expect("stage package");
        let custodian = InMemoryCustodian::generate();
        let trusted_key = custodian.public_key().to_vec();

        let activated =
            activate_staged_package_with_inventory(staged, "installer-test", &custodian)
                .expect("activate with persistent inventory");

        let inventory_path = root.join(activated.release_name()).join(INVENTORY_FILENAME);

        let mut signed: SignedPersistentInstallInventory =
            serde_json::from_slice(&fs::read(&inventory_path).expect("read inventory"))
                .expect("parse signed inventory");

        signed.inventory.package_version = "9.9.9".into();

        fs::write(
            &inventory_path,
            serde_json::to_vec(&signed).expect("serialize tampered inventory"),
        )
        .expect("write tampered inventory");

        assert_eq!(
            audit_persistent_installation(&root, &trusted_key),
            Err(InstallError::PayloadHashMismatch)
        );

        fs::remove_dir_all(&root).expect("remove test root");
    }

    #[test]
    fn persistent_inventory_audit_rejects_modified_installed_file() {
        let root = temporary_path("persistent-file-tamper");
        fs::create_dir(&root).expect("create installation root");

        let package = normal_package();
        let staged = stage_verified_package(&root, &package).expect("stage package");
        let custodian = InMemoryCustodian::generate();
        let trusted_key = custodian.public_key().to_vec();

        let activated =
            activate_staged_package_with_inventory(staged, "installer-test", &custodian)
                .expect("activate with persistent inventory");

        fs::write(
            root.join(activated.release_name())
                .join("config/runtime.json"),
            br#"{"runtime":"tampered"}"#,
        )
        .expect("tamper with installed data file");

        assert_eq!(
            audit_persistent_installation(&root, &trusted_key),
            Err(InstallError::DigestMismatch)
        );

        fs::remove_dir_all(&root).expect("remove test root");
    }

    #[test]
    fn persistent_audit_fails_closed_for_invalid_current_pointers() {
        for (case, pointer, expected_invalid_field) in [
            ("malformed", "not-a-release\\n", true),
            ("invalid-name", "release-not-a-valid-identifier\\n", true),
            (
                "missing-release",
                "release-00000000000000000000000000000000\\n",
                false,
            ),
        ] {
            let root = temporary_path(&format!("current-pointer-{case}"));
            fs::create_dir(&root).expect("create installation root");

            let staged = stage_verified_package(&root, &normal_package()).expect("stage package");
            let custodian = InMemoryCustodian::generate();
            let trusted_key = custodian.public_key().to_vec();

            activate_staged_package_with_inventory(staged, "installer-test", &custodian)
                .expect("activate valid installation");

            fs::write(root.join("current"), pointer).expect("corrupt current pointer");

            let result = audit_persistent_installation(&root, &trusted_key);
            assert!(
                result.is_err(),
                "{case}: invalid current pointer must not trigger automatic recovery"
            );

            if expected_invalid_field {
                assert_eq!(
                    result,
                    Err(InstallError::InvalidField("current_release_pointer")),
                    "{case}: malformed pointer must be rejected explicitly"
                );
            }

            fs::remove_dir_all(&root).expect("remove test root");
        }
    }

    #[test]
    fn persistent_audit_rejects_missing_inventory() {
        let root = temporary_path("persistent-missing");
        fs::create_dir(&root).expect("create installation root");

        let staged = stage_verified_package(&root, &normal_package()).expect("stage package");
        let custodian = InMemoryCustodian::generate();
        let trusted_key = custodian.public_key().to_vec();

        let activated =
            activate_staged_package_with_inventory(staged, "installer-test", &custodian)
                .expect("activate package");

        fs::remove_file(root.join(activated.release_name()).join(INVENTORY_FILENAME))
            .expect("remove inventory");

        assert!(audit_persistent_installation(&root, &trusted_key).is_err());

        fs::remove_dir_all(&root).expect("remove test root");
    }

    #[test]
    fn persistent_audit_rejects_symlinked_inventory() {
        let root = temporary_path("persistent-symlink");
        fs::create_dir(&root).expect("create installation root");

        let staged = stage_verified_package(&root, &normal_package()).expect("stage package");
        let custodian = InMemoryCustodian::generate();
        let trusted_key = custodian.public_key().to_vec();

        let activated =
            activate_staged_package_with_inventory(staged, "installer-test", &custodian)
                .expect("activate package");

        let inventory_path = root.join(activated.release_name()).join(INVENTORY_FILENAME);
        fs::remove_file(&inventory_path).expect("remove original inventory");
        symlink("/etc/passwd", &inventory_path).expect("substitute symlink");

        assert!(audit_persistent_installation(&root, &trusted_key).is_err());

        fs::remove_dir_all(&root).expect("remove test root");
    }

    #[test]
    fn persistent_audit_rejects_incorrect_inventory_permissions() {
        let root = temporary_path("persistent-mode");
        fs::create_dir(&root).expect("create installation root");

        let staged = stage_verified_package(&root, &normal_package()).expect("stage package");
        let custodian = InMemoryCustodian::generate();
        let trusted_key = custodian.public_key().to_vec();

        let activated =
            activate_staged_package_with_inventory(staged, "installer-test", &custodian)
                .expect("activate package");

        let inventory_path = root.join(activated.release_name()).join(INVENTORY_FILENAME);
        fs::set_permissions(&inventory_path, fs::Permissions::from_mode(0o644))
            .expect("change inventory permissions");

        assert_eq!(
            audit_persistent_installation(&root, &trusted_key),
            Err(InstallError::InvalidField("persistent_inventory_file"))
        );

        fs::remove_dir_all(&root).expect("remove test root");
    }

    #[test]
    fn persistent_audit_rejects_oversized_inventory() {
        let root = temporary_path("persistent-oversized");
        fs::create_dir(&root).expect("create installation root");

        let staged = stage_verified_package(&root, &normal_package()).expect("stage package");
        let custodian = InMemoryCustodian::generate();
        let trusted_key = custodian.public_key().to_vec();

        let activated =
            activate_staged_package_with_inventory(staged, "installer-test", &custodian)
                .expect("activate package");

        let inventory_path = root.join(activated.release_name()).join(INVENTORY_FILENAME);
        fs::write(
            &inventory_path,
            vec![b'A'; (MAX_INVENTORY_BYTES + 1) as usize],
        )
        .expect("write oversized inventory");
        fs::set_permissions(&inventory_path, fs::Permissions::from_mode(INVENTORY_MODE))
            .expect("set inventory permissions");

        assert_eq!(
            audit_persistent_installation(&root, &trusted_key),
            Err(InstallError::InvalidField("persistent_inventory_file"))
        );

        fs::remove_dir_all(&root).expect("remove test root");
    }

    #[test]
    fn activation_publishes_release_and_switches_current_pointer() {
        let root = temporary_path("activation-success");
        fs::create_dir(&root).expect("create installation root");

        let package = normal_package();
        let staged = stage_verified_package(&root, &package).expect("stage verified package");

        let old_stage = root.join(staged.stage_name());
        let activated = activate_staged_package(staged).expect("activate staged package");

        let release_name = activated.release_name().to_string();
        let release_path = root.join(&release_name);
        let current_path = root.join("current");

        assert!(!old_stage.exists(), "staging directory should be renamed");
        assert!(release_path.is_dir(), "release directory should exist");
        assert_eq!(
            fs::read_to_string(&current_path).expect("read current pointer"),
            format!("{release_name}\n")
        );
        assert_eq!(
            fs::read(release_path.join("bin/agent")).expect("read release executable"),
            b"#!/bin/sh\nprintf 'AIP agent\\n'\n"
        );
        assert_eq!(activated.executables().len(), 1);

        drop(activated);

        assert!(
            release_path.is_dir(),
            "dropping activation handle must not delete a published release"
        );

        fs::remove_dir_all(&root).expect("remove test root");
    }

    #[test]
    fn pointer_switch_faults_preserve_correct_state_at_each_stage() {
        let stages = [
            PointerSwitchStage::CreateTemporaryPointer,
            PointerSwitchStage::WritePointer,
            PointerSwitchStage::SyncPointer,
            PointerSwitchStage::RenamePointer,
            PointerSwitchStage::SyncInstallationRoot,
        ];

        for (index, stage) in stages.into_iter().enumerate() {
            let root = temporary_path(&format!("pointer-fault-{index}"));
            fs::create_dir(&root).expect("create installation root");

            let old_release = format!("release-{:032x}", index + 100);
            let new_release = format!("release-{:032x}", index + 200);

            fs::write(root.join("current"), format!("{old_release}\n"))
                .expect("create existing current pointer");

            let root_fd = open_install_root(&root).expect("open installation root");
            let mut reached_hook = false;

            let result =
                switch_current_pointer_with_hook(&root_fd, &new_release, |observed_stage| {
                    if observed_stage == stage {
                        reached_hook = true;
                        Err(InstallError::InvalidField("injected_pointer_fault"))
                    } else {
                        Ok(())
                    }
                });

            assert!(reached_hook, "fault hook was not reached at {stage:?}");
            assert!(result.is_err(), "injected fault at {stage:?} must fail");

            let current = fs::read_to_string(root.join("current"))
                .expect("read current pointer after injected fault");

            if stage == PointerSwitchStage::SyncInstallationRoot {
                assert_eq!(
                    current,
                    format!("{new_release}\n"),
                    "rename has happened; the new pointer must remain visible"
                );

                match result {
                    Err(InstallError::Io(message)) => assert!(
                        message.contains("durability is uncertain"),
                        "post-rename failure must report uncertain durability: {message}"
                    ),
                    other => panic!("expected an uncertain-durability I/O error, got {other:?}"),
                }
            } else {
                assert_eq!(
                    current,
                    format!("{old_release}\n"),
                    "pre-rename failure must preserve the old pointer"
                );
                assert_eq!(
                    result,
                    Err(InstallError::InvalidField("injected_pointer_fault"))
                );
            }

            assert!(
                fs::read_dir(&root)
                    .expect("read installation root")
                    .all(|entry| {
                        !entry
                            .expect("read directory entry")
                            .file_name()
                            .to_string_lossy()
                            .starts_with(".aip-current-")
                    }),
                "temporary pointer must be cleaned up after {stage:?}"
            );

            drop(root_fd);
            fs::remove_dir_all(&root).expect("remove test root");
        }
    }

    #[test]
    fn failed_pointer_switch_preserves_existing_current_directory_and_release() {
        let root = temporary_path("activation-failure");
        fs::create_dir(&root).expect("create installation root");

        let current_path = root.join("current");
        fs::create_dir(&current_path).expect("create blocking current directory");

        let package = normal_package();
        let staged = stage_verified_package(&root, &package).expect("stage verified package");

        let result = activate_staged_package(staged);

        assert!(
            result.is_err(),
            "directory must block current pointer replacement"
        );
        assert!(
            current_path.is_dir(),
            "existing current directory must remain untouched"
        );

        let release = fs::read_dir(&root)
            .expect("read installation root")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|entry| {
                entry
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("release-"))
            });

        assert!(
            release.as_ref().is_some_and(|path| path.is_dir()),
            "published release must remain available after pointer update failure"
        );

        assert!(
            fs::read_dir(&root).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".aip-current-")),
            "temporary pointer file should be cleaned up"
        );

        fs::remove_dir_all(&root).expect("remove test root");
    }

    #[test]
    fn child_waits_for_exclusive_installation_lock() {
        const ROOT: &str = "AIP_INSTALL_LOCK_CHILD_ROOT";
        const STARTED: &str = "AIP_INSTALL_LOCK_CHILD_STARTED";
        const ACQUIRED: &str = "AIP_INSTALL_LOCK_CHILD_ACQUIRED";

        let Ok(root) = std::env::var(ROOT) else {
            return;
        };

        let started = PathBuf::from(std::env::var(STARTED).expect("started marker path"));
        let acquired = PathBuf::from(std::env::var(ACQUIRED).expect("acquired marker path"));

        let root_fd = open_install_root(PathBuf::from(root).as_path())
            .expect("child opens installation root");

        fs::write(&started, b"started").expect("write child started marker");

        let _lock = acquire_installation_lock(&root_fd, true)
            .expect("child eventually acquires exclusive lock");

        fs::write(&acquired, b"acquired").expect("write child acquired marker");
    }

    #[test]
    fn exclusive_installation_lock_waits_for_other_process() {
        use std::{
            process::Command,
            thread,
            time::{Duration, Instant},
        };

        let root = temporary_path("lock-contention");
        fs::create_dir(&root).expect("create installation root");

        let started = root.with_extension("child-started");
        let acquired = root.with_extension("child-acquired");

        let root_fd = open_install_root(&root).expect("open installation root");
        let parent_lock =
            acquire_installation_lock(&root_fd, false).expect("parent acquires shared lock");

        let mut child = Command::new(std::env::current_exe().expect("test executable path"))
            .arg("--exact")
            .arg("linux::tests::child_waits_for_exclusive_installation_lock")
            .arg("--nocapture")
            .env("AIP_INSTALL_LOCK_CHILD_ROOT", &root)
            .env("AIP_INSTALL_LOCK_CHILD_STARTED", &started)
            .env("AIP_INSTALL_LOCK_CHILD_ACQUIRED", &acquired)
            .spawn()
            .expect("launch lock-test child");

        let deadline = Instant::now() + Duration::from_secs(5);
        while !started.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }

        assert!(
            started.exists(),
            "child should start and signal before attempting the exclusive lock"
        );
        thread::sleep(Duration::from_millis(100));
        assert!(
            !acquired.exists(),
            "child must not acquire an exclusive lock while parent holds a shared lock"
        );

        drop(parent_lock);

        let status = child.wait().expect("wait for lock-test child");
        assert!(
            status.success(),
            "child should acquire the lock after parent releases it; status: {status}"
        );
        assert!(
            acquired.exists(),
            "child should create its acquired marker after obtaining the lock"
        );

        fs::remove_file(&started).expect("remove started marker");
        fs::remove_file(&acquired).expect("remove acquired marker");
        fs::remove_dir_all(&root).expect("remove test installation root");
    }

    #[test]
    fn independent_shared_installation_locks_coexist() {
        let root = temporary_path("shared-locks");
        fs::create_dir(&root).expect("create installation root");

        let first_root_fd = open_install_root(&root).expect("open first root descriptor");
        let second_root_fd = open_install_root(&root).expect("open second root descriptor");

        let first_lock =
            acquire_installation_lock(&first_root_fd, false).expect("acquire first shared lock");
        let second_lock =
            acquire_installation_lock(&second_root_fd, false).expect("acquire second shared lock");

        drop(second_lock);
        drop(first_lock);
        fs::remove_dir_all(&root).expect("remove test installation root");
    }

    #[test]
    fn installation_lock_rejects_unsafe_permissions() {
        let root = temporary_path("lock-permissions");
        fs::create_dir(&root).expect("create installation root");

        let lock_path = root.join(INSTALL_LOCK_FILENAME);
        fs::write(&lock_path, b"").expect("create lock file");
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o644))
            .expect("set unsafe lock permissions");

        let root_fd = open_install_root(&root).expect("open installation root");
        assert!(
            acquire_installation_lock(&root_fd, true).is_err(),
            "installer must reject a lock file accessible by group or others"
        );

        fs::remove_dir_all(&root).expect("remove test installation root");
    }

    #[test]
    fn installation_lock_rejects_symlinked_lock_file() {
        let root = temporary_path("lock-symlink");
        let external = temporary_path("lock-symlink-target");

        fs::create_dir(&root).expect("create installation root");
        fs::write(&external, b"external sentinel").expect("create external target");
        symlink(&external, root.join(INSTALL_LOCK_FILENAME)).expect("create lock-file symlink");

        let root_fd = open_install_root(&root).expect("open installation root");
        assert!(
            acquire_installation_lock(&root_fd, true).is_err(),
            "installer must reject a symlinked lock file"
        );

        assert_eq!(
            fs::read(&external).expect("read external sentinel"),
            b"external sentinel",
            "lock acquisition must not modify the symlink target"
        );

        fs::remove_dir_all(&root).expect("remove test installation root");
        fs::remove_file(&external).expect("remove external target");
    }

    // Child-process entry point for the real process-termination test below.
    // The environment variables contain only an ephemeral test key and test paths.
    #[test]
    fn child_crashes_after_release_publication() {
        const ROOT: &str = "AIP_INSTALL_CRASH_CHILD_ROOT";
        const PRIVATE: &str = "AIP_INSTALL_CRASH_CHILD_PRIVATE";
        const PUBLIC: &str = "AIP_INSTALL_CRASH_CHILD_PUBLIC";
        const INSTALLATION_ID: &str = "AIP_INSTALL_CRASH_CHILD_INSTALLATION_ID";

        let Ok(root) = std::env::var(ROOT) else {
            return;
        };

        fn decode_hex(value: &str) -> Vec<u8> {
            assert_eq!(value.len() % 2, 0);
            value
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| {
                    let pair = std::str::from_utf8(pair).expect("hex is ASCII");
                    u8::from_str_radix(pair, 16).expect("valid hex")
                })
                .collect()
        }

        let private_key = decode_hex(&std::env::var(PRIVATE).expect("child private key"));
        let public_key = decode_hex(&std::env::var(PUBLIC).expect("child public key"));
        let installation_id_bytes =
            decode_hex(&std::env::var(INSTALLATION_ID).expect("installation ID"));
        let installation_id: [u8; 16] = installation_id_bytes
            .try_into()
            .expect("installation ID must be 16 bytes");

        let custodian = InMemoryCustodian::new(&private_key, &public_key)
            .expect("reconstruct test-only installer identity");
        let root = PathBuf::from(root);
        let staged = stage_verified_package(&root, &normal_package()).expect("stage child release");

        let release_name = "release-22222222222222222222222222222222";
        write_signed_inventory_to_stage(
            &staged,
            "installer-test",
            &custodian,
            installation_id,
            release_name,
        )
        .expect("write signed inventory in child staging directory");

        publish_staged_release(&staged, release_name).expect("publish child release");

        // Simulate abrupt process death: do not run StagedPackage::drop.
        unsafe { libc::_exit(86) }
    }

    #[test]
    fn process_crash_after_publication_is_recoverable_on_restart() {
        use std::process::Command;

        let root = temporary_path("process-crash-publication");
        fs::create_dir(&root).expect("create installation root");

        // The deterministic identity is generated once in the parent and
        // reconstructed in the child. It is ephemeral test material only.
        let key_pair = aip_crypto::generate_ed25519_keypair();
        let custodian = InMemoryCustodian::new(&key_pair.private_key, &key_pair.public_key)
            .expect("create parent test custodian");
        let trusted_key = custodian.public_key().to_vec();

        let first_stage =
            stage_verified_package(&root, &normal_package()).expect("stage initial package");
        let first =
            activate_staged_package_with_inventory(first_stage, "installer-test", &custodian)
                .expect("activate initial release");
        let original_release = first.release_name().to_string();
        let original_inventory =
            audit_persistent_installation(&root, &trusted_key).expect("audit initial release");

        fn encode_hex(bytes: &[u8]) -> String {
            let mut output = String::with_capacity(bytes.len() * 2);
            for byte in bytes {
                use std::fmt::Write as _;
                write!(&mut output, "{byte:02x}").expect("write hex");
            }
            output
        }

        let output = Command::new(std::env::current_exe().expect("test executable path"))
            .arg("--exact")
            .arg("linux::tests::child_crashes_after_release_publication")
            .arg("--nocapture")
            .env("AIP_INSTALL_CRASH_CHILD_ROOT", &root)
            .env(
                "AIP_INSTALL_CRASH_CHILD_PRIVATE",
                encode_hex(&key_pair.private_key),
            )
            .env(
                "AIP_INSTALL_CRASH_CHILD_PUBLIC",
                encode_hex(&key_pair.public_key),
            )
            .env(
                "AIP_INSTALL_CRASH_CHILD_INSTALLATION_ID",
                encode_hex(&original_inventory.installation_id),
            )
            .output()
            .expect("launch crash-test child process");

        assert_eq!(
            output.status.code(),
            Some(86),
            "child should terminate at the publication boundary; stdout: {}; stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );

        let report = inspect_installation_recovery(&root, &trusted_key)
            .expect("parent should scan installation after child termination");

        assert_eq!(
            report.current_release.as_deref(),
            Some(original_release.as_str()),
            "the previous release must remain active"
        );
        assert!(
            report.entries.iter().any(|entry| {
                entry.name == original_release
                    && entry.kind == RecoveryEntryKind::ValidCurrentRelease
            }),
            "recovery scan should authenticate the original current release"
        );
        assert!(
            report.entries.iter().any(|entry| {
                entry.name == "release-22222222222222222222222222222222"
                    && entry.kind == RecoveryEntryKind::PublishedInactiveRelease
            }),
            "recovery scan should recognize the child's published release as inactive"
        );

        fs::remove_dir_all(&root).expect("remove test installation root");
    }

    #[test]
    fn child_crashes_during_pointer_switch() {
        const ROOT: &str = "AIP_POINTER_CRASH_ROOT";
        const PRIVATE: &str = "AIP_POINTER_CRASH_PRIVATE";
        const PUBLIC: &str = "AIP_POINTER_CRASH_PUBLIC";
        const INSTALLATION_ID: &str = "AIP_POINTER_CRASH_INSTALLATION_ID";
        const STAGE: &str = "AIP_POINTER_CRASH_STAGE";

        let Ok(root) = std::env::var(ROOT) else {
            return;
        };

        fn decode_hex(value: &str) -> Vec<u8> {
            assert_eq!(value.len() % 2, 0);
            value
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| {
                    let pair = std::str::from_utf8(pair).expect("hex is ASCII");
                    u8::from_str_radix(pair, 16).expect("valid hex")
                })
                .collect()
        }

        let private_key = decode_hex(&std::env::var(PRIVATE).expect("private key"));
        let public_key = decode_hex(&std::env::var(PUBLIC).expect("public key"));
        let id_bytes = decode_hex(&std::env::var(INSTALLATION_ID).expect("installation ID"));
        let installation_id: [u8; 16] = id_bytes
            .try_into()
            .expect("installation ID must be 16 bytes");

        let target = match std::env::var(STAGE).expect("crash stage").as_str() {
            "create" => PointerSwitchStage::CreateTemporaryPointer,
            "write" => PointerSwitchStage::WritePointer,
            "sync-pointer" => PointerSwitchStage::SyncPointer,
            "rename" => PointerSwitchStage::RenamePointer,
            "sync-root" => PointerSwitchStage::SyncInstallationRoot,
            other => panic!("unknown crash stage: {other}"),
        };

        let custodian = InMemoryCustodian::new(&private_key, &public_key)
            .expect("reconstruct test installer identity");
        let root = PathBuf::from(root);
        let staged = stage_verified_package(&root, &normal_package()).expect("stage child release");

        let release_name = "release-33333333333333333333333333333333";

        write_signed_inventory_to_stage(
            &staged,
            "installer-test",
            &custodian,
            installation_id,
            release_name,
        )
        .expect("write signed child inventory");

        publish_staged_release(&staged, release_name).expect("publish child release");

        let result =
            switch_current_pointer_with_hook(&staged.root_fd, release_name, |observed_stage| {
                if observed_stage == target {
                    // Abrupt termination deliberately bypasses Rust destructors.
                    unsafe { libc::_exit(86) }
                }
                Ok(())
            });

        panic!("child unexpectedly completed pointer switch: {result:?}");
    }

    #[test]
    fn process_crashes_at_pointer_switch_boundaries_are_recoverable() {
        use std::process::Command;

        fn encode_hex(bytes: &[u8]) -> String {
            let mut output = String::with_capacity(bytes.len() * 2);
            for byte in bytes {
                use std::fmt::Write as _;
                write!(&mut output, "{byte:02x}").expect("write hex");
            }
            output
        }

        let stages = [
            ("create", false, false),
            ("write", false, true),
            ("sync-pointer", false, true),
            ("rename", false, true),
            ("sync-root", true, false),
        ];

        for (stage, new_release_is_current, expect_orphan_pointer) in stages {
            let root = temporary_path(&format!("process-pointer-crash-{stage}"));
            fs::create_dir(&root).expect("create installation root");

            let key_pair = aip_crypto::generate_ed25519_keypair();
            let custodian = InMemoryCustodian::new(&key_pair.private_key, &key_pair.public_key)
                .expect("create test installer identity");
            let trusted_key = custodian.public_key().to_vec();

            let first_stage =
                stage_verified_package(&root, &normal_package()).expect("stage initial package");
            let first =
                activate_staged_package_with_inventory(first_stage, "installer-test", &custodian)
                    .expect("activate initial release");

            let original_release = first.release_name().to_string();
            let original_inventory =
                audit_persistent_installation(&root, &trusted_key).expect("audit initial release");

            let output = Command::new(std::env::current_exe().expect("test executable path"))
                .arg("--exact")
                .arg("linux::tests::child_crashes_during_pointer_switch")
                .arg("--nocapture")
                .env("AIP_POINTER_CRASH_ROOT", &root)
                .env(
                    "AIP_POINTER_CRASH_PRIVATE",
                    encode_hex(&key_pair.private_key),
                )
                .env("AIP_POINTER_CRASH_PUBLIC", encode_hex(&key_pair.public_key))
                .env(
                    "AIP_POINTER_CRASH_INSTALLATION_ID",
                    encode_hex(&original_inventory.installation_id),
                )
                .env("AIP_POINTER_CRASH_STAGE", stage)
                .output()
                .expect("launch pointer-crash child");

            assert_eq!(
                output.status.code(),
                Some(86),
                "child should terminate at {stage}; stdout: {}; stderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );

            let report = inspect_installation_recovery(&root, &trusted_key)
                .expect("recovery scan after child termination");

            let expected_current = if new_release_is_current {
                "release-33333333333333333333333333333333"
            } else {
                original_release.as_str()
            };

            assert_eq!(
                report.current_release.as_deref(),
                Some(expected_current),
                "unexpected current release after crash at {stage}"
            );

            let old_kind = if new_release_is_current {
                RecoveryEntryKind::PublishedInactiveRelease
            } else {
                RecoveryEntryKind::ValidCurrentRelease
            };

            let new_kind = if new_release_is_current {
                RecoveryEntryKind::ValidCurrentRelease
            } else {
                RecoveryEntryKind::PublishedInactiveRelease
            };

            assert!(
                report
                    .entries
                    .iter()
                    .any(|entry| entry.name == original_release && entry.kind == old_kind),
                "original release has unexpected recovery classification after {stage}"
            );

            assert!(
                report.entries.iter().any(|entry| entry.name
                    == "release-33333333333333333333333333333333"
                    && entry.kind == new_kind),
                "new release has unexpected recovery classification after {stage}"
            );

            assert_eq!(
                report
                    .entries
                    .iter()
                    .any(|entry| entry.kind == RecoveryEntryKind::OrphanTemporaryPointer),
                expect_orphan_pointer,
                "unexpected temporary-pointer classification after {stage}"
            );

            fs::remove_dir_all(&root).expect("remove test installation root");
        }
    }

    #[test]
    fn recovery_scan_identifies_active_and_inactive_releases() {
        let root = temporary_path("recovery-active-inactive");
        fs::create_dir(&root).expect("create installation root");

        let custodian = InMemoryCustodian::generate();
        let trusted_key = custodian.public_key().to_vec();

        let first_stage =
            stage_verified_package(&root, &normal_package()).expect("stage first package");
        let first =
            activate_staged_package_with_inventory(first_stage, "installer-test", &custodian)
                .expect("activate first release");
        let first_name = first.release_name().to_string();
        let installation_id = audit_persistent_installation(&root, &trusted_key)
            .expect("audit first release")
            .installation_id;

        let second_stage =
            stage_verified_package(&root, &normal_package()).expect("stage second package");
        let second_name = format!("release-{}", random_hex_16());
        write_signed_inventory_to_stage(
            &second_stage,
            "installer-test",
            &custodian,
            installation_id,
            &second_name,
        )
        .expect("write second inventory");
        publish_staged_release(&second_stage, &second_name).expect("publish second release");
        drop(second_stage);

        let report =
            inspect_installation_recovery(&root, &trusted_key).expect("inspect recovery state");

        assert_eq!(report.current_release.as_deref(), Some(first_name.as_str()));
        assert!(report.entries.iter().any(|entry| {
            entry.name == first_name && entry.kind == RecoveryEntryKind::ValidCurrentRelease
        }));
        assert!(report.entries.iter().any(|entry| {
            entry.name == second_name && entry.kind == RecoveryEntryKind::PublishedInactiveRelease
        }));

        fs::remove_dir_all(&root).expect("remove test root");
    }

    #[test]
    fn recovery_scan_reports_orphan_staging_and_temporary_pointer_entries() {
        let root = temporary_path("recovery-orphans");
        fs::create_dir(&root).expect("create installation root");

        let custodian = InMemoryCustodian::generate();
        let trusted_key = custodian.public_key().to_vec();

        let staged = stage_verified_package(&root, &normal_package()).expect("stage package");
        activate_staged_package_with_inventory(staged, "installer-test", &custodian)
            .expect("activate package");

        let orphan_stage = ".aip-stage-00000000000000000000000000000001";
        let orphan_pointer = ".aip-current-00000000000000000000000000000002";
        fs::create_dir(root.join(orphan_stage)).expect("create orphan staging directory");
        fs::write(root.join(orphan_pointer), b"release-interrupted\n")
            .expect("create orphan temporary pointer");

        let report =
            inspect_installation_recovery(&root, &trusted_key).expect("inspect recovery state");

        assert!(report.entries.iter().any(|entry| {
            entry.name == orphan_stage && entry.kind == RecoveryEntryKind::IncompleteStaging
        }));
        assert!(report.entries.iter().any(|entry| {
            entry.name == orphan_pointer && entry.kind == RecoveryEntryKind::OrphanTemporaryPointer
        }));

        assert!(
            root.join(orphan_stage).is_dir(),
            "inspection must not delete staging"
        );
        assert!(
            root.join(orphan_pointer).is_file(),
            "inspection must not delete pointer"
        );

        fs::remove_dir_all(&root).expect("remove test root");
    }

    #[test]
    fn recovery_scan_rejects_symlinked_release_directory_without_following_it() {
        let root = temporary_path("recovery-symlink-release");
        let external = temporary_path("recovery-symlink-external");

        fs::create_dir(&root).expect("create installation root");
        fs::create_dir(&external).expect("create external directory");

        let custodian = InMemoryCustodian::generate();
        let trusted_key = custodian.public_key().to_vec();

        let staged =
            stage_verified_package(&root, &normal_package()).expect("stage legitimate package");
        let activated =
            activate_staged_package_with_inventory(staged, "installer-test", &custodian)
                .expect("activate legitimate release");

        let malicious_name = "release-44444444444444444444444444444444";
        let sentinel = external.join("outside-sentinel");
        fs::write(&sentinel, b"must remain untouched").expect("create external sentinel");

        symlink(&external, root.join(malicious_name))
            .expect("create symlink pretending to be a release");

        let report = inspect_installation_recovery(&root, &trusted_key)
            .expect("scan installation containing release symlink");

        assert_eq!(
            report.current_release.as_deref(),
            Some(activated.release_name()),
            "legitimate current release must remain active"
        );

        assert!(
            report.entries.iter().any(|entry| {
                entry.name == malicious_name
                    && entry.kind == RecoveryEntryKind::InvalidOrUnauthenticatedRelease
            }),
            "symlinked release directory must be rejected"
        );

        assert_eq!(
            fs::read(&sentinel).expect("read external sentinel"),
            b"must remain untouched",
            "scanner must not modify the external directory"
        );

        fs::remove_dir_all(&root).expect("remove test installation root");
        fs::remove_dir_all(&external).expect("remove external test directory");
    }

    #[test]
    fn recovery_scan_rejects_nested_directory_symlink_without_following_it() {
        let root = temporary_path("recovery-nested-symlink");
        let external = temporary_path("recovery-nested-external");

        fs::create_dir(&root).expect("create installation root");
        fs::create_dir(&external).expect("create external directory");

        let custodian = InMemoryCustodian::generate();
        let trusted_key = custodian.public_key().to_vec();

        let staged =
            stage_verified_package(&root, &normal_package()).expect("stage legitimate package");
        let activated =
            activate_staged_package_with_inventory(staged, "installer-test", &custodian)
                .expect("activate legitimate release");

        let sentinel = external.join("outside-sentinel");
        fs::write(&sentinel, b"must remain untouched").expect("create external sentinel");

        let release_path = root.join(activated.release_name());
        let config_path = release_path.join("config");

        fs::remove_dir_all(&config_path).expect("remove original nested directory");
        symlink(&external, &config_path).expect("replace nested directory with symlink");

        let report = inspect_installation_recovery(&root, &trusted_key)
            .expect("scan installation containing nested directory symlink");

        assert_eq!(
            report.current_release.as_deref(),
            Some(activated.release_name()),
            "authenticated current pointer should still be reported"
        );

        assert!(
            report.entries.iter().any(|entry| {
                entry.name == activated.release_name()
                    && entry.kind == RecoveryEntryKind::InvalidOrUnauthenticatedRelease
            }),
            "release with a nested directory symlink must be rejected"
        );

        assert_eq!(
            fs::read(&sentinel).expect("read external sentinel"),
            b"must remain untouched",
            "scanner must not follow or modify the external directory"
        );

        fs::remove_dir_all(&root).expect("remove installation root");
        fs::remove_dir_all(&external).expect("remove external directory");
    }

    #[test]
    fn recovery_scan_rejects_symlinked_release_inventory() {
        let root = temporary_path("recovery-symlink-inventory");
        let external = temporary_path("recovery-symlink-inventory-external");

        fs::create_dir(&root).expect("create installation root");
        fs::create_dir(&external).expect("create external directory");

        let custodian = InMemoryCustodian::generate();
        let trusted_key = custodian.public_key().to_vec();

        let first_stage =
            stage_verified_package(&root, &normal_package()).expect("stage initial package");
        let first =
            activate_staged_package_with_inventory(first_stage, "installer-test", &custodian)
                .expect("activate initial release");

        let installation_id = audit_persistent_installation(&root, &trusted_key)
            .expect("audit initial release")
            .installation_id;

        let second_stage =
            stage_verified_package(&root, &normal_package()).expect("stage second package");
        let second_name = format!("release-{}", random_hex_16());

        write_signed_inventory_to_stage(
            &second_stage,
            "installer-test",
            &custodian,
            installation_id,
            &second_name,
        )
        .expect("write second inventory");

        publish_staged_release(&second_stage, &second_name).expect("publish second release");
        drop(second_stage);

        let inventory_path = root.join(&second_name).join(".aip-inventory.json");
        let external_inventory = external.join("external-inventory.json");
        fs::write(
            &external_inventory,
            b"external inventory must not be trusted",
        )
        .expect("create external inventory");

        fs::remove_file(&inventory_path).expect("remove original inventory");
        symlink(&external_inventory, &inventory_path).expect("replace inventory with symlink");

        let report = inspect_installation_recovery(&root, &trusted_key)
            .expect("scan installation with symlinked inventory");

        assert_eq!(
            report.current_release.as_deref(),
            Some(first.release_name()),
            "original current release must remain active"
        );

        assert!(
            report.entries.iter().any(|entry| {
                entry.name == second_name
                    && entry.kind == RecoveryEntryKind::InvalidOrUnauthenticatedRelease
            }),
            "release with symlinked inventory must be rejected"
        );

        assert_eq!(
            fs::read(&external_inventory).expect("read external inventory"),
            b"external inventory must not be trusted",
            "scanner must not modify external inventory"
        );

        fs::remove_dir_all(&root).expect("remove installation root");
        fs::remove_dir_all(&external).expect("remove external directory");
    }

    #[test]
    fn descriptor_identity_checks_reject_replaced_directory_and_file() {
        let root = temporary_path("recovery-identity-replacement");
        fs::create_dir(&root).expect("create test root");

        let directory_name = c_name("staging-entry").expect("directory name");
        let original_directory = root.join("staging-entry");
        let displaced_directory = root.join("staging-entry-old");

        fs::create_dir(&original_directory).expect("create original directory");

        let root_fd = open_install_root(&root).expect("open test root");
        let original_directory_stat =
            stat_entry_at(&root_fd, &directory_name).expect("stat original directory");
        let original_directory_identity = identity_from_stat(&original_directory_stat);

        fs::rename(&original_directory, &displaced_directory).expect("displace original directory");
        fs::create_dir(&original_directory).expect("create replacement directory");

        let replacement_directory_fd =
            open_directory_at(&root_fd, &directory_name).expect("open replacement directory");

        assert!(
            !descriptor_matches_identity(&replacement_directory_fd, original_directory_identity)
                .expect("compare replacement directory identity"),
            "replacement directory must not match the original identity"
        );

        let file_name = c_name("temporary-pointer").expect("file name");
        let original_file = root.join("temporary-pointer");
        let displaced_file = root.join("temporary-pointer-old");

        fs::write(&original_file, b"original").expect("create original file");

        let original_file_stat = stat_entry_at(&root_fd, &file_name).expect("stat original file");
        let original_file_identity = identity_from_stat(&original_file_stat);

        fs::rename(&original_file, &displaced_file).expect("displace original file");
        fs::write(&original_file, b"replacement").expect("create replacement file");

        let replacement_file_fd =
            open_regular_file_at(&root_fd, &file_name).expect("open replacement file");

        assert!(
            !descriptor_matches_identity(&replacement_file_fd, original_file_identity)
                .expect("compare replacement file identity"),
            "replacement file must not match the original identity"
        );

        drop(replacement_directory_fd);
        drop(replacement_file_fd);
        drop(root_fd);

        fs::remove_dir_all(&root).expect("remove test root");
    }

    #[test]
    fn recovery_scan_rejects_release_replaced_between_stat_and_open() {
        use std::sync::mpsc;
        use std::thread;

        let root = temporary_path("recovery-concurrent-replacement");
        let external = temporary_path("recovery-concurrent-external");

        fs::create_dir(&root).expect("create installation root");
        fs::create_dir(&external).expect("create external directory");

        let custodian = InMemoryCustodian::generate();
        let trusted_key = custodian.public_key().to_vec();

        let staged =
            stage_verified_package(&root, &normal_package()).expect("stage legitimate package");
        let activated =
            activate_staged_package_with_inventory(staged, "installer-test", &custodian)
                .expect("activate legitimate release");

        let release_name = activated.release_name().to_string();
        let release_path = root.join(&release_name);
        let displaced_path = root.join(format!("{release_name}-displaced"));

        let sentinel = external.join("outside-sentinel");
        fs::write(&sentinel, b"must remain untouched").expect("create external sentinel");

        let (trigger_tx, trigger_rx) = mpsc::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel::<Result<(), String>>();

        let worker_root = root.clone();
        let worker_release_name = release_name.clone();
        let worker_displaced_path = displaced_path.clone();
        let worker_external = external.clone();

        let worker = thread::spawn(move || {
            trigger_rx
                .recv()
                .expect("wait for scanner identity observation");

            let original = worker_root.join(&worker_release_name);

            let result = fs::rename(&original, &worker_displaced_path)
                .and_then(|_| symlink(&worker_external, &original))
                .map_err(|error| error.to_string());

            done_tx.send(result).expect("send replacement result");
        });

        let report = inspect_installation_recovery_with_hook(&root, &trusted_key, |name| {
            if name == release_name {
                trigger_tx.send(()).expect("signal replacement worker");

                done_rx
                    .recv()
                    .expect("receive replacement result")
                    .expect("replace release with symlink");
            }
        })
        .expect("scan during synchronized release replacement");

        worker.join().expect("replacement worker must complete");

        assert_eq!(
            report.current_release.as_deref(),
            Some(release_name.as_str()),
            "current pointer observation should remain recorded"
        );

        assert!(
            report.entries.iter().any(|entry| {
                entry.name == release_name
                    && entry.kind == RecoveryEntryKind::InvalidOrUnauthenticatedRelease
            }),
            "replacement release symlink must be rejected"
        );

        assert_eq!(
            fs::read(&sentinel).expect("read external sentinel"),
            b"must remain untouched",
            "scanner must not follow or modify the external directory"
        );

        // Restore the original release before removing the test installation.
        fs::remove_file(&release_path).expect("remove replacement symlink");
        fs::rename(&displaced_path, &release_path).expect("restore original release");

        fs::remove_dir_all(&root).expect("remove installation root");
        fs::remove_dir_all(&external).expect("remove external directory");
    }

    #[test]
    fn recovery_scan_reports_current_pointer_replaced_during_scan() {
        use std::sync::mpsc;
        use std::thread;

        let root = temporary_path("recovery-current-pointer-replacement");
        fs::create_dir(&root).expect("create installation root");

        let custodian = InMemoryCustodian::generate();
        let trusted_key = custodian.public_key().to_vec();

        let first_staged =
            stage_verified_package(&root, &normal_package()).expect("stage first package");
        let first_activated =
            activate_staged_package_with_inventory(first_staged, "installer-test", &custodian)
                .expect("activate first package");
        let first_release = first_activated.release_name().to_string();

        let second_staged =
            stage_verified_package(&root, &normal_package()).expect("stage second package");
        let second_activated =
            activate_staged_package_with_inventory(second_staged, "installer-test", &custodian)
                .expect("activate second package");
        let second_release = second_activated.release_name().to_string();

        let root_fd = open_install_root(&root).expect("open installation root");
        switch_current_pointer(&root_fd, &first_release).expect("restore first current release");
        drop(root_fd);

        let (trigger_tx, trigger_rx) = mpsc::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel::<Result<(), String>>();

        let worker_root = root.clone();
        let worker_second_release = second_release.clone();

        let worker = thread::spawn(move || {
            trigger_rx
                .recv()
                .expect("wait for scanner release observation");

            let result = open_install_root(&worker_root)
                .map_err(|error| format!("{error:?}"))
                .and_then(|worker_root_fd| {
                    switch_current_pointer(&worker_root_fd, &worker_second_release)
                        .map_err(|error| format!("{error:?}"))
                });

            done_tx
                .send(result)
                .expect("send pointer replacement result");
        });

        let report = inspect_installation_recovery_with_hook(&root, &trusted_key, |name| {
            if name == first_release {
                trigger_tx
                    .send(())
                    .expect("signal pointer replacement worker");

                done_rx
                    .recv()
                    .expect("receive pointer replacement result")
                    .expect("atomically replace current pointer");
            }
        })
        .expect("scan during current-pointer replacement");

        worker
            .join()
            .expect("pointer replacement worker must complete");

        assert_eq!(
            report.current_release, None,
            "report must not claim a stable current release after pointer replacement"
        );

        assert!(
            report.entries.iter().any(|entry| {
                entry.name == "current"
                    && entry.kind == RecoveryEntryKind::CurrentPointerChangedDuringScan
            }),
            "report must explicitly identify the concurrent pointer replacement"
        );

        assert!(
            report.entries.iter().any(|entry| {
                entry.name == first_release
                    && entry.kind == RecoveryEntryKind::PublishedInactiveRelease
            }),
            "the initially current release must not remain classified as confirmed current"
        );

        assert!(
            report.entries.iter().any(|entry| {
                entry.name == second_release
                    && entry.kind == RecoveryEntryKind::PublishedInactiveRelease
            }),
            "the newly selected release must be reported as a published release"
        );

        let final_root_fd = open_install_root(&root).expect("reopen installation root");
        let (actual_current, _) =
            load_current_inventory(&final_root_fd, &trusted_key).expect("load final current");
        assert_eq!(
            actual_current, second_release,
            "atomic pointer switch must leave the second release active"
        );
        drop(final_root_fd);

        fs::remove_dir_all(&root).expect("remove test installation");
    }

    #[test]
    fn recovery_scan_rejects_real_directory_replaced_between_stat_and_open() {
        use std::sync::mpsc;
        use std::thread;

        let root = temporary_path("recovery-real-directory-replacement");
        fs::create_dir(&root).expect("create installation root");

        let custodian = InMemoryCustodian::generate();
        let trusted_key = custodian.public_key().to_vec();

        let staged =
            stage_verified_package(&root, &normal_package()).expect("stage legitimate package");
        let activated =
            activate_staged_package_with_inventory(staged, "installer-test", &custodian)
                .expect("activate legitimate release");

        let release_name = activated.release_name().to_string();
        let release_path = root.join(&release_name);
        let displaced_path = root.join(format!("{release_name}-displaced"));

        let (trigger_tx, trigger_rx) = mpsc::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel::<Result<(), String>>();

        let worker_root = root.clone();
        let worker_release_name = release_name.clone();
        let worker_displaced_path = displaced_path.clone();

        let worker = thread::spawn(move || {
            trigger_rx
                .recv()
                .expect("wait for scanner identity observation");

            let original = worker_root.join(&worker_release_name);

            let result = fs::rename(&original, &worker_displaced_path)
                .and_then(|_| fs::create_dir(&original))
                .and_then(|_| fs::write(original.join("replacement-marker"), b"replacement"))
                .map_err(|error| error.to_string());

            done_tx.send(result).expect("send replacement result");
        });

        let report = inspect_installation_recovery_with_hook(&root, &trusted_key, |name| {
            if name == release_name {
                trigger_tx.send(()).expect("signal replacement worker");

                done_rx
                    .recv()
                    .expect("receive replacement result")
                    .expect("replace release with a different real directory");
            }
        })
        .expect("scan during synchronized real-directory replacement");

        worker.join().expect("replacement worker must complete");

        assert_eq!(
            report.current_release.as_deref(),
            Some(release_name.as_str()),
            "current pointer observation should remain recorded"
        );

        assert!(
            report.entries.iter().any(|entry| {
                entry.name == release_name
                    && entry.kind == RecoveryEntryKind::InvalidOrUnauthenticatedRelease
            }),
            "replacement real directory must be rejected"
        );

        assert_eq!(
            fs::read(release_path.join("replacement-marker")).expect("read replacement marker"),
            b"replacement",
            "scanner must not modify the replacement directory"
        );

        // Restore the original release before removing the test installation.
        fs::remove_dir_all(&release_path).expect("remove replacement directory");
        fs::rename(&displaced_path, &release_path).expect("restore original release");

        fs::remove_dir_all(&root).expect("remove test installation");
    }

    #[test]
    fn recovery_scan_classifies_prefixed_entries_by_actual_file_type() {
        let root = temporary_path("recovery-entry-types");
        let external = temporary_path("recovery-entry-types-external");

        fs::create_dir(&root).expect("create installation root");
        fs::create_dir(&external).expect("create external directory");

        let custodian = InMemoryCustodian::generate();
        let trusted_key = custodian.public_key().to_vec();

        let staged =
            stage_verified_package(&root, &normal_package()).expect("stage legitimate package");
        let activated =
            activate_staged_package_with_inventory(staged, "installer-test", &custodian)
                .expect("activate legitimate package");

        let stage_file = ".aip-stage-11111111111111111111111111111111";
        let stage_symlink = ".aip-stage-22222222222222222222222222222222";
        let pointer_directory = ".aip-current-33333333333333333333333333333333";
        let pointer_symlink = ".aip-current-44444444444444444444444444444444";

        fs::write(root.join(stage_file), b"not a staging directory")
            .expect("create staging-prefixed regular file");
        symlink(&external, root.join(stage_symlink)).expect("create staging-prefixed symlink");

        fs::create_dir(root.join(pointer_directory)).expect("create pointer-prefixed directory");

        let external_file = external.join("external-pointer");
        fs::write(&external_file, b"external").expect("create external pointer target");
        symlink(&external_file, root.join(pointer_symlink))
            .expect("create pointer-prefixed symlink");

        let report = inspect_installation_recovery(&root, &trusted_key)
            .expect("inspect unexpected filesystem entry types");

        assert_eq!(
            report.current_release.as_deref(),
            Some(activated.release_name()),
            "legitimate current release must remain active"
        );

        for name in [
            stage_file,
            stage_symlink,
            pointer_directory,
            pointer_symlink,
        ] {
            assert!(
                report.entries.iter().any(|entry| {
                    entry.name == name && entry.kind == RecoveryEntryKind::UnexpectedFilesystemEntry
                }),
                "{name} must be classified as an unexpected filesystem entry"
            );
        }

        assert_eq!(
            fs::read(&external_file).expect("read external file"),
            b"external",
            "scanner must not modify external targets"
        );

        fs::remove_dir_all(&root).expect("remove installation root");
        fs::remove_dir_all(&external).expect("remove external directory");
    }

    #[test]
    fn recovery_scan_rejects_tampered_inactive_release() {
        let root = temporary_path("recovery-tampered-inactive");
        fs::create_dir(&root).expect("create installation root");

        let custodian = InMemoryCustodian::generate();
        let trusted_key = custodian.public_key().to_vec();

        let first_stage =
            stage_verified_package(&root, &normal_package()).expect("stage first package");
        let first =
            activate_staged_package_with_inventory(first_stage, "installer-test", &custodian)
                .expect("activate first release");

        let installation_id = audit_persistent_installation(&root, &trusted_key)
            .expect("audit first release")
            .installation_id;

        let second_stage =
            stage_verified_package(&root, &normal_package()).expect("stage second package");
        let second_name = format!("release-{}", random_hex_16());
        write_signed_inventory_to_stage(
            &second_stage,
            "installer-test",
            &custodian,
            installation_id,
            &second_name,
        )
        .expect("write second inventory");
        publish_staged_release(&second_stage, &second_name).expect("publish second release");
        drop(second_stage);

        fs::write(
            root.join(&second_name).join("bin/agent"),
            b"tampered after publication",
        )
        .expect("tamper with inactive release");

        let report =
            inspect_installation_recovery(&root, &trusted_key).expect("inspect recovery state");

        assert_eq!(
            report.current_release.as_deref(),
            Some(first.release_name()),
            "the original current release must remain selected"
        );
        assert!(report.entries.iter().any(|entry| {
            entry.name == second_name
                && entry.kind == RecoveryEntryKind::InvalidOrUnauthenticatedRelease
        }));

        fs::remove_dir_all(&root).expect("remove test root");
    }

    #[test]
    fn recovery_scan_reports_invalid_current_pointer_without_repair() {
        let root = temporary_path("recovery-invalid-current");
        fs::create_dir(&root).expect("create installation root");

        let custodian = InMemoryCustodian::generate();
        let trusted_key = custodian.public_key().to_vec();

        let staged = stage_verified_package(&root, &normal_package()).expect("stage package");
        activate_staged_package_with_inventory(staged, "installer-test", &custodian)
            .expect("activate package");

        fs::write(root.join("current"), b"not-a-valid-release\n").expect("corrupt current pointer");

        let report = inspect_installation_recovery(&root, &trusted_key)
            .expect("recovery scan should report invalid pointer");

        assert_eq!(report.current_release, None);
        assert!(report.entries.iter().any(|entry| {
            entry.name == "current" && entry.kind == RecoveryEntryKind::InvalidCurrentPointer
        }));
        assert_eq!(
            fs::read_to_string(root.join("current")).expect("read pointer"),
            "not-a-valid-release\n",
            "inspection must not repair the pointer"
        );

        fs::remove_dir_all(&root).expect("remove test root");
    }

    #[test]
    fn recovery_scan_reports_invalid_pointer_replaced_during_scan() {
        use std::sync::mpsc;
        use std::thread;

        let root = temporary_path("recovery-invalid-pointer-replacement");
        fs::create_dir(&root).expect("create installation root");

        let custodian = InMemoryCustodian::generate();
        let trusted_key = custodian.public_key().to_vec();

        let staged = stage_verified_package(&root, &normal_package()).expect("stage package");
        let activated =
            activate_staged_package_with_inventory(staged, "installer-test", &custodian)
                .expect("activate package");
        let release_name = activated.release_name().to_string();

        fs::write(root.join("current"), b"invalid-pointer\n")
            .expect("write invalid current pointer");

        let (trigger_tx, trigger_rx) = mpsc::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel::<Result<(), String>>();

        let worker_root = root.clone();
        let worker = thread::spawn(move || {
            trigger_rx.recv().expect("wait for scanner observation");

            let temporary = worker_root.join(".current-replacement");
            let result = fs::write(&temporary, b"another-invalid-pointer\n")
                .and_then(|_| fs::rename(&temporary, worker_root.join("current")))
                .map_err(|error| error.to_string());

            done_tx.send(result).expect("send replacement result");
        });

        let report = inspect_installation_recovery_with_hook(&root, &trusted_key, |name| {
            if name == release_name {
                trigger_tx.send(()).expect("signal replacement worker");
                done_rx
                    .recv()
                    .expect("receive replacement result")
                    .expect("replace invalid current pointer");
            }
        })
        .expect("scan during invalid pointer replacement");

        worker.join().expect("replacement worker must complete");

        assert_eq!(report.current_release, None);
        assert!(report.entries.iter().any(|entry| {
            entry.name == "current" && entry.kind == RecoveryEntryKind::InvalidCurrentPointer
        }));
        assert!(report.entries.iter().any(|entry| {
            entry.name == "current"
                && entry.kind == RecoveryEntryKind::CurrentPointerChangedDuringScan
        }));
        assert_eq!(
            fs::read_to_string(root.join("current")).expect("read replacement pointer"),
            "another-invalid-pointer\n",
            "scanner must not repair the replacement pointer"
        );

        fs::remove_dir_all(&root).expect("remove test installation");
    }

    #[test]
    fn recovery_scan_reports_missing_pointer_created_during_scan() {
        use std::sync::mpsc;
        use std::thread;

        let root = temporary_path("recovery-missing-pointer-created");
        fs::create_dir(&root).expect("create installation root");

        let custodian = InMemoryCustodian::generate();
        let trusted_key = custodian.public_key().to_vec();

        let staged = stage_verified_package(&root, &normal_package()).expect("stage package");
        let activated =
            activate_staged_package_with_inventory(staged, "installer-test", &custodian)
                .expect("activate package");
        let release_name = activated.release_name().to_string();

        fs::remove_file(root.join("current")).expect("remove current pointer");

        let (trigger_tx, trigger_rx) = mpsc::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel::<Result<(), String>>();

        let worker_root = root.clone();
        let worker_release_name = release_name.clone();

        let worker = thread::spawn(move || {
            trigger_rx.recv().expect("wait for scanner observation");

            let result = open_install_root(&worker_root)
                .map_err(|error| format!("{error:?}"))
                .and_then(|root_fd| {
                    switch_current_pointer(&root_fd, &worker_release_name)
                        .map_err(|error| format!("{error:?}"))
                });

            done_tx.send(result).expect("send pointer creation result");
        });

        let report = inspect_installation_recovery_with_hook(&root, &trusted_key, |name| {
            if name == release_name {
                trigger_tx.send(()).expect("signal pointer creation worker");
                done_rx
                    .recv()
                    .expect("receive pointer creation result")
                    .expect("create current pointer atomically");
            }
        })
        .expect("scan during missing pointer creation");

        worker
            .join()
            .expect("pointer creation worker must complete");

        assert_eq!(
            report.current_release, None,
            "report must not claim a stable current release"
        );
        assert!(report.entries.iter().any(|entry| {
            entry.name == "current" && entry.kind == RecoveryEntryKind::InvalidCurrentPointer
        }));
        assert!(report.entries.iter().any(|entry| {
            entry.name == "current"
                && entry.kind == RecoveryEntryKind::CurrentPointerChangedDuringScan
        }));

        let final_root_fd = open_install_root(&root).expect("reopen installation root");
        let (actual_current, _) =
            load_current_inventory(&final_root_fd, &trusted_key).expect("load created pointer");
        assert_eq!(
            actual_current, release_name,
            "concurrent pointer creation must remain intact"
        );
        drop(final_root_fd);

        fs::remove_dir_all(&root).expect("remove test installation");
    }

    #[test]
    fn recovery_scan_reports_new_current_after_uncertain_root_sync() {
        let root = temporary_path("recovery-uncertain-sync");
        fs::create_dir(&root).expect("create installation root");

        let custodian = InMemoryCustodian::generate();
        let trusted_key = custodian.public_key().to_vec();

        let first_stage =
            stage_verified_package(&root, &normal_package()).expect("stage first package");
        let first =
            activate_staged_package_with_inventory(first_stage, "installer-test", &custodian)
                .expect("activate first release");

        let installation_id = audit_persistent_installation(&root, &trusted_key)
            .expect("audit first release")
            .installation_id;

        let second_stage =
            stage_verified_package(&root, &normal_package()).expect("stage second package");
        let second_name = format!("release-{}", random_hex_16());
        write_signed_inventory_to_stage(
            &second_stage,
            "installer-test",
            &custodian,
            installation_id,
            &second_name,
        )
        .expect("write second inventory");
        publish_staged_release(&second_stage, &second_name).expect("publish second release");

        let root_fd = open_install_root(&root).expect("open installation root");
        let result = switch_current_pointer_with_hook(&root_fd, &second_name, |stage| {
            if stage == PointerSwitchStage::SyncInstallationRoot {
                Err(InstallError::InvalidField("injected_root_sync_fault"))
            } else {
                Ok(())
            }
        });

        assert!(
            result.is_err(),
            "injected root sync failure must be reported"
        );
        drop(root_fd);
        drop(second_stage);

        let report = inspect_installation_recovery(&root, &trusted_key)
            .expect("inspect state after uncertain sync");

        assert_eq!(
            report.current_release.as_deref(),
            Some(second_name.as_str())
        );
        assert!(report.entries.iter().any(|entry| {
            entry.name == second_name && entry.kind == RecoveryEntryKind::ValidCurrentRelease
        }));
        assert!(report.entries.iter().any(|entry| {
            entry.name == first.release_name()
                && entry.kind == RecoveryEntryKind::PublishedInactiveRelease
        }));

        fs::remove_dir_all(&root).expect("remove test root");
    }
}
