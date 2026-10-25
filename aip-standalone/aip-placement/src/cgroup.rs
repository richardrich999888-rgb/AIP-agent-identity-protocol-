//! Creating and removing one decision cgroup.
//!
//! A [`PlacementRoot`] is a directory in the cgroup v2 hierarchy owned by
//! the supervisor; every decision cgroup is a direct child named by
//! [`crate::name::decision_cgroup_name`]. Creation uses `mkdir`, which the
//! kernel makes exclusive: a second placement for the same decision fails
//! with `EEXIST`, so "one cgroup per decision" is the kernel's guarantee, not
//! a check this crate could get wrong.

use crate::name::decision_cgroup_name;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Why a placement could not be made or removed.
#[derive(Debug)]
pub enum PlacementError {
    /// No cgroup v2 hierarchy is mounted: structural attribution is not
    /// available on this host (ADR-019 §2).
    NoCgroup2,
    /// A cgroup for this decision already exists. Never reused.
    AlreadyPlaced(PathBuf),
    /// The cgroup still holds tasks and cannot be removed.
    StillPopulated(PathBuf),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl std::fmt::Display for PlacementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoCgroup2 => write!(f, "no cgroup v2 hierarchy is mounted"),
            Self::AlreadyPlaced(p) => write!(
                f,
                "{} already exists; a decision is placed once",
                p.display()
            ),
            Self::StillPopulated(p) => write!(f, "{} still holds tasks", p.display()),
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
        }
    }
}

impl std::error::Error for PlacementError {}

fn io(path: &Path, source: std::io::Error) -> PlacementError {
    PlacementError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// The supervisor-owned directory decision cgroups are created under.
#[derive(Debug, Clone)]
pub struct PlacementRoot {
    dir: PathBuf,
}

impl PlacementRoot {
    /// Use `dir`, which must already exist inside a cgroup v2 hierarchy.
    pub fn at(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Create `<cgroup2 mount>/<name>` if absent and use it.
    pub fn ensure(name: &str) -> Result<Self, PlacementError> {
        let mount = crate::mount::find_cgroup2_mount()
            .map_err(|e| io(Path::new("/proc/self/mountinfo"), e))?
            .ok_or(PlacementError::NoCgroup2)?;
        let dir = Path::new(&mount).join(name);
        match std::fs::create_dir(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(io(&dir, e)),
        }
        Ok(Self { dir })
    }

    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// Create the cgroup for `decision_id`. Fails if it already exists.
    pub fn place(&self, decision_id: &[u8; 16]) -> Result<DecisionCgroup, PlacementError> {
        let path = self.dir.join(decision_cgroup_name(decision_id));
        match std::fs::create_dir(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(PlacementError::AlreadyPlaced(path))
            }
            Err(e) => return Err(io(&path, e)),
        }
        DecisionCgroup::open(path, *decision_id)
    }
}

/// One decision's cgroup: its path, the kernel's id for it, and an open
/// directory descriptor for `clone3(CLONE_INTO_CGROUP)`.
#[derive(Debug)]
pub struct DecisionCgroup {
    path: PathBuf,
    decision_id: [u8; 16],
    id: u64,
    dir: OwnedFd,
}

impl DecisionCgroup {
    fn open(path: PathBuf, decision_id: [u8; 16]) -> Result<Self, PlacementError> {
        let c = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| {
            io(
                &path,
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "path holds a NUL"),
            )
        })?;
        // SAFETY: `c` is a valid NUL-terminated path; flags request a
        // directory descriptor only.
        let fd = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io(&path, std::io::Error::last_os_error()));
        }
        // SAFETY: `fd` was just returned by open and is owned by nothing else.
        let dir = unsafe { OwnedFd::from_raw_fd(fd) };
        // The cgroup id the kernel writes into perf samples and tracepoints
        // is the cgroup's kernfs node id, which cgroup2 exposes as the
        // directory's inode number. The live tests establish this equality
        // on the running kernel rather than assume it.
        let id = std::fs::metadata(&path).map_err(|e| io(&path, e))?.ino();
        Ok(Self {
            path,
            decision_id,
            id,
            dir,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn decision_id(&self) -> &[u8; 16] {
        &self.decision_id
    }

    /// The kernel's id for this cgroup (its cgroup2 inode number).
    pub fn id(&self) -> u64 {
        self.id
    }

    pub(crate) fn dir_fd(&self) -> i32 {
        self.dir.as_raw_fd()
    }

    /// Remove the cgroup. The kernel refuses while it holds tasks; that is
    /// reported, never forced — evicting running work is containment, not
    /// placement.
    pub fn remove(self) -> Result<(), PlacementError> {
        match std::fs::remove_dir(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::EBUSY) => {
                Err(PlacementError::StillPopulated(self.path.clone()))
            }
            Err(e) => Err(io(&self.path, e)),
        }
    }
}
