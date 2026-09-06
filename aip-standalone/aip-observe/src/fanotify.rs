//! Filesystem observation: `fanotify` in notification class with
//! `FAN_REPORT_PIDFD`, marked on a mount.
//!
//! **What this is.** For every file closed after being opened for writing
//! (`FAN_CLOSE_WRITE`; `FAN_MODIFY` for each write) on the marked mount, the
//! kernel queues an event carrying an open descriptor to the object and a
//! pidfd it created from the event's own `struct pid` when the event is
//! read — a binding to the process *instance* that acted, made by the
//! kernel, not by a pid number. If that process has already exited the
//! kernel reports `FAN_NOPIDFD` and the event is unbound. Queue overflow is
//! reported by the kernel as a `FAN_Q_OVERFLOW` record and counted as loss.
//! No eBPF, no syscall tracing.
//!
//! **What the probe keeps.** The kernel's current path of the object
//! (`readlink /proc/self/fd/<fd>`, with the ` (deleted)` suffix turned into
//! a flag), its device and inode (`fstat`), the event mask and the pid. The
//! descriptor is closed at once; nothing is read from the file.
//!
//! **What it proves.** That a process — bound through the kernel's pidfd —
//! completed a write to the object the kernel resolved to this path, on a
//! marked mount. It says nothing about the content written. The path is
//! resolved in the probe's mount namespace at read time; a rename between
//! the write and the read shows the new name, an unlink shows `deleted`.
//!
//! **What it cannot do here.** File-handle reporting (`FAN_REPORT_FID`,
//! which would identify the object independently of any path) is refused
//! with `ENODEV` on this host because the root filesystem reports a zero
//! fsid; it is not used and not claimed. Events carry no kernel timestamp:
//! the probe stamps them at read time, an upper bound on when they happened.
//!
//! **Privilege.** `CAP_SYS_ADMIN`. Without it [`FanotifyWatch::open`]
//! returns `Unavailable` and nothing is simulated.

use crate::linux::SourceError;

pub const FAN_MODIFY: u64 = 0x02;
pub const FAN_CLOSE_WRITE: u64 = 0x08;
pub const FAN_Q_OVERFLOW: u64 = 0x4000;

const FANOTIFY_METADATA_VERSION: u8 = 3;
const METADATA_LEN: usize = 24;
const INFO_HDR_LEN: usize = 4;
const FAN_EVENT_INFO_TYPE_PIDFD: u8 = 4;
const FAN_NOFD: i32 = -1;

/// One event as the kernel wrote it, before any descriptor is resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFileEvent {
    pub mask: u64,
    /// Open descriptor to the object, or `FAN_NOFD`.
    pub fd: i32,
    pub pid: u32,
    /// The kernel-created pidfd for the acting process, when it still
    /// existed at read time (`FAN_NOPIDFD` / `FAN_EPIDFD` → `None`).
    pub pidfd: Option<i32>,
}

fn u32_ne(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .map(|s| u32::from_ne_bytes([s[0], s[1], s[2], s[3]]))
}

fn malformed(what: &str) -> SourceError {
    SourceError::Malformed(format!("fanotify: {what}"))
}

/// Decode a buffer read from a fanotify descriptor into its events and the
/// number of `FAN_Q_OVERFLOW` records it carried. Pure; a truncated or
/// self-inconsistent buffer is refused whole — nothing in it is guessed at.
pub fn parse_fanotify_buffer(buf: &[u8]) -> Result<(Vec<RawFileEvent>, u64), SourceError> {
    let mut events = Vec::new();
    let mut overflow = 0u64;
    let mut off = 0usize;
    while off < buf.len() {
        let rest = &buf[off..];
        if rest.len() < METADATA_LEN {
            return Err(malformed("truncated metadata"));
        }
        let event_len = u32_ne(rest, 0).unwrap() as usize;
        let vers = rest[4];
        let metadata_len = u16::from_ne_bytes([rest[6], rest[7]]) as usize;
        if vers != FANOTIFY_METADATA_VERSION {
            return Err(malformed(&format!("metadata version {vers}")));
        }
        if event_len < METADATA_LEN || metadata_len < METADATA_LEN || metadata_len > event_len {
            return Err(malformed("inconsistent lengths"));
        }
        if event_len > rest.len() {
            return Err(malformed("event longer than buffer"));
        }
        let mask = u64::from_ne_bytes(rest[8..16].try_into().unwrap());
        let fd = i32::from_ne_bytes(rest[16..20].try_into().unwrap());
        let pid = i32::from_ne_bytes(rest[20..24].try_into().unwrap());
        let mut pidfd: Option<i32> = None;
        let mut ioff = metadata_len;
        while ioff < event_len {
            let info = &rest[ioff..event_len];
            if info.len() < INFO_HDR_LEN {
                return Err(malformed("truncated info header"));
            }
            let info_type = info[0];
            let info_len = u16::from_ne_bytes([info[2], info[3]]) as usize;
            if info_len < INFO_HDR_LEN || info_len > info.len() {
                return Err(malformed("inconsistent info length"));
            }
            if info_type == FAN_EVENT_INFO_TYPE_PIDFD {
                if info_len < 8 {
                    return Err(malformed("short pidfd info"));
                }
                let v = i32::from_ne_bytes(info[4..8].try_into().unwrap());
                pidfd = if v >= 0 { Some(v) } else { None };
            }
            ioff += info_len;
        }
        if mask & FAN_Q_OVERFLOW != 0 {
            overflow += 1;
        } else {
            events.push(RawFileEvent {
                mask,
                fd,
                pid: u32::try_from(pid).unwrap_or(0),
                pidfd,
            });
        }
        off += event_len;
    }
    let _ = FAN_NOFD;
    Ok((events, overflow))
}

#[cfg(target_os = "linux")]
mod sys {
    use super::*;
    use crate::linux::{PidFd, ProcEvent};
    use crate::observed::KernelLifecycleKind;
    use std::os::fd::RawFd;
    use std::os::unix::fs::MetadataExt;

    const FAN_CLASS_NOTIF: libc::c_uint = 0x0;
    const FAN_CLOEXEC: libc::c_uint = 0x1;
    const FAN_NONBLOCK: libc::c_uint = 0x2;
    const FAN_REPORT_PIDFD: libc::c_uint = 0x80;
    const FAN_MARK_ADD: libc::c_uint = 0x1;
    const FAN_MARK_MOUNT: libc::c_uint = 0x10;

    /// One event with its descriptor resolved and its kernel pidfd owned.
    pub struct FileObservation {
        pub event: ProcEvent,
        pub pidfd: Option<PidFd>,
    }

    /// The mount watch: one fanotify descriptor, one mount mark.
    pub struct FanotifyWatch {
        fd: RawFd,
        lost: u64,
        pending: std::collections::VecDeque<FileObservation>,
        buf: Vec<u8>,
    }

    impl std::fmt::Debug for FanotifyWatch {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("FanotifyWatch")
                .field("lost", &self.lost)
                .finish()
        }
    }

    impl Drop for FanotifyWatch {
        fn drop(&mut self) {
            // SAFETY: the fd was opened by this struct.
            unsafe { libc::close(self.fd) };
        }
    }

    impl FanotifyWatch {
        /// Watch the mount that holds `path` for `mask` (e.g.
        /// `FAN_CLOSE_WRITE`). `Unavailable` without `CAP_SYS_ADMIN` or when
        /// the mark is refused; nothing is simulated.
        pub fn open(path: &str, mask: u64) -> Result<FanotifyWatch, SourceError> {
            // SAFETY: plain syscall with integer arguments.
            let fd = unsafe {
                libc::fanotify_init(
                    FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK | FAN_REPORT_PIDFD,
                    (libc::O_RDONLY | libc::O_CLOEXEC) as libc::c_uint,
                )
            };
            if fd < 0 {
                let err = std::io::Error::last_os_error();
                return Err(SourceError::Unavailable(format!(
                    "fanotify_init: {err} (CAP_SYS_ADMIN required)"
                )));
            }
            let watch = FanotifyWatch {
                fd,
                lost: 0,
                pending: std::collections::VecDeque::new(),
                buf: vec![0u8; 64 * 1024],
            };
            let c = std::ffi::CString::new(path)
                .map_err(|_| SourceError::Unavailable("mount path has NUL".into()))?;
            // SAFETY: valid fd, valid NUL-terminated path.
            let rc = unsafe {
                libc::fanotify_mark(
                    fd,
                    FAN_MARK_ADD | FAN_MARK_MOUNT,
                    mask,
                    libc::AT_FDCWD,
                    c.as_ptr(),
                )
            };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                return Err(SourceError::Unavailable(format!(
                    "fanotify_mark({path}): {err}"
                )));
            }
            Ok(watch)
        }

        /// Overflow records the kernel reported since the last call, plus
        /// buffers this reader could not decode.
        pub fn take_lost(&mut self) -> u64 {
            std::mem::take(&mut self.lost)
        }

        /// Next completed event, waiting up to `timeout_ms`; `Ok(None)` on
        /// timeout.
        pub fn next_event(
            &mut self,
            timeout_ms: i32,
        ) -> Result<Option<FileObservation>, SourceError> {
            if let Some(o) = self.pending.pop_front() {
                return Ok(Some(o));
            }
            let mut pfd = libc::pollfd {
                fd: self.fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one valid pollfd.
            let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    return Ok(None);
                }
                return Err(SourceError::Unavailable(format!("poll: {err}")));
            }
            if rc == 0 {
                return Ok(None);
            }
            // SAFETY: the buffer is owned and correctly sized.
            let n = unsafe {
                libc::read(
                    self.fd,
                    self.buf.as_mut_ptr() as *mut libc::c_void,
                    self.buf.len(),
                )
            };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::Interrupted
                {
                    return Ok(None);
                }
                return Err(SourceError::Unavailable(format!("read: {err}")));
            }
            let (events, overflow) = match parse_fanotify_buffer(&self.buf[..n as usize]) {
                Ok(v) => v,
                Err(_) => {
                    self.lost += 1;
                    return Ok(None);
                }
            };
            self.lost += overflow;
            for e in events {
                let obs = Self::resolve(e);
                self.pending.push_back(obs);
            }
            Ok(self.pending.pop_front())
        }

        /// Resolve the object descriptor to the kernel's path and identity,
        /// close it, and take ownership of the pidfd.
        fn resolve(e: RawFileEvent) -> FileObservation {
            let mut ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            // SAFETY: valid timespec.
            unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
            let read_ns = ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64;
            let (mut path, mut deleted, mut dev, mut ino) = (String::new(), false, 0u64, 0u64);
            if e.fd >= 0 {
                if let Ok(p) = std::fs::read_link(format!("/proc/self/fd/{}", e.fd)) {
                    let s = p.to_string_lossy().into_owned();
                    if let Some(stripped) = s.strip_suffix(" (deleted)") {
                        path = stripped.to_string();
                        deleted = true;
                    } else {
                        path = s;
                    }
                }
                if let Ok(m) = std::fs::metadata(format!("/proc/self/fd/{}", e.fd)) {
                    dev = m.dev();
                    ino = m.ino();
                }
                // SAFETY: the descriptor was handed to us by the kernel and
                // is ours to close.
                unsafe { libc::close(e.fd) };
            }
            FileObservation {
                event: ProcEvent {
                    kind: KernelLifecycleKind::FileEvent {
                        mask: e.mask,
                        pid: e.pid,
                        path,
                        deleted,
                        dev,
                        ino,
                    },
                    cpu: 0,
                    timestamp_ns: read_ns,
                },
                pidfd: e.pidfd.map(|fd| PidFd::from_raw(fd, e.pid)),
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub use sys::{FanotifyWatch, FileObservation};
