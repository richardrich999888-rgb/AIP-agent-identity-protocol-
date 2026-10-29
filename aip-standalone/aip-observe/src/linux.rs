//! Kernel-mediated evidence sources: `pidfd`, the netlink process-event
//! connector, and the kernel socket tables.
//!
//! The parsers are pure and compiled everywhere so they can be tested against
//! hostile input on any platform. The syscall wrappers are Linux-only and
//! return explicit errors elsewhere; nothing here ever substitutes a weaker
//! identifier for a fact it could not obtain.
//!
//! # What each source is and is not
//!
//! | Source | Kernel-generated? | Root-forgeable content? | Loss signal |
//! |---|---|---|---|
//! | `PidFd` | the *binding to an instance* is kernel state; facts read through it are still procfs | yes (procfs) | none needed — a pidfd cannot be re-pointed |
//! | `ProcConnector` | yes: fork/exec/exit pushed by the kernel with its own CPU and monotonic timestamp | a root attacker can *inject* netlink messages only by spoofing the kernel's netlink source, which the kernel forbids from user space; it can still stop, starve, or race the reader | **yes** — `ENOBUFS` on receive |
//! | socket tables | yes (kernel tables) but *polled* | yes (procfs presentation) | none (polling) |
//!
//! No eBPF program, no tracepoint, no perf ring buffer and no XDP hook is
//! opened here. Those remain NOT_IMPLEMENTED.

use crate::observed::{KernelLifecycleKind, SocketEndpoint, SocketProtocol};
use crate::probe::ProbeError;

/// Why a kernel source could not deliver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceError {
    /// The source cannot be opened here (missing privilege, wrong namespace,
    /// unsupported platform). Observation is unavailable, nothing more.
    Unavailable(String),
    /// The kernel told us events were lost (`ENOBUFS`). Everything received
    /// afterwards is still genuine; everything *between* is unknown.
    EventsLost,
    /// The kernel handed us bytes this crate does not understand. Recorded,
    /// never interpreted.
    Malformed(String),
}

impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for SourceError {}

// ─── Process-event connector: pure parser ───

/// A decoded `struct proc_event` from the netlink process-event connector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcEvent {
    pub kind: KernelLifecycleKind,
    pub cpu: u32,
    /// Kernel monotonic nanoseconds since boot (`timestamp_ns`).
    pub timestamp_ns: u64,
    /// The cgroup v2 id the kernel wrote into the sample, when the source
    /// samples it (`PERF_SAMPLE_CGROUP`, ADR-019 §4). `NotSampled` for every
    /// source that cannot carry one — the netlink connector included.
    pub cgroup: crate::observed::CgroupSample,
}

const NLMSG_HDR_LEN: usize = 16;
const CN_MSG_LEN: usize = 20;
const PROC_EVENT_HDR_LEN: usize = 16; // what(4) cpu(4) timestamp_ns(8)

const PROC_EVENT_FORK: u32 = 0x0000_0001;
const PROC_EVENT_EXEC: u32 = 0x0000_0002;
const PROC_EVENT_EXIT: u32 = 0x8000_0000;

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .map(|s| u32::from_ne_bytes([s[0], s[1], s[2], s[3]]))
}

fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    b.get(off..off + 8)
        .map(|s| u64::from_ne_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

/// Decode one connector datagram (`nlmsghdr ‖ cn_msg ‖ proc_event`).
///
/// Rejects short, truncated or self-inconsistent buffers with
/// [`SourceError::Malformed`]; never panics; never guesses a field.
pub fn parse_proc_event(datagram: &[u8]) -> Result<ProcEvent, SourceError> {
    let nl_len = u32_at(datagram, 0)
        .ok_or_else(|| SourceError::Malformed("short nlmsghdr".into()))? as usize;
    if nl_len < NLMSG_HDR_LEN + CN_MSG_LEN + PROC_EVENT_HDR_LEN || nl_len > datagram.len() {
        return Err(SourceError::Malformed(format!(
            "nlmsg_len {nl_len} inconsistent with {} bytes received",
            datagram.len()
        )));
    }
    let cn_data_len = datagram
        .get(NLMSG_HDR_LEN + 16..NLMSG_HDR_LEN + 18)
        .map(|s| u16::from_ne_bytes([s[0], s[1]]) as usize)
        .ok_or_else(|| SourceError::Malformed("short cn_msg".into()))?;
    let body = &datagram[NLMSG_HDR_LEN + CN_MSG_LEN..nl_len];
    if cn_data_len > body.len() || cn_data_len < PROC_EVENT_HDR_LEN {
        return Err(SourceError::Malformed(format!(
            "cn_msg.len {cn_data_len} inconsistent with {} body bytes",
            body.len()
        )));
    }
    let body = &body[..cn_data_len];
    let what = u32_at(body, 0).unwrap();
    let cpu = u32_at(body, 4).unwrap();
    let timestamp_ns = u64_at(body, 8).unwrap();
    let field = |i: usize| {
        u32_at(body, PROC_EVENT_HDR_LEN + 4 * i)
            .ok_or_else(|| SourceError::Malformed(format!("event {what:#x} missing field {i}")))
    };
    let kind = match what {
        PROC_EVENT_FORK => KernelLifecycleKind::Fork {
            parent_pid: field(0)?,
            parent_tgid: field(1)?,
            child_pid: field(2)?,
            child_tgid: field(3)?,
        },
        PROC_EVENT_EXEC => KernelLifecycleKind::Exec {
            pid: field(0)?,
            tgid: field(1)?,
        },
        PROC_EVENT_EXIT => KernelLifecycleKind::Exit {
            pid: field(0)?,
            tgid: field(1)?,
            exit_code: field(2)?,
            exit_signal: field(3)?,
        },
        other => KernelLifecycleKind::Other { what: other },
    };
    Ok(ProcEvent {
        cgroup: crate::observed::CgroupSample::NotSampled,
        kind,
        cpu,
        timestamp_ns,
    })
}

// ─── Socket tables: pure parser ───

/// One row of `/proc/net/{tcp,tcp6,udp,udp6}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketRecord {
    pub protocol: SocketProtocol,
    pub local: SocketEndpoint,
    pub remote: SocketEndpoint,
    pub state: u8,
    pub uid: u32,
    pub inode: u64,
}

fn parse_endpoint(s: &str, v6: bool) -> Option<SocketEndpoint> {
    let (addr_hex, port_hex) = s.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let mut addr = [0u8; 16];
    if v6 {
        if addr_hex.len() != 32 {
            return None;
        }
        // Four little-endian u32 words.
        for w in 0..4 {
            let word = u32::from_str_radix(&addr_hex[w * 8..w * 8 + 8], 16).ok()?;
            addr[w * 4..w * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
    } else {
        if addr_hex.len() != 8 {
            return None;
        }
        let word = u32::from_str_radix(addr_hex, 16).ok()?;
        addr[..4].copy_from_slice(&word.to_le_bytes());
    }
    Some(SocketEndpoint {
        addr,
        is_v6: v6,
        port,
    })
}

/// Parse a socket table. Malformed rows are skipped and counted, never
/// guessed at; the caller decides what a non-zero count means.
pub fn parse_proc_net_table(text: &str, protocol: SocketProtocol) -> (Vec<SocketRecord>, usize) {
    let v6 = matches!(protocol, SocketProtocol::Tcp6 | SocketProtocol::Udp6);
    let mut out = Vec::new();
    let mut malformed = 0usize;
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        let parsed = (|| {
            if f.len() < 10 {
                return None;
            }
            let local = parse_endpoint(f[1], v6)?;
            let remote = parse_endpoint(f[2], v6)?;
            let state = u8::from_str_radix(f[3], 16).ok()?;
            let uid = f[7].parse::<u32>().ok()?;
            let inode = f[9].parse::<u64>().ok()?;
            Some(SocketRecord {
                protocol,
                local,
                remote,
                state,
                uid,
                inode,
            })
        })();
        match parsed {
            Some(r) => out.push(r),
            None => {
                if !line.trim().is_empty() {
                    malformed += 1;
                }
            }
        }
    }
    (out, malformed)
}

/// Parse the target of a `/proc/<pid>/fd/N` symlink into a socket inode.
pub fn parse_socket_link(target: &str) -> Option<u64> {
    let inner = target.strip_prefix("socket:[")?.strip_suffix(']')?;
    inner.parse::<u64>().ok()
}

// ─── Linux syscalls ───

#[cfg(target_os = "linux")]
mod sys {
    use super::*;
    use std::os::fd::RawFd;

    /// A kernel handle bound to one process *instance*. Unlike a pid, a
    /// pidfd cannot come to refer to a different process: after the process
    /// exits the descriptor reports "exited" forever.
    #[derive(Debug)]
    pub struct PidFd {
        fd: RawFd,
        pid: u32,
    }

    impl PidFd {
        /// Take ownership of a pidfd another kernel interface created for
        /// `pid` (fanotify's `FAN_REPORT_PIDFD`). The kernel bound it to the
        /// process instance behind the event, not to the number.
        pub fn from_raw(fd: RawFd, pid: u32) -> PidFd {
            PidFd { fd, pid }
        }

        pub fn open(pid: u32) -> Result<PidFd, ProbeError> {
            // SAFETY: plain syscall with integer arguments; result checked.
            let r = unsafe {
                libc::syscall(libc::SYS_pidfd_open, pid as libc::c_long, 0 as libc::c_long)
            };
            if r < 0 {
                let err = std::io::Error::last_os_error();
                // ESRCH: no such process. EINVAL: the kernel refuses the pid
                // outright (zero, or beyond pid_max). Both mean "nothing to
                // bind to here"; neither is turned into a weaker measurement.
                return Err(match err.raw_os_error() {
                    Some(libc::ESRCH) | Some(libc::EINVAL) => ProbeError::ProcessNotVisible { pid },
                    _ => ProbeError::Unavailable {
                        field: "pidfd",
                        reason: err.to_string(),
                    },
                });
            }
            Ok(PidFd {
                fd: r as RawFd,
                pid,
            })
        }

        pub fn pid(&self) -> u32 {
            self.pid
        }

        /// Poll with the given timeout. `Ok(true)` when the process has
        /// exited (the pidfd became readable), `Ok(false)` while it lives.
        pub fn wait_exit(&self, timeout_ms: i32) -> Result<bool, ProbeError> {
            let mut pfd = libc::pollfd {
                fd: self.fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: pollfd is a valid, initialised struct; nfds == 1.
            let r = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
            if r < 0 {
                return Err(ProbeError::Unavailable {
                    field: "pidfd",
                    reason: std::io::Error::last_os_error().to_string(),
                });
            }
            Ok(r > 0 && (pfd.revents & libc::POLLIN) != 0)
        }

        /// Is the bound instance still alive right now?
        pub fn is_alive(&self) -> Result<bool, ProbeError> {
            self.wait_exit(0).map(|exited| !exited)
        }
    }

    impl Drop for PidFd {
        fn drop(&mut self) {
            // SAFETY: fd was returned by pidfd_open and is owned here.
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    const NETLINK_CONNECTOR: libc::c_int = 11;
    const CN_IDX_PROC: u32 = 1;
    const CN_VAL_PROC: u32 = 1;
    const PROC_CN_MCAST_LISTEN: u32 = 1;
    const NLMSG_DONE: u16 = 3;

    /// The process (thread group) a task belongs to, and the task's own
    /// start time, read from `/proc/<tid>`. `/proc/<tid>` resolves for a
    /// non-leader thread although it is not listed. `None` if the task is
    /// gone or the files cannot be parsed.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ThreadOwner {
        pub tgid: u32,
        pub thread_start_ticks: u64,
    }

    pub fn thread_owner(tid: u32) -> Option<ThreadOwner> {
        let status = std::fs::read_to_string(format!("/proc/{tid}/status")).ok()?;
        let tgid = status
            .lines()
            .find_map(|l| l.strip_prefix("Tgid:"))?
            .trim()
            .parse()
            .ok()?;
        let stat = std::fs::read_to_string(format!("/proc/{tid}/stat")).ok()?;
        let thread_start_ticks =
            aip_core::execution_binding::parse_proc_stat_start_time(&stat).ok()?;
        Some(ThreadOwner {
            tgid,
            thread_start_ticks,
        })
    }

    /// A subscription to the kernel's process-event multicast group.
    #[derive(Debug)]
    pub struct ProcConnector {
        fd: RawFd,
    }

    impl ProcConnector {
        /// Open and subscribe. Requires `CAP_NET_ADMIN` in the initial
        /// network namespace; anywhere else this is `Unavailable`, which is
        /// exactly what a verifier must then be told.
        pub fn open() -> Result<ProcConnector, SourceError> {
            // SAFETY: plain socket creation; result checked.
            let fd = unsafe {
                libc::socket(
                    libc::AF_NETLINK,
                    libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                    NETLINK_CONNECTOR,
                )
            };
            if fd < 0 {
                return Err(SourceError::Unavailable(format!(
                    "netlink connector socket: {}",
                    std::io::Error::last_os_error()
                )));
            }
            let me = ProcConnector { fd };
            // SAFETY: sockaddr_nl is plain data; zeroed then filled.
            let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
            addr.nl_pid = 0; // kernel assigns a unique port id
            addr.nl_groups = CN_IDX_PROC;
            // SAFETY: addr is valid for the given length.
            let r = unsafe {
                libc::bind(
                    fd,
                    &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                )
            };
            if r < 0 {
                return Err(SourceError::Unavailable(format!(
                    "netlink connector bind: {}",
                    std::io::Error::last_os_error()
                )));
            }
            // nlmsghdr ‖ cn_msg ‖ u32 op
            let mut msg = Vec::with_capacity(NLMSG_HDR_LEN + CN_MSG_LEN + 4);
            let total = (NLMSG_HDR_LEN + CN_MSG_LEN + 4) as u32;
            msg.extend_from_slice(&total.to_ne_bytes());
            msg.extend_from_slice(&NLMSG_DONE.to_ne_bytes());
            msg.extend_from_slice(&0u16.to_ne_bytes()); // flags
            msg.extend_from_slice(&0u32.to_ne_bytes()); // seq
            msg.extend_from_slice(&0u32.to_ne_bytes()); // pid
            msg.extend_from_slice(&CN_IDX_PROC.to_ne_bytes());
            msg.extend_from_slice(&CN_VAL_PROC.to_ne_bytes());
            msg.extend_from_slice(&0u32.to_ne_bytes()); // cn seq
            msg.extend_from_slice(&0u32.to_ne_bytes()); // cn ack
            msg.extend_from_slice(&4u16.to_ne_bytes()); // cn len
            msg.extend_from_slice(&0u16.to_ne_bytes()); // cn flags
            msg.extend_from_slice(&PROC_CN_MCAST_LISTEN.to_ne_bytes());
            // SAFETY: buffer valid for its length.
            let s = unsafe { libc::send(fd, msg.as_ptr() as *const libc::c_void, msg.len(), 0) };
            if s < 0 {
                return Err(SourceError::Unavailable(format!(
                    "netlink connector subscribe: {}",
                    std::io::Error::last_os_error()
                )));
            }
            Ok(me)
        }

        /// Shrink the kernel receive buffer. Used by tests to force the
        /// `ENOBUFS` loss path deterministically; a production probe would
        /// instead enlarge it.
        pub fn set_receive_buffer(&self, bytes: i32) -> Result<(), SourceError> {
            // SAFETY: optval points to an i32 of the stated length.
            let r = unsafe {
                libc::setsockopt(
                    self.fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    &bytes as *const i32 as *const libc::c_void,
                    std::mem::size_of::<i32>() as libc::socklen_t,
                )
            };
            if r < 0 {
                return Err(SourceError::Unavailable(
                    std::io::Error::last_os_error().to_string(),
                ));
            }
            Ok(())
        }

        /// Enlarge the kernel receive buffer to `bytes`. Tries
        /// `SO_RCVBUFFORCE` first (needs `CAP_NET_ADMIN`, which opening the
        /// connector already required, and is not clamped by
        /// `net.core.rmem_max`), then falls back to `SO_RCVBUF`, which the
        /// kernel clamps. Returns the effective size the kernel reports, so
        /// the caller can log what it actually got rather than what it asked
        /// for. A larger buffer does not hide loss: overflow is still
        /// `ENOBUFS` and still counted.
        pub fn enlarge_receive_buffer(&self, bytes: i32) -> Result<i32, SourceError> {
            for opt in [libc::SO_RCVBUFFORCE, libc::SO_RCVBUF] {
                // SAFETY: optval points to an i32 of the stated length.
                let r = unsafe {
                    libc::setsockopt(
                        self.fd,
                        libc::SOL_SOCKET,
                        opt,
                        &bytes as *const i32 as *const libc::c_void,
                        std::mem::size_of::<i32>() as libc::socklen_t,
                    )
                };
                if r == 0 {
                    return self.receive_buffer();
                }
            }
            Err(SourceError::Unavailable(
                std::io::Error::last_os_error().to_string(),
            ))
        }

        /// The kernel's current receive-buffer size for this socket (the
        /// doubled value `SO_RCVBUF` reports, including bookkeeping).
        pub fn receive_buffer(&self) -> Result<i32, SourceError> {
            let mut v: i32 = 0;
            let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
            // SAFETY: optval points to an i32 and len holds its size.
            let r = unsafe {
                libc::getsockopt(
                    self.fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    &mut v as *mut i32 as *mut libc::c_void,
                    &mut len,
                )
            };
            if r < 0 {
                return Err(SourceError::Unavailable(
                    std::io::Error::last_os_error().to_string(),
                ));
            }
            Ok(v)
        }

        /// Receive the next event, waiting at most `timeout_ms`.
        /// `Ok(None)` on timeout; `Err(EventsLost)` when the kernel reports
        /// the receive queue overflowed; `Err(Malformed)` for bytes this
        /// crate does not understand.
        pub fn next_event(&self, timeout_ms: i32) -> Result<Option<ProcEvent>, SourceError> {
            let mut pfd = libc::pollfd {
                fd: self.fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: valid pollfd, nfds == 1.
            let r = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
            if r < 0 {
                return Err(SourceError::Unavailable(
                    std::io::Error::last_os_error().to_string(),
                ));
            }
            if r == 0 {
                return Ok(None);
            }
            let mut buf = vec![0u8; 8192];
            // SAFETY: buffer valid for its length.
            let n = unsafe {
                libc::recv(
                    self.fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                return match err.raw_os_error() {
                    Some(libc::ENOBUFS) => Err(SourceError::EventsLost),
                    Some(libc::EAGAIN) => Ok(None),
                    _ => Err(SourceError::Unavailable(err.to_string())),
                };
            }
            buf.truncate(n as usize);
            parse_proc_event(&buf).map(Some)
        }
    }

    impl Drop for ProcConnector {
        fn drop(&mut self) {
            // SAFETY: fd owned here.
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    /// Read the four kernel socket tables.
    pub fn snapshot_socket_tables() -> Result<(Vec<SocketRecord>, usize), ProbeError> {
        let mut all = Vec::new();
        let mut malformed = 0usize;
        for (path, proto) in [
            ("/proc/net/tcp", SocketProtocol::Tcp),
            ("/proc/net/tcp6", SocketProtocol::Tcp6),
            ("/proc/net/udp", SocketProtocol::Udp),
            ("/proc/net/udp6", SocketProtocol::Udp6),
        ] {
            match std::fs::read_to_string(path) {
                Ok(text) => {
                    let (rows, bad) = parse_proc_net_table(&text, proto);
                    all.extend(rows);
                    malformed += bad;
                }
                // A missing v6 table is a configuration fact, not a fault.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(ProbeError::Unavailable {
                        field: "socket_table",
                        reason: format!("{path}: {e}"),
                    })
                }
            }
        }
        Ok((all, malformed))
    }

    /// Socket inodes held open by `pid`, from `/proc/<pid>/fd`.
    pub fn socket_inodes_of(pid: u32) -> Result<Vec<u64>, ProbeError> {
        let dir = std::fs::read_dir(format!("/proc/{pid}/fd"))
            .map_err(|_| ProbeError::ProcessNotVisible { pid })?;
        let mut inodes = Vec::new();
        for entry in dir.flatten() {
            if let Ok(target) = std::fs::read_link(entry.path()) {
                if let Some(ino) = parse_socket_link(&target.to_string_lossy()) {
                    inodes.push(ino);
                }
            }
        }
        Ok(inodes)
    }
}

#[cfg(target_os = "linux")]
pub use sys::{
    snapshot_socket_tables, socket_inodes_of, thread_owner, PidFd, ProcConnector, ThreadOwner,
};

#[cfg(test)]
mod tests {
    use super::*;

    fn datagram(what: u32, fields: &[u32]) -> Vec<u8> {
        let payload_len = PROC_EVENT_HDR_LEN + 4 * fields.len();
        let total = NLMSG_HDR_LEN + CN_MSG_LEN + payload_len;
        let mut d = Vec::new();
        d.extend_from_slice(&(total as u32).to_ne_bytes());
        d.extend_from_slice(&3u16.to_ne_bytes());
        d.extend_from_slice(&0u16.to_ne_bytes());
        d.extend_from_slice(&0u32.to_ne_bytes());
        d.extend_from_slice(&0u32.to_ne_bytes());
        d.extend_from_slice(&1u32.to_ne_bytes()); // idx
        d.extend_from_slice(&1u32.to_ne_bytes()); // val
        d.extend_from_slice(&0u32.to_ne_bytes());
        d.extend_from_slice(&0u32.to_ne_bytes());
        d.extend_from_slice(&(payload_len as u16).to_ne_bytes());
        d.extend_from_slice(&0u16.to_ne_bytes());
        d.extend_from_slice(&what.to_ne_bytes());
        d.extend_from_slice(&3u32.to_ne_bytes()); // cpu
        d.extend_from_slice(&123_456_789u64.to_ne_bytes());
        for f in fields {
            d.extend_from_slice(&f.to_ne_bytes());
        }
        d
    }

    #[test]
    fn parses_fork_exec_exit_and_unknown() {
        let e = parse_proc_event(&datagram(PROC_EVENT_EXEC, &[42, 42])).unwrap();
        assert_eq!(e.kind, KernelLifecycleKind::Exec { pid: 42, tgid: 42 });
        assert_eq!(e.cpu, 3);
        assert_eq!(e.timestamp_ns, 123_456_789);

        let e = parse_proc_event(&datagram(PROC_EVENT_EXIT, &[42, 42, 256, 0])).unwrap();
        assert_eq!(
            e.kind,
            KernelLifecycleKind::Exit {
                pid: 42,
                tgid: 42,
                exit_code: 256,
                exit_signal: 0
            }
        );
        let e = parse_proc_event(&datagram(PROC_EVENT_FORK, &[1, 1, 2, 2])).unwrap();
        assert!(matches!(
            e.kind,
            KernelLifecycleKind::Fork { child_pid: 2, .. }
        ));
        let e = parse_proc_event(&datagram(0x200, &[5, 5, 0, 0])).unwrap();
        assert_eq!(e.kind, KernelLifecycleKind::Other { what: 0x200 });
    }

    #[test]
    fn malformed_datagrams_are_rejected_without_panicking() {
        let good = datagram(PROC_EVENT_EXEC, &[42, 42]);
        let cases: Vec<Vec<u8>> = vec![
            vec![],
            vec![0u8; 3],
            vec![0u8; NLMSG_HDR_LEN],
            good[..good.len() - 1].to_vec(), // truncated
            good[..NLMSG_HDR_LEN + CN_MSG_LEN + 8].to_vec(), // header claims more than present
            {
                let mut d = good.clone();
                d[0..4].copy_from_slice(&(u32::MAX).to_ne_bytes()); // absurd nlmsg_len
                d
            },
            {
                let mut d = good.clone();
                d[NLMSG_HDR_LEN + 16..NLMSG_HDR_LEN + 18].copy_from_slice(&0u16.to_ne_bytes()); // cn len 0
                d
            },
            datagram(PROC_EVENT_EXIT, &[42]), // exit with missing fields
            vec![0xffu8; 200],
        ];
        for c in cases {
            let r = std::panic::catch_unwind(|| parse_proc_event(&c));
            assert!(r.is_ok(), "panicked on {} bytes", c.len());
            assert!(
                r.unwrap().is_err(),
                "accepted malformed datagram of {} bytes",
                c.len()
            );
        }
    }

    #[test]
    fn socket_table_parser_handles_v4_v6_and_garbage() {
        let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                   0: 0100007F:871D 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2085 2 00000000e1eab290 100 0 0 10 0\n\
                   garbage line here\n\
                   1: ZZZZZZZZ:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 55 1 x 100 0 0 10 0\n";
        let (rows, bad) = parse_proc_net_table(tcp, SocketProtocol::Tcp);
        assert_eq!(rows.len(), 1);
        assert_eq!(bad, 2);
        let r = &rows[0];
        assert_eq!(&r.local.addr[..4], &[127, 0, 0, 1]);
        assert_eq!(r.local.port, 0x871d);
        assert_eq!(r.state, 0x0a);
        assert_eq!(r.inode, 2085);
        assert!(!r.local.is_v6);

        let tcp6 = "hdr\n   0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 77 1 x 100 0 0 10 0\n";
        let (rows, bad) = parse_proc_net_table(tcp6, SocketProtocol::Tcp6);
        assert_eq!(bad, 0);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].local.is_v6);
        assert_eq!(rows[0].local.port, 8080);
        assert_eq!(rows[0].local.addr[15], 1, "::1");

        assert_eq!(parse_socket_link("socket:[12345]"), Some(12345));
        assert_eq!(parse_socket_link("pipe:[12345]"), None);
        assert_eq!(parse_socket_link("socket:[x]"), None);
        assert_eq!(parse_socket_link("socket:[12345"), None);
        assert_eq!(parse_socket_link(""), None);
    }
}
