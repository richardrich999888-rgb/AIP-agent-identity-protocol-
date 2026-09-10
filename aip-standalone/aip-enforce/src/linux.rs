//! seccomp user-notify supervision on Linux.
//!
//! The workload is forked with `no_new_privs` and a classic-BPF seccomp
//! filter that returns `SECCOMP_RET_USER_NOTIF` for `execve` and `execveat`
//! and `SECCOMP_RET_ALLOW` for everything else. The listener fd is pulled
//! into the supervisor with `pidfd_getfd`, and every notified `execve` is
//! decided by [`crate::decide`] against the admitted epoch.
//!
//! No eBPF, no BPF-LSM, no kprobes: none of the three is available on the
//! validation kernel, and none is needed for this.
//!
//! # TOCTOU, stated
//!
//! The supervisor reads the target's `pathname` out of `/proc/<pid>/mem`,
//! then re-checks the notification id with `SECCOMP_IOCTL_NOTIF_ID_VALID`.
//! That guards against the *notification* going stale. It does not guard
//! against the target racing the file behind the path between the
//! supervisor's hash and the kernel's own open when the syscall is allowed
//! to `CONTINUE`. The residual is narrowed, not closed, by hashing through
//! `/proc/<pid>/root` (the target's own mount view) and by refusing
//! relative paths and fd-relative `execveat`. Closing it fully needs the
//! allowed programs on a read-only mount, which is a deployment obligation
//! this module states rather than pretends to meet. A decision that cannot
//! be made safely is a **deny**.

use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::FileExt;
use std::time::{SystemTime, UNIX_EPOCH};

use aip_crypto::sha256;
use aip_types::ProcessInstance;

use crate::cache::{EpochCache, EpochStatus};
use crate::decision::{
    decide, Decision, DegradedReason, EnforcerHealth, ProgramIdentity, SyscallRequest,
    UnhashableReason,
};
use crate::record::{
    EnforcementDecision, RequestKind, SignedEnforcementDecision, ENFORCEMENT_DECISION_VERSION,
};

// classic BPF opcodes — the six this filter uses.
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

// `struct seccomp_data` layout: `nr` at 0, `arch` at 4.
const SECCOMP_DATA_NR: u32 = 0;
const SECCOMP_DATA_ARCH: u32 = 4;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7;

/// Longest pathname the supervisor will read out of the target.
const PATH_MAX: usize = 4096;

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// The filter. Kills the process on a foreign architecture (the syscall
/// numbers would mean something else), notifies on the two exec syscalls,
/// allows the rest.
fn exec_notify_filter() -> [libc::sock_filter; 8] {
    [
        stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH),
        jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH, 1, 0),
        stmt(BPF_RET | BPF_K, libc::SECCOMP_RET_KILL_PROCESS),
        stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR),
        jump(BPF_JMP | BPF_JEQ | BPF_K, libc::SYS_execve as u32, 2, 0),
        jump(BPF_JMP | BPF_JEQ | BPF_K, libc::SYS_execveat as u32, 1, 0),
        stmt(BPF_RET | BPF_K, libc::SECCOMP_RET_ALLOW),
        stmt(BPF_RET | BPF_K, libc::SECCOMP_RET_USER_NOTIF),
    ]
}

/// A child running under the filter, and the listener that decides for it.
pub struct SupervisedChild {
    pid: libc::pid_t,
    listener: OwnedFd,
}

impl SupervisedChild {
    pub fn pid(&self) -> libc::pid_t {
        self.pid
    }

    /// Close the listener without ever serving it, then wait. The kernel
    /// fails every notified syscall in the child with `ENOSYS`: a supervisor
    /// that vanishes is fail-closed by the kernel, not by this crate. The
    /// live test pins that.
    pub fn close_listener_and_wait(self) -> io::Result<i32> {
        let pid = self.pid;
        drop(self.listener);
        wait_exit(pid)
    }
}

fn wait_exit(pid: libc::pid_t) -> io::Result<i32> {
    let mut status: libc::c_int = 0;
    // SAFETY: waitpid on a pid this process forked.
    let r = unsafe { libc::waitpid(pid, &mut status, 0) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(status)
}

/// Fork and exec `program` under the exec-notify filter.
///
/// `argv` must include `argv[0]`. Everything the child touches after `fork`
/// is async-signal-safe; the argument vector and the filter are built
/// before the fork for exactly that reason.
///
/// # The handshake, and why it exists
///
/// The listener fd is created in the child. If the child still holds it
/// when it blocks in `execve`, then closing the supervisor's copy releases
/// nothing — the child is holding open the very file that gates its own
/// syscall, and it waits forever. So the child hands the fd number to the
/// parent, **waits for the parent to say it has duplicated it**, closes its
/// own copy, and only then execs. After that the supervisor holds the only
/// reference, and dropping it makes the kernel fail the child's pending
/// syscalls with `ENOSYS`.
pub fn spawn_supervised(program: &CStr, argv: &[&CStr]) -> io::Result<SupervisedChild> {
    let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let mut filter = exec_notify_filter();
    let fprog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };

    // to_parent: child → parent, the listener fd number.
    // to_child:  parent → child, one byte meaning "I hold a copy; drop yours".
    let mut to_parent = [0 as libc::c_int; 2];
    let mut to_child = [0 as libc::c_int; 2];
    // SAFETY: valid two-element arrays.
    if unsafe { libc::pipe2(to_parent.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::pipe2(to_child.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: fork; the child path below calls only async-signal-safe
    // functions and then execs or exits.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        unsafe {
            libc::close(to_parent[0]);
            libc::close(to_child[1]);
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                libc::_exit(120);
            }
            let fd = libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER as libc::c_long,
                libc::SECCOMP_FILTER_FLAG_NEW_LISTENER as libc::c_long,
                &fprog as *const libc::sock_fprog,
            );
            if fd < 0 {
                libc::_exit(121);
            }
            let fd32 = fd as i32;
            let bytes = fd32.to_ne_bytes();
            if libc::write(to_parent[1], bytes.as_ptr() as *const libc::c_void, 4) != 4 {
                libc::_exit(122);
            }
            libc::close(to_parent[1]);
            // Wait for the parent to confirm it duplicated the listener. If
            // the pipe closes without a byte, the parent failed: exit rather
            // than run unsupervised.
            let mut ack = 0u8;
            if libc::read(to_child[0], &mut ack as *mut u8 as *mut libc::c_void, 1) != 1 {
                libc::_exit(123);
            }
            libc::close(to_child[0]);
            libc::close(fd32);
            libc::execv(program.as_ptr(), argv_ptrs.as_ptr());
            // exec refused (EPERM from the supervisor, ENOSYS if it is gone).
            libc::_exit(127);
        }
    }

    // parent
    // SAFETY: fds from the pipe2 calls above.
    unsafe {
        libc::close(to_parent[1]);
        libc::close(to_child[0]);
    }
    let fail = |pid: libc::pid_t, to_child_w: libc::c_int, err: io::Error| -> io::Error {
        // Closing the ack pipe without writing makes the child _exit(123).
        // SAFETY: fd from pipe2.
        unsafe { libc::close(to_child_w) };
        let _ = wait_exit(pid);
        err
    };

    let mut buf = [0u8; 4];
    // SAFETY: reading 4 bytes into a 4-byte buffer.
    let n = unsafe { libc::read(to_parent[0], buf.as_mut_ptr() as *mut libc::c_void, 4) };
    // SAFETY: fd from pipe2.
    unsafe { libc::close(to_parent[0]) };
    if n != 4 {
        return Err(fail(
            pid,
            to_child[1],
            io::Error::other("child did not install the seccomp filter"),
        ));
    }
    let child_fd = i32::from_ne_bytes(buf);

    // SAFETY: pidfd_open on our own child; pidfd_getfd duplicates the
    // listener into this process.
    let pidfd =
        unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::c_long, 0 as libc::c_long) };
    if pidfd < 0 {
        return Err(fail(pid, to_child[1], io::Error::last_os_error()));
    }
    let listener = unsafe {
        libc::syscall(
            libc::SYS_pidfd_getfd,
            pidfd,
            child_fd as libc::c_long,
            0 as libc::c_long,
        )
    };
    let getfd_err = io::Error::last_os_error();
    // SAFETY: fd from pidfd_open.
    unsafe { libc::close(pidfd as libc::c_int) };
    if listener < 0 {
        return Err(fail(pid, to_child[1], getfd_err));
    }
    // SAFETY: a fresh fd we own.
    let listener = unsafe { OwnedFd::from_raw_fd(listener as libc::c_int) };

    // Ack: the child may now drop its copy and exec.
    let ack = [1u8];
    // SAFETY: writing one byte from a one-byte buffer.
    let w = unsafe { libc::write(to_child[1], ack.as_ptr() as *const libc::c_void, 1) };
    // SAFETY: fd from pipe2.
    unsafe { libc::close(to_child[1]) };
    if w != 1 {
        let _ = wait_exit(pid);
        return Err(io::Error::other("child went away before the handshake"));
    }
    Ok(SupervisedChild { pid, listener })
}

/// What serving produced.
#[derive(Debug)]
pub struct Outcome {
    /// Raw `waitpid` status; decode with `libc::WEXITSTATUS`.
    pub wait_status: i32,
    pub records: Vec<SignedEnforcementDecision>,
    pub health: EnforcerHealth,
}

/// Decides for one supervised child until it exits.
pub struct Supervisor {
    enforcer_id: String,
    enforcer_private_key: Vec<u8>,
    cache: EpochCache,
    health: EnforcerHealth,
    boot_id: Option<[u8; 16]>,
    records: Vec<SignedEnforcementDecision>,
}

impl Supervisor {
    pub fn new(enforcer_id: &str, enforcer_private_key: &[u8], cache: EpochCache) -> Self {
        Self {
            enforcer_id: enforcer_id.to_string(),
            enforcer_private_key: enforcer_private_key.to_vec(),
            cache,
            health: EnforcerHealth::Nominal,
            boot_id: read_boot_id(),
            records: Vec::new(),
        }
    }

    pub fn cache_mut(&mut self) -> &mut EpochCache {
        &mut self.cache
    }

    /// Serve notifications until the child exits, then reap it.
    pub fn serve_until_exit(mut self, child: SupervisedChild) -> io::Result<Outcome> {
        let fd = child.listener.as_raw_fd();
        let pid = child.pid;
        let mut reaped: Option<i32> = None;
        loop {
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one valid pollfd.
            let r = unsafe { libc::poll(&mut pfd, 1, 20) };
            if r < 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                self.health = EnforcerHealth::Degraded(DegradedReason::ListenerLost);
                break;
            }
            if pfd.revents & libc::POLLIN != 0 {
                match self.serve_one(fd) {
                    Ok(()) => continue,
                    // ENOENT: the notification was already gone, or no task
                    // holds the filter any more. Fall through to the exit
                    // check rather than spinning on a readable-but-empty fd.
                    Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
                    Err(_) => {
                        self.health = EnforcerHealth::Degraded(DegradedReason::ListenerLost);
                        break;
                    }
                }
            }
            let mut status: libc::c_int = 0;
            // SAFETY: non-blocking wait on our child.
            let w = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if w == pid {
                reaped = Some(status);
                break;
            }
            if pfd.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                break;
            }
        }
        drop(child.listener);
        let wait_status = match reaped {
            Some(s) => s,
            None => wait_exit(pid)?,
        };
        Ok(Outcome {
            wait_status,
            records: self.records,
            health: self.health,
        })
    }

    fn serve_one(&mut self, fd: libc::c_int) -> io::Result<()> {
        // SAFETY: the kernel requires a zeroed struct of the right size.
        let mut notif: libc::seccomp_notif = unsafe { zeroed() };
        // SAFETY: ioctl with a pointer to a correctly sized, zeroed struct.
        if unsafe {
            libc::ioctl(
                fd,
                libc::SECCOMP_IOCTL_NOTIF_RECV as _,
                &mut notif as *mut _,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        let target_pid = notif.pid as libc::pid_t;
        let nr = notif.data.nr as libc::c_long;

        let (program, program_hash) = if nr == libc::SYS_execve {
            self.identify(target_pid, notif.data.args[0], notif.id, fd)
        } else if nr == libc::SYS_execveat {
            let dirfd = notif.data.args[0] as libc::c_int;
            let flags = notif.data.args[4] as libc::c_int;
            if dirfd != libc::AT_FDCWD || flags & libc::AT_EMPTY_PATH != 0 {
                (
                    ProgramIdentity::Unhashable(UnhashableReason::ExecveatUnsupported),
                    None,
                )
            } else {
                self.identify(target_pid, notif.data.args[1], notif.id, fd)
            }
        } else {
            // The filter only notifies on exec; anything else here is a
            // filter that is not the one this module installed.
            (
                ProgramIdentity::Unhashable(UnhashableReason::ExecveatUnsupported),
                None,
            )
        };

        let now_ms = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_millis() as u64,
            Err(_) => {
                self.health = EnforcerHealth::Degraded(DegradedReason::ClockUnavailable);
                0
            }
        };
        let request = SyscallRequest::Exec { program };
        let decision = decide(self.health, &self.cache, &request, now_ms);

        // SAFETY: zeroed response struct, then populated.
        let mut resp: libc::seccomp_notif_resp = unsafe { zeroed() };
        resp.id = notif.id;
        match decision {
            Decision::Allow => {
                resp.error = 0;
                resp.val = 0;
                resp.flags = libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32;
            }
            Decision::Deny(_) => {
                resp.error = -libc::EPERM;
                resp.val = 0;
                resp.flags = 0;
            }
        }
        // SAFETY: ioctl with a pointer to a correctly sized struct.
        if unsafe { libc::ioctl(fd, libc::SECCOMP_IOCTL_NOTIF_SEND as _, &resp as *const _) } < 0 {
            let e = io::Error::last_os_error();
            // The target died before we answered; nothing to decide for.
            if e.raw_os_error() != Some(libc::ENOENT) {
                return Err(e);
            }
        }

        let epoch_id = match self.cache.status(now_ms) {
            EpochStatus::Active(v) => Some(v.epoch().epoch_id),
            _ => None,
        };
        let record = EnforcementDecision {
            version: ENFORCEMENT_DECISION_VERSION,
            enforcer_id: self.enforcer_id.clone(),
            agent_id: self.cache.agent_id().to_string(),
            epoch_id,
            process: self.process_instance(target_pid),
            request: RequestKind::Exec,
            program_hash,
            decision,
            decided_at_ms: now_ms,
        };
        let signed = SignedEnforcementDecision::sign(record, &self.enforcer_private_key)
            .map_err(|_| io::Error::other("enforcer key cannot sign"))?;
        self.records.push(signed);
        Ok(())
    }

    /// Read the pathname from the target, confirm the notification is still
    /// live, and hash the file through the target's own root.
    fn identify(
        &self,
        pid: libc::pid_t,
        path_ptr: u64,
        notif_id: u64,
        fd: libc::c_int,
    ) -> (ProgramIdentity, Option<[u8; 32]>) {
        let path = match read_target_cstring(pid, path_ptr) {
            Ok(p) => p,
            Err(r) => return (ProgramIdentity::Unhashable(r), None),
        };
        // The pointer we just dereferenced belonged to a notification that
        // must still be pending, or the memory was someone else's.
        let mut id = notif_id;
        // SAFETY: ioctl with a pointer to a u64.
        if unsafe {
            libc::ioctl(
                fd,
                libc::SECCOMP_IOCTL_NOTIF_ID_VALID as _,
                &mut id as *mut u64,
            )
        } < 0
        {
            return (
                ProgramIdentity::Unhashable(UnhashableReason::TargetMemoryUnreadable),
                None,
            );
        }
        if !path.starts_with('/') {
            return (
                ProgramIdentity::Unhashable(UnhashableReason::RelativePath),
                None,
            );
        }
        match std::fs::read(format!("/proc/{pid}/root{path}")) {
            Ok(bytes) => {
                let h = sha256(&bytes);
                (ProgramIdentity::ContentHash(h), Some(h))
            }
            Err(_) => (
                ProgramIdentity::Unhashable(UnhashableReason::ReadFailed),
                None,
            ),
        }
    }

    fn process_instance(&self, pid: libc::pid_t) -> Option<ProcessInstance> {
        let boot_id = self.boot_id?;
        let pid_start_time_ticks = read_start_ticks(pid)?;
        Some(ProcessInstance {
            pid: pid as u32,
            pid_start_time_ticks,
            boot_id,
        })
    }
}

fn read_target_cstring(pid: libc::pid_t, addr: u64) -> Result<String, UnhashableReason> {
    let mem = File::open(format!("/proc/{pid}/mem"))
        .map_err(|_| UnhashableReason::TargetMemoryUnreadable)?;
    let mut out = Vec::with_capacity(256);
    let mut chunk = [0u8; 256];
    let mut off = addr;
    while out.len() < PATH_MAX {
        let n = mem
            .read_at(&mut chunk, off)
            .map_err(|_| UnhashableReason::TargetMemoryUnreadable)?;
        if n == 0 {
            return Err(UnhashableReason::TargetMemoryUnreadable);
        }
        if let Some(nul) = chunk[..n].iter().position(|&b| b == 0) {
            out.extend_from_slice(&chunk[..nul]);
            return String::from_utf8(out).map_err(|_| UnhashableReason::PathMalformed);
        }
        out.extend_from_slice(&chunk[..n]);
        off += n as u64;
    }
    Err(UnhashableReason::PathMalformed)
}

/// Field 22 of `/proc/<pid>/stat` — the process start time in clock ticks —
/// parsed after the last `)` so an executable name containing spaces or
/// parentheses cannot shift the fields.
fn read_start_ticks(pid: libc::pid_t) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = &stat[stat.rfind(')')? + 1..];
    // after ')' the next token is field 3 (state); starttime is field 22.
    after.split_whitespace().nth(22 - 3)?.parse().ok()
}

fn read_boot_id() -> Option<[u8; 16]> {
    let s = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let hex: String = s.trim().chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Decode a `waitpid` status into an exit code, if the process exited.
pub fn exit_code(wait_status: i32) -> Option<i32> {
    if libc::WIFEXITED(wait_status) {
        Some(libc::WEXITSTATUS(wait_status))
    } else {
        None
    }
}

#[allow(dead_code)]
const _: () = assert!(size_of::<libc::seccomp_notif>() > 0);
