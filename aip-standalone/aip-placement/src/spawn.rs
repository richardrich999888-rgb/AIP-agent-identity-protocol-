//! Starting a program inside a decision cgroup with
//! `clone3(CLONE_INTO_CGROUP | CLONE_PIDFD)` (Linux ≥ 5.7).
//!
//! The child is created *in* the cgroup: there is no instant at which it
//! runs outside it and no migration (`cgroup.procs` write) to observe. The
//! kernel also returns a pidfd, so the supervisor refers to the child by
//! process instance, never by a pid number that could be reused.
//!
//! Between `clone3` and `execve` the child runs only `execve` and `_exit` —
//! both async-signal-safe — on pointers prepared before the call, because
//! the parent may be multi-threaded and the child inherits only the calling
//! thread.

use crate::cgroup::DecisionCgroup;
use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// `CLONE_PIDFD` (`linux/sched.h`).
const CLONE_PIDFD: u64 = 0x0000_1000;
/// `CLONE_INTO_CGROUP` (`linux/sched.h`, 5.7).
const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;
/// `P_PIDFD` for `waitid` (`linux/wait.h`, 5.4).
const P_PIDFD: libc::idtype_t = 3;
/// Exit status the child reports if `execve` itself fails.
pub const EXEC_FAILED_STATUS: i32 = 127;

/// `struct clone_args`, `CLONE_ARGS_SIZE_VER2` (88 bytes), every field
/// explicit.
#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

/// Why a program could not be started.
#[derive(Debug)]
pub enum SpawnError {
    /// An argument or environment entry holds a NUL byte.
    InteriorNul,
    /// `clone3` failed; `ENOSYS`/`E2BIG`/`EINVAL` on a kernel without
    /// `CLONE_INTO_CGROUP` means the property is unavailable here.
    Clone(std::io::Error),
}

impl std::fmt::Display for SpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InteriorNul => write!(f, "argument or environment holds a NUL byte"),
            Self::Clone(e) => write!(f, "clone3(CLONE_INTO_CGROUP): {e}"),
        }
    }
}

impl std::error::Error for SpawnError {}

/// A started child: its pid (for matching kernel events) and the pidfd that
/// names its instance.
#[derive(Debug)]
pub struct Child {
    pid: i32,
    pidfd: OwnedFd,
}

impl Child {
    pub fn pid(&self) -> i32 {
        self.pid
    }

    /// Wait for the child to exit; its exit status, or `128 + signal` if a
    /// signal ended it.
    pub fn wait(self) -> std::io::Result<i32> {
        // SAFETY: zeroed siginfo is a valid out-parameter for waitid.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        loop {
            // SAFETY: waitid on a pidfd we own, writing into `info`.
            let rc = unsafe {
                libc::waitid(
                    P_PIDFD,
                    self.pidfd.as_raw_fd() as libc::id_t,
                    &mut info,
                    libc::WEXITED,
                )
            };
            if rc == 0 {
                break;
            }
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
        // SAFETY: waitid filled a CLD_* record.
        let status = unsafe { info.si_status() };
        Ok(if info.si_code == libc::CLD_EXITED {
            status
        } else {
            128 + status
        })
    }
}

/// Start `program` with `argv` (including `argv[0]`) and exactly `env` —
/// nothing inherited implicitly — inside `cgroup`.
pub fn spawn_into(
    cgroup: &DecisionCgroup,
    program: &CStr,
    argv: &[&str],
    env: &[&str],
) -> Result<Child, SpawnError> {
    let owned = |v: &[&str]| -> Result<Vec<CString>, SpawnError> {
        v.iter()
            .map(|s| CString::new(*s).map_err(|_| SpawnError::InteriorNul))
            .collect()
    };
    let argv = owned(argv)?;
    let env = owned(env)?;
    let mut argv_p: Vec<*const libc::c_char> = argv.iter().map(|c| c.as_ptr()).collect();
    argv_p.push(std::ptr::null());
    let mut env_p: Vec<*const libc::c_char> = env.iter().map(|c| c.as_ptr()).collect();
    env_p.push(std::ptr::null());

    let mut pidfd: i32 = -1;
    let args = CloneArgs {
        flags: CLONE_PIDFD | CLONE_INTO_CGROUP,
        pidfd: &mut pidfd as *mut i32 as u64,
        exit_signal: libc::SIGCHLD as u64,
        cgroup: cgroup.dir_fd() as u64,
        ..Default::default()
    };
    // SAFETY: `args` is a fully initialised clone_args of the declared size.
    // In the child (return 0) only execve and _exit run, on pointers built
    // above, which stay valid because the child has a copy of this memory.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &args as *const CloneArgs,
            std::mem::size_of::<CloneArgs>(),
        )
    };
    if rc == 0 {
        // SAFETY: async-signal-safe calls only; see module docs.
        unsafe {
            libc::execve(program.as_ptr(), argv_p.as_ptr(), env_p.as_ptr());
            libc::_exit(EXEC_FAILED_STATUS);
        }
    }
    if rc < 0 {
        return Err(SpawnError::Clone(std::io::Error::last_os_error()));
    }
    // SAFETY: the kernel wrote a new pidfd owned by this process.
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
    Ok(Child {
        pid: rc as i32,
        pidfd,
    })
}
