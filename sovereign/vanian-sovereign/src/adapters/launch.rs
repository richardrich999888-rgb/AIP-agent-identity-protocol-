//! Runner-private exec acknowledgement. This is not an independent observer.
//!
//! The trusted `vanian` helper runs as namespace init. It observes a positive
//! PTRACE_EVENT_EXEC for its own child, detaches before user code runs, and
//! reports that child's terminal wait status on an inherited private socket.
//! EOF, diagnostic text and launcher exit codes are never exec acknowledgements.
use std::io::{self, Read, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;

use crate::agent::evidence::ExitOutcome;

pub const HELPER_COMMAND: &str = "__sandbox_launch";
const MAGIC: &[u8; 8] = b"AIPLEX01";
const FRAME_LEN: usize = 13;
pub const SETUP_BUDGET_MS: u64 = 10_000;

pub fn read_result(stream: &mut UnixStream) -> io::Result<ExitOutcome> {
    let mut frame = Vec::new();
    stream
        .take((FRAME_LEN + 1) as u64)
        .read_to_end(&mut frame)?;
    if frame.len() != FRAME_LEN || &frame[..8] != MAGIC {
        return Err(io::Error::other(
            "missing or malformed exec acknowledgement",
        ));
    }
    let value = i32::from_le_bytes(frame[9..13].try_into().expect("length checked"));
    match (frame[8], value) {
        (0, 0..=255) => Ok(ExitOutcome::Code(value)),
        (1, 1..=64) => Ok(ExitOutcome::Signal(value)),
        _ => Err(io::Error::other("invalid tool wait status")),
    }
}

fn write_result(stream: &mut UnixStream, exit: ExitOutcome) -> io::Result<()> {
    let (kind, value) = match exit {
        ExitOutcome::Code(c) => (0, c),
        ExitOutcome::Signal(s) => (1, s),
    };
    let mut frame = Vec::from(MAGIC.as_slice());
    frame.push(kind);
    frame.extend_from_slice(&value.to_le_bytes());
    stream.write_all(&frame)
}

/// Only the single-threaded CLI dispatch invokes this. Never call it from a
/// multithreaded library host: the Linux implementation forks before exec.
pub fn helper(args: &[String]) -> io::Result<()> {
    if args.len() < 3 {
        return Err(io::Error::other("invalid internal launch arguments"));
    }
    let fd: RawFd = args[0].parse().map_err(io::Error::other)?;
    let timeout: u64 = args[1].parse().map_err(io::Error::other)?;
    if fd < 3 || timeout == 0 || timeout > crate::agent::tool::MAX_TIMEOUT_MS {
        return Err(io::Error::other(
            "invalid internal launch channel or deadline",
        ));
    }
    // Validate the descriptor before assuming ownership. It is a private
    // inherited socket, not a pathname the tool can open or stdout it controls.
    let mut socket_type: libc::c_int = 0;
    let mut size = std::mem::size_of_val(&socket_type) as libc::socklen_t;
    // SAFETY: writable typed output pointers, fd is checked by the kernel.
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut socket_type as *mut libc::c_int).cast(),
            &mut size,
        )
    } != 0
        || socket_type != libc::SOCK_STREAM
    {
        return Err(io::Error::other("launch channel is not a stream socket"));
    }
    // SAFETY: this process owns the validated inherited descriptor.
    let mut stream = unsafe { UnixStream::from_raw_fd(fd) };
    // The tool must not inherit the reporting endpoint after exec.
    // SAFETY: fcntl operates on our live descriptor.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
        return Err(io::Error::last_os_error());
    }
    let exit = execute(&args[2..], timeout)?;
    write_result(&mut stream, exit)
}

#[cfg(not(target_os = "linux"))]
fn execute(_: &[String], _: u64) -> io::Result<ExitOutcome> {
    Err(io::Error::other("exec acknowledgement requires Linux"))
}

#[cfg(target_os = "linux")]
fn execute(argv: &[String], timeout_ms: u64) -> io::Result<ExitOutcome> {
    use std::ffi::CString;
    let strings: Vec<CString> = argv
        .iter()
        .map(|s| CString::new(s.as_bytes()))
        .collect::<Result<_, _>>()
        .map_err(io::Error::other)?;
    let mut pointers: Vec<*const libc::c_char> = strings.iter().map(|s| s.as_ptr()).collect();
    pointers.push(std::ptr::null());
    // SAFETY: CLI helper is single threaded. All allocation/argument work is
    // complete; child calls only async-signal-safe syscalls and then exec/_exit.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        // SAFETY: child path owns no Rust cleanup; never return into Rust.
        unsafe {
            if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) == -1 {
                libc::_exit(125);
            }
            libc::raise(libc::SIGSTOP);
            libc::execv(pointers[0], pointers.as_ptr());
            libc::_exit(126);
        }
    }
    finish_child(pid, timeout_ms)
}

#[cfg(target_os = "linux")]
fn finish_child(pid: libc::pid_t, timeout_ms: u64) -> io::Result<ExitOutcome> {
    use std::time::{Duration, Instant};
    let mut child = Tracee { pid, reaped: false };
    let setup_deadline = Instant::now() + Duration::from_millis(SETUP_BUDGET_MS);
    let initial = child.wait_until(setup_deadline)?;
    if !libc::WIFSTOPPED(initial) || libc::WSTOPSIG(initial) != libc::SIGSTOP {
        return Err(io::Error::other(format!("tracee failed before launch setup (wait status {initial}; exit 125 means PTRACE_TRACEME unavailable)")));
    }
    trace(
        libc::PTRACE_SETOPTIONS,
        pid,
        (libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_EXITKILL) as usize,
    )?;
    trace(libc::PTRACE_CONT, pid, 0)?;
    let event = child.wait_until(setup_deadline)?;
    if !libc::WIFSTOPPED(event)
        || libc::WSTOPSIG(event) != libc::SIGTRAP
        || event >> 16 != libc::PTRACE_EVENT_EXEC
    {
        return Err(io::Error::other(
            "no successful kernel exec event for the tool",
        ));
    }
    // Do not trace application execution. Its normal signal and ptrace behavior
    // resumes after this positive exec event. Same-admin trust limits remain.
    trace(libc::PTRACE_DETACH, pid, 0)?;
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let status = match child.wait_until(deadline) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::TimedOut => {
            // SAFETY: unreaped direct child retains this pid, so no PID reuse.
            if unsafe { libc::kill(pid, libc::SIGKILL) } == -1 {
                return Err(io::Error::last_os_error());
            }
            child.wait_until(Instant::now() + Duration::from_millis(SETUP_BUDGET_MS))?
        }
        Err(e) => return Err(e),
    };
    if libc::WIFEXITED(status) {
        Ok(ExitOutcome::Code(libc::WEXITSTATUS(status)))
    } else if libc::WIFSIGNALED(status) {
        Ok(ExitOutcome::Signal(libc::WTERMSIG(status)))
    } else {
        Err(io::Error::other(
            "tool did not reach a terminal wait status",
        ))
    }
}

#[cfg(target_os = "linux")]
fn trace(request: libc::c_uint, pid: libc::pid_t, data: usize) -> io::Result<()> {
    // SAFETY: requests used here take no address pointer; data is an option mask
    // or zero. Only the helper's own still-unreaped child is addressed.
    if unsafe {
        libc::ptrace(
            request,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            data as *mut libc::c_void,
        )
    } == -1
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
struct Tracee {
    pid: libc::pid_t,
    reaped: bool,
}

#[cfg(target_os = "linux")]
impl Tracee {
    fn wait_until(&mut self, deadline: std::time::Instant) -> io::Result<i32> {
        loop {
            let mut status = 0;
            // SAFETY: writable wait status; wait for exactly our direct child.
            let result = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
            if result == self.pid {
                self.reaped = libc::WIFEXITED(status) || libc::WIFSIGNALED(status);
                return Ok(status);
            }
            if result == -1 {
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::Interrupted {
                    return Err(e);
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "launch/tool deadline",
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for Tracee {
    fn drop(&mut self) {
        if !self.reaped {
            // SAFETY: unreaped direct child cannot have had its pid reused.
            unsafe {
                libc::kill(self.pid, libc::SIGKILL);
            }
            // Cleanup is also bounded by the outer namespace watchdog.
            loop {
                let result = unsafe { libc::waitpid(self.pid, std::ptr::null_mut(), 0) };
                if result != -1 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn incomplete_duplicate_and_invalid_acknowledgements_are_refused() {
        let mut valid = Vec::from(MAGIC.as_slice());
        valid.push(0);
        valid.extend_from_slice(&127_i32.to_le_bytes());
        let mut invalid_kind = valid.clone();
        invalid_kind[8] = 2;
        let mut invalid_code = valid.clone();
        invalid_code[9..13].copy_from_slice(&256_i32.to_le_bytes());
        for bad in [
            vec![],
            b"STARTED".to_vec(),
            valid[..12].to_vec(),
            [valid.clone(), valid.clone()].concat(),
            invalid_kind,
            invalid_code,
        ] {
            let (mut reader, mut writer) = UnixStream::pair().unwrap();
            writer.write_all(&bad).unwrap();
            drop(writer);
            assert!(read_result(&mut reader).is_err());
        }
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        writer.write_all(&valid).unwrap();
        drop(writer);
        assert_eq!(read_result(&mut reader).unwrap(), ExitOutcome::Code(127));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn pre_exec_death_never_returns_a_tool_status() {
        // Child operations are async-signal-safe; no Rust cleanup after fork.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) == -1 {
                    libc::_exit(125);
                }
                libc::raise(libc::SIGSTOP);
                libc::kill(libc::getpid(), libc::SIGKILL);
                libc::_exit(126);
            }
        }
        let error = finish_child(pid, 1000).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("no successful kernel exec event"),
            "{error}"
        );
    }
}
