//! Kernel-pushed socket sends: the `sock:sock_send_length` tracepoint,
//! sampled through `perf_event_open` (`perf`).
//!
//! **What it carries.** The kernel fires it in `sock_sendmsg`, in the
//! **sending task's** context, with the socket's kernel identity (`sk`),
//! address family, protocol, the value `sendmsg` is returning (`ret`: the
//! byte count accepted, or a negative error) and the send flags. Measured on
//! this host before implementation: a 19-byte loopback send produced one
//! record under the sender's pid with `length = 19`.
//!
//! **What it proves.** That a task handed that many bytes to the kernel for
//! send on that socket at a kernel time — and, because it runs in the
//! caller, which task. The endpoint is not in the record; the socket-state
//! transitions of the same `sk` name it. The **content** of the bytes is not
//! observed and never will be by this source (I23): the count is the whole
//! of the evidence, and no hash of the payload is claimed anywhere.
//!
//! **What it does not prove.** What the bytes were, that they left the host,
//! or anything on a host whose root disables or starves the ring. A failed
//! send (`ret ≤ 0`) accepted nothing and is not a send.

use crate::linux::{ProcEvent, SourceError};
use crate::observed::{KernelLifecycleKind, SocketProtocol};
use crate::perf::{i32_at, u16_at, u64_at, RawFormat};

pub const SOCK_SEND_TRACEPOINT: &str = "sock/sock_send_length";

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const IPPROTO_TCP: u16 = 6;

fn malformed(what: &str) -> SourceError {
    SourceError::Malformed(format!("send record: {what}"))
}

/// Decode one `sock_send_length` record. Pure. TCP over IPv4/IPv6 with a
/// positive byte count only; everything else is `Malformed` and is not a
/// send.
pub fn parse_sock_send_record(
    fmt: &RawFormat,
    raw: &[u8],
    current_pid: u32,
) -> Result<KernelLifecycleKind, SourceError> {
    if raw.len() < fmt.record_len {
        return Err(malformed(&format!(
            "{} bytes, layout needs {}",
            raw.len(),
            fmt.record_len
        )));
    }
    let sk = u64_at(raw, fmt.field("sk", 8)?).ok_or_else(|| malformed("truncated at sk"))?;
    let family =
        u16_at(raw, fmt.field("family", 2)?).ok_or_else(|| malformed("truncated at family"))?;
    let protocol =
        u16_at(raw, fmt.field("protocol", 2)?).ok_or_else(|| malformed("truncated at protocol"))?;
    let ret = i32_at(raw, fmt.field("ret", 4)?).ok_or_else(|| malformed("truncated at ret"))?;
    let flags =
        i32_at(raw, fmt.field("flags", 4)?).ok_or_else(|| malformed("truncated at flags"))?;
    if protocol != IPPROTO_TCP {
        return Err(malformed(&format!("protocol {protocol} is not TCP")));
    }
    let protocol = match family {
        AF_INET => SocketProtocol::Tcp,
        AF_INET6 => SocketProtocol::Tcp6,
        other => return Err(malformed(&format!("family {other} unsupported"))),
    };
    let bytes = u32::try_from(ret)
        .ok()
        .filter(|b| *b > 0)
        .ok_or_else(|| malformed(&format!("sendmsg returned {ret}: nothing was sent")))?;
    Ok(KernelLifecycleKind::SocketSend {
        protocol,
        sk,
        bytes,
        flags: flags as u32,
        current_pid,
    })
}

#[cfg(target_os = "linux")]
mod sys {
    use super::*;
    use crate::perf::PerfTracepoints;

    /// The send tracepoint source.
    #[derive(Debug)]
    pub struct SockSendTracer {
        perf: PerfTracepoints,
        id: u32,
    }

    impl SockSendTracer {
        /// Open the tracepoint on every online CPU. `Unavailable` when
        /// tracefs, the tracepoint (kernels before 6.4) or the perf
        /// permission is missing; nothing is simulated.
        pub fn open() -> Result<SockSendTracer, SourceError> {
            let perf = PerfTracepoints::open(&[SOCK_SEND_TRACEPOINT])?;
            let id = perf
                .format_named(SOCK_SEND_TRACEPOINT)
                .map(|f| f.id)
                .ok_or_else(|| SourceError::Malformed("send tracepoint missing".into()))?;
            // Every interpreted field must be present with its size, or the
            // layout is refused now rather than misread later.
            let f = perf.format(id).expect("format registered");
            f.field("sk", 8)?;
            f.field("family", 2)?;
            f.field("protocol", 2)?;
            f.field("ret", 4)?;
            f.field("flags", 4)?;
            Ok(SockSendTracer { perf, id })
        }

        pub fn take_lost(&mut self) -> u64 {
            self.perf.take_lost()
        }

        /// Next decoded TCP send, waiting up to `timeout_ms`; `Ok(None)` on
        /// timeout. Records that are not TCP sends with a positive count are
        /// skipped — they are out of scope, not loss.
        pub fn next_event(&mut self, timeout_ms: i32) -> Result<Option<ProcEvent>, SourceError> {
            loop {
                let Some(s) = self.perf.next_sample(timeout_ms)? else {
                    return Ok(None);
                };
                if s.tracepoint_id != self.id {
                    continue;
                }
                let Some(fmt) = self.perf.format(self.id) else {
                    continue;
                };
                match parse_sock_send_record(fmt, &s.raw, s.pid) {
                    Ok(kind) => {
                        return Ok(Some(ProcEvent {
                            kind,
                            cpu: s.cpu,
                            timestamp_ns: s.timestamp_ns,
                        }))
                    }
                    Err(_) => continue,
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub use sys::SockSendTracer;
