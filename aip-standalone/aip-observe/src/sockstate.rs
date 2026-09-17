//! Kernel-pushed TCP socket state transitions: the `sock:inet_sock_set_state`
//! tracepoint, sampled through `perf_event_open`.
//!
//! **What this is.** For every TCP state change the kernel fires a
//! tracepoint carrying the socket's kernel identity, old and new state,
//! family, protocol and endpoints. `perf_event_open(PERF_TYPE_TRACEPOINT)`
//! delivers each firing into a per-CPU ring buffer with the kernel's own
//! timestamp (`CLOCK_MONOTONIC`, requested explicitly), the CPU, and the task
//! that was current — and a `PERF_RECORD_LOST` record whenever the ring
//! overflowed. No eBPF program, no XDP, no packet capture: this is the
//! kernel's static tracepoint read through the perf ring.
//!
//! **What it proves.** That the kernel changed a socket's state at a kernel
//! time, and the order of such changes. For the `connect()` call itself
//! (`CLOSE → SYN_SENT`) the current task *is* the caller; the completion
//! (`SYN_SENT → ESTABLISHED`) runs in softirq context and its current task
//! is not meaningful. Linking the two is the reconciler's job, through `sk`.
//!
//! **What it does not prove.** Nothing about payload or bytes; nothing about
//! the process behind a transition until the probe anchors it (`probe`);
//! nothing on a host whose root can disable, filter or starve the ring.
//!
//! **Privilege.** `perf_event_open` on a tracepoint needs
//! `perf_event_paranoid ≤ -1`, or `CAP_PERFMON`/`CAP_SYS_ADMIN`; tracefs must
//! be mounted to read the tracepoint id and record layout. Where any is
//! missing, [`SockStateTracer::open`] returns `Unavailable` and this
//! mechanism simply does not exist for the host — nothing is simulated.
//!
//! The record layout is **read from tracefs at open time**, never assumed:
//! field offsets differ between kernels, and a wrong offset would silently
//! mislabel endpoints.

use crate::linux::{ProcEvent, SourceError};
use crate::observed::{BootClockAnchor, KernelLifecycleKind, SocketEndpoint, SocketProtocol};

pub use crate::perf::TraceField;
use crate::perf::{i32_at, u16_at, u64_at, RawFormat};

pub const SOCK_STATE_TRACEPOINT: &str = "sock/inet_sock_set_state";

/// The record layout of `sock:inet_sock_set_state`, parsed from the
/// tracefs `format` file. Only the fields this crate interprets are kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TracepointFormat {
    pub id: u32,
    pub skaddr: TraceField,
    pub oldstate: TraceField,
    pub newstate: TraceField,
    pub sport: TraceField,
    pub dport: TraceField,
    pub family: TraceField,
    pub protocol: TraceField,
    pub saddr: TraceField,
    pub daddr: TraceField,
    pub saddr_v6: TraceField,
    pub daddr_v6: TraceField,
    /// Total record length implied by the last field.
    pub record_len: usize,
}

impl TracepointFormat {
    /// Parse the `format` file text plus the `id`. Every interpreted field
    /// must be present with a plausible size, or the format is refused.
    pub fn parse(id: u32, format: &str) -> Result<TracepointFormat, SourceError> {
        Self::from_raw(&RawFormat::parse(id, SOCK_STATE_TRACEPOINT, format)?)
    }

    pub fn from_raw(raw: &RawFormat) -> Result<TracepointFormat, SourceError> {
        Ok(TracepointFormat {
            id: raw.id,
            skaddr: raw.field("skaddr", 8)?.clone(),
            oldstate: raw.field("oldstate", 4)?.clone(),
            newstate: raw.field("newstate", 4)?.clone(),
            sport: raw.field("sport", 2)?.clone(),
            dport: raw.field("dport", 2)?.clone(),
            family: raw.field("family", 2)?.clone(),
            protocol: raw.field("protocol", 2)?.clone(),
            saddr: raw.field("saddr", 4)?.clone(),
            daddr: raw.field("daddr", 4)?.clone(),
            saddr_v6: raw.field("saddr_v6", 16)?.clone(),
            daddr_v6: raw.field("daddr_v6", 16)?.clone(),
            record_len: raw.record_len,
        })
    }
}

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const IPPROTO_TCP: u16 = 6;

/// Decode one raw tracepoint record into a [`KernelLifecycleKind::SocketState`].
/// Pure: no syscalls, no interpretation beyond the record's own fields.
/// Non-TCP transitions and malformed records are `Malformed`, never guessed.
pub fn parse_sock_state_record(
    fmt: &TracepointFormat,
    raw: &[u8],
    current_pid: u32,
) -> Result<KernelLifecycleKind, SourceError> {
    if raw.len() < fmt.record_len {
        return Err(SourceError::Malformed(format!(
            "tracepoint record {} bytes, layout needs {}",
            raw.len(),
            fmt.record_len
        )));
    }
    let family = u16_at(raw, &fmt.family).ok_or_else(|| malformed("family"))?;
    let protocol = u16_at(raw, &fmt.protocol).ok_or_else(|| malformed("protocol"))?;
    if protocol != IPPROTO_TCP {
        return Err(SourceError::Malformed(format!(
            "socket state protocol {protocol} is not TCP"
        )));
    }
    let (proto, v6) = match family {
        AF_INET => (SocketProtocol::Tcp, false),
        AF_INET6 => (SocketProtocol::Tcp6, true),
        other => {
            return Err(SourceError::Malformed(format!(
                "socket state family {other} unsupported"
            )))
        }
    };
    let sport = u16_at(raw, &fmt.sport).ok_or_else(|| malformed("sport"))?;
    let dport = u16_at(raw, &fmt.dport).ok_or_else(|| malformed("dport"))?;
    let (saddr, daddr) = if v6 {
        (
            raw[fmt.saddr_v6.offset..fmt.saddr_v6.offset + 16].to_vec(),
            raw[fmt.daddr_v6.offset..fmt.daddr_v6.offset + 16].to_vec(),
        )
    } else {
        (
            raw[fmt.saddr.offset..fmt.saddr.offset + 4].to_vec(),
            raw[fmt.daddr.offset..fmt.daddr.offset + 4].to_vec(),
        )
    };
    let endpoint = |addr: &[u8], port: u16| {
        let mut a = [0u8; 16];
        a[..addr.len()].copy_from_slice(addr);
        SocketEndpoint {
            addr: a,
            is_v6: v6,
            port,
        }
    };
    let old = i32_at(raw, &fmt.oldstate).ok_or_else(|| malformed("oldstate"))?;
    let new = i32_at(raw, &fmt.newstate).ok_or_else(|| malformed("newstate"))?;
    let state = |v: i32, what: &str| -> Result<u8, SourceError> {
        u8::try_from(v).map_err(|_| SourceError::Malformed(format!("{what} {v} out of range")))
    };
    Ok(KernelLifecycleKind::SocketState {
        protocol: proto,
        local: endpoint(&saddr, sport),
        remote: endpoint(&daddr, dport),
        old_state: state(old, "oldstate")?,
        new_state: state(new, "newstate")?,
        sk: u64_at(raw, &fmt.skaddr).ok_or_else(|| malformed("skaddr"))?,
        current_pid,
    })
}

fn malformed(field: &str) -> SourceError {
    SourceError::Malformed(format!("tracepoint record truncated at `{field}`"))
}

/// Sample the host's realtime and boot clocks back-to-back.
#[cfg(target_os = "linux")]
pub fn boot_clock_anchor() -> Result<BootClockAnchor, SourceError> {
    fn now(clock: libc::clockid_t) -> Result<(u64, u64), SourceError> {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `ts` is a valid, writable timespec.
        let rc = unsafe { libc::clock_gettime(clock, &mut ts) };
        if rc != 0 {
            return Err(SourceError::Unavailable(format!(
                "clock_gettime({clock}) failed"
            )));
        }
        Ok((ts.tv_sec as u64, ts.tv_nsec as u64))
    }
    let (ms, mn) = now(libc::CLOCK_MONOTONIC)?;
    let (bs, bn) = now(libc::CLOCK_BOOTTIME)?;
    let (rs, rn) = now(libc::CLOCK_REALTIME)?;
    Ok(BootClockAnchor {
        realtime_ms: rs * 1_000 + rn / 1_000_000,
        boottime_ns: bs * 1_000_000_000 + bn,
        monotonic_ns: ms * 1_000_000_000 + mn,
        clk_tck: crate::probe::clk_tck() as u32,
    })
}

#[cfg(target_os = "linux")]
mod sys {
    use super::*;
    use crate::health::MechanismIntegrity;
    use crate::perf::PerfTracepoints;

    /// The tracepoint source: the shared perf rings, one tracepoint.
    #[derive(Debug)]
    pub struct SockStateTracer {
        perf: PerfTracepoints,
        format: TracepointFormat,
    }

    impl SockStateTracer {
        /// Open the tracepoint on every online CPU. `Unavailable` when tracefs
        /// or the perf permission is missing; nothing is simulated in that case.
        pub fn open() -> Result<SockStateTracer, SourceError> {
            let perf = PerfTracepoints::open(&[SOCK_STATE_TRACEPOINT])?;
            let raw = perf
                .format_named(SOCK_STATE_TRACEPOINT)
                .ok_or_else(|| SourceError::Malformed("socket tracepoint missing".into()))?;
            let format = TracepointFormat::from_raw(raw)?;
            Ok(SockStateTracer { perf, format })
        }

        pub fn format(&self) -> &TracepointFormat {
            &self.format
        }

        /// Records the kernel reported lost since the last call, from
        /// `PERF_RECORD_LOST`. Resets the counter.
        pub fn take_lost(&mut self) -> u64 {
            self.perf.take_lost()
        }

        /// Is a foreign eBPF program gating the `sock:inet_sock_set_state`
        /// tracepoint this tracer samples? A perf-tracepoint mechanism shares
        /// the kernel's per-tracepoint submission gate with `sched` and
        /// `sock:sock_send_length`, so the same observation-integrity finding
        /// applies: a foreign program can suppress this tracer's transitions
        /// host-wide with no dropped-record accounting. The collector feeds
        /// this to [`crate::CollectorSigner::note_mechanism_integrity`] each
        /// health cycle so a blinded socket-state sensor signs
        /// [`crate::ObserverState::IntegrityUnknown`] instead of a false
        /// `Active`. Fail-closed: a refused query is
        /// [`MechanismIntegrity::Unverifiable`], never a silent `Verified`.
        pub fn mechanism_integrity(&self) -> MechanismIntegrity {
            MechanismIntegrity::from_foreign_program_query(self.perf.foreign_bpf_program_count())
        }

        /// Next decoded transition, waiting up to `timeout_ms` for the rings.
        /// `Ok(None)` on timeout. Records that are not TCP state transitions
        /// or that fail to decode are skipped and counted as lost, never
        /// guessed at.
        pub fn next_event(&mut self, timeout_ms: i32) -> Result<Option<ProcEvent>, SourceError> {
            loop {
                let Some(s) = self.perf.next_sample(timeout_ms)? else {
                    return Ok(None);
                };
                match parse_sock_state_record(&self.format, &s.raw, s.pid) {
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
pub use sys::SockStateTracer;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observed::tcp_state;

    const FORMAT: &str = "name: inet_sock_set_state
ID: 1427
format:
\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;
\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;
\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;
\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;

\tfield:const void * skaddr;\toffset:8;\tsize:8;\tsigned:0;
\tfield:int oldstate;\toffset:16;\tsize:4;\tsigned:1;
\tfield:int newstate;\toffset:20;\tsize:4;\tsigned:1;
\tfield:__u16 sport;\toffset:24;\tsize:2;\tsigned:0;
\tfield:__u16 dport;\toffset:26;\tsize:2;\tsigned:0;
\tfield:__u16 family;\toffset:28;\tsize:2;\tsigned:0;
\tfield:__u16 protocol;\toffset:30;\tsize:2;\tsigned:0;
\tfield:__u8 saddr[4];\toffset:32;\tsize:4;\tsigned:0;
\tfield:__u8 daddr[4];\toffset:36;\tsize:4;\tsigned:0;
\tfield:__u8 saddr_v6[16];\toffset:40;\tsize:16;\tsigned:0;
\tfield:__u8 daddr_v6[16];\toffset:56;\tsize:16;\tsigned:0;
";

    fn record(family: u16, proto: u16, old: i32, new: i32, sport: u16, dport: u16) -> Vec<u8> {
        let mut r = vec![0u8; 72];
        r[8..16].copy_from_slice(&0xdead_beef_cafe_f00du64.to_ne_bytes());
        r[16..20].copy_from_slice(&old.to_ne_bytes());
        r[20..24].copy_from_slice(&new.to_ne_bytes());
        r[24..26].copy_from_slice(&sport.to_ne_bytes());
        r[26..28].copy_from_slice(&dport.to_ne_bytes());
        r[28..30].copy_from_slice(&family.to_ne_bytes());
        r[30..32].copy_from_slice(&proto.to_ne_bytes());
        r[32..36].copy_from_slice(&[127, 0, 0, 1]);
        r[36..40].copy_from_slice(&[10, 0, 0, 5]);
        r[40..56].copy_from_slice(&[0xfe; 16]);
        r[56..72].copy_from_slice(&[0xfd; 16]);
        r
    }

    #[test]
    fn format_is_parsed_from_tracefs_text_not_assumed() {
        let f = TracepointFormat::parse(1427, FORMAT).unwrap();
        assert_eq!(f.skaddr.offset, 8);
        assert_eq!(f.daddr_v6.offset, 56);
        assert_eq!(f.record_len, 72);
        // A layout missing an interpreted field is refused.
        let broken = FORMAT.replace("field:__u16 dport;", "field:__u16 xport;");
        assert!(matches!(
            TracepointFormat::parse(1427, &broken),
            Err(SourceError::Malformed(_))
        ));
        // A field with an unexpected size is refused rather than misread.
        let resized = FORMAT.replace("skaddr;\toffset:8;\tsize:8;", "skaddr;\toffset:8;\tsize:4;");
        assert!(matches!(
            TracepointFormat::parse(1427, &resized),
            Err(SourceError::Malformed(_))
        ));
    }

    #[test]
    fn connect_initiation_and_completion_decode_with_kernel_semantics() {
        let f = TracepointFormat::parse(1427, FORMAT).unwrap();
        let syn = parse_sock_state_record(
            &f,
            &record(
                2,
                6,
                tcp_state::CLOSE as i32,
                tcp_state::SYN_SENT as i32,
                0,
                443,
            ),
            4242,
        )
        .unwrap();
        assert!(syn.is_connect_initiation());
        assert_eq!(
            syn.subject_pid(),
            Some(4242),
            "connect() runs in the caller"
        );
        let est = parse_sock_state_record(
            &f,
            &record(
                2,
                6,
                tcp_state::SYN_SENT as i32,
                tcp_state::ESTABLISHED as i32,
                51000,
                443,
            ),
            777,
        )
        .unwrap();
        assert!(est.is_connect_established());
        assert_eq!(
            est.subject_pid(),
            None,
            "handshake completion runs in softirq; its current task names nobody"
        );
        if let KernelLifecycleKind::SocketState {
            remote, local, sk, ..
        } = est
        {
            assert_eq!(&remote.addr[..4], &[10, 0, 0, 5]);
            assert_eq!(remote.port, 443);
            assert_eq!(local.port, 51000);
            assert!(!remote.is_v6);
            assert_eq!(sk, 0xdead_beef_cafe_f00d);
        } else {
            unreachable!()
        }
    }

    #[test]
    fn non_tcp_unknown_family_and_short_records_are_refused_not_guessed() {
        let f = TracepointFormat::parse(1427, FORMAT).unwrap();
        assert!(parse_sock_state_record(&f, &record(2, 132, 7, 2, 0, 1), 1).is_err()); // SCTP
        assert!(parse_sock_state_record(&f, &record(17, 6, 7, 2, 0, 1), 1).is_err()); // AF_PACKET
        assert!(parse_sock_state_record(&f, &record(2, 6, 7, 2, 0, 1)[..40], 1).is_err());
        assert!(parse_sock_state_record(&f, &record(2, 6, 7, 300, 0, 1), 1).is_err());
    }

    #[test]
    fn v6_records_take_the_v6_addresses() {
        let f = TracepointFormat::parse(1427, FORMAT).unwrap();
        let k = parse_sock_state_record(&f, &record(10, 6, 2, 1, 1, 2), 1).unwrap();
        if let KernelLifecycleKind::SocketState {
            protocol, remote, ..
        } = k
        {
            assert_eq!(protocol, SocketProtocol::Tcp6);
            assert!(remote.is_v6);
            assert_eq!(remote.addr, [0xfd; 16]);
        } else {
            unreachable!()
        }
    }

    #[test]
    fn boot_clock_anchor_places_boot_time_on_the_wall_clock() {
        let a = BootClockAnchor {
            realtime_ms: 1_000_000,
            boottime_ns: 5_000_000_000,
            monotonic_ns: 5_000_000_000,
            clk_tck: 100,
        };
        assert_eq!(a.wall_ms(5_000_000_000), 1_000_000);
        assert_eq!(a.wall_ms(6_500_000_000), 1_001_500);
        assert_eq!(a.wall_ms(4_000_000_000), 999_000);
    }
}
