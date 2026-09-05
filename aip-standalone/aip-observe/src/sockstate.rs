//! Kernel-pushed TCP socket state transitions: the `sock:inet_sock_set_state`
//! tracepoint, sampled through `perf_event_open`.
//!
//! **What this is.** For every TCP state change the kernel fires a
//! tracepoint carrying the socket's kernel identity, old and new state,
//! family, protocol and endpoints. `perf_event_open(PERF_TYPE_TRACEPOINT)`
//! delivers each firing into a per-CPU ring buffer with the kernel's own
//! timestamp (`CLOCK_BOOTTIME`, requested explicitly), the CPU, and the task
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

/// One field of a tracepoint record as tracefs describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceField {
    pub name: String,
    pub offset: usize,
    pub size: usize,
}

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
        let mut fields: Vec<TraceField> = Vec::new();
        for line in format.lines() {
            let line = line.trim();
            if !line.starts_with("field:") {
                continue;
            }
            let mut name = None;
            let mut offset = None;
            let mut size = None;
            for part in line.split(';') {
                let part = part.trim();
                if let Some(decl) = part.strip_prefix("field:") {
                    // "field:__u8 saddr[4]" → last token, strip array suffix.
                    let last = decl.split_whitespace().last().unwrap_or("");
                    let base = last.split('[').next().unwrap_or(last);
                    name = Some(base.trim_start_matches('*').to_string());
                } else if let Some(v) = part.strip_prefix("offset:") {
                    offset = v.trim().parse::<usize>().ok();
                } else if let Some(v) = part.strip_prefix("size:") {
                    size = v.trim().parse::<usize>().ok();
                }
            }
            if let (Some(name), Some(offset), Some(size)) = (name, offset, size) {
                fields.push(TraceField { name, offset, size });
            }
        }
        let get = |n: &str, want: usize| -> Result<TraceField, SourceError> {
            let f = fields
                .iter()
                .find(|f| f.name == n)
                .cloned()
                .ok_or_else(|| SourceError::Malformed(format!("tracepoint format lacks `{n}`")))?;
            if f.size != want {
                return Err(SourceError::Malformed(format!(
                    "tracepoint field `{n}` has size {}, expected {want}",
                    f.size
                )));
            }
            Ok(f)
        };
        let record_len = fields.iter().map(|f| f.offset + f.size).max().unwrap_or(0);
        Ok(TracepointFormat {
            id,
            skaddr: get("skaddr", 8)?,
            oldstate: get("oldstate", 4)?,
            newstate: get("newstate", 4)?,
            sport: get("sport", 2)?,
            dport: get("dport", 2)?,
            family: get("family", 2)?,
            protocol: get("protocol", 2)?,
            saddr: get("saddr", 4)?,
            daddr: get("daddr", 4)?,
            saddr_v6: get("saddr_v6", 16)?,
            daddr_v6: get("daddr_v6", 16)?,
            record_len,
        })
    }
}

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const IPPROTO_TCP: u16 = 6;

fn u16_at(raw: &[u8], f: &TraceField) -> Option<u16> {
    raw.get(f.offset..f.offset + 2)
        .map(|b| u16::from_ne_bytes([b[0], b[1]]))
}
fn i32_at(raw: &[u8], f: &TraceField) -> Option<i32> {
    raw.get(f.offset..f.offset + 4)
        .map(|b| i32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
}
fn u64_at(raw: &[u8], f: &TraceField) -> Option<u64> {
    raw.get(f.offset..f.offset + 8)
        .map(|b| u64::from_ne_bytes(b.try_into().unwrap()))
}

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
    let (bs, bn) = now(libc::CLOCK_BOOTTIME)?;
    let (rs, rn) = now(libc::CLOCK_REALTIME)?;
    Ok(BootClockAnchor {
        realtime_ms: rs * 1_000 + rn / 1_000_000,
        boottime_ns: bs * 1_000_000_000 + bn,
    })
}

#[cfg(target_os = "linux")]
mod sys {
    use super::*;
    use std::os::fd::RawFd;

    // perf_event_attr, ABI size 128 (PERF_ATTR_SIZE_VER7). Defined here rather
    // than relying on a libc binding so the offsets are explicit and match
    // the kernel uapi header field for field.
    #[repr(C)]
    #[derive(Default)]
    struct PerfEventAttr {
        type_: u32,
        size: u32,
        config: u64,
        sample_period: u64,
        sample_type: u64,
        read_format: u64,
        flags: u64,
        wakeup_events: u32,
        bp_type: u32,
        config1: u64,
        config2: u64,
        branch_sample_type: u64,
        sample_regs_user: u64,
        sample_stack_user: u32,
        clockid: i32,
        sample_regs_intr: u64,
        aux_watermark: u32,
        sample_max_stack: u16,
        reserved_2: u16,
        aux_sample_size: u32,
        reserved_3: u32,
        sig_data: u64,
        config3: u64,
    }

    const PERF_ATTR_SIZE: u32 = 128;
    const PERF_TYPE_TRACEPOINT: u32 = 2;
    const PERF_SAMPLE_TID: u64 = 1 << 1;
    const PERF_SAMPLE_TIME: u64 = 1 << 2;
    const PERF_SAMPLE_CPU: u64 = 1 << 7;
    const PERF_SAMPLE_RAW: u64 = 1 << 10;
    const ATTR_FLAG_DISABLED: u64 = 1;
    const ATTR_FLAG_USE_CLOCKID: u64 = 1 << 34;
    const PERF_FLAG_FD_CLOEXEC: libc::c_ulong = 1 << 3;
    const PERF_RECORD_LOST: u32 = 2;
    const PERF_RECORD_SAMPLE: u32 = 9;
    const PERF_EVENT_IOC_ENABLE: libc::c_ulong = 0x2400;
    const DATA_PAGES: usize = 8;

    // perf_event_mmap_page: only the fields read here, at their uapi offsets.
    const MMAP_DATA_HEAD: usize = 1024;
    const MMAP_DATA_TAIL: usize = 1032;
    const MMAP_DATA_OFFSET: usize = 1040;
    const MMAP_DATA_SIZE: usize = 1048;

    struct Ring {
        fd: RawFd,
        cpu: u32,
        map: *mut u8,
        map_len: usize,
    }

    impl Ring {
        fn read_u64(&self, off: usize) -> u64 {
            // SAFETY: `off` is inside the header page of a live mapping.
            unsafe { std::ptr::read_volatile(self.map.add(off) as *const u64) }
        }
        fn write_tail(&self, v: u64) {
            // SAFETY: as above; the tail is user-space owned.
            unsafe { std::ptr::write_volatile(self.map.add(MMAP_DATA_TAIL) as *mut u64, v) }
        }
        /// Copy `len` bytes starting at ring position `pos` (wrapping).
        fn copy(&self, data_off: usize, data_size: usize, pos: u64, len: usize) -> Vec<u8> {
            let mut out = Vec::with_capacity(len);
            for i in 0..len {
                let idx = ((pos as usize) + i) % data_size;
                // SAFETY: data_off + idx is inside the mapping.
                out.push(unsafe { *self.map.add(data_off + idx) });
            }
            out
        }
    }

    impl Drop for Ring {
        fn drop(&mut self) {
            // SAFETY: the mapping and fd were created by this struct.
            unsafe {
                libc::munmap(self.map as *mut libc::c_void, self.map_len);
                libc::close(self.fd);
            }
        }
    }

    /// The tracepoint source: one perf ring per online CPU.
    pub struct SockStateTracer {
        format: TracepointFormat,
        rings: Vec<Ring>,
        lost: u64,
        pending: std::collections::VecDeque<ProcEvent>,
    }

    impl std::fmt::Debug for SockStateTracer {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SockStateTracer")
                .field("tracepoint_id", &self.format.id)
                .field("cpus", &self.rings.len())
                .field("lost", &self.lost)
                .finish()
        }
    }

    fn tracefs_root() -> Option<&'static str> {
        ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]
            .into_iter()
            .find(|p| std::path::Path::new(p).join("events").is_dir())
    }

    impl SockStateTracer {
        /// Open the tracepoint on every online CPU. `Unavailable` when tracefs
        /// or the perf permission is missing; nothing is simulated in that case.
        pub fn open() -> Result<SockStateTracer, SourceError> {
            let root = tracefs_root().ok_or_else(|| {
                SourceError::Unavailable("tracefs is not mounted (/sys/kernel/tracing)".into())
            })?;
            let ev = format!("{root}/events/sock/inet_sock_set_state");
            let id: u32 = std::fs::read_to_string(format!("{ev}/id"))
                .map_err(|e| SourceError::Unavailable(format!("{ev}/id: {e}")))?
                .trim()
                .parse()
                .map_err(|_| SourceError::Malformed("tracepoint id is not a number".into()))?;
            let fmt_text = std::fs::read_to_string(format!("{ev}/format"))
                .map_err(|e| SourceError::Unavailable(format!("{ev}/format: {e}")))?;
            let format = TracepointFormat::parse(id, &fmt_text)?;

            // SAFETY: sysconf has no preconditions.
            let ncpu = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
            if ncpu <= 0 {
                return Err(SourceError::Unavailable("cannot count CPUs".into()));
            }
            let page = {
                // SAFETY: as above.
                let p = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
                if p <= 0 {
                    4096
                } else {
                    p as usize
                }
            };
            let mut rings = Vec::new();
            for cpu in 0..ncpu as i32 {
                let attr = PerfEventAttr {
                    type_: PERF_TYPE_TRACEPOINT,
                    size: PERF_ATTR_SIZE,
                    config: id as u64,
                    sample_period: 1,
                    sample_type: PERF_SAMPLE_TID
                        | PERF_SAMPLE_TIME
                        | PERF_SAMPLE_CPU
                        | PERF_SAMPLE_RAW,
                    flags: ATTR_FLAG_DISABLED | ATTR_FLAG_USE_CLOCKID,
                    wakeup_events: 1,
                    clockid: libc::CLOCK_BOOTTIME,
                    ..Default::default()
                };
                // SAFETY: `attr` is a fully initialised repr(C) struct of the
                // declared size; pid = -1 / cpu = N asks for all tasks on one CPU.
                let fd = unsafe {
                    libc::syscall(
                        libc::SYS_perf_event_open,
                        &attr as *const PerfEventAttr,
                        -1 as libc::pid_t,
                        cpu,
                        -1 as libc::c_int,
                        PERF_FLAG_FD_CLOEXEC,
                    )
                };
                if fd < 0 {
                    let err = std::io::Error::last_os_error();
                    return Err(SourceError::Unavailable(format!(
                        "perf_event_open(tracepoint {id}, cpu {cpu}): {err}"
                    )));
                }
                let fd = fd as RawFd;
                let map_len = page * (1 + DATA_PAGES);
                // SAFETY: mapping a perf fd with a header page plus a
                // power-of-two number of data pages, as the perf ABI requires.
                let map = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        map_len,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_SHARED,
                        fd,
                        0,
                    )
                };
                if map == libc::MAP_FAILED {
                    let err = std::io::Error::last_os_error();
                    // SAFETY: fd is ours.
                    unsafe { libc::close(fd) };
                    return Err(SourceError::Unavailable(format!("perf mmap: {err}")));
                }
                rings.push(Ring {
                    fd,
                    cpu: cpu as u32,
                    map: map as *mut u8,
                    map_len,
                });
            }
            for r in &rings {
                // SAFETY: ioctl on a perf fd we own.
                let rc = unsafe { libc::ioctl(r.fd, PERF_EVENT_IOC_ENABLE as _, 0) };
                if rc != 0 {
                    let err = std::io::Error::last_os_error();
                    return Err(SourceError::Unavailable(format!("perf enable: {err}")));
                }
            }
            Ok(SockStateTracer {
                format,
                rings,
                lost: 0,
                pending: Default::default(),
            })
        }

        pub fn format(&self) -> &TracepointFormat {
            &self.format
        }

        /// Records the kernel reported lost since the last call, from
        /// `PERF_RECORD_LOST`. Resets the counter.
        pub fn take_lost(&mut self) -> u64 {
            std::mem::take(&mut self.lost)
        }

        /// Next decoded transition, waiting up to `timeout_ms` for the rings.
        /// `Ok(None)` on timeout. Records that are not TCP state transitions
        /// or that fail to decode are skipped and counted as lost, never
        /// guessed at.
        pub fn next_event(&mut self, timeout_ms: i32) -> Result<Option<ProcEvent>, SourceError> {
            if let Some(ev) = self.pending.pop_front() {
                return Ok(Some(ev));
            }
            self.drain_rings();
            if let Some(ev) = self.pending.pop_front() {
                return Ok(Some(ev));
            }
            let mut fds: Vec<libc::pollfd> = self
                .rings
                .iter()
                .map(|r| libc::pollfd {
                    fd: r.fd,
                    events: libc::POLLIN,
                    revents: 0,
                })
                .collect();
            // SAFETY: `fds` is a valid array of pollfd of the given length.
            let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    return Ok(None);
                }
                return Err(SourceError::Unavailable(format!("poll: {err}")));
            }
            self.drain_rings();
            Ok(self.pending.pop_front())
        }

        fn drain_rings(&mut self) {
            let fmt = self.format.clone();
            let mut lost = 0u64;
            let mut out = Vec::new();
            for r in &self.rings {
                let data_off = r.read_u64(MMAP_DATA_OFFSET) as usize;
                let data_size = r.read_u64(MMAP_DATA_SIZE) as usize;
                if data_size == 0 {
                    continue;
                }
                let head = r.read_u64(MMAP_DATA_HEAD);
                let mut tail = r.read_u64(MMAP_DATA_TAIL);
                while tail < head {
                    let hdr = r.copy(data_off, data_size, tail, 8);
                    let rtype = u32::from_ne_bytes(hdr[0..4].try_into().unwrap());
                    let rsize = u16::from_ne_bytes(hdr[6..8].try_into().unwrap()) as usize;
                    if rsize < 8 || (rsize as u64) > head - tail {
                        // Corrupt header: abandon this ring's pending data.
                        lost += 1;
                        tail = head;
                        break;
                    }
                    let rec = r.copy(data_off, data_size, tail, rsize);
                    match rtype {
                        PERF_RECORD_LOST => {
                            // header(8) id(8) lost(8)
                            if rec.len() >= 24 {
                                lost += u64::from_ne_bytes(rec[16..24].try_into().unwrap());
                            }
                        }
                        PERF_RECORD_SAMPLE => match decode_sample(&fmt, &rec, r.cpu) {
                            Some(ev) => out.push(ev),
                            None => lost += 1,
                        },
                        _ => {}
                    }
                    tail += rsize as u64;
                }
                r.write_tail(tail);
            }
            // Deliver in kernel time order across CPUs.
            out.sort_by_key(|e| e.timestamp_ns);
            self.pending.extend(out);
            self.lost += lost;
        }
    }

    /// PERF_RECORD_SAMPLE with sample_type TID|TIME|CPU|RAW:
    /// header(8) pid(4) tid(4) time(8) cpu(4) res(4) raw_size(4) raw[...]
    fn decode_sample(fmt: &TracepointFormat, rec: &[u8], ring_cpu: u32) -> Option<ProcEvent> {
        if rec.len() < 8 + 4 + 4 + 8 + 4 + 4 + 4 {
            return None;
        }
        let pid = u32::from_ne_bytes(rec[8..12].try_into().ok()?);
        let time = u64::from_ne_bytes(rec[16..24].try_into().ok()?);
        let cpu = u32::from_ne_bytes(rec[24..28].try_into().ok()?);
        let raw_size = u32::from_ne_bytes(rec[32..36].try_into().ok()?) as usize;
        let raw = rec.get(36..36 + raw_size)?;
        let kind = parse_sock_state_record(fmt, raw, pid).ok()?;
        Some(ProcEvent {
            kind,
            cpu: if cpu == 0 && ring_cpu != 0 {
                ring_cpu
            } else {
                cpu
            },
            timestamp_ns: time,
        })
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
        };
        assert_eq!(a.wall_ms(5_000_000_000), 1_000_000);
        assert_eq!(a.wall_ms(6_500_000_000), 1_001_500);
        assert_eq!(a.wall_ms(4_000_000_000), 999_000);
    }
}
