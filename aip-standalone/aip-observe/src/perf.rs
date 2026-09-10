//! Kernel static tracepoints sampled through `perf_event_open`, shared by
//! every tracepoint-backed source in this crate.
//!
//! One `perf_event_open(PERF_TYPE_TRACEPOINT)` per (tracepoint, online CPU),
//! `sample_type = TID | TIME | CPU | RAW`, `sample_period = 1`,
//! `use_clockid` with **`CLOCK_MONOTONIC`** — requested explicitly, never the
//! PMU's default clock. Measured on this kernel: the tracepoint PMU accepts
//! `CLOCK_MONOTONIC`/`MONOTONIC_RAW` and rejects `BOOTTIME`, `REALTIME` and
//! `TAI` with `EINVAL` (non-NMI-safe clocks need a PMU capability the
//! software tracepoint PMU lacks). Process start ticks in `/proc/<pid>/stat`
//! are on the *boot* clock, so a [`crate::observed::BootClockAnchor`] samples
//! realtime, boottime and monotonic together and the verifier converts. Each ring is a header page plus a
//! power-of-two number of data pages. `PERF_RECORD_SAMPLE` yields the raw
//! tracepoint record (dispatched by its `common_type`, which is the
//! tracepoint id); `PERF_RECORD_LOST` yields a loss count. No eBPF program,
//! no XDP, no packet capture.
//!
//! Record layouts are **read from tracefs at open time**, never assumed.
//! `__data_loc char[]` fields are decoded by the (length << 16 | offset) word
//! they carry, into the record's own bytes.
//!
//! Privilege: `perf_event_paranoid ≤ -1`, or `CAP_PERFMON`/`CAP_SYS_ADMIN`;
//! tracefs mounted. Otherwise `open` is `Unavailable` and nothing is
//! simulated.

use crate::linux::SourceError;

/// One field of a tracepoint record as tracefs describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceField {
    pub name: String,
    pub offset: usize,
    pub size: usize,
    /// `__data_loc` fields hold a 4-byte (len << 16 | offset) locator.
    pub data_loc: bool,
}

/// A tracepoint's record layout, parsed from its tracefs `format` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFormat {
    pub id: u32,
    pub name: String,
    pub fields: Vec<TraceField>,
    /// Fixed-part length implied by the last field.
    pub record_len: usize,
}

impl RawFormat {
    pub fn parse(id: u32, name: &str, format: &str) -> Result<RawFormat, SourceError> {
        let mut fields = Vec::new();
        for line in format.lines() {
            let line = line.trim();
            if !line.starts_with("field:") {
                continue;
            }
            let (mut fname, mut offset, mut size, mut data_loc) = (None, None, None, false);
            for part in line.split(';') {
                let part = part.trim();
                if let Some(decl) = part.strip_prefix("field:") {
                    data_loc = decl.contains("__data_loc");
                    let last = decl.split_whitespace().last().unwrap_or("");
                    let base = last.split('[').next().unwrap_or(last);
                    fname = Some(base.trim_start_matches('*').to_string());
                } else if let Some(v) = part.strip_prefix("offset:") {
                    offset = v.trim().parse::<usize>().ok();
                } else if let Some(v) = part.strip_prefix("size:") {
                    size = v.trim().parse::<usize>().ok();
                }
            }
            if let (Some(name), Some(offset), Some(size)) = (fname, offset, size) {
                fields.push(TraceField {
                    name,
                    offset,
                    size,
                    data_loc,
                });
            }
        }
        if fields.is_empty() {
            return Err(SourceError::Malformed(format!(
                "tracepoint {name} format has no fields"
            )));
        }
        let record_len = fields.iter().map(|f| f.offset + f.size).max().unwrap_or(0);
        Ok(RawFormat {
            id,
            name: name.to_string(),
            fields,
            record_len,
        })
    }

    /// The named field, required to have exactly `size` bytes.
    pub fn field(&self, name: &str, size: usize) -> Result<&TraceField, SourceError> {
        let f = self.fields.iter().find(|f| f.name == name).ok_or_else(|| {
            SourceError::Malformed(format!("tracepoint {} lacks `{name}`", self.name))
        })?;
        if f.size != size {
            return Err(SourceError::Malformed(format!(
                "tracepoint {} field `{name}` has size {}, expected {size}",
                self.name, f.size
            )));
        }
        Ok(f)
    }
}

/// Read a `__data_loc char[]` field: the bytes it points at, without any
/// trailing NUL. `None` if the locator points outside the record.
pub fn data_loc<'a>(raw: &'a [u8], f: &TraceField) -> Option<&'a [u8]> {
    if !f.data_loc || f.size != 4 {
        return None;
    }
    let word = raw.get(f.offset..f.offset + 4)?;
    let word = u32::from_ne_bytes([word[0], word[1], word[2], word[3]]);
    let off = (word & 0xffff) as usize;
    let len = (word >> 16) as usize;
    let bytes = raw.get(off..off + len)?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    Some(&bytes[..end])
}

pub fn u16_at(raw: &[u8], f: &TraceField) -> Option<u16> {
    raw.get(f.offset..f.offset + 2)
        .map(|b| u16::from_ne_bytes([b[0], b[1]]))
}
pub fn i32_at(raw: &[u8], f: &TraceField) -> Option<i32> {
    raw.get(f.offset..f.offset + 4)
        .map(|b| i32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
}
pub fn u64_at(raw: &[u8], f: &TraceField) -> Option<u64> {
    raw.get(f.offset..f.offset + 8)
        .map(|b| u64::from_ne_bytes(b.try_into().unwrap()))
}

/// One decoded `PERF_RECORD_SAMPLE`: which tracepoint, the current task's
/// pid, the kernel's `CLOCK_MONOTONIC` stamp, the CPU, and the raw record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawSample {
    pub tracepoint_id: u32,
    pub pid: u32,
    pub timestamp_ns: u64,
    pub cpu: u32,
    pub raw: Vec<u8>,
}

/// Decode a `PERF_RECORD_SAMPLE` body laid out as
/// header(8) pid(4) tid(4) time(8) cpu(4) res(4) raw_size(4) raw[...].
/// The tracepoint id is the record's `common_type` (first two bytes of raw).
pub fn decode_sample(rec: &[u8], ring_cpu: u32) -> Option<RawSample> {
    if rec.len() < 36 {
        return None;
    }
    let pid = u32::from_ne_bytes(rec[8..12].try_into().ok()?);
    let time = u64::from_ne_bytes(rec[16..24].try_into().ok()?);
    let cpu = u32::from_ne_bytes(rec[24..28].try_into().ok()?);
    let raw_size = u32::from_ne_bytes(rec[32..36].try_into().ok()?) as usize;
    let raw = rec.get(36..36 + raw_size)?;
    if raw.len() < 2 {
        return None;
    }
    let tracepoint_id = u16::from_ne_bytes([raw[0], raw[1]]) as u32;
    Some(RawSample {
        tracepoint_id,
        pid,
        timestamp_ns: time,
        cpu: if cpu == 0 && ring_cpu != 0 {
            ring_cpu
        } else {
            cpu
        },
        raw: raw.to_vec(),
    })
}

#[cfg(target_os = "linux")]
mod sys {
    use super::*;
    use std::collections::{HashMap, VecDeque};
    use std::os::fd::RawFd;

    // perf_event_attr, ABI size 128 (PERF_ATTR_SIZE_VER7). Declared here so
    // the offsets are explicit and match the kernel uapi header.
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
    // Bitfield position of `use_clockid` in `perf_event_attr` (uapi order:
    // disabled=0 … mmap2=23, comm_exec=24, use_clockid=25). Getting this bit
    // wrong is silent: the kernel simply stamps samples with its default
    // clock, and process start ticks (boot clock) then disagree with event
    // stamps by an offset. Verified against `/proc/<pid>/stat` start ticks.
    const ATTR_FLAG_USE_CLOCKID: u64 = 1 << 25;
    const PERF_FLAG_FD_CLOEXEC: libc::c_ulong = 1 << 3;
    const PERF_RECORD_LOST: u32 = 2;
    const PERF_RECORD_SAMPLE: u32 = 9;
    const PERF_EVENT_IOC_ENABLE: libc::c_ulong = 0x2400;
    /// `_IOWR('$', 10, struct perf_event_query_bpf)` — `'$'` is 0x24, the
    /// struct is 8 bytes (two `__u32` before the flexible `ids[]`):
    /// `(dir=3 << 30) | (8 << 16) | (0x24 << 8) | 10`. Queries the eBPF
    /// programs attached to this perf event's tracepoint — the kernel reads
    /// `event->tp_event->prog_array`, the array **shared** by every perf
    /// consumer of that tracepoint, so a program attached by another process
    /// is reported here. This is how the observer sees the gate that the
    /// observation-integrity finding turns against it.
    const PERF_EVENT_IOC_QUERY_BPF: libc::c_ulong = 0xC008_240A;
    /// Data pages per ring (a power of two). Eight pages held a burst of a
    /// few hundred records; host-wide tracepoints (every fork, exec and
    /// send on the host) overflowed that between two drains under load,
    /// and every overflow is counted loss that degrades the observer.
    /// Sixty-four pages (256 KiB per CPU per tracepoint) absorb a burst of
    /// several thousand records; loss stays counted, never hidden.
    const DATA_PAGES: usize = 64;

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

    fn tracefs_root() -> Option<&'static str> {
        ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]
            .into_iter()
            .find(|p| std::path::Path::new(p).join("events").is_dir())
    }

    /// A set of tracepoints sampled together, one ring per (tracepoint, CPU).
    pub struct PerfTracepoints {
        formats: HashMap<u32, RawFormat>,
        rings: Vec<Ring>,
        lost: u64,
        pending: VecDeque<RawSample>,
    }

    impl std::fmt::Debug for PerfTracepoints {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("PerfTracepoints")
                .field(
                    "tracepoints",
                    &self
                        .formats
                        .values()
                        .map(|f| f.name.clone())
                        .collect::<Vec<_>>(),
                )
                .field("rings", &self.rings.len())
                .field("lost", &self.lost)
                .finish()
        }
    }

    impl PerfTracepoints {
        /// Open `names` (as `subsystem/event`) on every online CPU.
        pub fn open(names: &[&str]) -> Result<PerfTracepoints, SourceError> {
            let root = tracefs_root().ok_or_else(|| {
                SourceError::Unavailable(
                    "tracefs is not mounted (/sys/kernel/tracing); mount -t tracefs nodev /sys/kernel/tracing"
                        .into(),
                )
            })?;
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
            let mut formats = HashMap::new();
            let mut rings = Vec::new();
            for name in names {
                let ev = format!("{root}/events/{name}");
                let id: u32 = std::fs::read_to_string(format!("{ev}/id"))
                    .map_err(|e| SourceError::Unavailable(format!("{ev}/id: {e}")))?
                    .trim()
                    .parse()
                    .map_err(|_| SourceError::Malformed(format!("{name}: id is not a number")))?;
                let text = std::fs::read_to_string(format!("{ev}/format"))
                    .map_err(|e| SourceError::Unavailable(format!("{ev}/format: {e}")))?;
                formats.insert(id, RawFormat::parse(id, name, &text)?);
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
                        clockid: libc::CLOCK_MONOTONIC,
                        ..Default::default()
                    };
                    // SAFETY: `attr` is a fully initialised repr(C) struct of
                    // the declared size; pid=-1/cpu=N samples all tasks on one CPU.
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
                            "perf_event_open({name}, cpu {cpu}): {err}"
                        )));
                    }
                    let fd = fd as RawFd;
                    let map_len = page * (1 + DATA_PAGES);
                    // SAFETY: header page plus a power-of-two number of data
                    // pages, as the perf ABI requires.
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
            }
            for r in &rings {
                // SAFETY: ioctl on a perf fd we own.
                let rc = unsafe { libc::ioctl(r.fd, PERF_EVENT_IOC_ENABLE as _, 0) };
                if rc != 0 {
                    let err = std::io::Error::last_os_error();
                    return Err(SourceError::Unavailable(format!("perf enable: {err}")));
                }
            }
            Ok(PerfTracepoints {
                formats,
                rings,
                lost: 0,
                pending: VecDeque::new(),
            })
        }

        pub fn format(&self, tracepoint_id: u32) -> Option<&RawFormat> {
            self.formats.get(&tracepoint_id)
        }

        pub fn format_named(&self, name: &str) -> Option<&RawFormat> {
            self.formats.values().find(|f| f.name == name)
        }

        /// Records the kernel reported lost since the last call
        /// (`PERF_RECORD_LOST`, plus records this reader could not decode).
        pub fn take_lost(&mut self) -> u64 {
            std::mem::take(&mut self.lost)
        }

        /// How many eBPF programs are attached to the tracepoints this
        /// observer samples. Sniffer Dog attaches none of its own, so any
        /// non-zero result is a **foreign** program sitting on the
        /// tracepoint's shared eBPF submission gate — able to suppress this
        /// observer's samples host-wide with no dropped-record accounting.
        /// That is the observation-integrity finding
        /// (`docs/OBSERVATION_INTEGRITY_REQUIREMENTS.md`); this is the
        /// observer's synchronous check for it, so it can sign
        /// [`crate::ObserverState::IntegrityUnknown`] rather than a false
        /// `Active`.
        ///
        /// Returns the largest program count seen across the sampled
        /// tracepoints. `Err` means the kernel refused the query (e.g. no
        /// `CAP_PERFMON`): the observer cannot establish integrity, which a
        /// fail-closed caller treats as unverified, not as clean.
        pub fn foreign_bpf_program_count(&self) -> std::io::Result<u32> {
            // The kernel caps `ids_len` at BPF_TRACE_MAX_PROGS (64); a larger
            // value is rejected with E2BIG before `prog_cnt` is written. 64 is
            // also the most programs a tracepoint can carry, so this never
            // truncates a real count.
            const MAX_PROGS: usize = 64;
            #[repr(C)]
            struct PerfEventQueryBpf {
                ids_len: u32,
                prog_cnt: u32,
                ids: [u32; MAX_PROGS],
            }
            let mut worst = 0u32;
            for r in &self.rings {
                let mut q = PerfEventQueryBpf {
                    ids_len: MAX_PROGS as u32,
                    prog_cnt: 0,
                    ids: [0; MAX_PROGS],
                };
                // SAFETY: ioctl on a perf fd we own; `q` is a fully
                // initialised repr(C) buffer the kernel writes `prog_cnt` and
                // up to `ids_len` ids into.
                let rc = unsafe {
                    libc::ioctl(
                        r.fd,
                        PERF_EVENT_IOC_QUERY_BPF as _,
                        &mut q as *mut PerfEventQueryBpf,
                    )
                };
                if rc != 0 {
                    let err = std::io::Error::last_os_error();
                    // ENOSPC: more programs than our (large) buffer holds; the
                    // kernel still wrote the true `prog_cnt`, which is all we
                    // need. Any other error means we could not establish it.
                    if err.raw_os_error() != Some(libc::ENOSPC) {
                        return Err(err);
                    }
                }
                worst = worst.max(q.prog_cnt);
            }
            Ok(worst)
        }

        /// Next sample in kernel-time order, waiting up to `timeout_ms`.
        pub fn next_sample(&mut self, timeout_ms: i32) -> Result<Option<RawSample>, SourceError> {
            if let Some(s) = self.pending.pop_front() {
                return Ok(Some(s));
            }
            self.drain_rings();
            if let Some(s) = self.pending.pop_front() {
                return Ok(Some(s));
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
                        lost += 1;
                        tail = head;
                        break;
                    }
                    let rec = r.copy(data_off, data_size, tail, rsize);
                    match rtype {
                        PERF_RECORD_LOST => {
                            if rec.len() >= 24 {
                                lost += u64::from_ne_bytes(rec[16..24].try_into().unwrap());
                            }
                        }
                        PERF_RECORD_SAMPLE => match decode_sample(&rec, r.cpu) {
                            Some(s) => out.push(s),
                            None => lost += 1,
                        },
                        _ => {}
                    }
                    tail += rsize as u64;
                }
                r.write_tail(tail);
            }
            out.sort_by_key(|s| s.timestamp_ns);
            self.pending.extend(out);
            self.lost += lost;
        }
    }
}

#[cfg(target_os = "linux")]
pub use sys::PerfTracepoints;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_loc_fields_are_decoded_by_their_locator_word() {
        let fmt = RawFormat::parse(
            256,
            "sched/sched_process_exec",
            "field:__data_loc char[] filename;\toffset:8;\tsize:4;\tsigned:0;\n\
             field:pid_t pid;\toffset:12;\tsize:4;\tsigned:1;\n\
             field:pid_t old_pid;\toffset:16;\tsize:4;\tsigned:1;\n",
        )
        .unwrap();
        let f = fmt.field("filename", 4).unwrap();
        assert!(f.data_loc);
        // Record: fixed part 20 bytes, string "/bin/x\0" at offset 20, len 7.
        let mut raw = vec![0u8; 27];
        let word: u32 = (7 << 16) | 20;
        raw[8..12].copy_from_slice(&word.to_ne_bytes());
        raw[20..27].copy_from_slice(b"/bin/x\0");
        assert_eq!(data_loc(&raw, f), Some(&b"/bin/x"[..]));
        // A locator outside the record is refused.
        let bad: u32 = (7 << 16) | 100;
        raw[8..12].copy_from_slice(&bad.to_ne_bytes());
        assert_eq!(data_loc(&raw, f), None);
        // A non-data_loc field never yields a string.
        assert_eq!(data_loc(&raw, fmt.field("pid", 4).unwrap()), None);
    }

    #[test]
    fn sample_decoding_takes_the_tracepoint_id_from_common_type() {
        let mut rec = vec![0u8; 36 + 8];
        rec[8..12].copy_from_slice(&4242u32.to_ne_bytes());
        rec[16..24].copy_from_slice(&777u64.to_ne_bytes());
        rec[24..28].copy_from_slice(&2u32.to_ne_bytes());
        rec[32..36].copy_from_slice(&8u32.to_ne_bytes());
        rec[36..38].copy_from_slice(&257u16.to_ne_bytes());
        let s = decode_sample(&rec, 2).unwrap();
        assert_eq!(s.tracepoint_id, 257);
        assert_eq!(s.pid, 4242);
        assert_eq!(s.timestamp_ns, 777);
        assert_eq!(s.cpu, 2);
        assert!(decode_sample(&rec[..30], 0).is_none());
    }
}
