//! Kernel-pushed process creation and execution: the
//! `sched:sched_process_fork` and `sched:sched_process_exec` tracepoints,
//! sampled through `perf_event_open` (`perf`).
//!
//! **What they carry.** `sched_process_fork` fires in the **parent's** task
//! context with `parent_pid`, `child_pid` and both `comm`s; `sched_process_exec`
//! fires in the **new image's** task context with the kernel's own `filename`
//! (the path the kernel executed), `pid` and `old_pid`. Measured on this host
//! before implementation; see `SNIFFER_DOG.md`.
//!
//! **What they prove.** That the kernel created a process and that a process
//! replaced its image, at kernel times, and — because fork runs in the parent
//! — which task did the spawning. The *content* of the executed image is not
//! in the event: the probe hashes `/proc/<pid>/exe` under a pidfd anchor.
//!
//! **What they do not prove.** Arguments, environment, what the child did,
//! or anything on a host whose root disables or starves the ring.

use crate::linux::{ProcEvent, SourceError};
use crate::observed::KernelLifecycleKind;
use crate::perf::{data_loc, i32_at, RawFormat};

pub const FORK_TRACEPOINT: &str = "sched/sched_process_fork";
pub const EXEC_TRACEPOINT: &str = "sched/sched_process_exec";

/// Decode a `sched_process_fork` record.
pub fn parse_fork_record(fmt: &RawFormat, raw: &[u8]) -> Result<KernelLifecycleKind, SourceError> {
    if raw.len() < fmt.record_len {
        return Err(SourceError::Malformed(format!(
            "fork record {} bytes, layout needs {}",
            raw.len(),
            fmt.record_len
        )));
    }
    let parent_pid = i32_at(raw, fmt.field("parent_pid", 4)?)
        .ok_or_else(|| SourceError::Malformed("fork record truncated at parent_pid".into()))?;
    let child_pid = i32_at(raw, fmt.field("child_pid", 4)?)
        .ok_or_else(|| SourceError::Malformed("fork record truncated at child_pid".into()))?;
    let (parent_pid, child_pid) = match (u32::try_from(parent_pid), u32::try_from(child_pid)) {
        (Ok(p), Ok(c)) => (p, c),
        _ => {
            return Err(SourceError::Malformed(
                "fork record has a negative pid".into(),
            ))
        }
    };
    let comm = |name: &str| -> String {
        fmt.field(name, 4)
            .ok()
            .and_then(|f| data_loc(raw, f))
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default()
    };
    Ok(KernelLifecycleKind::ProcessSpawn {
        parent_pid,
        child_pid,
        parent_comm: comm("parent_comm"),
        child_comm: comm("child_comm"),
    })
}

/// Decode a `sched_process_exec` record.
pub fn parse_exec_record(fmt: &RawFormat, raw: &[u8]) -> Result<KernelLifecycleKind, SourceError> {
    if raw.len() < fmt.record_len {
        return Err(SourceError::Malformed(format!(
            "exec record {} bytes, layout needs {}",
            raw.len(),
            fmt.record_len
        )));
    }
    let pid = i32_at(raw, fmt.field("pid", 4)?)
        .ok_or_else(|| SourceError::Malformed("exec record truncated at pid".into()))?;
    let old_pid = i32_at(raw, fmt.field("old_pid", 4)?)
        .ok_or_else(|| SourceError::Malformed("exec record truncated at old_pid".into()))?;
    let (pid, old_pid) = match (u32::try_from(pid), u32::try_from(old_pid)) {
        (Ok(p), Ok(o)) => (p, o),
        _ => {
            return Err(SourceError::Malformed(
                "exec record has a negative pid".into(),
            ))
        }
    };
    let filename = data_loc(raw, fmt.field("filename", 4)?)
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .ok_or_else(|| SourceError::Malformed("exec record filename locator invalid".into()))?;
    Ok(KernelLifecycleKind::ProcessExec {
        pid,
        old_pid,
        filename,
    })
}

#[cfg(target_os = "linux")]
mod sys {
    use super::*;
    use crate::health::MechanismIntegrity;
    use crate::perf::PerfTracepoints;

    /// The fork + exec tracepoint source.
    #[derive(Debug)]
    pub struct ProcessTracer {
        perf: PerfTracepoints,
        fork_id: u32,
        exec_id: u32,
    }

    impl ProcessTracer {
        /// Open both tracepoints on every online CPU. `Unavailable` when
        /// tracefs or the perf permission is missing; nothing is simulated.
        pub fn open() -> Result<ProcessTracer, SourceError> {
            let perf = PerfTracepoints::open(&[FORK_TRACEPOINT, EXEC_TRACEPOINT])?;
            let fork_id = perf
                .format_named(FORK_TRACEPOINT)
                .map(|f| f.id)
                .ok_or_else(|| SourceError::Malformed("fork tracepoint missing".into()))?;
            let exec_id = perf
                .format_named(EXEC_TRACEPOINT)
                .map(|f| f.id)
                .ok_or_else(|| SourceError::Malformed("exec tracepoint missing".into()))?;
            Ok(ProcessTracer {
                perf,
                fork_id,
                exec_id,
            })
        }

        pub fn take_lost(&mut self) -> u64 {
            self.perf.take_lost()
        }

        /// The tracer's mechanism-integrity finding: is a foreign eBPF program
        /// gating the `sched:sched_process_{fork,exec}` tracepoints it samples?
        /// Both are perf-tracepoint mechanisms exposed to the eBPF submission
        /// gate, so a program on either can silently suppress this tracer's
        /// events. The collector feeds this to
        /// [`crate::CollectorSigner::note_mechanism_integrity`] each health
        /// cycle so a blinded tracer signs
        /// [`crate::ObserverState::IntegrityUnknown`] instead of a false
        /// `Active`.
        ///
        /// Fail-closed: if the kernel refuses the query, integrity cannot be
        /// established, so the finding is `ForeignTracepointGate` (unknown),
        /// never a silent `Verified`.
        pub fn mechanism_integrity(&self) -> MechanismIntegrity {
            match self.perf.foreign_bpf_program_count() {
                Ok(0) => MechanismIntegrity::Verified,
                Ok(n) => MechanismIntegrity::ForeignTracepointGate {
                    foreign_programs: n,
                },
                // Cannot establish capability → not clean.
                Err(_) => MechanismIntegrity::ForeignTracepointGate {
                    foreign_programs: 0,
                },
            }
        }

        /// Next decoded fork or exec, waiting up to `timeout_ms`; `Ok(None)`
        /// on timeout. Undecodable records are counted as lost, never guessed.
        pub fn next_event(&mut self, timeout_ms: i32) -> Result<Option<ProcEvent>, SourceError> {
            loop {
                let Some(s) = self.perf.next_sample(timeout_ms)? else {
                    return Ok(None);
                };
                let decoded = if s.tracepoint_id == self.fork_id {
                    self.perf
                        .format(self.fork_id)
                        .and_then(|f| parse_fork_record(f, &s.raw).ok())
                } else if s.tracepoint_id == self.exec_id {
                    self.perf
                        .format(self.exec_id)
                        .and_then(|f| parse_exec_record(f, &s.raw).ok())
                } else {
                    None
                };
                match decoded {
                    Some(kind) => {
                        return Ok(Some(ProcEvent {
                            kind,
                            cpu: s.cpu,
                            timestamp_ns: s.timestamp_ns,
                        }))
                    }
                    None => {
                        // Count and continue; a record we cannot read is loss.
                        self.perf.take_lost();
                        continue;
                    }
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub use sys::ProcessTracer;

#[cfg(test)]
mod tests {
    use super::*;

    const FORK_FMT: &str = "field:__data_loc char[] parent_comm;\toffset:8;\tsize:4;\tsigned:0;
field:pid_t parent_pid;\toffset:12;\tsize:4;\tsigned:1;
field:__data_loc char[] child_comm;\toffset:16;\tsize:4;\tsigned:0;
field:pid_t child_pid;\toffset:20;\tsize:4;\tsigned:1;
";
    const EXEC_FMT: &str = "field:__data_loc char[] filename;\toffset:8;\tsize:4;\tsigned:0;
field:pid_t pid;\toffset:12;\tsize:4;\tsigned:1;
field:pid_t old_pid;\toffset:16;\tsize:4;\tsigned:1;
";

    fn fork_record(parent: i32, child: i32) -> Vec<u8> {
        let mut r = vec![0u8; 24 + 16];
        let pc: u32 = (6 << 16) | 24;
        let cc: u32 = (6 << 16) | 30;
        r[8..12].copy_from_slice(&pc.to_ne_bytes());
        r[12..16].copy_from_slice(&parent.to_ne_bytes());
        r[16..20].copy_from_slice(&cc.to_ne_bytes());
        r[20..24].copy_from_slice(&child.to_ne_bytes());
        r[24..30].copy_from_slice(b"agent\0");
        r[30..36].copy_from_slice(b"sleep\0");
        r
    }

    fn exec_record(pid: i32, old: i32, filename: &[u8]) -> Vec<u8> {
        let mut r = vec![0u8; 20 + filename.len() + 1];
        let loc: u32 = (((filename.len() + 1) as u32) << 16) | 20;
        r[8..12].copy_from_slice(&loc.to_ne_bytes());
        r[12..16].copy_from_slice(&pid.to_ne_bytes());
        r[16..20].copy_from_slice(&old.to_ne_bytes());
        r[20..20 + filename.len()].copy_from_slice(filename);
        r
    }

    #[test]
    fn fork_decodes_parent_as_the_actor_and_child_as_the_subject_of_the_spawn() {
        let f = RawFormat::parse(257, FORK_TRACEPOINT, FORK_FMT).unwrap();
        let k = parse_fork_record(&f, &fork_record(1000, 1001)).unwrap();
        assert_eq!(
            k,
            KernelLifecycleKind::ProcessSpawn {
                parent_pid: 1000,
                child_pid: 1001,
                parent_comm: "agent".into(),
                child_comm: "sleep".into(),
            }
        );
        assert_eq!(
            k.subject_pid(),
            Some(1000),
            "the spawning task is the actor"
        );
        assert_eq!(k.spawned_child_pid(), Some(1001));
    }

    #[test]
    fn exec_decodes_the_kernel_filename_and_the_new_image_task() {
        let f = RawFormat::parse(256, EXEC_TRACEPOINT, EXEC_FMT).unwrap();
        let k = parse_exec_record(&f, &exec_record(1001, 1001, b"/bin/sleep")).unwrap();
        assert_eq!(
            k,
            KernelLifecycleKind::ProcessExec {
                pid: 1001,
                old_pid: 1001,
                filename: "/bin/sleep".into(),
            }
        );
        assert_eq!(k.subject_pid(), Some(1001));
    }

    #[test]
    fn malformed_records_are_refused_not_guessed() {
        let f = RawFormat::parse(257, FORK_TRACEPOINT, FORK_FMT).unwrap();
        assert!(parse_fork_record(&f, &fork_record(1000, 1001)[..20]).is_err());
        assert!(parse_fork_record(&f, &fork_record(-1, 1001)).is_err());
        let e = RawFormat::parse(256, EXEC_TRACEPOINT, EXEC_FMT).unwrap();
        assert!(parse_exec_record(&e, &exec_record(1001, 1001, b"/bin/sleep")[..16]).is_err());
        let mut bad_loc = exec_record(1001, 1001, b"/bin/sleep");
        let loc: u32 = (40 << 16) | 20; // length past the record
        bad_loc[8..12].copy_from_slice(&loc.to_ne_bytes());
        assert!(parse_exec_record(&e, &bad_loc).is_err());
        // A fork layout missing a field is refused.
        let broken = FORK_FMT.replace("child_pid", "kid_pid");
        let f2 = RawFormat::parse(257, FORK_TRACEPOINT, &broken).unwrap();
        assert!(parse_fork_record(&f2, &fork_record(1, 2)).is_err());
    }
}
