//! Kernel-pushed cgroup placement events: the `cgroup:cgroup_mkdir`,
//! `cgroup:cgroup_rmdir` and `cgroup:cgroup_attach_task` tracepoints,
//! sampled through `perf_event_open` (ADR-019 §3, §6).
//!
//! **What they carry.** `mkdir`/`rmdir`: the hierarchy, the cgroup's level,
//! its kernel id and its path. `attach_task`: the destination's hierarchy,
//! level, id and path, the moved task's pid and `comm`. Each fires in the
//! **acting task's** context, so the sample's pid is the creator, remover or
//! writer of `cgroup.procs`. Layouts are read from tracefs at open; the ones
//! in the tests are this development kernel's (6.18).
//!
//! **What they prove.** That the kernel created, removed or migrated into a
//! cgroup at a kernel time, and which task did it. Placement by
//! `clone3(CLONE_INTO_CGROUP)` is not a migration and produces no attach
//! event (established on this kernel by `aip-placement/tests/kernel_facts`).
//!
//! **What they do not prove.** That the creator was entitled to create it —
//! the reconciler decides that from the creator's measured identity — or
//! anything at all on a host whose root starves or gates the ring.

use crate::linux::SourceError;
use crate::observed::KernelLifecycleKind;
use crate::perf::{data_loc, i32_at, u64_at, RawFormat};

pub const MKDIR_TRACEPOINT: &str = "cgroup/cgroup_mkdir";
pub const RMDIR_TRACEPOINT: &str = "cgroup/cgroup_rmdir";
pub const ATTACH_TRACEPOINT: &str = "cgroup/cgroup_attach_task";

fn need(raw: &[u8], fmt: &RawFormat) -> Result<(), SourceError> {
    if raw.len() < fmt.record_len {
        return Err(SourceError::Malformed(format!(
            "{} record {} bytes, layout needs {}",
            fmt.name,
            raw.len(),
            fmt.record_len
        )));
    }
    Ok(())
}

fn non_negative(fmt: &RawFormat, raw: &[u8], field: &str) -> Result<u32, SourceError> {
    let v = i32_at(raw, fmt.field(field, 4)?)
        .ok_or_else(|| SourceError::Malformed(format!("{} truncated at {field}", fmt.name)))?;
    u32::try_from(v)
        .map_err(|_| SourceError::Malformed(format!("{} has a negative {field}", fmt.name)))
}

fn id(fmt: &RawFormat, raw: &[u8], field: &str) -> Result<u64, SourceError> {
    u64_at(raw, fmt.field(field, 8)?)
        .ok_or_else(|| SourceError::Malformed(format!("{} truncated at {field}", fmt.name)))
}

fn string(fmt: &RawFormat, raw: &[u8], field: &str) -> Result<String, SourceError> {
    let f = fmt.field(field, 4)?;
    data_loc(raw, f)
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .ok_or_else(|| {
            SourceError::Malformed(format!("{} {field} locator outside record", fmt.name))
        })
}

/// Decode a `cgroup_mkdir` record; `actor_pid` is the sample's task.
pub fn parse_mkdir_record(
    fmt: &RawFormat,
    raw: &[u8],
    actor_pid: u32,
) -> Result<KernelLifecycleKind, SourceError> {
    need(raw, fmt)?;
    Ok(KernelLifecycleKind::CgroupCreated {
        hierarchy: non_negative(fmt, raw, "root")?,
        level: non_negative(fmt, raw, "level")?,
        cgroup_id: id(fmt, raw, "id")?,
        path: string(fmt, raw, "path")?,
        creator_pid: actor_pid,
    })
}

/// Decode a `cgroup_rmdir` record; `actor_pid` is the sample's task.
pub fn parse_rmdir_record(
    fmt: &RawFormat,
    raw: &[u8],
    actor_pid: u32,
) -> Result<KernelLifecycleKind, SourceError> {
    need(raw, fmt)?;
    Ok(KernelLifecycleKind::CgroupRemoved {
        hierarchy: non_negative(fmt, raw, "root")?,
        level: non_negative(fmt, raw, "level")?,
        cgroup_id: id(fmt, raw, "id")?,
        path: string(fmt, raw, "path")?,
        remover_pid: actor_pid,
    })
}

/// Decode a `cgroup_attach_task` record; `actor_pid` is the sample's task —
/// the writer of `cgroup.procs`, not necessarily the task moved.
pub fn parse_attach_record(
    fmt: &RawFormat,
    raw: &[u8],
    actor_pid: u32,
) -> Result<KernelLifecycleKind, SourceError> {
    need(raw, fmt)?;
    Ok(KernelLifecycleKind::CgroupAttach {
        hierarchy: non_negative(fmt, raw, "dst_root")?,
        dst_level: non_negative(fmt, raw, "dst_level")?,
        dst_cgroup_id: id(fmt, raw, "dst_id")?,
        dst_path: string(fmt, raw, "dst_path")?,
        pid: non_negative(fmt, raw, "pid")?,
        comm: string(fmt, raw, "comm")?,
        writer_pid: actor_pid,
    })
}

#[cfg(target_os = "linux")]
mod sys {
    use super::*;
    use crate::health::MechanismIntegrity;
    use crate::linux::ProcEvent;
    use crate::observed::CgroupSample;
    use crate::perf::{PerfTracepoints, SampleLayout};

    /// The cgroup placement tracepoint source.
    #[derive(Debug)]
    pub struct CgroupTracer {
        perf: PerfTracepoints,
        mkdir_id: u32,
        rmdir_id: u32,
        attach_id: u32,
    }

    impl CgroupTracer {
        /// Open all three tracepoints on every online CPU, with the acting
        /// task's cgroup in each sample. No fallback layout: a kernel without
        /// `PERF_SAMPLE_CGROUP` has no cgroup v2 attribution to place, so the
        /// source is `Unavailable` and nothing is simulated.
        pub fn open() -> Result<CgroupTracer, SourceError> {
            let perf = PerfTracepoints::open_with(
                &[MKDIR_TRACEPOINT, RMDIR_TRACEPOINT, ATTACH_TRACEPOINT],
                SampleLayout::WITH_CGROUP,
            )?;
            let id_of = |name: &str| {
                perf.format_named(name)
                    .map(|f| f.id)
                    .ok_or_else(|| SourceError::Malformed(format!("{name} tracepoint missing")))
            };
            Ok(CgroupTracer {
                mkdir_id: id_of(MKDIR_TRACEPOINT)?,
                rmdir_id: id_of(RMDIR_TRACEPOINT)?,
                attach_id: id_of(ATTACH_TRACEPOINT)?,
                perf,
            })
        }

        pub fn take_lost(&mut self) -> u64 {
            self.perf.take_lost()
        }

        /// The perf-gate integrity finding for these tracepoints, fail-closed
        /// exactly as [`crate::ProcessTracer::mechanism_integrity`].
        pub fn mechanism_integrity(&self) -> MechanismIntegrity {
            MechanismIntegrity::from_foreign_program_query(self.perf.foreign_bpf_program_count())
        }

        /// Next decoded placement event, waiting up to `timeout_ms`.
        /// Undecodable records are counted as lost, never guessed.
        pub fn next_event(&mut self, timeout_ms: i32) -> Result<Option<ProcEvent>, SourceError> {
            loop {
                let Some(s) = self.perf.next_sample(timeout_ms)? else {
                    return Ok(None);
                };
                let decoded = self.perf.format(s.tracepoint_id).and_then(|f| {
                    if s.tracepoint_id == self.mkdir_id {
                        parse_mkdir_record(f, &s.raw, s.pid).ok()
                    } else if s.tracepoint_id == self.rmdir_id {
                        parse_rmdir_record(f, &s.raw, s.pid).ok()
                    } else if s.tracepoint_id == self.attach_id {
                        parse_attach_record(f, &s.raw, s.pid).ok()
                    } else {
                        None
                    }
                });
                match decoded {
                    Some(kind) => {
                        return Ok(Some(ProcEvent {
                            kind,
                            cpu: s.cpu,
                            timestamp_ns: s.timestamp_ns,
                            cgroup: s.cgroup_id.map_or(CgroupSample::NotSampled, |cgroup_id| {
                                CgroupSample::Sampled { cgroup_id }
                            }),
                        }))
                    }
                    None => {
                        self.perf.take_lost();
                        continue;
                    }
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub use sys::CgroupTracer;

#[cfg(test)]
mod tests {
    use super::*;

    // This kernel's layouts (tracefs, 6.18.44).
    const DIR_FMT: &str = "field:int root;\toffset:8;\tsize:4;\tsigned:1;
field:int level;\toffset:12;\tsize:4;\tsigned:1;
field:u64 id;\toffset:16;\tsize:8;\tsigned:0;
field:__data_loc char[] path;\toffset:24;\tsize:4;\tsigned:0;
";
    const ATTACH_FMT: &str = "field:int dst_root;\toffset:8;\tsize:4;\tsigned:1;
field:int dst_level;\toffset:12;\tsize:4;\tsigned:1;
field:u64 dst_id;\toffset:16;\tsize:8;\tsigned:0;
field:int pid;\toffset:24;\tsize:4;\tsigned:1;
field:__data_loc char[] dst_path;\toffset:28;\tsize:4;\tsigned:0;
field:__data_loc char[] comm;\toffset:32;\tsize:4;\tsigned:0;
";

    fn loc(raw: &mut [u8], at: usize, off: usize, len: usize) {
        raw[at..at + 4].copy_from_slice(&(((len as u32) << 16) | off as u32).to_ne_bytes());
    }

    fn dir_record(root: i32, level: i32, id: u64, path: &[u8]) -> Vec<u8> {
        let mut raw = vec![0u8; 28 + path.len() + 1];
        raw[8..12].copy_from_slice(&root.to_ne_bytes());
        raw[12..16].copy_from_slice(&level.to_ne_bytes());
        raw[16..24].copy_from_slice(&id.to_ne_bytes());
        raw[28..28 + path.len()].copy_from_slice(path);
        loc(&mut raw, 24, 28, path.len() + 1);
        raw
    }

    fn attach_record(level: i32, id: u64, pid: i32, path: &[u8], comm: &[u8]) -> Vec<u8> {
        let base = 36;
        let mut raw = vec![0u8; base + path.len() + 1 + comm.len() + 1];
        raw[12..16].copy_from_slice(&level.to_ne_bytes());
        raw[16..24].copy_from_slice(&id.to_ne_bytes());
        raw[24..28].copy_from_slice(&pid.to_ne_bytes());
        raw[base..base + path.len()].copy_from_slice(path);
        loc(&mut raw, 28, base, path.len() + 1);
        let c = base + path.len() + 1;
        raw[c..c + comm.len()].copy_from_slice(comm);
        loc(&mut raw, 32, c, comm.len() + 1);
        raw
    }

    fn fmt(name: &str, body: &str) -> RawFormat {
        RawFormat::parse(400, name, body).unwrap()
    }

    #[test]
    fn mkdir_and_rmdir_decode_with_the_acting_task() {
        let f = fmt(MKDIR_TRACEPOINT, DIR_FMT);
        let raw = dir_record(0, 2, 9001, b"/aip/00112233445566778899aabbccddeeff");
        assert_eq!(
            parse_mkdir_record(&f, &raw, 77).unwrap(),
            KernelLifecycleKind::CgroupCreated {
                hierarchy: 0,
                level: 2,
                cgroup_id: 9001,
                path: "/aip/00112233445566778899aabbccddeeff".into(),
                creator_pid: 77,
            }
        );
        let r = fmt(RMDIR_TRACEPOINT, DIR_FMT);
        assert!(matches!(
            parse_rmdir_record(&r, &raw, 78).unwrap(),
            KernelLifecycleKind::CgroupRemoved {
                cgroup_id: 9001,
                remover_pid: 78,
                ..
            }
        ));
    }

    #[test]
    fn attach_decodes_the_moved_task_apart_from_the_writer() {
        let f = fmt(ATTACH_TRACEPOINT, ATTACH_FMT);
        let raw = attach_record(2, 9001, 4242, b"/aip/x", b"sh");
        assert_eq!(
            parse_attach_record(&f, &raw, 77).unwrap(),
            KernelLifecycleKind::CgroupAttach {
                hierarchy: 0,
                dst_level: 2,
                dst_cgroup_id: 9001,
                dst_path: "/aip/x".into(),
                pid: 4242,
                comm: "sh".into(),
                writer_pid: 77,
            }
        );
    }

    #[test]
    fn malformed_records_are_refused_not_guessed() {
        let f = fmt(MKDIR_TRACEPOINT, DIR_FMT);
        let good = dir_record(0, 2, 9001, b"/aip/x");
        assert!(parse_mkdir_record(&f, &good[..20], 1).is_err(), "truncated");
        assert!(
            parse_mkdir_record(&f, &dir_record(-1, 2, 1, b"/x"), 1).is_err(),
            "negative root"
        );
        assert!(
            parse_mkdir_record(&f, &dir_record(0, -2, 1, b"/x"), 1).is_err(),
            "negative level"
        );
        let mut bad = good.clone();
        loc(&mut bad, 24, 200, 4);
        assert!(
            parse_mkdir_record(&f, &bad, 1).is_err(),
            "path locator outside the record"
        );
        let a = fmt(ATTACH_TRACEPOINT, ATTACH_FMT);
        assert!(
            parse_attach_record(&a, &attach_record(2, 1, -5, b"/x", b"c"), 1).is_err(),
            "negative pid"
        );
    }
}
