//! On the running kernel: the sched tracer asks for, and receives, the
//! cgroup v2 id of the task an exec fired in — the id of the cgroup this
//! test runs in, as the hierarchy reports it (the directory's inode).
//!
//! Needs tracefs, perf permission and a cgroup v2 hierarchy. Without them it
//! prints `SKIPPED — <why>`, or fails under `AIP_REQUIRE_LIVE=1`.

#![cfg(target_os = "linux")]

use aip_observe::{CgroupSample, KernelLifecycleKind, ProcessTracer};
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(5);
const POLL_MS: i32 = 20;

fn skip(why: &str) {
    if std::env::var_os("AIP_REQUIRE_LIVE").is_some() {
        panic!("cgroup_live: required live capability missing — {why}");
    }
    eprintln!("cgroup_live: SKIPPED — {why}");
}

/// The cgroup v2 directory this process lives in, from `/proc/self/cgroup`
/// (`0::<path>`) under the v2 mount from `/proc/self/mountinfo`.
fn own_v2_cgroup_dir() -> Option<std::path::PathBuf> {
    let rel = std::fs::read_to_string("/proc/self/cgroup")
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("0::").map(str::to_owned))?;
    let mount = std::fs::read_to_string("/proc/self/mountinfo")
        .ok()?
        .lines()
        .find_map(|l| {
            let f: Vec<&str> = l.split(' ').collect();
            let sep = f.iter().position(|x| *x == "-")?;
            (f.get(sep + 1) == Some(&"cgroup2")).then(|| f[4].to_owned())
        })?;
    Some(std::path::Path::new(&mount).join(rel.trim_start_matches('/')))
}

#[test]
fn an_exec_sample_carries_the_execing_tasks_cgroup_id() {
    let mut tracer = match ProcessTracer::open() {
        Ok(t) => t,
        Err(e) => return skip(&format!("sched tracer unavailable: {e:?}")),
    };
    let Some(dir) = own_v2_cgroup_dir() else {
        return skip("no cgroup v2 hierarchy for this process");
    };
    let expected = std::fs::metadata(&dir).unwrap().ino();
    assert!(
        tracer.samples_cgroup(),
        "this kernel accepts PERF_SAMPLE_CGROUP"
    );

    let child = std::process::Command::new("/bin/true").spawn().unwrap();
    let pid = child.id();
    let _ = { child }.wait();
    let start = Instant::now();
    while start.elapsed() < DEADLINE {
        let Some(ev) = tracer.next_event(POLL_MS).unwrap() else {
            continue;
        };
        if matches!(ev.kind, KernelLifecycleKind::ProcessExec { pid: p, .. } if p == pid) {
            assert_eq!(
                ev.cgroup,
                CgroupSample::Sampled {
                    cgroup_id: expected
                }
            );
            return;
        }
    }
    panic!("no exec event for pid {pid} within {DEADLINE:?}");
}
