//! The kernel facts ADR-019 rests on, established on the running kernel
//! through the observer's own perf sampler — not assumed from documentation.
//!
//! Each test needs root, a cgroup v2 hierarchy and a mounted tracefs. A host
//! without one prints `SKIPPED — <reason>` and asserts nothing: an absent
//! capability is reported, never simulated (loop rule 9). On the development
//! host all three are present and every test runs.

#![cfg(target_os = "linux")]

mod common;

use aip_observe::{data_loc, PerfTracepoints, RawSample, SampleLayout};
use aip_placement::{spawn_into, PlacementError, PlacementRoot};
use std::collections::BTreeSet;
use std::ffi::CStr;
use std::time::{Duration, Instant};

const ROOT_NAME: &str = "aip-placement-kernel-facts";
/// How long to keep draining after an action, for samples still in flight.
const SETTLE: Duration = Duration::from_millis(300);
const POLL_MS: i32 = 20;
/// Short-lived children per run of the XI-H2-shaped workload.
const CHILDREN: usize = 100;
/// Placements created and removed in the id-reuse test.
const CHURN: usize = 200;

const TRUE: &CStr = c"/bin/true";
const SH: &CStr = c"/bin/sh";
const SLEEP: &CStr = c"/bin/sleep";

/// Removes a test's placement even when the test panics. Test-only: in the
/// library, when a placement is removed is policy, not a destructor's side
/// effect. An already-removed directory is not an error here.
struct Cleanup(std::path::PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.0);
    }
}

fn guard(cg: &aip_placement::DecisionCgroup) -> Cleanup {
    Cleanup(cg.path().to_path_buf())
}

/// One decision point for the whole file; each placement is a fresh signed
/// decision from it.
fn decisions() -> &'static common::Authorised {
    static A: std::sync::OnceLock<common::Authorised> = std::sync::OnceLock::new();
    A.get_or_init(common::authorised)
}

/// Place a fresh signed decision.
fn place(root: &PlacementRoot) -> aip_placement::DecisionCgroup {
    let a = decisions();
    root.place(&a.expectation(), &a.authority(), a.now).unwrap()
}

fn root_or_skip(test: &str) -> Option<PlacementRoot> {
    match PlacementRoot::ensure(ROOT_NAME) {
        Ok(r) => Some(r),
        Err(e) => {
            common::skip(test, &format!("no placement root: {e}"));
            None
        }
    }
}

fn sampler_or_skip(test: &str, names: &[&str]) -> Option<PerfTracepoints> {
    match PerfTracepoints::open_with(names, SampleLayout::WITH_CGROUP) {
        Ok(t) => Some(t),
        Err(e) => {
            common::skip(
                test,
                &format!("perf sampler with PERF_SAMPLE_CGROUP unavailable: {e:?}"),
            );
            None
        }
    }
}

/// Every sample until `SETTLE` passes with nothing new.
fn drain(t: &mut PerfTracepoints) -> Vec<RawSample> {
    let mut out = Vec::new();
    let mut quiet_since = Instant::now();
    while quiet_since.elapsed() < SETTLE {
        if let Some(s) = t.next_sample(POLL_MS).unwrap() {
            out.push(s);
            quiet_since = Instant::now();
        }
    }
    out
}

fn named<'a>(t: &PerfTracepoints, samples: &'a [RawSample], name: &str) -> Vec<&'a RawSample> {
    let id = t.format_named(name).unwrap().id;
    samples.iter().filter(|s| s.tracepoint_id == id).collect()
}

fn string_field(t: &PerfTracepoints, name: &str, field: &str, s: &RawSample) -> String {
    let f = t
        .format_named(name)
        .unwrap()
        .field(field, 4)
        .unwrap()
        .clone();
    String::from_utf8_lossy(data_loc(&s.raw, &f).unwrap()).into_owned()
}

fn u64_field(t: &PerfTracepoints, name: &str, field: &str, s: &RawSample) -> u64 {
    let f = t
        .format_named(name)
        .unwrap()
        .field(field, 8)
        .unwrap()
        .clone();
    aip_observe::perf::u64_at(&s.raw, &f).unwrap()
}

fn i32_field(t: &PerfTracepoints, name: &str, field: &str, s: &RawSample) -> i32 {
    let f = t
        .format_named(name)
        .unwrap()
        .field(field, 4)
        .unwrap()
        .clone();
    aip_observe::perf::i32_at(&s.raw, &f).unwrap()
}

const EXEC: &str = "sched/sched_process_exec";
const MKDIR: &str = "cgroup/cgroup_mkdir";
const ATTACH: &str = "cgroup/cgroup_attach_task";

/// The id the kernel writes into an exec sample is the id the placement
/// reports for its cgroup (the cgroup2 inode number).
#[test]
fn an_exec_sample_carries_the_placements_cgroup_id() {
    let (Some(root), Some(mut t)) = (root_or_skip("f1"), sampler_or_skip("f1", &[EXEC])) else {
        return;
    };
    let cg = place(&root);
    let _g_cg = guard(&cg);
    let child = spawn_into(&cg, TRUE, &["true"], &[]).unwrap();
    let pid = child.pid() as u32;
    assert_eq!(child.wait().unwrap(), 0);
    let samples = drain(&mut t);
    assert_eq!(
        t.take_lost(),
        0,
        "kernel reported loss; result not interpretable"
    );
    let mine: Vec<_> = named(&t, &samples, EXEC)
        .into_iter()
        .filter(|s| s.pid == pid)
        .collect();
    assert_eq!(mine.len(), 1, "exactly one exec by the child");
    assert_eq!(mine[0].cgroup_id, Some(cg.id()));
    cg.remove().unwrap();
}

/// The XI-H2 shape: a shell spawning children that exit at once. Every one
/// of their execs carries the placement's cgroup id — nothing has to be
/// alive when the observer looks.
#[test]
fn every_short_lived_child_of_a_placed_shell_is_attributed() {
    let (Some(root), Some(mut t)) = (root_or_skip("f2"), sampler_or_skip("f2", &[EXEC])) else {
        return;
    };
    let cg = place(&root);
    let _g_cg = guard(&cg);
    let script = format!("i=0; while [ $i -lt {CHILDREN} ]; do /bin/true; i=$((i+1)); done");
    let child = spawn_into(&cg, SH, &["sh", "-c", &script], &[]).unwrap();
    assert_eq!(child.wait().unwrap(), 0);
    let samples = drain(&mut t);
    assert_eq!(
        t.take_lost(),
        0,
        "kernel reported loss; count not interpretable"
    );
    let in_cg: Vec<_> = named(&t, &samples, EXEC)
        .into_iter()
        .filter(|s| s.cgroup_id == Some(cg.id()))
        .collect();
    let trues = in_cg
        .iter()
        .filter(|s| string_field(&t, EXEC, "filename", s) == "/bin/true")
        .count();
    assert_eq!(trues, CHILDREN, "every short-lived child attributed");
    assert_eq!(
        in_cg.len(),
        CHILDREN + 1,
        "the shell and its children, nothing else"
    );
    cg.remove().unwrap();
}

/// Attribution is by placement, not by binary: the same program run outside
/// the placement is not attributed to it.
#[test]
fn a_decoy_running_the_same_binary_outside_is_not_attributed() {
    let (Some(root), Some(mut t)) = (root_or_skip("f3"), sampler_or_skip("f3", &[EXEC])) else {
        return;
    };
    let cg = place(&root);
    let _g_cg = guard(&cg);
    let inside = spawn_into(&cg, TRUE, &["true"], &[]).unwrap();
    let inside_pid = inside.pid() as u32;
    let decoy = std::process::Command::new("/bin/true").spawn().unwrap();
    let decoy_pid = decoy.id();
    assert_eq!(inside.wait().unwrap(), 0);
    let _ = { decoy }.wait();
    let samples = drain(&mut t);
    assert_eq!(t.take_lost(), 0);
    let execs = named(&t, &samples, EXEC);
    let of = |pid| execs.iter().find(|s| s.pid == pid).copied().unwrap();
    assert_eq!(of(inside_pid).cgroup_id, Some(cg.id()));
    let d = of(decoy_pid);
    assert!(
        d.cgroup_id.is_some(),
        "the decoy's sample still names its own cgroup"
    );
    assert_ne!(d.cgroup_id, Some(cg.id()));
    cg.remove().unwrap();
}

fn attaches_of(t: &PerfTracepoints, samples: &[RawSample], pid: i32) -> Vec<RawSample> {
    named(t, samples, ATTACH)
        .into_iter()
        .filter(|s| i32_field(t, ATTACH, "pid", s) == pid)
        .cloned()
        .collect()
}

/// Placement by `CLONE_INTO_CGROUP` is not a migration; writing
/// `cgroup.procs` is, and the attach sample names the writer.
#[test]
fn clone_into_cgroup_is_not_a_migration_but_a_procs_write_is() {
    let (Some(root), Some(mut t)) = (root_or_skip("f4"), sampler_or_skip("f4", &[ATTACH])) else {
        return;
    };
    let a = place(&root);
    let _g_a = guard(&a);
    let b = place(&root);
    let _g_b = guard(&b);
    let child = spawn_into(&a, SLEEP, &["sleep", "1"], &[]).unwrap();
    let pid = child.pid();
    let before = drain(&mut t);
    assert!(
        attaches_of(&t, &before, pid).is_empty(),
        "CLONE_INTO_CGROUP produced an attach event"
    );

    std::fs::write(b.path().join("cgroup.procs"), pid.to_string()).unwrap();
    let after = drain(&mut t);
    assert_eq!(t.take_lost(), 0);
    let moved = attaches_of(&t, &after, pid);
    // A hybrid host also carries v1 hierarchies; the v2 move is the one
    // whose destination id is the v2 cgroup's.
    let v2: Vec<_> = moved
        .iter()
        .filter(|s| u64_field(&t, ATTACH, "dst_id", s) == b.id())
        .collect();
    assert_eq!(v2.len(), 1, "exactly one v2 migration recorded: {moved:?}");
    assert_eq!(
        v2[0].pid,
        std::process::id(),
        "the sample names the writing task"
    );
    assert_eq!(child.wait().unwrap(), 0);
    a.remove().unwrap();
    b.remove().unwrap();
}

/// A placement's creation is visible to the observer with the kernel's id
/// and the creating task — what lets the reconciler require that the
/// creator was the supervisor (ADR-019 §3).
#[test]
fn cgroup_mkdir_names_the_creating_task_and_the_id() {
    let (Some(root), Some(mut t)) = (root_or_skip("f5"), sampler_or_skip("f5", &[MKDIR])) else {
        return;
    };
    let cg = place(&root);
    let _g_cg = guard(&cg);
    let id = *cg.decision_id();
    let samples = drain(&mut t);
    assert_eq!(t.take_lost(), 0);
    let made: Vec<_> = named(&t, &samples, MKDIR)
        .into_iter()
        .filter(|s| u64_field(&t, MKDIR, "id", s) == cg.id())
        .collect();
    assert_eq!(made.len(), 1);
    assert_eq!(made[0].pid, std::process::id());
    let path = string_field(&t, MKDIR, "path", made[0]);
    assert!(
        path.ends_with(&aip_placement::decision_cgroup_name(&id)),
        "path {path} names the decision"
    );
    cg.remove().unwrap();
}

/// Ids are not reused while placements come and go within one boot.
/// Empirical over `CHURN` placements; the kernel-source argument is in
/// ADR-019 §4.
#[test]
fn cgroup_ids_are_not_reused_under_churn() {
    let Some(root) = root_or_skip("f6") else {
        return;
    };
    let mut seen = BTreeSet::new();
    for _ in 0..CHURN {
        let cg = place(&root);
        let _g_cg = guard(&cg);
        assert!(seen.insert(cg.id()), "cgroup id {} reused", cg.id());
        cg.remove().unwrap();
    }
}

#[test]
fn a_decision_is_placed_once() {
    let Some(root) = root_or_skip("f7") else {
        return;
    };
    let a = decisions();
    let ee = a.expectation();
    let cg = root.place(&ee, &a.authority(), a.now).unwrap();
    let _g_cg = guard(&cg);
    assert!(matches!(
        root.place(&ee, &a.authority(), a.now),
        Err(PlacementError::AlreadyPlaced(_))
    ));
    cg.remove().unwrap();
}

/// Removing a placement that still holds work is refused, not forced.
#[test]
fn a_populated_placement_is_not_removed() {
    let Some(root) = root_or_skip("f8") else {
        return;
    };
    let cg = place(&root);
    let _g_cg = guard(&cg);
    let path = cg.path().to_path_buf();
    let child = spawn_into(&cg, SLEEP, &["sleep", "1"], &[]).unwrap();
    assert!(matches!(
        cg.remove(),
        Err(PlacementError::StillPopulated(_))
    ));
    assert!(path.is_dir());
    assert_eq!(child.wait().unwrap(), 0);
    std::fs::remove_dir(&path).unwrap();
}
