//! Delegation-chain presentation: turn the [`LineageEdge`]s the engine
//! derives from attested batches into a deterministic, auditable report.
//!
//! # What this module is, and what it is not
//!
//! [`crate::derive_lineage_edges`] is the domain: it decides *whether* a
//! parent→child edge is supported by signed evidence (an anchored fork, a
//! paired exec, a start-verified child). This module does not re-decide any
//! of that. It only **orders and renders** the edges the domain returned, so
//! the same archive always produces byte-identical output regardless of the
//! order the batches happened to arrive in.
//!
//! # Why ordering is load-bearing
//!
//! An auditor compares two runs, or a run against a recorded baseline, by
//! diffing the text. If the edge order depended on a `HashMap` iteration or
//! on file arrival order, an identical delegation chain would diff as
//! changed. The order here is a total order over fields that are all present
//! on every edge — `(batch_sequence, fork ns, child pid, child start tick)`
//! — so it is deterministic and stable, and never falls back to insertion
//! order.
//!
//! # What a rendered edge asserts
//!
//! Exactly what the edge asserts: that the collector-signed evidence contains
//! an anchored fork by `parent` and a start-verified exec of `child`, paired
//! through the batch's clock anchor. It does **not** assert that the child
//! was authorised, nor attribute it to any agent identity — that is the
//! reconciler's job (`reconcile_lineage`), against a decision-point-signed
//! `ExpectedExecution`. This report is the observed lineage alone.

use std::fmt::Write as _;

use crate::action::LineageEdge;

/// Order `edges` into the canonical audit order, in place.
///
/// Total order over `(batch_sequence, fork.kernel_timestamp_ns,
/// child.pid, child.pid_start_time_ticks)`. Every component is present on
/// every edge, so no two distinct edges compare equal by accident and the
/// sort never depends on prior order. Deterministic: the same set of edges
/// always yields the same sequence.
pub fn sort_edges(edges: &mut [LineageEdge]) {
    edges.sort_by(|a, b| {
        a.batch_sequence
            .cmp(&b.batch_sequence)
            .then(a.fork.kernel_timestamp_ns.cmp(&b.fork.kernel_timestamp_ns))
            .then(a.child.process.pid.cmp(&b.child.process.pid))
            .then(
                a.child
                    .process
                    .pid_start_time_ticks
                    .cmp(&b.child.process.pid_start_time_ticks),
            )
    });
}

/// Count of distinct parent instances across `edges`.
///
/// Two edges share a parent only if the full [`aip_types::ProcessInstance`]
/// matches — pid *and* start tick *and* boot id — because a recycled pid is a
/// different instance. Used in the summary line, not for any verdict.
pub fn distinct_parents(edges: &[LineageEdge]) -> usize {
    let mut seen: Vec<&aip_types::ProcessInstance> = Vec::new();
    for e in edges {
        if !seen.iter().any(|p| **p == e.parent.process) {
            seen.push(&e.parent.process);
        }
    }
    seen.len()
}

/// Render one edge as a single line: parent instance → child instance, the
/// executed image's content hash, the kernel filename (context), the
/// mechanism, and the batch sequence that carried the fork.
///
/// The content hash is the identity; the path is shown after it, labelled, so
/// no reader mistakes the kernel's `filename` for proof of what ran.
pub fn render_edge(edge: &LineageEdge) -> String {
    format!(
        "seq={seq} fork@{fork}ns  \
         parent pid={ppid} start={pstart}  ->  \
         child pid={cpid} start={cstart}  \
         image={image}  path={path:?}  via={mech:?}",
        seq = edge.batch_sequence,
        fork = edge.fork.kernel_timestamp_ns,
        ppid = edge.parent.process.pid,
        pstart = edge.parent.process.pid_start_time_ticks,
        cpid = edge.child.process.pid,
        cstart = edge.child.process.pid_start_time_ticks,
        image = hex32(&edge.image_sha256),
        path = edge.filename,
        mech = edge.mechanism,
    )
}

/// Render the full report: a header, one line per edge in canonical order,
/// and a trailing summary. Pure over `edges`; the caller supplies the count
/// of batches examined so the header can state coverage without this module
/// touching the archive.
///
/// `edges` is taken by value and sorted here, so the caller cannot pass a
/// differently-ordered slice and get non-canonical output.
pub fn render_report(mut edges: Vec<LineageEdge>, batches_examined: usize) -> String {
    sort_edges(&mut edges);
    let mut out = String::new();
    let _ = writeln!(
        out,
        "DELEGATION CHAIN (observed lineage, collector-signed evidence)"
    );
    let _ = writeln!(
        out,
        "batches examined : {batches_examined}\nedges derived    : {}",
        edges.len()
    );
    let _ = writeln!(out, "distinct parents : {}", distinct_parents(&edges));
    let _ = writeln!(out, "---");
    if edges.is_empty() {
        // An explicit statement, never a blank pass: no start-verified
        // parent→child edge is supported by this evidence.
        let _ = writeln!(
            out,
            "NO EDGE: the evidence supports no start-verified parent->child \
             execution. This is not an attribution to no one; it is the \
             absence of the proof an edge requires (an anchored fork paired \
             with a start-verified exec)."
        );
        return out;
    }
    for e in &edges {
        let _ = writeln!(out, "{}", render_edge(e));
    }
    let _ = writeln!(
        out,
        "---\nEach line is observed lineage only. Attribution to an authorised \
         agent identity is a reconciler verdict against a signed \
         ExpectedExecution, not asserted here."
    );
    out
}

/// Lowercase hex of a 32-byte digest, with no allocation surprises: fixed
/// 64-char output.
fn hex32(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use aip_observe::{ObservedProcess, SourceMechanism};
    use aip_types::ProcessInstance;

    use crate::action::EventPosition;

    fn proc(pid: u32, start: u64, image: u8) -> ObservedProcess {
        ObservedProcess {
            process: ProcessInstance {
                pid,
                pid_start_time_ticks: start,
                boot_id: [9u8; 16],
            },
            exe_content_sha256: [image; 32],
            exe_path: "/x".into(),
            container: None,
        }
    }

    fn edge(seq: u64, fork_ns: u64, ppid: u32, cpid: u32, cstart: u64) -> LineageEdge {
        LineageEdge {
            parent: proc(ppid, 100, 1),
            child: proc(cpid, cstart, 2),
            fork: EventPosition {
                batch_sequence: seq,
                index: 0,
                kernel_timestamp_ns: fork_ns,
            },
            exec: EventPosition {
                batch_sequence: seq,
                index: 1,
                kernel_timestamp_ns: fork_ns + 1,
            },
            image_sha256: [2u8; 32],
            filename: "/usr/bin/python3".into(),
            mechanism: SourceMechanism::SchedTracepoint,
            batch_sequence: seq,
        }
    }

    #[test]
    fn ordering_is_total_and_independent_of_input_order() {
        let a = edge(2, 500, 10, 20, 7);
        let b = edge(1, 900, 11, 21, 8);
        let c = edge(1, 400, 12, 22, 9);
        let mut forward = vec![a.clone(), b.clone(), c.clone()];
        let mut reverse = vec![c.clone(), b.clone(), a.clone()];
        sort_edges(&mut forward);
        sort_edges(&mut reverse);
        assert_eq!(forward, reverse, "sort must not depend on input order");
        // Expected order: seq 1 (ns 400), seq 1 (ns 900), seq 2 (ns 500).
        assert_eq!(forward[0].fork.kernel_timestamp_ns, 400);
        assert_eq!(forward[1].fork.kernel_timestamp_ns, 900);
        assert_eq!(forward[2].batch_sequence, 2);
    }

    #[test]
    fn a_recycled_pid_is_a_distinct_parent() {
        // Same pid, different start tick and thus a different instance.
        let mut e1 = edge(1, 100, 10, 20, 7);
        let mut e2 = edge(2, 200, 10, 21, 8);
        e1.parent.process.pid_start_time_ticks = 100;
        e2.parent.process.pid_start_time_ticks = 200;
        assert_eq!(distinct_parents(&[e1, e2]), 2);
    }

    #[test]
    fn one_parent_two_children_is_one_distinct_parent() {
        let e1 = edge(1, 100, 10, 20, 7);
        let mut e2 = edge(1, 150, 10, 21, 8);
        // Same parent instance (pid + start tick), two children.
        e2.parent = e1.parent.clone();
        assert_eq!(distinct_parents(&[e1, e2]), 1);
    }

    #[test]
    fn an_empty_report_states_no_edge_not_a_blank_pass() {
        let text = render_report(vec![], 3);
        assert!(text.contains("batches examined : 3"), "{text}");
        assert!(text.contains("edges derived    : 0"), "{text}");
        assert!(text.contains("NO EDGE"), "{text}");
    }

    #[test]
    fn a_rendered_edge_shows_the_content_hash_and_labels_the_path() {
        let text = render_report(vec![edge(1, 100, 10, 20, 7)], 1);
        assert!(text.contains("parent pid=10"), "{text}");
        assert!(text.contains("child pid=20"), "{text}");
        assert!(text.contains(&"02".repeat(32)), "image hash absent: {text}");
        assert!(text.contains("path="), "path label absent: {text}");
        assert!(
            text.contains("Attribution to an authorised agent identity"),
            "the observed-only disclaimer must be present: {text}"
        );
    }

    #[test]
    fn the_report_is_byte_stable_across_runs() {
        let e = vec![edge(2, 500, 10, 20, 7), edge(1, 400, 12, 22, 9)];
        let first = render_report(e.clone(), 2);
        let second = render_report(e, 2);
        assert_eq!(first, second);
    }
}
