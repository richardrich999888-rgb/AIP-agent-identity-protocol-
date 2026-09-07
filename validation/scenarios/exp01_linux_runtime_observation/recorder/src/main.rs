//! Drives Sniffer Dog 2.0's live process-lifecycle sensor and records exactly
//! what it emitted.
//!
//! This binary is an instrument driver, not an observer. It adds no sensing,
//! defines no evidence semantics, decodes nothing itself, and makes no
//! judgement about any event. It calls `aip_observe::ProcessTracer` — the
//! production sensor — and serialises its output verbatim so the comparison
//! step has something to compare.
//!
//! Reported loss is written out as loss. A record the sensor could not decode
//! is loss, and appears as such. Nothing is inferred to fill a gap: an
//! unobserved window is unobserved, which is Vanian's own rule.
//!
//! Usage: exp01-recorder <out.jsonl> <duration_ms>

use aip_observe::observed::KernelLifecycleKind;
use aip_observe::ProcessTracer;
use std::io::Write;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: exp01-recorder <out.jsonl> <duration_ms>");
        std::process::exit(2);
    }
    let out_path = &args[1];
    let duration_ms: u64 = args[2].parse().expect("duration_ms must be a number");

    let mut tracer = match ProcessTracer::open() {
        Ok(t) => t,
        Err(e) => {
            // Unavailable is a result, not a reason to substitute something
            // weaker. The harness records it and the experiment reports
            // BLOCKED rather than proceeding with a different instrument.
            eprintln!("exp01-recorder: sensor unavailable: {e:?}");
            std::process::exit(3);
        }
    };

    let mut out = std::io::BufWriter::new(
        std::fs::File::create(out_path).expect("cannot create output file"),
    );
    writeln!(out, "# sniffer dog 2.0 live capture (aip_observe::ProcessTracer)").unwrap();
    writeln!(out, "# mechanism: perf_event_open(PERF_TYPE_TRACEPOINT), CLOCK_MONOTONIC").unwrap();
    writeln!(out, "# tracepoints: sched:sched_process_fork, sched:sched_process_exec").unwrap();
    writeln!(out, "# duration_ms: {duration_ms}").unwrap();

    // Signal readiness only once the sensor is actually open, so the harness
    // never starts the subject against a sensor that has not attached.
    eprintln!("READY");

    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(duration_ms);
    let mut seq: u64 = 0;
    let mut lost_total: u64 = 0;

    while std::time::Instant::now() < deadline {
        let remaining = deadline
            .saturating_duration_since(std::time::Instant::now())
            .as_millis()
            .min(200) as i32;
        match tracer.next_event(remaining.max(1)) {
            Ok(Some(ev)) => {
                seq += 1;
                let line = match &ev.kind {
                    KernelLifecycleKind::ProcessExec {
                        pid,
                        old_pid,
                        filename,
                    } => format!(
                        r#"{{"seq":{seq},"kind":"exec","pid":{pid},"old_pid":{old_pid},"filename":{},"cpu":{},"kernel_monotonic_ns":{}}}"#,
                        json_string(filename),
                        ev.cpu,
                        ev.timestamp_ns
                    ),
                    KernelLifecycleKind::ProcessSpawn {
                        parent_pid,
                        child_pid,
                        parent_comm,
                        child_comm,
                    } => format!(
                        r#"{{"seq":{seq},"kind":"spawn","parent_pid":{parent_pid},"child_pid":{child_pid},"parent_comm":{},"child_comm":{},"cpu":{},"kernel_monotonic_ns":{}}}"#,
                        json_string(parent_comm),
                        json_string(child_comm),
                        ev.cpu,
                        ev.timestamp_ns
                    ),
                    // Any other variant is recorded as "seen but not
                    // interpreted here" rather than silently dropped: a
                    // dropped event is indistinguishable from an absent one,
                    // and this file is used to reason about absence.
                    other => format!(
                        r#"{{"seq":{seq},"kind":"other","debug":{},"cpu":{},"kernel_monotonic_ns":{}}}"#,
                        json_string(&format!("{other:?}")),
                        ev.cpu,
                        ev.timestamp_ns
                    ),
                };
                writeln!(out, "{line}").unwrap();
                // Flush per event, deliberately. A recorder that loses its
                // buffer when it is terminated produces an empty file that
                // is indistinguishable from "the observer saw nothing" —
                // which is the exact confusion this whole exercise exists to
                // prevent. Evidence already gathered must survive the
                // observer being stopped.
                out.flush().unwrap();
            }
            Ok(None) => {}
            Err(e) => {
                writeln!(out, r#"{{"kind":"source_error","detail":{}}}"#, json_string(&format!("{e:?}"))).unwrap();
                break;
            }
        }
        let lost = tracer.take_lost();
        if lost > 0 {
            lost_total += lost;
            writeln!(out, r#"{{"kind":"loss","count":{lost}}}"#).unwrap();
        }
    }

    let lost = tracer.take_lost();
    lost_total += lost;
    if lost > 0 {
        writeln!(out, r#"{{"kind":"loss","count":{lost}}}"#).unwrap();
    }
    writeln!(out, r#"{{"kind":"summary","events":{seq},"lost":{lost_total}}}"#).unwrap();
    out.flush().unwrap();
    eprintln!("exp01-recorder: {seq} events, {lost_total} lost");
}

/// Minimal JSON string escaping. The recorder has no serde dependency on
/// purpose: it should not be able to reshape what the sensor produced.
fn json_string(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}
