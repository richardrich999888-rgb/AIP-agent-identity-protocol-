//! Adapters: a third-party observer's output becomes [`ExternalExec`] events.
//!
//! Each adapter is deliberately strict. A line it does not understand is
//! **counted and reported**, never silently skipped: an adapter that quietly
//! drops half an observer's output would manufacture the very finding this
//! tool exists to detect — "the independent observer saw nothing here" — out
//! of its own parsing bug.

use crate::{ExecOutcome, ExternalExec, ExternalSource};

/// What an adapter made of an observer's output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub events: Vec<ExternalExec>,
    /// Lines that did not parse as an event and were not recognised banner or
    /// comment lines. Non-zero means the report below is incomplete, and the
    /// report says so rather than presenting itself as whole.
    pub unparsed: usize,
}

/// Parse the output of the shipped bpftrace program, whose every event line is
///
/// ```text
/// AIPX <nsecs> <pid> <filename>
/// ```
///
/// `nsecs` is `bpf_ktime_get_ns()` — kernel monotonic, the same domain as
/// AIP's `kernel_timestamp_ns`, so it is carried through unconverted here and
/// normalised once, against the batch anchor, by the comparison.
pub fn parse_bpftrace(text: &str) -> Parsed {
    let mut events = Vec::new();
    let mut unparsed = 0usize;
    for line in text.lines() {
        let l = line.trim();
        // bpftrace's own banner and blank lines are expected, not failures.
        if l.is_empty() || l.starts_with("Attaching") || l.starts_with("ERROR:") {
            continue;
        }
        let Some(rest) = l.strip_prefix("AIPX ") else {
            unparsed += 1;
            continue;
        };
        let mut it = rest.splitn(3, ' ');
        let (Some(ns), Some(pid), Some(image)) = (it.next(), it.next(), it.next()) else {
            unparsed += 1;
            continue;
        };
        let (Ok(ns), Ok(pid)) = (ns.parse::<u64>(), pid.parse::<u32>()) else {
            unparsed += 1;
            continue;
        };
        events.push(ExternalExec {
            source: ExternalSource::Bpftrace,
            pid,
            monotonic_ns: Some(ns),
            wall_ms: None,
            image: image.trim().to_string(),
            // sched:sched_process_exec fires only on a successful exec, so
            // there is no failure class to report here.
            outcome: ExecOutcome::NotReported,
        });
    }
    Parsed { events, unparsed }
}

/// Parse raw `auditd` log lines for `execve` SYSCALL records.
///
/// A record looks like
///
/// ```text
/// type=SYSCALL msg=audit(1789914920.810:123): arch=c000003e syscall=59 ... pid=456 ... comm="echo" exe="/bin/echo" key="aipxcheck"
/// ```
///
/// Only `type=SYSCALL` records for syscall 59 (`execve` on x86-64) are taken.
/// The stamp inside `audit(...)` is wall-clock seconds with millisecond
/// precision, so these events arrive already in the comparison domain.
///
/// Non-SYSCALL records (`EXECVE`, `PATH`, `CWD`, `PROCTITLE`) belong to the
/// same event and are skipped deliberately rather than counted as unparsed —
/// counting them would report a 4x parse failure on a perfectly good log.
pub fn parse_auditd(text: &str) -> Parsed {
    let mut events = Vec::new();
    let mut unparsed = 0usize;
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if !l.starts_with("type=SYSCALL") {
            continue; // a companion record of the same event, not a failure
        }
        // execve is syscall 59 on x86-64; anything else is a different rule's
        // record sharing the log and is not an exec.
        if field(l, "syscall=").is_none_or(|v| v != "59") {
            continue;
        }
        let (Some(wall_ms), Some(pid)) = (
            audit_stamp_ms(l),
            field(l, "pid=").and_then(|v| v.parse::<u32>().ok()),
        ) else {
            unparsed += 1;
            continue;
        };
        let image = quoted(l, "exe=")
            .or_else(|| quoted(l, "comm="))
            .unwrap_or_default();
        // `success=yes|no` distinguishes an execution from a failed attempt.
        // A record without the field is treated as failed: an attempt that
        // cannot be shown to have succeeded must not be demanded of AIP.
        let outcome = match field(l, "success=") {
            Some("yes") => ExecOutcome::Succeeded,
            _ => ExecOutcome::Failed,
        };
        events.push(ExternalExec {
            source: ExternalSource::Auditd,
            pid,
            monotonic_ns: None,
            wall_ms: Some(wall_ms),
            image,
            outcome,
        });
    }
    Parsed { events, unparsed }
}

/// `msg=audit(<secs>.<millis>:<serial>)` -> wall-clock milliseconds.
fn audit_stamp_ms(line: &str) -> Option<i64> {
    let start = line.find("audit(")? + "audit(".len();
    let rest = &line[start..];
    let end = rest.find(':')?;
    let stamp = &rest[..end];
    let (secs, millis) = stamp.split_once('.')?;
    let secs: i64 = secs.parse().ok()?;
    // The fractional part is exactly three digits in every kernel that emits
    // this format; parse defensively rather than assuming.
    let millis: i64 = millis.parse().ok()?;
    if !(0..1000).contains(&millis) {
        return None;
    }
    secs.checked_mul(1000)?.checked_add(millis)
}

/// An unquoted `key=value` field, up to the next space.
fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let i = find_field(line, key)? + key.len();
    let rest = &line[i..];
    Some(rest.split(' ').next().unwrap_or(rest))
}

/// A `key="value"` field.
fn quoted(line: &str, key: &str) -> Option<String> {
    let i = find_field(line, key)? + key.len();
    let rest = line[i..].strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Find `key` only where it begins a field — at the start of the line or after
/// a space. Without this, `pid=` matches inside `ppid=` and the parser reports
/// the parent's pid as the process that exec'd, which silently mis-attributes
/// every event.
fn find_field(line: &str, key: &str) -> Option<usize> {
    let mut from = 0usize;
    while let Some(rel) = line[from..].find(key) {
        let at = from + rel;
        if at == 0 || line.as_bytes()[at - 1] == b' ' {
            return Some(at);
        }
        from = at + 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bpftrace_lines_parse_with_the_banner_ignored() {
        let out = "Attaching 1 probe...\nAIPX 317277893267 818 /bin/echo\nAIPX 317279605154 819 /usr/bin/env\n";
        let p = parse_bpftrace(out);
        assert_eq!(p.unparsed, 0);
        assert_eq!(p.events.len(), 2);
        assert_eq!(p.events[0].pid, 818);
        assert_eq!(p.events[0].monotonic_ns, Some(317_277_893_267));
        assert_eq!(p.events[0].image, "/bin/echo");
    }

    #[test]
    fn a_malformed_bpftrace_line_is_counted_never_silently_dropped() {
        let p = parse_bpftrace("AIPX notanumber 5 /bin/x\nAIPX 1 2 /bin/y\n");
        assert_eq!(p.events.len(), 1);
        assert_eq!(p.unparsed, 1, "a bad line must be reported, not hidden");
    }

    #[test]
    fn an_unrecognised_line_is_counted() {
        let p = parse_bpftrace("some other tool's output\n");
        assert_eq!(p.unparsed, 1);
    }

    const SYSCALL: &str = r#"type=SYSCALL msg=audit(1789914920.810:123): arch=c000003e syscall=59 success=yes exit=0 ppid=100 pid=456 auid=0 uid=0 comm="echo" exe="/bin/echo" key="aipxcheck""#;

    #[test]
    fn an_auditd_execve_record_parses_to_wall_ms() {
        let p = parse_auditd(SYSCALL);
        assert_eq!(p.unparsed, 0);
        assert_eq!(p.events.len(), 1);
        let e = &p.events[0];
        assert_eq!(e.pid, 456);
        assert_eq!(e.wall_ms, Some(1_789_914_920_810));
        assert_eq!(e.image, "/bin/echo");
    }

    /// The bug this guards: `pid=` also occurs inside `ppid=`. Taking the first
    /// textual match attributes every exec to its parent.
    #[test]
    fn pid_is_not_taken_from_inside_ppid() {
        let p = parse_auditd(SYSCALL);
        assert_eq!(p.events[0].pid, 456, "must not report ppid 100");
    }

    #[test]
    fn companion_records_are_skipped_not_counted_as_failures() {
        let log = format!(
            "{SYSCALL}\ntype=EXECVE msg=audit(1789914920.810:123): argc=2 a0=\"echo\"\ntype=PATH msg=audit(1789914920.810:123): name=\"/bin/echo\"\n"
        );
        let p = parse_auditd(&log);
        assert_eq!(p.events.len(), 1);
        assert_eq!(p.unparsed, 0, "EXECVE/PATH belong to the same event");
    }

    #[test]
    fn a_non_execve_syscall_record_is_not_an_exec() {
        let line = SYSCALL.replace("syscall=59", "syscall=257");
        assert_eq!(parse_auditd(&line).events.len(), 0);
    }

    #[test]
    fn a_syscall_record_with_a_broken_stamp_is_counted_unparsed() {
        let line = SYSCALL.replace("audit(1789914920.810:123)", "audit(bogus:123)");
        let p = parse_auditd(&line);
        assert_eq!(p.events.len(), 0);
        assert_eq!(p.unparsed, 1);
    }

    #[test]
    fn comm_is_used_when_exe_is_absent() {
        let line = SYSCALL.replace(r#" exe="/bin/echo""#, "");
        let p = parse_auditd(&line);
        assert_eq!(p.events[0].image, "echo");
    }
}
