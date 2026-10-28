//! Rendering. Deterministic: the same assessment renders to the same bytes.
//!
//! Every value written to CSV is quoted per RFC 4180 when it needs to be, and
//! a value beginning with `=`, `+`, `-`, `@`, tab or carriage return is
//! prefixed with an apostrophe. These reports are opened in spreadsheets, and
//! a cell that begins with `=` is a formula.

use crate::assess::Assessment;
use crate::diff::Change;
use crate::finding::Priority;
use std::fmt::Write;

/// Characters that make a spreadsheet treat a cell as a formula.
const FORMULA_LEADERS: [char; 6] = ['=', '+', '-', '@', '\t', '\r'];

/// One CSV field, safe for spreadsheets.
pub fn csv_field(raw: &str) -> String {
    let guarded = if raw.starts_with(FORMULA_LEADERS) {
        format!("'{raw}")
    } else {
        raw.to_string()
    };
    if guarded.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

/// The assessment as pretty JSON with a trailing newline.
pub fn assessment_json(a: &Assessment) -> String {
    let mut s = serde_json::to_string_pretty(a).expect("an assessment is plain data");
    s.push('\n');
    s
}

/// One row per field.
pub fn fields_csv(a: &Assessment) -> String {
    let mut out = String::from("component,name,path,standing,detail\n");
    for f in &a.fields {
        let _ = writeln!(
            out,
            "{},{},{},{},{}",
            f.component.code(),
            csv_field(f.component.name()),
            csv_field(&f.path),
            f.standing.label(),
            csv_field(&f.standing.detail()),
        );
    }
    out
}

/// One row per finding.
pub fn findings_csv(a: &Assessment) -> String {
    let mut out = String::from("priority,component,path,message\n");
    for f in &a.findings {
        let _ = writeln!(
            out,
            "{},{},{},{}",
            f.priority.as_str(),
            f.component.code(),
            csv_field(&f.path),
            csv_field(&f.message),
        );
    }
    out
}

/// A human-readable report.
pub fn assessment_text(a: &Assessment) -> String {
    let s = &a.summary;
    let mut out = String::new();
    let _ = writeln!(out, "AIBOM evidence-gap assessment");
    let _ = writeln!(out, "  agent      {}", a.agent_id);
    let _ = writeln!(out, "  manifest   sha256:{}", a.manifest_sha256);
    let _ = writeln!(out, "  assessed   {} ms", a.assessed_at_ms);
    let _ = writeln!(out, "  seal       {:?}", a.seal);
    let _ = writeln!(out);
    let independent = s.verified + s.observed;
    let _ = writeln!(
        out,
        "{} of {} fields are backed by an independent verifier; {} rest on the author's word; {} cannot be established by any mechanism here.",
        independent, s.fields, s.self_reported, s.unknowable
    );
    let _ = writeln!(
        out,
        "  verified {}  observed {}  discovered {}  self-reported {}  unknowable {}  lapsed {}  contradicted {}  evidence-rejected {}",
        s.verified, s.observed, s.discovered, s.self_reported, s.unknowable, s.lapsed, s.contradicted, s.evidence_rejected
    );
    let _ = writeln!(
        out,
        "  findings: critical {}  high {}  medium {}  info {}",
        s.critical, s.high, s.medium, s.info
    );
    for p in [
        Priority::Critical,
        Priority::High,
        Priority::Medium,
        Priority::Info,
    ] {
        let group: Vec<_> = a.findings.iter().filter(|f| f.priority == p).collect();
        if group.is_empty() {
            continue;
        }
        let _ = writeln!(out, "\n{}", p.as_str());
        for f in group {
            let _ = writeln!(out, "  [{}] {}  {}", f.component.code(), f.path, f.message);
        }
    }
    let _ = writeln!(out, "\nFIELDS");
    for f in &a.fields {
        let _ = writeln!(
            out,
            "  [{}] {:<44} {:<18} {}",
            f.component.code(),
            f.path,
            f.standing.label(),
            f.standing.detail()
        );
    }
    let _ = writeln!(
        out,
        "\nThis assessment states what backs each declared field. It does not establish what the agent did."
    );
    out
}

/// Changes as pretty JSON.
pub fn changes_json(changes: &[Change]) -> String {
    let mut s = serde_json::to_string_pretty(changes).expect("changes are plain data");
    s.push('\n');
    s
}

/// Changes as text.
pub fn changes_text(changes: &[Change]) -> String {
    let mut out = String::new();
    if changes.is_empty() {
        out.push_str("no changes\n");
    }
    for c in changes {
        let _ = writeln!(
            out,
            "{:<9} [{}] {}  {:?}",
            format!("{:?}", c.direction),
            c.component.code(),
            c.key,
            c.change
        );
    }
    out
}
