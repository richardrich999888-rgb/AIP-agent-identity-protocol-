//! The verification report: findings with severities, an optional
//! line-by-line trace, and the pass/fail decision the exit code rides on.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    /// Integrity breach, broken chain, corrupted signature — always fails.
    Fail,
    /// Suspect but not conclusive (e.g. placeholder digests); fails only
    /// under `--strict`.
    Warn,
    /// Context worth reporting; never affects the verdict.
    Info,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    /// Which verification step produced this (e.g. "anchor-chain").
    pub step: &'static str,
    pub message: String,
}

#[derive(Debug, Default, Serialize)]
pub struct Stats {
    pub anchors: usize,
    pub packets: usize,
    pub ledger_entries: usize,
    /// Merkle root over the evidence packet set, when packets were examined.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packet_merkle_root: Option<String>,
}

#[derive(Debug, Default)]
pub struct Report {
    pub findings: Vec<Finding>,
    /// Per-record verification trace, printed under `--verbose`.
    pub trace: Vec<String>,
    pub stats: Stats,
}

impl Report {
    pub fn fail(&mut self, step: &'static str, message: impl Into<String>) {
        self.findings.push(Finding {
            severity: Severity::Fail,
            step,
            message: message.into(),
        });
    }

    pub fn warn(&mut self, step: &'static str, message: impl Into<String>) {
        self.findings.push(Finding {
            severity: Severity::Warn,
            step,
            message: message.into(),
        });
    }

    pub fn info(&mut self, step: &'static str, message: impl Into<String>) {
        self.findings.push(Finding {
            severity: Severity::Info,
            step,
            message: message.into(),
        });
    }

    pub fn trace(&mut self, line: impl Into<String>) {
        self.trace.push(line.into());
    }

    pub fn failures(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Fail)
            .count()
    }

    pub fn warnings(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Warn)
            .count()
    }

    /// The certification verdict. Warnings fail only under `--strict`.
    pub fn passed(&self, strict: bool) -> bool {
        self.failures() == 0 && (!strict || self.warnings() == 0)
    }

    /// Machine-readable result document for `--json`.
    pub fn to_json(&self, strict: bool) -> serde_json::Value {
        serde_json::json!({
            "pass": self.passed(strict),
            "strict": strict,
            "stats": self.stats,
            "findings": self.findings,
        })
    }
}
