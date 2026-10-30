//! One-shot decision consumption.
//!
//! An `ExpectedExecution` is valid for a time window; without a consumption
//! record it could be presented to the runner repeatedly inside that window.
//! The guard records each `decision_id` before execution and refuses a
//! second use. The file guard appends with `O_APPEND` and fsyncs before
//! returning, so a crash after consumption cannot re-enable the decision
//! (fail closed: a crash may waste a decision, never double-spend one).

use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

/// Consumption outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayError {
    AlreadyConsumed,
    Io(String),
}

/// Records decisions as consumed.
pub trait ReplayGuard {
    /// Atomically mark `decision_id` consumed, or fail if it already was.
    fn consume(&mut self, decision_id: &[u8; 16]) -> Result<(), ReplayError>;
}

/// In-memory guard for tests.
#[derive(Default)]
pub struct MemoryReplayGuard(BTreeSet<[u8; 16]>);

impl ReplayGuard for MemoryReplayGuard {
    fn consume(&mut self, id: &[u8; 16]) -> Result<(), ReplayError> {
        if self.0.insert(*id) {
            Ok(())
        } else {
            Err(ReplayError::AlreadyConsumed)
        }
    }
}

/// Append-only file guard: one lowercase hex decision id per line.
///
/// Single-writer assumption: one runner per state directory. Concurrent
/// runners on the same file are not supported in this slice.
pub struct FileReplayGuard {
    path: PathBuf,
}

impl FileReplayGuard {
    /// Use `path` as the consumption log (created on first use).
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn seen(&self, hex_id: &str) -> Result<bool, ReplayError> {
        let f = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(ReplayError::Io(e.to_string())),
        };
        for line in BufReader::new(f).lines() {
            if line.map_err(|e| ReplayError::Io(e.to_string()))?.trim() == hex_id {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl ReplayGuard for FileReplayGuard {
    fn consume(&mut self, id: &[u8; 16]) -> Result<(), ReplayError> {
        let h = hex::encode(id);
        if self.seen(&h)? {
            return Err(ReplayError::AlreadyConsumed);
        }
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| ReplayError::Io(e.to_string()))?;
        writeln!(f, "{h}").map_err(|e| ReplayError::Io(e.to_string()))?;
        f.sync_all().map_err(|e| ReplayError::Io(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_guard_refuses_second_use() {
        let mut g = MemoryReplayGuard::default();
        assert_eq!(g.consume(&[1; 16]), Ok(()));
        assert_eq!(g.consume(&[1; 16]), Err(ReplayError::AlreadyConsumed));
        assert_eq!(g.consume(&[2; 16]), Ok(()));
    }

    #[test]
    fn file_guard_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("consumed.log");
        assert_eq!(FileReplayGuard::new(p.clone()).consume(&[7; 16]), Ok(()));
        // New instance = process restart.
        assert_eq!(
            FileReplayGuard::new(p).consume(&[7; 16]),
            Err(ReplayError::AlreadyConsumed)
        );
    }
}
