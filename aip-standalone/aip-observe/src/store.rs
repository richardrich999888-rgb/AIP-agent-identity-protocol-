//! Durable collector state (Gate 8).
//!
//! Three files in one directory, each with one job:
//!
//! ```text
//! collector.snapshot.json     the chain position (CollectorSnapshot),
//!                             rewritten atomically after every signature
//! health.archive.jsonl        every SignedSensorHealth this collector
//!                             emitted, appended, never rewritten
//! continuity.reports.jsonl    every SignedContinuityReport, appended
//! ```
//!
//! The store proves nothing on its own. It is the pair of independently
//! held records — the state and the archive of the collector's *own signed*
//! health — that [`crate::attest::verify_continuity`] audits on resume: a
//! state file can be deleted, rolled back or edited, but an archive record
//! it disagrees with is a signature the collector itself produced.
//!
//! Corruption is an error, never absence: a state file that does not parse
//! is [`StoreError::Corrupt`], not "no state", because treating it as no
//! state would let a damaged file start a second chain under the same key.
//! Forged or foreign archive lines are a different matter — they parse, and
//! resume ignores them because they do not verify under the collector's key.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::attest::CollectorSnapshot;
use crate::health::SignedSensorHealth;
use crate::runtime::SignedContinuityReport;

pub const SNAPSHOT_FILE: &str = "collector.snapshot.json";
pub const ARCHIVE_FILE: &str = "health.archive.jsonl";
pub const REPORTS_FILE: &str = "continuity.reports.jsonl";

#[derive(Debug)]
pub enum StoreError {
    Io(std::io::Error),
    /// A file is present but is not what it must be. Never treated as
    /// absence.
    Corrupt {
        path: PathBuf,
        reason: String,
    },
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Io(e) => write!(f, "store i/o: {e}"),
            StoreError::Corrupt { path, reason } => {
                write!(f, "corrupt {}: {reason}", path.display())
            }
        }
    }
}

impl std::error::Error for StoreError {}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError::Io(e)
    }
}

/// A collector's state directory.
#[derive(Debug, Clone)]
pub struct CollectorStore {
    dir: PathBuf,
}

impl CollectorStore {
    /// Open (creating if needed) the directory. Opening reads nothing.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, StoreError> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn snapshot_path(&self) -> PathBuf {
        self.dir.join(SNAPSHOT_FILE)
    }

    pub fn archive_path(&self) -> PathBuf {
        self.dir.join(ARCHIVE_FILE)
    }

    pub fn reports_path(&self) -> PathBuf {
        self.dir.join(REPORTS_FILE)
    }

    /// `Ok(None)` only when the file does not exist. Anything else that is
    /// not a snapshot is `Corrupt`.
    pub fn load_snapshot(&self) -> Result<Option<CollectorSnapshot>, StoreError> {
        let path = self.snapshot_path();
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(StoreError::Io(e)),
        };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| StoreError::Corrupt {
                path,
                reason: e.to_string(),
            })
    }

    /// Write the snapshot atomically: a temporary file in the same
    /// directory, fsync, rename over the old one. A crash leaves either the
    /// old snapshot or the new one, never a torn file.
    pub fn save_snapshot(&self, snapshot: &CollectorSnapshot) -> Result<(), StoreError> {
        let path = self.snapshot_path();
        let tmp = self
            .dir
            .join(format!("{SNAPSHOT_FILE}.tmp.{}", std::process::id()));
        let bytes = serde_json::to_vec(snapshot).map_err(|e| StoreError::Corrupt {
            path: path.clone(),
            reason: e.to_string(),
        })?;
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// Append one health record to the archive (one JSON object per line).
    pub fn append_health(&self, health: &SignedSensorHealth) -> Result<(), StoreError> {
        append_line(&self.archive_path(), health)
    }

    /// Every record in the archive, in file order. A line that is not a
    /// health record is `Corrupt`: an archive is not something to read
    /// around.
    pub fn load_archive(&self) -> Result<Vec<SignedSensorHealth>, StoreError> {
        load_lines(&self.archive_path())
    }

    /// Append one continuity report.
    pub fn append_report(&self, report: &SignedContinuityReport) -> Result<(), StoreError> {
        append_line(&self.reports_path(), report)
    }

    /// Every continuity report, in file order.
    pub fn load_reports(&self) -> Result<Vec<SignedContinuityReport>, StoreError> {
        load_lines(&self.reports_path())
    }
}

fn append_line<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), StoreError> {
    let mut line = serde_json::to_vec(value).map_err(|e| StoreError::Corrupt {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })?;
    line.push(b'\n');
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(&line)?;
    f.sync_all()?;
    Ok(())
}

fn load_lines<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Vec<T>, StoreError> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(StoreError::Io(e)),
    };
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let v = serde_json::from_str(line).map_err(|e| StoreError::Corrupt {
            path: path.to_path_buf(),
            reason: format!("line {}: {e}", n + 1),
        })?;
        out.push(v);
    }
    Ok(out)
}
