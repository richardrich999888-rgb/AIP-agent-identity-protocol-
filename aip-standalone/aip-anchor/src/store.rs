//! Persistence for a witness. The only module here that touches the
//! filesystem.
//!
//! Two things are stored and they fail differently. Receipts are the
//! evidence and must survive a crash, so every append is flushed and
//! `fsync`ed before the witness reports success. The resumable state is
//! derived — it can be rebuilt by replaying the receipts — so it is kept as
//! a convenience and never trusted over the receipt file.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use crate::{WitnessReceipt, WitnessState};

/// Why a store operation failed. Distinct from [`crate::WitnessError`]:
/// these are IO conditions, not judgements about a log.
#[derive(Debug)]
pub enum StoreError {
    Io(std::io::Error),
    /// A line in the receipt file is not a receipt. The file is not
    /// silently truncated at that point: a corrupt receipt log is a fact an
    /// operator has to see, because the alternative is a witness that
    /// quietly forgets what it countersigned.
    Corrupt {
        line: usize,
        reason: String,
    },
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Corrupt { line, reason } => write!(
                f,
                "receipt file line {line} is not a receipt ({reason}); refusing to continue \
                 from a record that cannot be read, because skipping it would silently \
                 discard a countersignature"
            ),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// An append-only JSONL file of receipts.
///
/// One receipt per line, in issue order. The format is deliberately plain:
/// the receipts are what an institution hands a third party, and a format
/// that needs this crate to read is a format that can be lost with it.
pub struct FileReceiptStore {
    path: PathBuf,
}

impl FileReceiptStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append a receipt and make it durable before returning.
    ///
    /// The `fsync` is not optional. A witness that acknowledges a receipt
    /// it has not committed to disk can lose exactly the countersignature
    /// that a later audit needs, and lose it in the crash that a rewrite
    /// would be hidden behind.
    pub fn append(&self, receipt: &WitnessReceipt) -> Result<(), StoreError> {
        let mut line = serde_json::to_string(receipt).map_err(|e| StoreError::Corrupt {
            line: 0,
            reason: e.to_string(),
        })?;
        line.push('\n');
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        f.write_all(line.as_bytes())?;
        f.flush()?;
        f.sync_all()?;
        Ok(())
    }

    /// Read every receipt, in file order.
    pub fn load(&self) -> Result<Vec<WitnessReceipt>, StoreError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let f = File::open(&self.path)?;
        let mut out = Vec::new();
        for (i, line) in BufReader::new(f).lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let r: WitnessReceipt =
                serde_json::from_str(&line).map_err(|e| StoreError::Corrupt {
                    line: i + 1,
                    reason: e.to_string(),
                })?;
            out.push(r);
        }
        Ok(out)
    }

    /// Rebuild resumable state by replaying the receipt file.
    ///
    /// Derived rather than stored, so a witness cannot be restarted into a
    /// state that disagrees with its own evidence — which is how a rollback
    /// would be slipped past a restart.
    pub fn resume_state(&self) -> Result<WitnessState, StoreError> {
        let receipts = self.load()?;
        let Some(last) = receipts.last() else {
            return Ok(WitnessState::default());
        };
        Ok(WitnessState {
            log_id: Some(last.log_id),
            last_size: last.size,
            last_root: last.root,
            last_head_digest: last.head_digest,
            last_receipt_digest: last.digest(),
            receipts_issued: receipts.len() as u64,
        })
    }
}
