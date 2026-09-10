//! Replay protection (Skill 9 §13, §14): a warrant id is consumed by the
//! decision that acts on it, before actuation, and is never a second
//! authorization — not after a failure, not after a restart.
//!
//! Uniqueness key: the warrant id. Consumed state: the ledger. Persistence:
//! [`FileReplayLedger`] appends each id to a file and fsyncs before the
//! decision proceeds, so a restart reloads every consumed id. Rollback of
//! the ledger file is a deployment matter; a shortened file re-enables
//! exactly the ids it drops and nothing else, and `contain` fails toward no
//! containment when the ledger cannot be written.

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};

pub trait ReplayLedger {
    fn is_consumed(&self, warrant_id: &[u8; 16]) -> bool;
    /// Record the id as consumed, durably where the ledger is durable.
    fn consume(&mut self, warrant_id: &[u8; 16]) -> Result<(), String>;
}

/// In-memory ledger: consumed ids are forgotten when the process ends.
#[derive(Debug, Default)]
pub struct MemoryReplayLedger {
    consumed: HashSet<[u8; 16]>,
}

impl ReplayLedger for MemoryReplayLedger {
    fn is_consumed(&self, warrant_id: &[u8; 16]) -> bool {
        self.consumed.contains(warrant_id)
    }

    fn consume(&mut self, warrant_id: &[u8; 16]) -> Result<(), String> {
        self.consumed.insert(*warrant_id);
        Ok(())
    }
}

/// Append-only file of consumed warrant ids, one lowercase hex id per line.
#[derive(Debug)]
pub struct FileReplayLedger {
    path: PathBuf,
    consumed: HashSet<[u8; 16]>,
}

impl FileReplayLedger {
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut consumed = HashSet::new();
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                for line in text.lines() {
                    if let Some(id) = parse_hex_id(line.trim()) {
                        consumed.insert(id);
                    } else if !line.trim().is_empty() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("ledger line is not a warrant id: {line:?}"),
                        ));
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        Ok(Self { path, consumed })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl ReplayLedger for FileReplayLedger {
    fn is_consumed(&self, warrant_id: &[u8; 16]) -> bool {
        self.consumed.contains(warrant_id)
    }

    fn consume(&mut self, warrant_id: &[u8; 16]) -> Result<(), String> {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| e.to_string())?;
        let mut line: String = warrant_id.iter().map(|b| format!("{b:02x}")).collect();
        line.push('\n');
        f.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
        self.consumed.insert(*warrant_id);
        Ok(())
    }
}

fn parse_hex_id(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}
