//! Append-only experience log (one owner-only JSONL file per installation).
//! Admission rules are the pure [`crate::capability::experience::admit`]:
//! the recording principal's tenant and the installation's security domain
//! must match the experience; self-verification is refused. Reads return only
//! the requested tenant's records.

use std::io::Write;
use std::path::{Path, PathBuf};

use vanian_sovereign::ports::{PortError, PortErrorKind};

use crate::capability::experience::{admit, Experience};

/// Maximum serialized size of one experience (bytes).
pub const MAX_EXPERIENCE_BYTES: usize = 64 * 1024;

pub struct ExperienceLog {
    path: PathBuf,
}

fn st(e: impl std::fmt::Display) -> PortError {
    PortError::new(PortErrorKind::Storage, e.to_string())
}

impl ExperienceLog {
    pub fn open(path: &Path) -> Self {
        Self { path: path.into() }
    }

    /// Admit and append. Duplicate ids are refused (experience is immutable).
    pub fn record(
        &self,
        e: &Experience,
        principal_tenant: &str,
        domain: &str,
    ) -> Result<(), PortError> {
        use std::os::unix::fs::OpenOptionsExt;
        admit(e, principal_tenant, domain).map_err(|x| {
            PortError::new(
                PortErrorKind::ContractViolation,
                format!("experience refused: {x:?}"),
            )
        })?;
        if self.read_all()?.iter().any(|x| x.id == e.id) {
            return Err(PortError::new(
                PortErrorKind::ContractViolation,
                format!("experience {} already recorded", e.id),
            ));
        }
        let line = serde_json::to_string(e).map_err(st)?;
        if line.len() > MAX_EXPERIENCE_BYTES {
            return Err(PortError::new(
                PortErrorKind::InvalidInput,
                "experience too large",
            ));
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&self.path)
            .map_err(st)?;
        writeln!(f, "{line}").map_err(st)
    }

    fn read_all(&self) -> Result<Vec<Experience>, PortError> {
        let s = match std::fs::read_to_string(&self.path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(st(e)),
        };
        s.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                serde_json::from_str(l)
                    .map_err(|e| PortError::new(PortErrorKind::ContractViolation, e.to_string()))
            })
            .collect()
    }

    /// Experiences of one tenant only.
    pub fn for_tenant(&self, tenant: &str) -> Result<Vec<Experience>, PortError> {
        Ok(self
            .read_all()?
            .into_iter()
            .filter(|e| e.tenant == tenant)
            .collect())
    }
}
