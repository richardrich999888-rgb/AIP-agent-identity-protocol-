//! File-backed capability store: one owner-only JSON file per artifact
//! version, named by its content hash. Loading re-checks the hash; a record
//! whose artifact no longer matches its recorded hash is reported, never
//! silently trusted (and `Record::executable` is false for it anyway).

use std::path::{Path, PathBuf};

use vanian_sovereign::ports::{PortError, PortErrorKind};

use crate::capability::lifecycle::Record;
use crate::ports::CapabilityStore;

/// Directory of records.
pub struct FileStore {
    dir: PathBuf,
}

fn st(e: impl std::fmt::Display) -> PortError {
    PortError::new(PortErrorKind::Storage, e.to_string())
}

impl FileStore {
    /// Open or create `dir` (mode 0700).
    pub fn open(dir: &Path) -> Result<Self, PortError> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(dir).map_err(st)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(st)?;
        Ok(Self { dir: dir.into() })
    }

    /// Records whose stored hash does not match their content.
    pub fn tampered(&self) -> Result<Vec<String>, PortError> {
        Ok(self
            .all()?
            .into_iter()
            .filter(|r| r.capability.content_hash() != r.capability_hash)
            .map(|r| r.capability_hash)
            .collect())
    }
}

impl CapabilityStore for FileStore {
    fn all(&self) -> Result<Vec<Record>, PortError> {
        let mut out = Vec::new();
        let mut names: Vec<_> = std::fs::read_dir(&self.dir)
            .map_err(st)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect();
        names.sort();
        for p in names {
            if p.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let b = std::fs::read(&p).map_err(st)?;
            let r: Record = serde_json::from_slice(&b).map_err(|e| {
                PortError::new(
                    PortErrorKind::ContractViolation,
                    format!("{}: {e}", p.display()),
                )
            })?;
            out.push(r);
        }
        Ok(out)
    }

    fn put(&mut self, r: &Record) -> Result<(), PortError> {
        let name = format!(
            "{}-v{}-{}.json",
            r.capability.id,
            r.capability.version,
            &r.capability_hash[..16]
        );
        if name.contains('/') || name.starts_with('.') {
            return Err(PortError::new(
                PortErrorKind::InvalidInput,
                "capability id is not a safe file name",
            ));
        }
        let path = self.dir.join(&name);
        let tmp = self.dir.join(format!(".{name}.tmp"));
        let body = serde_json::to_vec_pretty(r).map_err(st)?;
        let _ = std::fs::remove_file(&tmp);
        aip_crypto::custody::create_owner_only(&tmp, &body).map_err(|e| st(format!("{e:?}")))?;
        std::fs::rename(&tmp, &path).map_err(st)
    }
}
