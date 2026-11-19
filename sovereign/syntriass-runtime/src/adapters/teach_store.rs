//! File-backed teach-session store: one owner-only JSON file per session,
//! under a per-tenant directory, named by the session's content hash.
//!
//! Layout, relative to the store root (`<state>/teach`):
//!
//! ```text
//! <root>/<tenant>/<session_id>.json      mode 0600
//! ```
//!
//! The tenant is a path component, which is why
//! [`crate::domain::teach`] constrains identifiers to
//! `[A-Za-z0-9._:-]` with no leading dot: `..` or a slash would otherwise
//! reach outside the tenant's directory. The core owns that rule, so this
//! adapter re-checks it only as a guard against being handed a session that
//! was deserialised rather than built (`load` on an untrusted file).
//!
//! Reading re-derives the content hash and refuses a session whose
//! `session_id` no longer names its content, rather than returning it with a
//! warning. A tampered session is not a session.

use std::path::{Path, PathBuf};

use crate::domain::teach::TeachSession;

/// Directory of per-tenant session directories.
pub struct TeachStore {
    root: PathBuf,
}

/// Why a store operation failed. Distinct from `TeachError`, which is about
/// an expert's input; these are about the filesystem and about trust in what
/// was read back from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    Io(String),
    /// The file did not parse as a session.
    Malformed {
        path: String,
        detail: String,
    },
    /// `session_id` does not match the content it names.
    Tampered {
        path: String,
        recorded: String,
        computed: String,
    },
    /// The session's tenant or id is not a safe path component.
    UnsafeName {
        field: &'static str,
        value: String,
    },
    NotFound {
        tenant: String,
        session_id: String,
    },
    /// A file already exists for this content hash.
    Exists(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Io(e) => write!(f, "{e}"),
            StoreError::Malformed { path, detail } => write!(f, "{path}: {detail}"),
            StoreError::Tampered {
                path,
                recorded,
                computed,
            } => write!(
                f,
                "{path}: session_id {recorded} does not match its content (computed {computed})"
            ),
            StoreError::UnsafeName { field, value } => {
                write!(f, "{field}: not a safe path component: {value:?}")
            }
            StoreError::NotFound { tenant, session_id } => {
                write!(f, "no session {session_id} for tenant {tenant}")
            }
            StoreError::Exists(p) => write!(f, "{p}: already exists"),
        }
    }
}

impl std::error::Error for StoreError {}

fn io(e: impl std::fmt::Display) -> StoreError {
    StoreError::Io(e.to_string())
}

/// Reject anything that is not a single safe path component.
fn safe_component(field: &'static str, value: &str) -> Result<(), StoreError> {
    let ok = !value.is_empty()
        && !value.starts_with('.')
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'));
    if ok {
        Ok(())
    } else {
        Err(StoreError::UnsafeName {
            field,
            value: value.to_string(),
        })
    }
}

impl TeachStore {
    /// Open or create the store root (mode 0700).
    pub fn open(root: &Path) -> Result<Self, StoreError> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(root).map_err(io)?;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).map_err(io)?;
        Ok(Self { root: root.into() })
    }

    /// Directory holding one tenant's sessions, created at mode 0700.
    fn tenant_dir(&self, tenant: &str) -> Result<PathBuf, StoreError> {
        use std::os::unix::fs::PermissionsExt;
        safe_component("tenant", tenant)?;
        let dir = self.root.join(tenant);
        std::fs::create_dir_all(&dir).map_err(io)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).map_err(io)?;
        Ok(dir)
    }

    /// Path a session is stored at, without creating anything.
    pub fn path_of(&self, tenant: &str, session_id: &str) -> Result<PathBuf, StoreError> {
        safe_component("tenant", tenant)?;
        safe_component("session_id", session_id)?;
        Ok(self.root.join(tenant).join(format!("{session_id}.json")))
    }

    /// Write a session. Refuses to overwrite: the file name is the content
    /// hash, so an existing file with this name already holds this content,
    /// and a second write would mean either a repeat or a collision.
    pub fn put(&self, session: &TeachSession) -> Result<PathBuf, StoreError> {
        safe_component("session_id", &session.session_id)?;
        let dir = self.tenant_dir(&session.tenant)?;
        let path = dir.join(format!("{}.json", session.session_id));
        if path.exists() {
            return Err(StoreError::Exists(path.display().to_string()));
        }
        let body = serde_json::to_vec_pretty(session).map_err(|e| StoreError::Malformed {
            path: path.display().to_string(),
            detail: e.to_string(),
        })?;
        // Written owner-only and created exclusively: a pre-existing path
        // under this name is an error, not a target to truncate.
        aip_crypto::custody::create_owner_only(&path, &body)
            .map_err(|e| StoreError::Io(format!("{e:?}")))?;
        Ok(path)
    }

    /// Read one session, verifying its content hash.
    pub fn get(&self, tenant: &str, session_id: &str) -> Result<TeachSession, StoreError> {
        let path = self.path_of(tenant, session_id)?;
        if !path.exists() {
            return Err(StoreError::NotFound {
                tenant: tenant.to_string(),
                session_id: session_id.to_string(),
            });
        }
        self.load(&path)
    }

    /// Parse and verify one session file.
    pub fn load(&self, path: &Path) -> Result<TeachSession, StoreError> {
        let bytes = std::fs::read(path).map_err(io)?;
        let session: TeachSession =
            serde_json::from_slice(&bytes).map_err(|e| StoreError::Malformed {
                path: path.display().to_string(),
                detail: e.to_string(),
            })?;
        let computed = session.content_hash();
        if computed != session.session_id {
            return Err(StoreError::Tampered {
                path: path.display().to_string(),
                recorded: session.session_id,
                computed,
            });
        }
        Ok(session)
    }

    /// Every session for one tenant, ordered by session id. A tenant with no
    /// directory yet has no sessions, which is not an error.
    pub fn list(&self, tenant: &str) -> Result<Vec<TeachSession>, StoreError> {
        safe_component("tenant", tenant)?;
        let dir = self.root.join(tenant);
        if !dir.is_dir() {
            return Ok(Vec::new());
        }
        let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
            .map_err(io)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
            .collect();
        paths.sort();
        paths.iter().map(|p| self.load(p)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::teach::{CitedClause, Example, Extraction, Label, SessionInput};
    use std::os::unix::fs::PermissionsExt;

    const SHA: &str = "3333333333333333333333333333333333333333333333333333333333333333";
    const NOW: u64 = 1_762_000_000_000;

    fn session(tenant: &str, task: &str) -> TeachSession {
        let text = "Samples must be stored between 10 C and 25 C.";
        TeachSession::open(
            SessionInput {
                tenant: tenant.into(),
                task: task.into(),
                expert_id: "expert:qa-lead".into(),
                document: "policy.pdf".into(),
                document_sha256: SHA.into(),
                pages: vec![4],
                clauses: vec![CitedClause {
                    document: "policy.pdf".into(),
                    document_sha256: SHA.into(),
                    page: 4,
                    index: 0,
                    text: text.into(),
                    char_start: 0,
                    char_end: text.chars().count() as u32,
                    extraction: Extraction::PdfText,
                }],
                rule: "Reject anything outside 10 to 25 degrees.".into(),
                examples: vec![
                    Example {
                        id: "e1".into(),
                        text: "Stored at 18 C.".into(),
                        label: Label::Allowed,
                        reason: "within range".into(),
                    },
                    Example {
                        id: "e2".into(),
                        text: "Stored at 31 C.".into(),
                        label: Label::NotAllowed,
                        reason: "above 25".into(),
                    },
                ],
            },
            NOW,
        )
        .expect("fixture is valid")
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).expect("stat").permissions().mode() & 0o777
    }

    #[test]
    fn the_store_root_and_tenant_directory_are_owner_only() {
        let tmp = tempfile::tempdir().expect("tmp");
        let root = tmp.path().join("teach");
        let store = TeachStore::open(&root).expect("open");
        assert_eq!(mode_of(&root), 0o700);
        store.put(&session("acme", "t1")).expect("put");
        assert_eq!(mode_of(&root.join("acme")), 0o700);
    }

    #[test]
    fn a_session_file_is_written_mode_0600() {
        let tmp = tempfile::tempdir().expect("tmp");
        let store = TeachStore::open(&tmp.path().join("teach")).expect("open");
        let path = store.put(&session("acme", "t1")).expect("put");
        assert_eq!(mode_of(&path), 0o600, "{}", path.display());
    }

    #[test]
    fn a_session_is_stored_under_its_tenant_and_named_by_its_hash() {
        let tmp = tempfile::tempdir().expect("tmp");
        let store = TeachStore::open(&tmp.path().join("teach")).expect("open");
        let s = session("acme", "t1");
        let path = store.put(&s).expect("put");
        assert_eq!(
            path,
            tmp.path()
                .join("teach")
                .join("acme")
                .join(format!("{}.json", s.session_id))
        );
    }

    #[test]
    fn a_stored_session_reads_back_unchanged() {
        let tmp = tempfile::tempdir().expect("tmp");
        let store = TeachStore::open(&tmp.path().join("teach")).expect("open");
        let s = session("acme", "t1");
        store.put(&s).expect("put");
        assert_eq!(store.get("acme", &s.session_id).expect("get"), s);
    }

    #[test]
    fn a_tampered_session_is_refused_not_returned() {
        let tmp = tempfile::tempdir().expect("tmp");
        let store = TeachStore::open(&tmp.path().join("teach")).expect("open");
        let s = session("acme", "t1");
        let path = store.put(&s).expect("put");

        // Flip a label in the file without recomputing session_id — exactly
        // what an edit by hand or a disk-level change looks like.
        let text = std::fs::read_to_string(&path).expect("read");
        let edited = text.replacen("\"allowed\"", "\"not_allowed\"", 1);
        assert_ne!(text, edited, "fixture must contain the label");
        std::fs::remove_file(&path).expect("rm");
        std::fs::write(&path, edited).expect("write");

        match store.get("acme", &s.session_id) {
            Err(StoreError::Tampered {
                recorded, computed, ..
            }) => {
                assert_eq!(recorded, s.session_id);
                assert_ne!(computed, s.session_id);
            }
            other => panic!("expected Tampered, got {other:?}"),
        }
    }

    #[test]
    fn a_tampered_session_also_fails_a_tenant_listing() {
        // `list` must not be a way around `get`'s hash check.
        let tmp = tempfile::tempdir().expect("tmp");
        let store = TeachStore::open(&tmp.path().join("teach")).expect("open");
        let s = session("acme", "t1");
        let path = store.put(&s).expect("put");
        let text = std::fs::read_to_string(&path).expect("read");
        std::fs::remove_file(&path).expect("rm");
        std::fs::write(&path, text.replacen("18 C", "99 C", 1)).expect("write");
        assert!(matches!(
            store.list("acme"),
            Err(StoreError::Tampered { .. })
        ));
    }

    #[test]
    fn writing_the_same_session_twice_is_refused() {
        let tmp = tempfile::tempdir().expect("tmp");
        let store = TeachStore::open(&tmp.path().join("teach")).expect("open");
        let s = session("acme", "t1");
        store.put(&s).expect("first put");
        assert!(matches!(store.put(&s), Err(StoreError::Exists(_))));
    }

    #[test]
    fn a_missing_session_is_not_found_rather_than_an_io_error() {
        let tmp = tempfile::tempdir().expect("tmp");
        let store = TeachStore::open(&tmp.path().join("teach")).expect("open");
        match store.get("acme", &"a".repeat(64)) {
            Err(StoreError::NotFound { tenant, .. }) => assert_eq!(tenant, "acme"),
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn a_tenant_with_no_sessions_lists_empty_and_is_not_an_error() {
        let tmp = tempfile::tempdir().expect("tmp");
        let store = TeachStore::open(&tmp.path().join("teach")).expect("open");
        assert!(store.list("never-taught").expect("list").is_empty());
    }

    #[test]
    fn one_tenants_sessions_are_not_listed_for_another() {
        let tmp = tempfile::tempdir().expect("tmp");
        let store = TeachStore::open(&tmp.path().join("teach")).expect("open");
        let a = session("acme", "t1");
        let b = session("beta", "t1");
        store.put(&a).expect("put a");
        store.put(&b).expect("put b");
        let listed: Vec<String> = store
            .list("acme")
            .expect("list")
            .into_iter()
            .map(|s| s.session_id)
            .collect();
        assert_eq!(listed, vec![a.session_id.clone()]);
        // And a cross-tenant read by id does not reach the other tenant's file.
        assert!(matches!(
            store.get("acme", &b.session_id),
            Err(StoreError::NotFound { .. })
        ));
    }

    #[test]
    fn a_listing_is_ordered_by_session_id() {
        let tmp = tempfile::tempdir().expect("tmp");
        let store = TeachStore::open(&tmp.path().join("teach")).expect("open");
        let mut ids = Vec::new();
        for task in ["t1", "t2", "t3"] {
            let s = session("acme", task);
            store.put(&s).expect("put");
            ids.push(s.session_id);
        }
        ids.sort();
        let listed: Vec<String> = store
            .list("acme")
            .expect("list")
            .into_iter()
            .map(|s| s.session_id)
            .collect();
        assert_eq!(listed, ids);
    }

    #[test]
    fn an_unsafe_tenant_or_session_name_cannot_reach_outside_the_store() {
        let tmp = tempfile::tempdir().expect("tmp");
        let store = TeachStore::open(&tmp.path().join("teach")).expect("open");
        for bad in ["..", "../..", "a/b", ".hidden", "", "with space"] {
            assert!(
                matches!(
                    store.get(bad, &"a".repeat(64)),
                    Err(StoreError::UnsafeName {
                        field: "tenant",
                        ..
                    })
                ),
                "tenant {bad:?} was accepted"
            );
            assert!(
                matches!(
                    store.list(bad),
                    Err(StoreError::UnsafeName {
                        field: "tenant",
                        ..
                    })
                ),
                "list({bad:?}) was accepted"
            );
            assert!(
                matches!(
                    store.get("acme", bad),
                    Err(StoreError::UnsafeName {
                        field: "session_id",
                        ..
                    })
                ),
                "session {bad:?} was accepted"
            );
        }
    }

    #[test]
    fn a_file_that_is_not_a_session_is_reported_as_malformed() {
        let tmp = tempfile::tempdir().expect("tmp");
        let root = tmp.path().join("teach");
        let store = TeachStore::open(&root).expect("open");
        let dir = root.join("acme");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join(format!("{}.json", "b".repeat(64)));
        std::fs::write(&path, "{\"schema\": \"wrong\"}").expect("write");
        assert!(matches!(
            store.load(&path),
            Err(StoreError::Malformed { .. })
        ));
        assert!(matches!(
            store.list("acme"),
            Err(StoreError::Malformed { .. })
        ));
    }

    #[test]
    fn non_json_files_in_a_tenant_directory_are_ignored_by_a_listing() {
        let tmp = tempfile::tempdir().expect("tmp");
        let root = tmp.path().join("teach");
        let store = TeachStore::open(&root).expect("open");
        let s = session("acme", "t1");
        store.put(&s).expect("put");
        std::fs::write(root.join("acme").join("notes.txt"), "scratch").expect("write");
        assert_eq!(store.list("acme").expect("list").len(), 1);
    }

    #[test]
    fn every_store_error_prints_what_was_wrong() {
        let cases = vec![
            StoreError::Io("disk full".into()),
            StoreError::Malformed {
                path: "/x.json".into(),
                detail: "eof".into(),
            },
            StoreError::Tampered {
                path: "/x.json".into(),
                recorded: "a".repeat(64),
                computed: "b".repeat(64),
            },
            StoreError::UnsafeName {
                field: "tenant",
                value: "..".into(),
            },
            StoreError::NotFound {
                tenant: "acme".into(),
                session_id: "a".repeat(64),
            },
            StoreError::Exists("/x.json".into()),
        ];
        for c in cases {
            assert!(!c.to_string().is_empty(), "{c:?} printed nothing");
        }
    }
}
