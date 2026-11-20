//! Finding recorded in docs/enterprise-wow/ADR-001-decisionpoint-revocation.md:
//! `RevocationLog::revoke` discards the error from `save()`
//! (`let _ = self.save();`). A revocation that could not be written is
//! reported as done, holds in memory, and is gone after a restart.
//!
//! `finding_*` pins **current** behaviour. When `revoke` returns the
//! persistence error, flip it to expect that error. Do not delete it.

use std::path::PathBuf;

use aip_core::revocation::RevocationLog;
use aip_types::RevocationReason;

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("aip-revlog-finding-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn finding_unpersisted_revocation_is_reported_done_and_lost_on_restart() {
    let dir = scratch("lost");
    // The log's parent "directory" is a regular file, so save() cannot create it.
    let blocker = dir.join("blocker");
    std::fs::write(&blocker, b"not a directory").unwrap();
    let path = blocker.join("revocations.json");

    let mut log = RevocationLog::with_file(&path).unwrap();
    let jti = [7u8; 16];
    let entries = log.revoke(
        jti,
        RevocationReason::AgentCompromised,
        "security-officer",
        false,
        None,
    );

    // Reported as done, and effective in this process...
    assert_eq!(entries.len(), 1);
    assert!(log.is_revoked(&jti));
    // ...but nothing reached storage...
    assert!(!path.exists());
    // ...so after a restart the agent is no longer revoked.
    let restarted = RevocationLog::with_file(&path).unwrap();
    assert!(
        !restarted.is_revoked(&jti),
        "finding fixed? flip this test and update ADR-001"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn control_persisted_revocation_survives_restart() {
    let dir = scratch("kept");
    let path = dir.join("revocations.json");
    let mut log = RevocationLog::with_file(&path).unwrap();
    let jti = [9u8; 16];
    log.revoke(
        jti,
        RevocationReason::AgentCompromised,
        "security-officer",
        false,
        None,
    );
    assert!(path.exists());
    assert!(RevocationLog::with_file(&path).unwrap().is_revoked(&jti));
    std::fs::remove_dir_all(&dir).unwrap();
}
