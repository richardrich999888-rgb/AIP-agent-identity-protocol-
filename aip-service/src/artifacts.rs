//! Signed verdicts and access ledgers, stored and served by the regulated
//! entity's own service (R10 of `docs/pilot/RBI_REQUIREMENTS_COVERAGE.md`,
//! matrix row C5).
//!
//! # What this tier adds, and what it must not
//!
//! Before this, a reconciliation verdict existed only where it was computed.
//! An inspector asking a bank "what did your agent do last Tuesday" had no
//! endpoint to ask. This adds one.
//!
//! What it must not add is a second source of truth. A verdict and an access
//! ledger are **already self-verifying documents**: each carries the
//! signature of the authority that produced it, over a canonical encoding a
//! third party recomputes. So this tier stores the bytes verbatim and hands
//! them back verbatim. The service is a filing cabinet, not a notary:
//!
//! - It **verifies before it stores**, under anchors the caller supplies.
//!   Storing a document that does not verify would make the service a
//!   laundry — a forged verdict would acquire the bank's endpoint as its
//!   provenance. A refusal here costs nothing; an acceptance is permanent.
//! - It **adds no signature of its own**. Nothing the service says makes a
//!   verdict more true, and a service counter-signature would invite a
//!   reader to trust the endpoint instead of the document.
//! - It **stores the exact bytes**. A response re-serialised from parsed
//!   structures would verify only if this crate's serialiser happened to
//!   agree with the producer's; the whole point is that an auditor can pipe
//!   the response into `nexora-verify` with their own keys.
//!
//! # Tenancy
//!
//! The same envelope rule as evidence: the tenant comes from the caller's
//! API key, never from the body, and a cross-tenant read returns 404 —
//! identical to not-found, so existence does not leak.

use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// What kind of signed document a row holds.
///
/// A closed set, because the storage layer is generic over these but the
/// verification that precedes a write is not: each kind is checked by the
/// crate that defines it, under that crate's anchors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactKind {
    /// `aip_reconcile::SignedReconciliation` — one verdict.
    Verdict,
    /// `aip_ledger::AccessLedger` — one agent, one window.
    AccessLedger,
    /// Original collector archive strings, verified before admission under
    /// the institution's configured tenant-bound observer anchors.
    ObserverArchive,
    /// Immutable same-run input, reevaluated under tenant-configured anchors.
    RunBundle,
}

impl ArtifactKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verdict => "verdict",
            Self::AccessLedger => "access_ledger",
            Self::ObserverArchive => "observer_archive",
            Self::RunBundle => "run_bundle",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "verdict" => Some(Self::Verdict),
            "access_ledger" => Some(Self::AccessLedger),
            "observer_archive" => Some(Self::ObserverArchive),
            "run_bundle" => Some(Self::RunBundle),
            _ => None,
        }
    }
}

/// One stored document plus the envelope the service files it under.
///
/// Everything outside `body` is an index. None of it is trusted on read: a
/// consumer that cares recomputes from `body`, which is what the producer
/// signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredArtifact {
    /// Hex SHA-256 of the document's own canonical bytes — not of the JSON,
    /// so two serialisations of one document file under one id and a
    /// re-submission is idempotent rather than duplicated.
    pub id: String,
    pub kind: ArtifactKind,
    /// Storage envelope, from the caller's key. Not inside any signature.
    pub tenant_id: String,
    /// The agent a document concerns, when it names one. A verdict does not:
    /// a `Reconciliation` carries a decision and evidence references, and
    /// attribution is the reconciler's finding, not a field.
    pub agent_id: Option<String>,
    /// Coverage window, when the document has one.
    pub from_ms: Option<i64>,
    pub to_ms: Option<i64>,
    /// When the service filed it. The service's clock, about its own act.
    pub stored_at_ms: i64,
    /// The document, verbatim, exactly as submitted.
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactStoreError {
    /// The id exists under a different tenant. Returned to the caller as a
    /// generic 404, never as a distinguishable error: see `get`.
    TenantConflict,
    Backend(String),
}

impl std::fmt::Display for ArtifactStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TenantConflict => write!(f, "artifact id exists under another tenant"),
            Self::Backend(e) => write!(f, "artifact store: {e}"),
        }
    }
}

impl std::error::Error for ArtifactStoreError {}

#[async_trait::async_trait]
pub trait ArtifactStore: Send + Sync {
    /// Read/write readiness without filing a document or changing evidence.
    async fn check_health(&self) -> Result<(), ArtifactStoreError>;
    /// File a document. Idempotent within a tenant: the id is a digest of
    /// the document, so re-submitting the same bytes is a no-op rather than
    /// a duplicate row.
    async fn put(&self, artifact: StoredArtifact) -> Result<String, ArtifactStoreError>;

    /// One document, only if it belongs to `tenant_id`.
    async fn get(
        &self,
        tenant_id: &str,
        kind: ArtifactKind,
        id: &str,
    ) -> Result<Option<StoredArtifact>, ArtifactStoreError>;

    /// Every document of `kind` this tenant holds for `agent_id`, newest
    /// window last.
    async fn for_agent(
        &self,
        tenant_id: &str,
        kind: ArtifactKind,
        agent_id: &str,
    ) -> Result<Vec<StoredArtifact>, ArtifactStoreError>;
}

// ─── JSONL / in-memory backend ─────────────────────────────────────────────

/// Append-only JSONL, mirroring [`crate::store::JsonlEvidenceStore`].
///
/// Development, air-gapped single-node use, and a migration source. It has
/// the same durability caveat as its evidence counterpart — no fsync, no
/// cross-process locking — and the same remedy: use PostgreSQL, under
/// `deploy/sql/hardening.sql`, for anything an inspector will read.
pub struct JsonlArtifactStore {
    path: Option<std::path::PathBuf>,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    /// `(tenant, kind, id)` → row.
    by_key: HashMap<(String, String, String), StoredArtifact>,
    /// `id` → tenant, so a cross-tenant id collision is detectable.
    owner: HashMap<String, String>,
    /// An unsuccessful append can leave a partial record. Refuse further
    /// writes until an operator repairs/reopens the store.
    write_failed: bool,
}

impl JsonlArtifactStore {
    pub fn in_memory() -> Self {
        Self {
            path: None,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Open (creating if absent) and replay an append-only file.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ArtifactStoreError> {
        let path = path.as_ref().to_path_buf();
        // Check writability at startup, not after acknowledging a filing.
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| ArtifactStoreError::Backend(format!("open {}: {e}", path.display())))?;
        let mut inner = Inner::default();
        if path.exists() {
            let text = std::fs::read_to_string(&path).map_err(|e| {
                ArtifactStoreError::Backend(format!("read {}: {e}", path.display()))
            })?;
            if !text.is_empty() && !text.ends_with('\n') {
                return Err(ArtifactStoreError::Backend(
                    "artifact file has an incomplete final append; recover it before reopening"
                        .into(),
                ));
            }
            for (index, line) in text
                .lines()
                .enumerate()
                .filter(|(_, l)| !l.trim().is_empty())
            {
                // Skipping a damaged line would advertise a complete store
                // after losing evidence. Preserve the bytes and refuse to
                // open until recovery is reviewed.
                let a = serde_json::from_str::<StoredArtifact>(line).map_err(|e| {
                    ArtifactStoreError::Backend(format!(
                        "invalid artifact record at line {}: {e}",
                        index + 1
                    ))
                })?;
                inner.owner.insert(a.id.clone(), a.tenant_id.clone());
                inner.by_key.insert(
                    (
                        a.tenant_id.clone(),
                        a.kind.as_str().to_string(),
                        a.id.clone(),
                    ),
                    a,
                );
            }
        }
        Ok(Self {
            path: Some(path),
            inner: Mutex::new(inner),
        })
    }
}

#[async_trait::async_trait]
impl ArtifactStore for JsonlArtifactStore {
    async fn check_health(&self) -> Result<(), ArtifactStoreError> {
        if self.inner.lock().unwrap().write_failed {
            return Err(ArtifactStoreError::Backend(
                "artifact store requires recovery after failed append".into(),
            ));
        }
        if let Some(path) = &self.path {
            // No create flag: a Reader health request never creates files.
            std::fs::OpenOptions::new()
                .read(true)
                .append(true)
                .open(path)
                .map_err(|e| ArtifactStoreError::Backend(format!("artifact readiness: {e}")))?;
        }
        Ok(())
    }
    async fn put(&self, artifact: StoredArtifact) -> Result<String, ArtifactStoreError> {
        let id = artifact.id.clone();
        let mut inner = self.inner.lock().unwrap();
        if inner.write_failed {
            return Err(ArtifactStoreError::Backend(
                "artifact append failed; recover the store before retrying".into(),
            ));
        }
        if let Some(existing) = inner.owner.get(&id) {
            if existing != &artifact.tenant_id {
                return Err(ArtifactStoreError::TenantConflict);
            }
            // Same tenant, same bytes: already filed.
            return Ok(id);
        }
        if let Some(path) = &self.path {
            let line = serde_json::to_string(&artifact)
                .map_err(|e| ArtifactStoreError::Backend(e.to_string()))?;
            let append = (|| -> Result<(), ArtifactStoreError> {
                let mut f = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|e| ArtifactStoreError::Backend(format!("open: {e}")))?;
                writeln!(f, "{line}")
                    .map_err(|e| ArtifactStoreError::Backend(format!("write: {e}")))?;
                f.sync_data()
                    .map_err(|e| ArtifactStoreError::Backend(format!("sync: {e}")))?;
                Ok(())
            })();
            if let Err(e) = append {
                inner.write_failed = true;
                return Err(e);
            }
        }
        // Publish only after persistence succeeds. A failed filing must
        // never turn into a successful in-memory idempotency response.
        inner.owner.insert(id.clone(), artifact.tenant_id.clone());
        inner.by_key.insert(
            (
                artifact.tenant_id.clone(),
                artifact.kind.as_str().to_string(),
                id.clone(),
            ),
            artifact,
        );
        Ok(id)
    }

    async fn get(
        &self,
        tenant_id: &str,
        kind: ArtifactKind,
        id: &str,
    ) -> Result<Option<StoredArtifact>, ArtifactStoreError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .by_key
            .get(&(
                tenant_id.to_string(),
                kind.as_str().to_string(),
                id.to_string(),
            ))
            .cloned())
    }

    async fn for_agent(
        &self,
        tenant_id: &str,
        kind: ArtifactKind,
        agent_id: &str,
    ) -> Result<Vec<StoredArtifact>, ArtifactStoreError> {
        let inner = self.inner.lock().unwrap();
        let mut out: Vec<StoredArtifact> = inner
            .by_key
            .values()
            .filter(|a| {
                a.tenant_id == tenant_id
                    && a.kind == kind
                    && a.agent_id.as_deref() == Some(agent_id)
            })
            .cloned()
            .collect();
        out.sort_by(|a, b| {
            a.from_ms
                .cmp(&b.from_ms)
                .then(a.to_ms.cmp(&b.to_ms))
                .then(a.id.cmp(&b.id))
        });
        Ok(out)
    }
}

// ─── PostgreSQL backend ────────────────────────────────────────────────────

#[cfg(feature = "postgres")]
pub mod pg {
    use super::*;
    use deadpool_postgres::Pool;

    // The DDL lives with the evidence schema in `store/pg.rs`, applied in one
    // place so `deploy/sql/hardening.sql` cannot cover one tier and miss the
    // other.

    pub struct PostgresArtifactStore {
        pool: Pool,
    }

    fn be<E: std::fmt::Display>(e: E) -> ArtifactStoreError {
        ArtifactStoreError::Backend(e.to_string())
    }

    impl PostgresArtifactStore {
        /// Share the evidence store's pool: one connection pool per process,
        /// so the tenant GUC discipline and the pool limits are the same for
        /// both tiers.
        pub fn with_pool(pool: Pool) -> Self {
            Self { pool }
        }

        fn row_to_artifact(r: &tokio_postgres::Row) -> Option<StoredArtifact> {
            Some(StoredArtifact {
                id: r.get("id"),
                kind: ArtifactKind::parse(r.get::<_, &str>("kind"))?,
                tenant_id: r.get("tenant_id"),
                agent_id: r.get("agent_id"),
                from_ms: r.get("from_ms"),
                to_ms: r.get("to_ms"),
                stored_at_ms: r.get("stored_at_ms"),
                body: r.get("body"),
            })
        }
    }

    #[async_trait::async_trait]
    impl ArtifactStore for PostgresArtifactStore {
        async fn check_health(&self) -> Result<(), ArtifactStoreError> {
            let c = self.pool.get().await.map_err(be)?;
            let row = c.query_one("SELECT has_table_privilege(current_user, 'signed_artifacts', 'SELECT') AND has_table_privilege(current_user, 'signed_artifacts', 'INSERT')", &[]).await.map_err(be)?;
            if !row.get::<_, bool>(0) {
                return Err(ArtifactStoreError::Backend(
                    "artifact store lacks read/write privileges".into(),
                ));
            }
            Ok(())
        }
        async fn put(&self, a: StoredArtifact) -> Result<String, ArtifactStoreError> {
            let mut c = self.pool.get().await.map_err(be)?;
            let tx = c.transaction().await.map_err(be)?;
            // Row-level security reads this; see store/pg.rs for why it is
            // set per transaction rather than per connection.
            tx.execute(
                "SELECT set_config('aip.tenant_id', $1, true)",
                &[&a.tenant_id],
            )
            .await
            .map_err(be)?;

            if let Some(row) = tx
                .query_opt(
                    "SELECT tenant_id FROM signed_artifacts WHERE kind=$1 AND id=$2",
                    &[&a.kind.as_str(), &a.id],
                )
                .await
                .map_err(be)?
            {
                let existing: String = row.get(0);
                tx.commit().await.map_err(be)?;
                if existing != a.tenant_id {
                    return Err(ArtifactStoreError::TenantConflict);
                }
                return Ok(a.id);
            }

            let inserted = tx
                .execute(
                    "INSERT INTO signed_artifacts
                     (id, kind, tenant_id, agent_id, from_ms, to_ms, stored_at_ms, body)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (kind,id) DO NOTHING",
                    &[
                        &a.id,
                        &a.kind.as_str(),
                        &a.tenant_id,
                        &a.agent_id,
                        &a.from_ms,
                        &a.to_ms,
                        &a.stored_at_ms,
                        &a.body,
                    ],
                )
                .await
                .map_err(be)?;
            if inserted == 0 {
                // A concurrent same-tenant insertion is idempotent; an
                // invisible other-tenant row is a generic tenant conflict.
                let owned = tx
                    .query_opt(
                        "SELECT id FROM signed_artifacts WHERE kind=$1 AND id=$2 AND tenant_id=$3",
                        &[&a.kind.as_str(), &a.id, &a.tenant_id],
                    )
                    .await
                    .map_err(be)?;
                if owned.is_none() {
                    return Err(ArtifactStoreError::TenantConflict);
                }
            }
            tx.commit().await.map_err(be)?;
            Ok(a.id)
        }

        async fn get(
            &self,
            tenant_id: &str,
            kind: ArtifactKind,
            id: &str,
        ) -> Result<Option<StoredArtifact>, ArtifactStoreError> {
            let mut c = self.pool.get().await.map_err(be)?;
            let tx = c.transaction().await.map_err(be)?;
            tx.execute(
                "SELECT set_config('aip.tenant_id', $1, true)",
                &[&tenant_id],
            )
            .await
            .map_err(be)?;
            let row = tx
                .query_opt(
                    "SELECT * FROM signed_artifacts
                     WHERE kind=$1 AND id=$2 AND tenant_id=$3",
                    &[&kind.as_str(), &id, &tenant_id],
                )
                .await
                .map_err(be)?;
            tx.commit().await.map_err(be)?;
            Ok(row.as_ref().and_then(Self::row_to_artifact))
        }

        async fn for_agent(
            &self,
            tenant_id: &str,
            kind: ArtifactKind,
            agent_id: &str,
        ) -> Result<Vec<StoredArtifact>, ArtifactStoreError> {
            let mut c = self.pool.get().await.map_err(be)?;
            let tx = c.transaction().await.map_err(be)?;
            tx.execute(
                "SELECT set_config('aip.tenant_id', $1, true)",
                &[&tenant_id],
            )
            .await
            .map_err(be)?;
            let rows = tx
                .query(
                    "SELECT * FROM signed_artifacts
                     WHERE tenant_id=$1 AND kind=$2 AND agent_id=$3
                     ORDER BY from_ms ASC NULLS FIRST, to_ms ASC NULLS FIRST, id ASC",
                    &[&tenant_id, &kind.as_str(), &agent_id],
                )
                .await
                .map_err(be)?;
            tx.commit().await.map_err(be)?;
            Ok(rows.iter().filter_map(Self::row_to_artifact).collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(tenant: &str, id: &str, agent: Option<&str>, from: i64) -> StoredArtifact {
        StoredArtifact {
            id: id.into(),
            kind: ArtifactKind::AccessLedger,
            tenant_id: tenant.into(),
            agent_id: agent.map(|s| s.to_string()),
            from_ms: Some(from),
            to_ms: Some(from + 1_000),
            stored_at_ms: 42,
            body: format!("{{\"id\":\"{id}\"}}"),
        }
    }

    #[tokio::test]
    async fn a_cross_tenant_read_is_empty_not_an_error() {
        let s = JsonlArtifactStore::in_memory();
        s.put(artifact("acme", "a1", Some("agent"), 0))
            .await
            .unwrap();
        assert!(s
            .get("acme", ArtifactKind::AccessLedger, "a1")
            .await
            .unwrap()
            .is_some());
        assert!(
            s.get("globex", ArtifactKind::AccessLedger, "a1")
                .await
                .unwrap()
                .is_none(),
            "another tenant must read nothing, indistinguishable from absent"
        );
    }

    #[tokio::test]
    async fn the_same_document_filed_twice_is_one_row() {
        let s = JsonlArtifactStore::in_memory();
        let a = artifact("acme", "a1", Some("agent"), 0);
        assert_eq!(s.put(a.clone()).await.unwrap(), "a1");
        assert_eq!(s.put(a).await.unwrap(), "a1");
        assert_eq!(
            s.for_agent("acme", ArtifactKind::AccessLedger, "agent")
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn an_id_already_held_by_another_tenant_is_refused() {
        let s = JsonlArtifactStore::in_memory();
        s.put(artifact("acme", "a1", Some("agent"), 0))
            .await
            .unwrap();
        assert_eq!(
            s.put(artifact("globex", "a1", Some("agent"), 0)).await,
            Err(ArtifactStoreError::TenantConflict)
        );
    }

    #[tokio::test]
    async fn a_kind_does_not_answer_for_another_kind() {
        let s = JsonlArtifactStore::in_memory();
        s.put(artifact("acme", "a1", Some("agent"), 0))
            .await
            .unwrap();
        assert!(s
            .get("acme", ArtifactKind::Verdict, "a1")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn an_agent_listing_is_ordered_by_window_and_scoped_to_one_agent() {
        let s = JsonlArtifactStore::in_memory();
        s.put(artifact("acme", "later", Some("agent"), 5_000))
            .await
            .unwrap();
        s.put(artifact("acme", "earlier", Some("agent"), 1_000))
            .await
            .unwrap();
        s.put(artifact("acme", "other", Some("someone-else"), 0))
            .await
            .unwrap();
        let ids: Vec<String> = s
            .for_agent("acme", ArtifactKind::AccessLedger, "agent")
            .await
            .unwrap()
            .into_iter()
            .map(|a| a.id)
            .collect();
        assert_eq!(ids, vec!["earlier".to_string(), "later".to_string()]);
    }

    #[tokio::test]
    async fn a_failed_append_never_publishes_or_acknowledges_a_retry() {
        let path = std::env::temp_dir().join(format!("artifact_failure_{}", uuid::Uuid::new_v4()));
        let s = JsonlArtifactStore::open(&path).unwrap();
        // Replace the destination with a directory to force an actual I/O
        // failure even when the test runs as a privileged user.
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let a = artifact("acme", "failed", Some("agent"), 0);
        assert!(s.put(a.clone()).await.is_err());
        assert!(s.check_health().await.is_err());
        assert!(s
            .get("acme", ArtifactKind::AccessLedger, "failed")
            .await
            .unwrap()
            .is_none());
        std::fs::remove_dir(&path).unwrap();
        assert!(
            s.put(a).await.is_err(),
            "a failed store must require recovery"
        );
        let reopened = JsonlArtifactStore::open(&path).unwrap();
        assert!(reopened
            .get("acme", ArtifactKind::AccessLedger, "failed")
            .await
            .unwrap()
            .is_none());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn damaged_records_are_preserved_and_refused_instead_of_skipped() {
        let path = std::env::temp_dir().join(format!("artifact_damaged_{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, b"{truncated").unwrap();
        assert!(JsonlArtifactStore::open(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"{truncated");
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn acknowledged_filings_survive_reopening() {
        let path = std::env::temp_dir().join(format!("artifact_restart_{}", uuid::Uuid::new_v4()));
        let s = JsonlArtifactStore::open(&path).unwrap();
        s.put(artifact("acme", "persisted", Some("agent"), 0))
            .await
            .unwrap();
        drop(s);
        let s = JsonlArtifactStore::open(&path).unwrap();
        assert!(s
            .get("acme", ArtifactKind::AccessLedger, "persisted")
            .await
            .unwrap()
            .is_some());
        std::fs::remove_file(path).unwrap();
    }
}
