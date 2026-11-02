//! PostgreSQL-backed [`EvidenceStore`] (feature `postgres`).
//!
//! Durable, transactional metadata store for enterprise deployment. Each
//! `store` is a single transaction that writes the packet row plus the
//! derived authority graph (nodes + edges), so the accountability graph is
//! materialised and tenant-isolated in SQL. The signed EvidencePacket itself
//! is stored verbatim as JSON in `evidence_json` and re-verifies identically.

use std::str::FromStr;

use aip_protocol::{AccountabilityGraph, EvidencePacket};
use deadpool_postgres::{Manager, ManagerConfig, Object, Pool, RecyclingMethod};
use tokio_postgres::error::SqlState;
use tokio_postgres::NoTls;

use super::{integrity_status, EvidenceStore, StoreError};

/// DDL applied on connect (idempotent). Mirrors `deploy/sql/schema.sql`.
pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS evidence_packets (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT   NOT NULL,
    packet_hash         TEXT   NOT NULL,
    created_at          BIGINT NOT NULL,
    evidence_json       TEXT   NOT NULL,
    verification_status TEXT   NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_tenant  ON evidence_packets(tenant_id);
CREATE INDEX IF NOT EXISTS idx_evidence_hash    ON evidence_packets(packet_hash);
CREATE INDEX IF NOT EXISTS idx_evidence_created ON evidence_packets(created_at);

CREATE TABLE IF NOT EXISTS authority_nodes (
    tenant_id  TEXT NOT NULL,
    packet_id  TEXT NOT NULL,
    node_id    TEXT NOT NULL,
    kind       TEXT NOT NULL,
    label      TEXT NOT NULL,
    PRIMARY KEY (tenant_id, packet_id, node_id)
);
CREATE INDEX IF NOT EXISTS idx_nodes_tenant ON authority_nodes(tenant_id);

CREATE TABLE IF NOT EXISTS authority_edges (
    tenant_id  TEXT NOT NULL,
    packet_id  TEXT NOT NULL,
    from_node  TEXT NOT NULL,
    to_node    TEXT NOT NULL,
    relation   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_edges_tenant ON authority_edges(tenant_id);

-- Signed verdicts and access ledgers (R10). Created with the evidence
-- schema, so `deploy/sql/hardening.sql` covers it under the same grants and
-- the same row-level policy: an artifact tier with weaker storage controls
-- than the evidence tier would be the place an inspector's answer went to be
-- edited.
CREATE TABLE IF NOT EXISTS signed_artifacts (
    id            TEXT   NOT NULL,
    kind          TEXT   NOT NULL,
    tenant_id     TEXT   NOT NULL,
    agent_id      TEXT,
    from_ms       BIGINT,
    to_ms         BIGINT,
    stored_at_ms  BIGINT NOT NULL,
    body          TEXT   NOT NULL,
    PRIMARY KEY (kind, id)
);
CREATE INDEX IF NOT EXISTS idx_artifacts_tenant ON signed_artifacts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_agent  ON signed_artifacts(tenant_id, kind, agent_id);
"#;

fn be<E: std::fmt::Display>(e: E) -> StoreError {
    StoreError::Backend(e.to_string())
}

pub struct PostgresEvidenceStore {
    pool: Pool,
}

impl PostgresEvidenceStore {
    /// Connect (pooled) to `database_url` and apply the schema.
    pub async fn connect(database_url: &str) -> Result<Self, StoreError> {
        let pg_cfg = tokio_postgres::Config::from_str(database_url).map_err(be)?;
        let mgr = Manager::from_config(
            pg_cfg,
            NoTls,
            ManagerConfig {
                recycling_method: RecyclingMethod::Fast,
            },
        );
        let pool = Pool::builder(mgr).max_size(16).build().map_err(be)?;
        let store = Self { pool };
        store.init_schema().await?;
        Ok(store)
    }

    /// The connection pool, so the artifact store (R10) shares it rather
    /// than opening a second one: one pool per process keeps the tenant-GUC
    /// discipline and the connection limits identical for both tiers.
    pub fn pool(&self) -> Pool {
        self.pool.clone()
    }

    async fn client(&self) -> Result<Object, StoreError> {
        self.pool.get().await.map_err(be)
    }

    async fn init_schema(&self) -> Result<(), StoreError> {
        // Serialize DDL across concurrent connections with a session advisory
        // lock — concurrent CREATE TABLE/INDEX IF NOT EXISTS can otherwise race
        // on the system catalogs.
        const SCHEMA_LOCK_KEY: i64 = 0x0A1_5C4E_2026;
        let c = self.client().await?;
        c.execute("SELECT pg_advisory_lock($1)", &[&SCHEMA_LOCK_KEY])
            .await
            .map_err(be)?;
        let result = c.batch_execute(SCHEMA).await;
        let _ = c
            .execute("SELECT pg_advisory_unlock($1)", &[&SCHEMA_LOCK_KEY])
            .await;
        match result {
            Ok(()) => Ok(()),
            // A hardened deployment (deploy/sql/hardening.sql) gives the
            // service a role with no DDL privilege, on purpose: a service
            // that can create a table can drop one. That role cannot run
            // this DDL and must not fail to start because of it — but it
            // also must not start against a database that has no schema at
            // all, so the tables are confirmed to exist instead.
            Err(e) if e.code() == Some(&SqlState::INSUFFICIENT_PRIVILEGE) => {
                self.require_provisioned_schema().await
            }
            Err(e) => Err(be(e)),
        }
    }

    /// Confirm the tables this service needs are already present.
    ///
    /// Used only when the connecting role is not permitted to create them.
    /// The alternative — starting anyway and failing on the first request —
    /// turns a provisioning mistake into a runtime one.
    async fn require_provisioned_schema(&self) -> Result<(), StoreError> {
        let c = self.client().await?;
        for table in [
            "evidence_packets",
            "authority_nodes",
            "authority_edges",
            "signed_artifacts",
        ] {
            let row = c
                .query_one("SELECT to_regclass($1) IS NOT NULL", &[&table])
                .await
                .map_err(be)?;
            let present: bool = row.get(0);
            if !present {
                return Err(StoreError::Backend(format!(
                    "table `{table}` is absent and this role may not create it: \
                     apply deploy/sql/schema.sql and deploy/sql/hardening.sql as \
                     the owning role before starting the service"
                )));
            }
        }
        Ok(())
    }

    /// Declare the tenant this connection is acting for, for the remainder of
    /// the current transaction.
    ///
    /// Row-level security (`deploy/sql/hardening.sql`) reads
    /// `aip.tenant_id`, and with no value set the policy admits no rows at
    /// all — a connection that has not said who it is sees nothing. `is_local
    /// = true` scopes the setting to the transaction, which is what makes it
    /// safe under a connection pool: a pooled connection cannot carry one
    /// request's tenant into the next.
    ///
    /// On a database without the policy applied this is an inert session
    /// variable, so the same code path serves both deployments.
    async fn declare_tenant(
        tx: &tokio_postgres::Transaction<'_>,
        tenant_id: &str,
    ) -> Result<(), StoreError> {
        tx.execute(
            "SELECT set_config('aip.tenant_id', $1, true)",
            &[&tenant_id],
        )
        .await
        .map_err(be)?;
        Ok(())
    }

    /// Test/diagnostic helper: count materialised authority nodes for a tenant.
    pub async fn tenant_node_count(&self, tenant_id: &str) -> Result<i64, StoreError> {
        let mut c = self.client().await?;
        let tx = c.transaction().await.map_err(be)?;
        Self::declare_tenant(&tx, tenant_id).await?;
        let row = tx
            .query_one(
                "SELECT count(*) FROM authority_nodes WHERE tenant_id=$1",
                &[&tenant_id],
            )
            .await
            .map_err(be)?;
        tx.commit().await.map_err(be)?;
        Ok(row.get(0))
    }

    /// Test/diagnostic helper: count materialised authority edges for a tenant.
    pub async fn tenant_edge_count(&self, tenant_id: &str) -> Result<i64, StoreError> {
        let mut c = self.client().await?;
        let tx = c.transaction().await.map_err(be)?;
        Self::declare_tenant(&tx, tenant_id).await?;
        let row = tx
            .query_one(
                "SELECT count(*) FROM authority_edges WHERE tenant_id=$1",
                &[&tenant_id],
            )
            .await
            .map_err(be)?;
        tx.commit().await.map_err(be)?;
        Ok(row.get(0))
    }
}

#[async_trait::async_trait]
impl EvidenceStore for PostgresEvidenceStore {
    async fn store(&self, tenant_id: &str, packet: &EvidencePacket) -> Result<String, StoreError> {
        let id = packet.packet_id_hex();
        let mut client = self.client().await?;
        let tx = client.transaction().await.map_err(be)?;
        Self::declare_tenant(&tx, tenant_id).await?;

        // Idempotency + tenant-conflict check.
        if let Some(row) = tx
            .query_opt("SELECT tenant_id FROM evidence_packets WHERE id=$1", &[&id])
            .await
            .map_err(be)?
        {
            let existing: String = row.get(0);
            tx.commit().await.map_err(be)?;
            if existing != tenant_id {
                return Err(StoreError::TenantConflict);
            }
            return Ok(id);
        }

        let json = packet.to_json_compact().map_err(be)?;
        let created_at = packet.created_at as i64;
        let hash = hex::encode(packet.packet_hash);
        let status = integrity_status(packet);

        let inserted = tx
            .execute(
                "INSERT INTO evidence_packets \
             (id, tenant_id, packet_hash, created_at, evidence_json, verification_status) \
             VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (id) DO NOTHING",
                &[&id, &tenant_id, &hash, &created_at, &json, &status],
            )
            .await
            .map_err(be)?;
        if inserted == 0 {
            let owned = tx
                .query_opt(
                    "SELECT id FROM evidence_packets WHERE id=$1 AND tenant_id=$2",
                    &[&id, &tenant_id],
                )
                .await
                .map_err(be)?;
            if owned.is_none() {
                return Err(StoreError::TenantConflict);
            }
            tx.commit().await.map_err(be)?;
            return Ok(id);
        }

        // Materialise the accountability graph for durable, SQL-queryable,
        // tenant-isolated authority data.
        let graph = AccountabilityGraph::from_packet(packet);
        for node in &graph.nodes {
            tx.execute(
                "INSERT INTO authority_nodes (tenant_id, packet_id, node_id, kind, label) \
                 VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
                &[
                    &tenant_id,
                    &id,
                    &node.id,
                    &format!("{:?}", node.kind),
                    &node.label,
                ],
            )
            .await
            .map_err(be)?;
        }
        for edge in &graph.edges {
            tx.execute(
                "INSERT INTO authority_edges (tenant_id, packet_id, from_node, to_node, relation) \
                 VALUES ($1,$2,$3,$4,$5)",
                &[
                    &tenant_id,
                    &id,
                    &edge.from,
                    &edge.to,
                    &format!("{:?}", edge.relation),
                ],
            )
            .await
            .map_err(be)?;
        }

        tx.commit().await.map_err(be)?;
        Ok(id)
    }

    async fn get(&self, tenant_id: &str, id: &str) -> Result<Option<EvidencePacket>, StoreError> {
        let mut c = self.client().await?;
        let tx = c.transaction().await.map_err(be)?;
        Self::declare_tenant(&tx, tenant_id).await?;
        let row = tx
            .query_opt(
                "SELECT evidence_json FROM evidence_packets WHERE id=$1 AND tenant_id=$2",
                &[&id, &tenant_id],
            )
            .await
            .map_err(be)?;
        tx.commit().await.map_err(be)?;
        match row {
            None => Ok(None),
            Some(r) => {
                let json: String = r.get(0);
                Ok(Some(EvidencePacket::from_json(&json).map_err(be)?))
            }
        }
    }

    async fn all_for_tenant(&self, tenant_id: &str) -> Result<Vec<EvidencePacket>, StoreError> {
        let mut c = self.client().await?;
        let tx = c.transaction().await.map_err(be)?;
        Self::declare_tenant(&tx, tenant_id).await?;
        let rows = tx
            .query(
                "SELECT evidence_json FROM evidence_packets \
                 WHERE tenant_id=$1 ORDER BY created_at ASC, id ASC",
                &[&tenant_id],
            )
            .await
            .map_err(be)?;
        tx.commit().await.map_err(be)?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let json: String = r.get(0);
            out.push(EvidencePacket::from_json(&json).map_err(be)?);
        }
        Ok(out)
    }

    /// Rows visible to this connection.
    ///
    /// Under row-level security there is deliberately no such thing as a
    /// cross-tenant total: the connection declares no tenant here, so the
    /// policy admits nothing and this reports zero. That is the control
    /// working, not a fault. A per-tenant figure comes from
    /// [`Self::all_for_tenant`]; this exists for startup logging on
    /// deployments that have not applied the policy.
    async fn count(&self) -> Result<usize, StoreError> {
        let c = self.client().await?;
        let row = c
            .query_one("SELECT count(*) FROM evidence_packets", &[])
            .await
            .map_err(be)?;
        let n: i64 = row.get(0);
        Ok(n as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::sample_packet;

    // Integration tests run only when a database is available. Set
    //   AIP_TEST_DATABASE_URL=postgresql://aip:aip@127.0.0.1:5432/aip
    // and run: cargo test -p airon-aip --features postgres
    fn test_url() -> Option<String> {
        std::env::var("AIP_TEST_DATABASE_URL").ok()
    }

    fn unique_tenant() -> String {
        format!("t_{}", uuid::Uuid::new_v4().simple())
    }

    #[tokio::test]
    async fn pg_store_get_all_count_roundtrip() {
        let Some(url) = test_url() else {
            eprintln!("skip: AIP_TEST_DATABASE_URL unset");
            return;
        };
        let store = PostgresEvidenceStore::connect(&url).await.unwrap();
        let tenant = unique_tenant();
        let (p1, _) = sample_packet();
        let (p2, _) = sample_packet();

        let id1 = store.store(&tenant, &p1).await.unwrap();
        store.store(&tenant, &p2).await.unwrap();

        // get (tenant-scoped)
        let got = store.get(&tenant, &id1).await.unwrap().unwrap();
        assert_eq!(got.packet_hash, p1.packet_hash);

        // all_for_tenant
        assert_eq!(store.all_for_tenant(&tenant).await.unwrap().len(), 2);

        // idempotent re-store
        assert_eq!(store.store(&tenant, &p1).await.unwrap(), id1);
        assert_eq!(store.all_for_tenant(&tenant).await.unwrap().len(), 2);

        // authority graph materialised + tenant-scoped
        assert!(store.tenant_node_count(&tenant).await.unwrap() >= 2);
        assert!(store.tenant_edge_count(&tenant).await.unwrap() >= 2);
    }

    #[tokio::test]
    async fn pg_cross_tenant_isolation() {
        let Some(url) = test_url() else {
            eprintln!("skip: AIP_TEST_DATABASE_URL unset");
            return;
        };
        let store = PostgresEvidenceStore::connect(&url).await.unwrap();
        let ta = unique_tenant();
        let tb = unique_tenant();
        let (packet, _) = sample_packet();
        let id = store.store(&ta, &packet).await.unwrap();

        assert!(store.get(&tb, &id).await.unwrap().is_none());
        assert!(store.get(&ta, &id).await.unwrap().is_some());
        assert_eq!(store.all_for_tenant(&tb).await.unwrap().len(), 0);
        assert_eq!(store.tenant_node_count(&tb).await.unwrap(), 0);
    }

    // Run: cargo test --release --features postgres pg_benchmark_10k -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "benchmark — run explicitly with --ignored against a live DB"]
    async fn pg_benchmark_10k() {
        use std::time::Instant;
        let Some(url) = test_url() else {
            eprintln!("skip: AIP_TEST_DATABASE_URL unset");
            return;
        };
        let store = PostgresEvidenceStore::connect(&url).await.unwrap();
        let tenant = unique_tenant();
        const N: usize = 10_000;

        // Pre-generate signed packets (excluded from timing).
        let packets: Vec<_> = (0..N).map(|_| sample_packet().0).collect();

        let t0 = Instant::now();
        for p in &packets {
            store.store(&tenant, p).await.unwrap();
        }
        let insert = t0.elapsed();

        let mid_id = packets[N / 2].packet_id_hex();
        let t1 = Instant::now();
        for _ in 0..1_000 {
            store.get(&tenant, &mid_id).await.unwrap().unwrap();
        }
        let get = t1.elapsed();

        let t2 = Instant::now();
        let all = store.all_for_tenant(&tenant).await.unwrap();
        let fetch = t2.elapsed();
        assert_eq!(all.len(), N);

        // Authority query = fetch tenant packets + build index + resolve action.
        let action_hex = hex::encode(packets[N / 2].actions[0].action_id);
        let t3 = Instant::now();
        let all2 = store.all_for_tenant(&tenant).await.unwrap();
        let graph = crate::authority::AuthorityGraph::from_packets(all2);
        let _ = graph.who_authorized(&action_hex).unwrap();
        let authority = t3.elapsed();

        eprintln!("=== PostgresEvidenceStore benchmark (N={N}) ===");
        eprintln!(
            "insert:    {:?} total | {:.0} packets/sec | {:.3} ms/packet",
            insert,
            N as f64 / insert.as_secs_f64(),
            insert.as_secs_f64() * 1000.0 / N as f64
        );
        eprintln!(
            "get by id: {:.3} ms mean (1000 lookups)",
            get.as_secs_f64() * 1000.0 / 1000.0
        );
        eprintln!("fetch {N}: {fetch:?} (all_for_tenant)");
        eprintln!("authority query (fetch+build+resolve): {authority:?}");
    }

    #[tokio::test]
    async fn pg_tenant_conflict_on_id_reuse() {
        let Some(url) = test_url() else {
            eprintln!("skip: AIP_TEST_DATABASE_URL unset");
            return;
        };
        let store = PostgresEvidenceStore::connect(&url).await.unwrap();
        let (packet, _) = sample_packet();
        let ta = unique_tenant();
        let tb = unique_tenant();
        store.store(&ta, &packet).await.unwrap();
        assert!(matches!(
            store.store(&tb, &packet).await,
            Err(StoreError::TenantConflict)
        ));
    }
}
