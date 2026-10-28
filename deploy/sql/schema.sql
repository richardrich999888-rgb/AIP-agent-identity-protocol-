-- AIP Evidence Vault — PostgreSQL schema.
-- Applied automatically by PostgresEvidenceStore on startup (idempotent).
-- Kept here as the canonical reference and for manual provisioning / review.
-- Source of truth: aip-service/src/store/pg.rs (const SCHEMA).

CREATE TABLE IF NOT EXISTS evidence_packets (
    id                  TEXT PRIMARY KEY,   -- hex packet id
    tenant_id           TEXT   NOT NULL,    -- storage envelope (not part of signed evidence)
    packet_hash         TEXT   NOT NULL,    -- hex SHA-256 of canonical bytes
    created_at          BIGINT NOT NULL,    -- Unix ms from the packet
    evidence_json       TEXT   NOT NULL,    -- verbatim signed EvidencePacket (re-verifies identically)
    verification_status TEXT   NOT NULL     -- integrity self-check at store time
);
CREATE INDEX IF NOT EXISTS idx_evidence_tenant  ON evidence_packets(tenant_id);
CREATE INDEX IF NOT EXISTS idx_evidence_hash    ON evidence_packets(packet_hash);
CREATE INDEX IF NOT EXISTS idx_evidence_created ON evidence_packets(created_at);

-- Materialised accountability graph (tenant-isolated), derived from each packet.
CREATE TABLE IF NOT EXISTS authority_nodes (
    tenant_id  TEXT NOT NULL,
    packet_id  TEXT NOT NULL,
    node_id    TEXT NOT NULL,
    kind       TEXT NOT NULL,   -- Principal | AuthorityGrant | Delegation | Agent | Decision | Action | Receipt
    label      TEXT NOT NULL,
    PRIMARY KEY (tenant_id, packet_id, node_id)
);
CREATE INDEX IF NOT EXISTS idx_nodes_tenant ON authority_nodes(tenant_id);

CREATE TABLE IF NOT EXISTS authority_edges (
    tenant_id  TEXT NOT NULL,
    packet_id  TEXT NOT NULL,
    from_node  TEXT NOT NULL,
    to_node    TEXT NOT NULL,
    relation   TEXT NOT NULL    -- Issues | Delegates | ActsUnder | Decides | Performs | Produces
);
CREATE INDEX IF NOT EXISTS idx_edges_tenant ON authority_edges(tenant_id);

-- Existing signed verdicts, access ledgers and observation records. This is
-- the same table used by aip-service's artifact store, not a second vault.
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
