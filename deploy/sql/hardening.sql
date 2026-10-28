-- AIP Evidence Vault — storage controls (R13 of
-- docs/pilot/RBI_REQUIREMENTS_COVERAGE.md; rows D7 and E5).
--
-- Applied ONCE by a database administrator, as the role that OWNS the
-- tables. The service never runs this and cannot: that is the point.
--
-- ─── Why the application cannot enforce this ───────────────────────────────
--
-- aip-service already filters every query by tenant and exposes no delete
-- path. Both of those are application code, and application code is what an
-- attacker who reaches the service gets to run. An evidence store whose
-- immutability is a property of the program that writes to it is immutable
-- only until that program is replaced.
--
-- These controls sit in the database, under a role the service does not
-- hold. After this script runs, a service that has been fully compromised
-- still cannot delete or alter a stored packet, because the connection it
-- holds has not been granted the privilege.
--
-- ─── The two roles ─────────────────────────────────────────────────────────
--
--   aip_owner  owns the tables. Runs migrations. Runs the retention job.
--              Its credentials are held by the DBA, not by the service, and
--              are not present in the service's environment.
--
--   aip_app    the service's login. SELECT and INSERT only. No DELETE, no
--              UPDATE, no TRUNCATE, no DDL. This is the only role whose
--              password appears in AIP_DATABASE_URL.
--
-- Substitute your own role names below if your site uses different ones;
-- nothing else in this file depends on the spelling.

\set ON_ERROR_STOP on

BEGIN;

-- ─── 1. Privileges ─────────────────────────────────────────────────────────
--
-- Revoke first, then grant exactly what the service needs. Revoking from
-- PUBLIC matters: without it, any role that can connect inherits whatever
-- PUBLIC holds on these tables.

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;

GRANT USAGE ON SCHEMA public TO aip_app;

REVOKE ALL ON evidence_packets, authority_nodes, authority_edges, signed_artifacts FROM aip_app;
GRANT SELECT, INSERT ON evidence_packets, authority_nodes, authority_edges, signed_artifacts TO aip_app;

-- Future tables created by the owner default to the same shape, so a
-- migration that adds a table does not silently hand the service DELETE.
ALTER DEFAULT PRIVILEGES FOR ROLE aip_owner IN SCHEMA public
    REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE aip_owner IN SCHEMA public
    GRANT SELECT, INSERT ON TABLES TO aip_app;

-- ─── 2. Retention and legal hold ───────────────────────────────────────────
--
-- CERT-In directs that logs be retained for 180 days. That is a floor, not a
-- target, and it is expressed as a CHECK so a misconfigured retention policy
-- is refused at write time rather than discovered at an inspection.

CREATE TABLE IF NOT EXISTS evidence_retention (
    tenant_id      TEXT PRIMARY KEY,
    -- Days to retain. The floor is 180; a site with a longer obligation
    -- (segment regulator, contractual, litigation) sets a larger value.
    retain_days    INTEGER NOT NULL,
    set_by         TEXT    NOT NULL,
    set_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT retention_floor_180_days CHECK (retain_days >= 180)
);

-- A hold names what must not be deleted and why. A row here outranks any
-- retention policy: retention says when evidence *may* go, a hold says it
-- may not, and the hold wins.
CREATE TABLE IF NOT EXISTS evidence_legal_hold (
    tenant_id   TEXT NOT NULL,
    -- Evidence packet or signed-artifact ID. NULL means "every evidence
    -- record of this tenant": the shape a regulator's
    -- direction usually takes.
    packet_id   TEXT,
    reason      TEXT NOT NULL,
    placed_by   TEXT NOT NULL,
    placed_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    released_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_hold_tenant_packet
    ON evidence_legal_hold(tenant_id, coalesce(packet_id, ''))
    WHERE released_at IS NULL;

GRANT SELECT ON evidence_retention, evidence_legal_hold TO aip_app;

-- ─── 3. The hold is enforced by the database, not by the retention job ─────
--
-- A trigger, because the retention job is a program and programs are
-- forgotten, mis-scheduled and rewritten. This binds the owner too: the role
-- that runs retention cannot delete a held packet either, and that is
-- deliberate — a legal hold that the operator can step around is not a legal
-- hold.

CREATE OR REPLACE FUNCTION refuse_delete_under_legal_hold()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    hold_reason TEXT;
BEGIN
    SELECT reason INTO hold_reason
    FROM evidence_legal_hold
    WHERE released_at IS NULL
      AND tenant_id = OLD.tenant_id
      AND (packet_id IS NULL OR packet_id = OLD.id)
    LIMIT 1;

    IF hold_reason IS NOT NULL THEN
        RAISE EXCEPTION
            'evidence record % is under legal hold (%) and cannot be deleted',
            OLD.id, hold_reason
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN OLD;
END;
$$;

DROP TRIGGER IF EXISTS trg_refuse_delete_under_legal_hold ON evidence_packets;
CREATE TRIGGER trg_refuse_delete_under_legal_hold
    BEFORE DELETE ON evidence_packets
    FOR EACH ROW EXECUTE FUNCTION refuse_delete_under_legal_hold();

-- A signed verdict, access ledger or observation must not lose the same
-- legal-hold protection merely because it lives in the artifact table.
DROP TRIGGER IF EXISTS trg_refuse_delete_under_legal_hold ON signed_artifacts;
CREATE TRIGGER trg_refuse_delete_under_legal_hold
    BEFORE DELETE ON signed_artifacts
    FOR EACH ROW EXECUTE FUNCTION refuse_delete_under_legal_hold();

-- Evidence is append-only. An UPDATE would let a packet's stored JSON be
-- edited while its id and hash column stayed put; the signature would then
-- fail on read, which is detectable but only if someone reads it. Refusing
-- the write is better than detecting it later.
CREATE OR REPLACE FUNCTION refuse_update_of_evidence()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION
        'evidence_packets is append-only; packet % cannot be modified', OLD.id
        USING ERRCODE = 'restrict_violation';
END;
$$;

DROP TRIGGER IF EXISTS trg_refuse_update_of_evidence ON evidence_packets;
CREATE TRIGGER trg_refuse_update_of_evidence
    BEFORE UPDATE ON evidence_packets
    FOR EACH ROW EXECUTE FUNCTION refuse_update_of_evidence();

CREATE OR REPLACE FUNCTION refuse_update_of_signed_artifact()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION
        'signed_artifacts is append-only; % record % cannot be modified', OLD.kind, OLD.id
        USING ERRCODE = 'restrict_violation';
END;
$$;

DROP TRIGGER IF EXISTS trg_refuse_update_of_signed_artifact ON signed_artifacts;
CREATE TRIGGER trg_refuse_update_of_signed_artifact
    BEFORE UPDATE ON signed_artifacts
    FOR EACH ROW EXECUTE FUNCTION refuse_update_of_signed_artifact();

-- ─── 4. Row-level security ─────────────────────────────────────────────────
--
-- Defence in depth behind the application's WHERE clause. The service sets
-- `aip.tenant_id` on its connection from the API key it authenticated, and
-- the database then refuses rows of any other tenant even if a query forgets
-- its filter — the single-forgotten-WHERE disclosure the audit named.
--
-- FORCE so the policy applies to the table owner as well during ordinary
-- access; the retention job sets the GUC per tenant like anyone else.

ALTER TABLE evidence_packets  ENABLE ROW LEVEL SECURITY;
ALTER TABLE authority_nodes   ENABLE ROW LEVEL SECURITY;
ALTER TABLE authority_edges   ENABLE ROW LEVEL SECURITY;
ALTER TABLE signed_artifacts  ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence_packets  FORCE ROW LEVEL SECURITY;
ALTER TABLE authority_nodes   FORCE ROW LEVEL SECURITY;
ALTER TABLE authority_edges   FORCE ROW LEVEL SECURITY;
ALTER TABLE signed_artifacts  FORCE ROW LEVEL SECURITY;

-- `current_setting(..., true)` returns NULL rather than erroring when the
-- GUC is unset, and NULL = tenant_id is never true — so a connection that
-- has not declared a tenant sees nothing at all. Failing closed here is the
-- whole value of the control.
DROP POLICY IF EXISTS tenant_isolation ON evidence_packets;
CREATE POLICY tenant_isolation ON evidence_packets
    USING (tenant_id = current_setting('aip.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aip.tenant_id', true));

DROP POLICY IF EXISTS tenant_isolation ON authority_nodes;
CREATE POLICY tenant_isolation ON authority_nodes
    USING (tenant_id = current_setting('aip.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aip.tenant_id', true));

DROP POLICY IF EXISTS tenant_isolation ON authority_edges;
CREATE POLICY tenant_isolation ON authority_edges
    USING (tenant_id = current_setting('aip.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aip.tenant_id', true));

DROP POLICY IF EXISTS tenant_isolation ON signed_artifacts;
CREATE POLICY tenant_isolation ON signed_artifacts
    USING (tenant_id = current_setting('aip.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('aip.tenant_id', true));

COMMIT;

-- ─── What this file does not do ────────────────────────────────────────────
--
-- It does not back anything up. Immutability and durability are different
-- properties: a table nobody can delete from is still lost with its disk.
-- Backup, restore and the tested restore drill are the operator's, and
-- docs/BACKUP_AND_RECOVERY.md states what must be exercised before a
-- production rollout.
--
-- It does not make the database trustworthy to the *operator's* own DBA. A
-- role that can DROP TRIGGER can remove the legal hold. What it does is make
-- that an act with a name, performed by a credential the service does not
-- hold, which is the difference between a control and a hope.
