//! R13 — the storage controls, proven against a real PostgreSQL.
//!
//! Every assertion here is about what the **database** refuses, not about
//! what the service declines to ask for. An evidence store whose
//! immutability is a property of the program writing to it is immutable only
//! until that program is replaced, so the controls that matter are the ones
//! that hold when the service is assumed compromised.
//!
//! # Running these
//!
//! They need a database and a superuser connection, because provisioning
//! roles and applying `deploy/sql/hardening.sql` is a DBA's job by design:
//!
//! ```text
//! AIP_TEST_ADMIN_DATABASE_URL=postgresql://postgres@127.0.0.1:5432/aip \
//!     cargo test -p airon-aip --features postgres --test storage_controls
//! ```
//!
//! ```text
//! AIP_TEST_ADMIN_DATABASE_URL=postgresql://postgres@127.0.0.1:5432/postgres \
//!     cargo test -p airon-aip --features postgres --test storage_controls -- --ignored
//! ```
//!
//! # Why they are `#[ignore]` rather than self-skipping
//!
//! The existing `pg.rs` suite returns early when no database is configured,
//! so it reports `ok` while exercising nothing — the audit recorded that as
//! a suite that cannot fail. A suite whose whole subject is "the database
//! refuses this" must not be able to do the same. Marked `#[ignore]`, an
//! unconfigured run reports them as **ignored**, which is the truth, and a
//! configured run that is misconfigured **fails** rather than skipping: with
//! the variable set, every panic below is a real refusal that did not
//! happen.

#![cfg(feature = "postgres")]

use tokio_postgres::{Client, NoTls};

const ADMIN_URL: &str = "AIP_TEST_ADMIN_DATABASE_URL";
/// Roles named by `deploy/sql/hardening.sql`.
const OWNER: &str = "aip_owner";
const APP: &str = "aip_app";

fn admin_url() -> String {
    std::env::var(ADMIN_URL).unwrap_or_else(|_| {
        panic!(
            "{ADMIN_URL} is not set. These tests prove what the database refuses \\
             and cannot be checked without one; set it to a superuser connection \\
             string, e.g. postgresql://postgres@127.0.0.1:5432/aip"
        )
    })
}

/// Connect and return the client, driving the connection task in the
/// background so queries make progress.
async fn connect(url: &str) -> Client {
    let (client, conn) = tokio_postgres::connect(url, NoTls)
        .await
        .unwrap_or_else(|e| panic!("connect {url}: {e}"));
    tokio::spawn(async move {
        let _ = conn.await;
    });
    client
}

/// The database these tests provision.
///
/// Deliberately **not** the one `AIP_TEST_DATABASE_URL` names. Hardening is
/// a property of a whole database: once applied, a role with no grants sees
/// nothing, so the ordinary store tests and these cannot share one. Keeping
/// them apart here means an operator can point both variables at the same
/// server without the suites destroying each other's assumptions.
const HARDENED_DB: &str = "aip_hardening_test";

/// Split the admin URL into `(scheme, userinfo@host:port)`.
fn admin_parts() -> (String, String) {
    let admin = admin_url();
    let (scheme, rest) = admin.split_once("://").expect("scheme");
    // Drop the database path; keep userinfo, host and port.
    let authority = rest.split('/').next().unwrap_or(rest).to_string();
    (scheme.to_string(), authority)
}

/// Admin connection to the hardened test database.
fn admin_hardened_url() -> String {
    let (scheme, authority) = admin_parts();
    format!("{scheme}://{authority}/{HARDENED_DB}")
}

/// A connection string for `role` against the hardened test database.
fn role_url(role: &str) -> String {
    let (scheme, authority) = admin_parts();
    let hostpart = authority
        .rsplit_once('@')
        .map(|(_, h)| h.to_string())
        .unwrap_or(authority);
    format!("{scheme}://{role}:{role}@{hostpart}/{HARDENED_DB}")
}

/// Provision the two roles and apply schema + hardening as the owner —
/// exactly once for the whole suite.
///
/// Cargo runs these tests concurrently in one process, and concurrent DDL on
/// the same catalog rows fails with "tuple concurrently updated". Each test
/// therefore works in its own tenant rather than its own schema, which is
/// also closer to the deployment being modelled: one hardened database, many
/// tenants.
static PROVISIONED: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

async fn provision() {
    PROVISIONED.get_or_init(provision_once).await;
}

async fn provision_once() {
    // Create the dedicated database from a connection to whatever the
    // operator pointed at; CREATE DATABASE cannot run inside a transaction
    // and errors if it already exists, so the error is the idempotency.
    let bootstrap = connect(&admin_url()).await;
    let _ = bootstrap
        .execute(&format!("CREATE DATABASE {HARDENED_DB}"), &[])
        .await;
    drop(bootstrap);

    let admin = connect(&admin_hardened_url()).await;

    for role in [OWNER, APP] {
        let _ = admin
            .batch_execute(&format!(
                "DO $$ BEGIN
                   IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN
                     CREATE ROLE {role} LOGIN PASSWORD '{role}';
                   END IF;
                 END $$;"
            ))
            .await;
    }
    admin
        .batch_execute(&format!(
            "GRANT CREATE, USAGE ON SCHEMA public TO {OWNER};
             GRANT {OWNER} TO current_user;"
        ))
        .await
        .expect("grant schema to owner");

    // Start from a clean slate so a previous run's rows and triggers do not
    // decide this one.
    admin
        .batch_execute(
            "DROP TABLE IF EXISTS evidence_legal_hold, evidence_retention,
                                  authority_edges, authority_nodes, evidence_packets CASCADE;",
        )
        .await
        .expect("drop");

    // The owner creates the tables, so it owns them.
    let owner = connect(&role_url(OWNER)).await;
    owner
        .batch_execute(airon_aip::store::pg::SCHEMA)
        .await
        .expect("schema as owner");

    let hardening = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("deploy/sql/hardening.sql"),
    )
    .expect("read hardening.sql");
    // `\set ON_ERROR_STOP` is a psql directive, not SQL.
    let hardening: String = hardening
        .lines()
        .filter(|l| !l.trim_start().starts_with("\\set"))
        .collect::<Vec<_>>()
        .join("\n");
    owner
        .batch_execute(&hardening)
        .await
        .expect("apply hardening.sql as owner");
}

/// The server's own message for a failed statement.
///
/// `tokio_postgres::Error` displays as the bare string "db error"; everything
/// a reader needs — the RAISE text, the constraint name — is in the database
/// error it wraps. Asserting on `to_string()` therefore passes or fails for
/// reasons unrelated to what the database said.
fn db_message(err: &tokio_postgres::Error) -> String {
    err.as_db_error()
        .map(|e| {
            let mut m = e.message().to_string();
            if let Some(c) = e.constraint() {
                m.push_str(" [constraint ");
                m.push_str(c);
                m.push(']');
            }
            m
        })
        .unwrap_or_else(|| err.to_string())
}

/// Insert one row directly, as the given client, for `tenant`.
async fn insert_packet(c: &Client, tenant: &str, id: &str) -> Result<u64, tokio_postgres::Error> {
    c.execute("SELECT set_config('aip.tenant_id', $1, false)", &[&tenant])
        .await?;
    c.execute(
        "INSERT INTO evidence_packets
             (id, tenant_id, packet_hash, created_at, evidence_json, verification_status)
         VALUES ($1, $2, 'deadbeef', 1, '{}', 'ok')",
        &[&id, &tenant],
    )
    .await
}

// ─── The privilege the service does not hold ───────────────────────────────

/// The control the RBI coverage matrix names: the service role cannot delete
/// evidence, and the refusal comes from the database.
#[tokio::test]
#[ignore = "needs a database: set AIP_TEST_ADMIN_DATABASE_URL (see module docs) and run with --ignored"]
async fn the_service_role_cannot_delete_evidence() {
    provision().await;
    let app = connect(&role_url(APP)).await;
    insert_packet(&app, "t-delete", "p-delete")
        .await
        .expect("insert");

    let err = app
        .execute("DELETE FROM evidence_packets WHERE id = 'p-delete'", &[])
        .await
        .expect_err("the service role must not be able to delete evidence");
    assert_eq!(
        err.code(),
        Some(&tokio_postgres::error::SqlState::INSUFFICIENT_PRIVILEGE),
        "expected a privilege refusal, got: {err}"
    );

    // And the row is still there, read back through the same connection.
    let row = app
        .query_one(
            "SELECT count(*) FROM evidence_packets WHERE id = 'p-delete'",
            &[],
        )
        .await
        .expect("read back");
    let n: i64 = row.get(0);
    assert_eq!(n, 1, "the packet must survive the attempt");
}

/// Evidence is append-only: the service cannot edit a stored packet either.
/// An UPDATE would let the JSON be rewritten while the id and hash column
/// stayed put, which is detectable on read but only if someone reads it.
#[tokio::test]
#[ignore = "needs a database: set AIP_TEST_ADMIN_DATABASE_URL (see module docs) and run with --ignored"]
async fn the_service_role_cannot_modify_stored_evidence() {
    provision().await;
    let app = connect(&role_url(APP)).await;
    insert_packet(&app, "t-update", "p-update")
        .await
        .expect("insert");

    let err = app
        .execute(
            "UPDATE evidence_packets SET evidence_json = '{\"tampered\":true}' WHERE id = 'p-update'",
            &[],
        )
        .await
        .expect_err("the service role must not be able to rewrite evidence");
    assert_eq!(
        err.code(),
        Some(&tokio_postgres::error::SqlState::INSUFFICIENT_PRIVILEGE),
        "expected a privilege refusal, got: {err}"
    );
}

#[tokio::test]
#[ignore = "needs a database: set AIP_TEST_ADMIN_DATABASE_URL (see module docs) and run with --ignored"]
async fn the_service_role_cannot_truncate_or_drop() {
    provision().await;
    let app = connect(&role_url(APP)).await;

    for statement in [
        "TRUNCATE evidence_packets",
        "DROP TABLE evidence_packets",
        "ALTER TABLE evidence_packets DISABLE ROW LEVEL SECURITY",
        "DROP TRIGGER trg_refuse_delete_under_legal_hold ON evidence_packets",
    ] {
        let err = app
            .execute(statement, &[])
            .await
            .unwrap_err_or_else(statement);
        assert!(
            matches!(
                err.code(),
                Some(&tokio_postgres::error::SqlState::INSUFFICIENT_PRIVILEGE)
                    | Some(&tokio_postgres::error::SqlState::SYNTAX_ERROR)
            ),
            "`{statement}` must be refused, got: {err}"
        );
    }
}

// ─── Row-level security ────────────────────────────────────────────────────

/// The single-forgotten-WHERE disclosure. A query with no tenant filter at
/// all returns only the declared tenant's rows.
#[tokio::test]
#[ignore = "needs a database: set AIP_TEST_ADMIN_DATABASE_URL (see module docs) and run with --ignored"]
async fn a_query_that_forgets_its_tenant_filter_still_cannot_cross_tenants() {
    provision().await;
    let app = connect(&role_url(APP)).await;
    insert_packet(&app, "t-rls-a", "p-acme")
        .await
        .expect("acme");
    insert_packet(&app, "t-rls-b", "p-globex")
        .await
        .expect("globex");

    // Acting as acme, with a query that filters on nothing.
    app.execute("SELECT set_config('aip.tenant_id', 't-rls-a', false)", &[])
        .await
        .unwrap();
    let rows = app
        .query("SELECT id FROM evidence_packets", &[])
        .await
        .expect("unfiltered select");
    let ids: Vec<String> = rows.iter().map(|r| r.get(0)).collect();
    assert_eq!(ids, vec!["p-acme".to_string()], "RLS must scope the result");
}

/// A connection that has not said who it is sees nothing at all. Failing
/// closed here is the whole value of the control: a bug that loses the
/// tenant must lose access, not gain it.
#[tokio::test]
#[ignore = "needs a database: set AIP_TEST_ADMIN_DATABASE_URL (see module docs) and run with --ignored"]
async fn a_connection_with_no_declared_tenant_sees_nothing() {
    provision().await;
    let app = connect(&role_url(APP)).await;
    insert_packet(&app, "t-undeclared", "p-undeclared")
        .await
        .expect("insert");

    // A fresh connection, no GUC set.
    let fresh = connect(&role_url(APP)).await;
    let row = fresh
        .query_one("SELECT count(*) FROM evidence_packets", &[])
        .await
        .expect("count");
    let n: i64 = row.get(0);
    assert_eq!(n, 0, "an undeclared connection must see no rows");
}

/// Writing into another tenant is refused by the policy's WITH CHECK, not
/// merely hidden by its USING clause.
#[tokio::test]
#[ignore = "needs a database: set AIP_TEST_ADMIN_DATABASE_URL (see module docs) and run with --ignored"]
async fn a_write_into_another_tenant_is_refused_by_the_policy() {
    provision().await;
    let app = connect(&role_url(APP)).await;
    app.execute(
        "SELECT set_config('aip.tenant_id', 't-cross-a', false)",
        &[],
    )
    .await
    .unwrap();
    let err = app
        .execute(
            "INSERT INTO evidence_packets
                 (id, tenant_id, packet_hash, created_at, evidence_json, verification_status)
             VALUES ('p-cross', 't-cross-b', 'deadbeef', 1, '{}', 'ok')",
            &[],
        )
        .await
        .expect_err("acme must not write a globex row");
    assert_eq!(
        err.code(),
        Some(&tokio_postgres::error::SqlState::INSUFFICIENT_PRIVILEGE),
        "expected a policy refusal, got: {err}"
    );
}

// ─── Legal hold and retention ──────────────────────────────────────────────

/// A hold binds the **owner**, the role that runs the retention job. A legal
/// hold the operator can step around is not a legal hold.
#[tokio::test]
#[ignore = "needs a database: set AIP_TEST_ADMIN_DATABASE_URL (see module docs) and run with --ignored"]
async fn a_held_packet_cannot_be_deleted_even_by_the_owner() {
    provision().await;
    let app = connect(&role_url(APP)).await;
    insert_packet(&app, "t-hold", "p-held")
        .await
        .expect("insert");

    let owner = connect(&role_url(OWNER)).await;
    owner
        .execute("SELECT set_config('aip.tenant_id', 't-hold', false)", &[])
        .await
        .unwrap();
    owner
        .execute(
            "INSERT INTO evidence_legal_hold (tenant_id, packet_id, reason, placed_by)
             VALUES ('t-hold', 'p-held', 'RBI inspection ref 2026/11', 'dpo@acme')",
            &[],
        )
        .await
        .expect("place hold");

    let err = owner
        .execute("DELETE FROM evidence_packets WHERE id = 'p-held'", &[])
        .await
        .expect_err("a held packet must not be deletable by the owner either");
    assert!(
        db_message(&err).contains("legal hold"),
        "the refusal must name the hold: {}",
        db_message(&err)
    );

    // Releasing the hold restores the owner's ability to run retention.
    owner
        .execute(
            "UPDATE evidence_legal_hold SET released_at = now() WHERE packet_id = 'p-held'",
            &[],
        )
        .await
        .expect("release");
    let deleted = owner
        .execute("DELETE FROM evidence_packets WHERE id = 'p-held'", &[])
        .await
        .expect("delete after release");
    assert_eq!(deleted, 1);
}

/// A tenant-wide hold, the shape a regulator's direction usually takes.
#[tokio::test]
#[ignore = "needs a database: set AIP_TEST_ADMIN_DATABASE_URL (see module docs) and run with --ignored"]
async fn a_tenant_wide_hold_covers_packets_it_never_named() {
    provision().await;
    let app = connect(&role_url(APP)).await;
    insert_packet(&app, "t-wide", "p-wide-1")
        .await
        .expect("insert");

    let owner = connect(&role_url(OWNER)).await;
    owner
        .execute("SELECT set_config('aip.tenant_id', 't-wide', false)", &[])
        .await
        .unwrap();
    owner
        .execute(
            "INSERT INTO evidence_legal_hold (tenant_id, packet_id, reason, placed_by)
             VALUES ('t-wide', NULL, 'segment regulator direction', 'dpo@acme')",
            &[],
        )
        .await
        .expect("place tenant-wide hold");

    // A packet stored *after* the hold was placed is covered too.
    insert_packet(&app, "t-wide", "p-wide-2")
        .await
        .expect("insert 2");
    for id in ["p-wide-1", "p-wide-2"] {
        let err = owner
            .execute("DELETE FROM evidence_packets WHERE id = $1", &[&id])
            .await
            .expect_err("tenant-wide hold must cover this");
        assert!(
            db_message(&err).contains("legal hold"),
            "{id}: {}",
            db_message(&err)
        );
    }

    // Another tenant is unaffected: a hold is not a global freeze.
    insert_packet(&app, "t-wide-other", "p-other")
        .await
        .expect("insert other");
    owner
        .execute(
            "SELECT set_config('aip.tenant_id', 't-wide-other', false)",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        owner
            .execute("DELETE FROM evidence_packets WHERE id = 'p-other'", &[])
            .await
            .expect("other tenant deletable"),
        1
    );
}

/// The CERT-In floor is a constraint, so a misconfigured retention policy is
/// refused at write time rather than discovered at an inspection.
#[tokio::test]
#[ignore = "needs a database: set AIP_TEST_ADMIN_DATABASE_URL (see module docs) and run with --ignored"]
async fn a_retention_policy_below_the_180_day_floor_is_refused() {
    provision().await;
    let owner = connect(&role_url(OWNER)).await;

    let err = owner
        .execute(
            "INSERT INTO evidence_retention (tenant_id, retain_days, set_by)
             VALUES ('t-retention', 90, 'ops')",
            &[],
        )
        .await
        .expect_err("90 days is below the CERT-In floor");
    assert!(
        db_message(&err).contains("retention_floor_180_days"),
        "the refusal must name the constraint: {}",
        db_message(&err)
    );

    // The floor itself, and anything above it, is accepted.
    for days in [180i32, 365, 2_555] {
        owner
            .execute(
                "DELETE FROM evidence_retention WHERE tenant_id = 't-retention'",
                &[],
            )
            .await
            .ok();
        owner
            .execute(
                "INSERT INTO evidence_retention (tenant_id, retain_days, set_by)
                 VALUES ('t-retention', $1, 'ops')",
                &[&days],
            )
            .await
            .unwrap_or_else(|e| panic!("{days} days must be accepted: {e}"));
    }
}

// ─── The service still works against a hardened database ───────────────────

/// The controls are only useful if the service runs under them. This drives
/// the real store through its own API as the restricted role.
#[tokio::test]
#[ignore = "needs a database: set AIP_TEST_ADMIN_DATABASE_URL (see module docs) and run with --ignored"]
async fn the_store_operates_normally_as_the_restricted_role() {
    provision().await;
    use airon_aip::store::{pg::PostgresEvidenceStore, EvidenceStore};

    let store = PostgresEvidenceStore::connect(&role_url(APP))
        .await
        .expect("the service must start against a hardened database it cannot provision");

    let (packet, _issuers) = airon_aip::test_support::sample_packet();
    let id = store.store("t-store", &packet).await.expect("store");
    let back = store.get("t-store", &id).await.expect("get");
    assert!(back.is_some(), "a tenant must read back its own packet");

    // And the isolation the application enforces is now also enforced under
    // it: another tenant reads nothing, by policy as well as by WHERE.
    let cross = store
        .get("t-store-other", &id)
        .await
        .expect("cross-tenant get");
    assert!(cross.is_none(), "cross-tenant read must be empty");
}

/// Small helper so a refused statement reads as an expectation rather than a
/// bare unwrap, and names the statement when it unexpectedly succeeds.
trait UnwrapErrOrElse {
    fn unwrap_err_or_else(self, what: &str) -> tokio_postgres::Error;
}

impl UnwrapErrOrElse for Result<u64, tokio_postgres::Error> {
    fn unwrap_err_or_else(self, what: &str) -> tokio_postgres::Error {
        match self {
            Ok(_) => panic!("`{what}` succeeded and must not have"),
            Err(e) => e,
        }
    }
}
