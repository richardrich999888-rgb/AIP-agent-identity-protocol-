//! aip-migrate — import a JSONL Evidence Vault into PostgreSQL.
//!
//! Idempotent: re-running imports only packets not already present (the
//! Postgres store is idempotent per packet id within a tenant). Each record's
//! tenant is preserved.
//!
//! Usage:
//!   aip-migrate --source /var/lib/aip/evidence.jsonl \
//!               --database-url postgresql://aip:aip@127.0.0.1:5432/aip
//!
//! Env fallbacks: AIP_VAULT_PATH (source), DATABASE_URL.
//! Requires building with `--features postgres`.

use airon_aip::store::{EvidenceStore, JsonlEvidenceStore, PostgresEvidenceStore, StoreError};

fn arg_value(flag: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}

#[tokio::main]
async fn main() {
    let source = arg_value("--source")
        .or_else(|| std::env::var("AIP_VAULT_PATH").ok())
        .unwrap_or_else(|| "/var/lib/aip/evidence.jsonl".to_owned());
    let database_url = arg_value("--database-url")
        .or_else(|| std::env::var("DATABASE_URL").ok())
        .unwrap_or_else(|| {
            eprintln!("error: --database-url or DATABASE_URL required");
            std::process::exit(1);
        });

    eprintln!("aip-migrate: source={source}  →  postgres");

    let jsonl = JsonlEvidenceStore::load(&source);
    let records = jsonl.records();
    eprintln!(
        "aip-migrate: {} record(s) found in JSONL source",
        records.len()
    );

    let pg = match PostgresEvidenceStore::connect(&database_url).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: cannot connect to PostgreSQL: {e}");
            std::process::exit(1);
        }
    };

    let mut imported = 0usize;
    let mut already = 0usize;
    let mut conflicts = 0usize;
    let total = records.len();

    for r in records {
        let id = r.packet.packet_id_hex();
        // Idempotency: check if it already exists for this tenant first.
        let existed = matches!(pg.get(&r.tenant_id, &id).await, Ok(Some(_)));
        match pg.store(&r.tenant_id, &r.packet).await {
            Ok(_) if existed => already += 1,
            Ok(_) => imported += 1,
            Err(StoreError::TenantConflict) => {
                conflicts += 1;
                eprintln!("warn: {id} exists under a different tenant — skipping");
            }
            Err(e) => {
                eprintln!("error importing {id}: {e}");
                std::process::exit(1);
            }
        }
    }

    eprintln!(
        "aip-migrate: done. total={total} imported={imported} already_present={already} conflicts={conflicts}"
    );
    let final_count = pg.count().await.unwrap_or(0);
    eprintln!("aip-migrate: postgres now holds {final_count} packet(s)");
}
