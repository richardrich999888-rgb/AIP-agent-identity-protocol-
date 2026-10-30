//! SQLite FTS5 corpus with access control inside the query.
//!
//! Schema: a `documents` table holds authoritative metadata; an external-
//! content FTS5 index covers title+body. Search joins the index to the
//! metadata and filters `tenant = ?` and `class_rank <= ?` in the same
//! statement, so rows the principal may not read are never returned to the
//! process. Results then pass through [`crate::policy::retrieval::enforce`]
//! as a second, independent check; any row it drops is reported as a
//! contract violation rather than silently filtered.
//!
//! Query text is never interpolated into SQL. It is reduced to quoted FTS5
//! terms (alphanumeric only) and bound as a parameter, so user text cannot
//! inject FTS5 operators (`NEAR`, column filters, `*`) or SQL.

use rusqlite::{params, Connection, OpenFlags};
use std::path::Path;

use crate::domain::corpus::{Classification, Document, Ident, Passage, Principal};
use crate::policy::retrieval;
use crate::ports::{CorpusStore, PortError, PortErrorKind};

/// Maximum number of query terms passed to FTS5.
const MAX_TERMS: usize = 32;
/// Maximum passage characters returned per hit (bounds prompt size).
const MAX_PASSAGE_CHARS: usize = 1800;
/// Hard ceiling on `limit`.
const MAX_LIMIT: usize = 20;

const SCHEMA: &str = "
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS documents (
  rowid       INTEGER PRIMARY KEY,
  tenant      TEXT NOT NULL,
  doc_id      TEXT NOT NULL,
  title       TEXT NOT NULL,
  class_rank  INTEGER NOT NULL CHECK (class_rank BETWEEN 0 AND 2),
  body        TEXT NOT NULL,
  version     INTEGER NOT NULL,
  UNIQUE (tenant, doc_id)
);
CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
  title, body, content='documents', content_rowid='rowid', tokenize='unicode61'
);
CREATE TRIGGER IF NOT EXISTS documents_ai AFTER INSERT ON documents BEGIN
  INSERT INTO documents_fts(rowid, title, body) VALUES (new.rowid, new.title, new.body);
END;
CREATE TRIGGER IF NOT EXISTS documents_ad AFTER DELETE ON documents BEGIN
  INSERT INTO documents_fts(documents_fts, rowid, title, body) VALUES ('delete', old.rowid, old.title, old.body);
END;
CREATE TRIGGER IF NOT EXISTS documents_au AFTER UPDATE ON documents BEGIN
  INSERT INTO documents_fts(documents_fts, rowid, title, body) VALUES ('delete', old.rowid, old.title, old.body);
  INSERT INTO documents_fts(rowid, title, body) VALUES (new.rowid, new.title, new.body);
END;
";

/// SQLite-backed [`CorpusStore`].
pub struct SqliteCorpus {
    conn: Connection,
}

fn storage(e: rusqlite::Error) -> PortError {
    PortError::new(PortErrorKind::Storage, e.to_string())
}

impl SqliteCorpus {
    /// Open (creating if absent) a corpus database file.
    pub fn open(path: &Path) -> Result<Self, PortError> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(storage)?;
        conn.execute_batch(SCHEMA).map_err(storage)?;
        Ok(Self { conn })
    }

    /// In-memory corpus for tests.
    pub fn in_memory() -> Result<Self, PortError> {
        let conn = Connection::open_in_memory().map_err(storage)?;
        conn.execute_batch(SCHEMA).map_err(storage)?;
        Ok(Self { conn })
    }
}

/// Reduce free text to a bound FTS5 MATCH expression: each alphanumeric run
/// becomes a double-quoted term, joined with OR. Returns `None` when no
/// usable term remains.
pub fn to_fts_query(text: &str) -> Option<String> {
    let terms: Vec<String> = text
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.chars().count() >= 2)
        .take(MAX_TERMS)
        .map(|t| format!("\"{}\"", t.to_lowercase()))
        .collect();
    if terms.is_empty() {
        None
    } else {
        Some(terms.join(" OR "))
    }
}

fn rank_to_class(rank: i64) -> Result<Classification, PortError> {
    match rank {
        0 => Ok(Classification::Public),
        1 => Ok(Classification::Internal),
        2 => Ok(Classification::Restricted),
        r => Err(PortError::new(
            PortErrorKind::ContractViolation,
            format!("class_rank {r}"),
        )),
    }
}

impl CorpusStore for SqliteCorpus {
    fn ingest(&mut self, doc: &Document) -> Result<(), PortError> {
        doc.validate()
            .map_err(|e| PortError::new(PortErrorKind::InvalidInput, e.to_string()))?;
        // Versioning: a re-ingest of the same (tenant, doc_id) replaces the
        // row and increments `version` atomically.
        self.conn
            .execute(
                "INSERT INTO documents (tenant, doc_id, title, class_rank, body, version)
                 VALUES (?1, ?2, ?3, ?4, ?5, 1)
                 ON CONFLICT(tenant, doc_id) DO UPDATE SET
                   title=excluded.title, class_rank=excluded.class_rank,
                   body=excluded.body, version=documents.version + 1",
                params![
                    doc.tenant.as_str(),
                    doc.doc_id.as_str(),
                    doc.title,
                    doc.classification.rank(),
                    doc.body
                ],
            )
            .map_err(storage)?;
        Ok(())
    }

    fn search(
        &self,
        principal: &Principal,
        query: &str,
        limit: usize,
    ) -> Result<Vec<Passage>, PortError> {
        let Some(fts) = to_fts_query(query) else {
            return Ok(Vec::new());
        };
        let limit = limit.clamp(1, MAX_LIMIT) as i64;
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT d.doc_id, d.title, d.class_rank, d.body, bm25(documents_fts) AS score
                 FROM documents_fts JOIN documents d ON d.rowid = documents_fts.rowid
                 WHERE documents_fts MATCH ?1 AND d.tenant = ?2 AND d.class_rank <= ?3
                 ORDER BY score ASC, d.doc_id ASC
                 LIMIT ?4",
            )
            .map_err(storage)?;
        let rows = stmt
            .query_map(
                params![
                    fts,
                    principal.tenant.as_str(),
                    principal.clearance.rank(),
                    limit
                ],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, f64>(4)?,
                    ))
                },
            )
            .map_err(storage)?;
        let mut out = Vec::new();
        for row in rows {
            let (doc_id, title, rank, body, bm25) = row.map_err(storage)?;
            out.push(Passage {
                doc_id: Ident::new(&doc_id)
                    .map_err(|e| PortError::new(PortErrorKind::ContractViolation, e.to_string()))?,
                title,
                classification: rank_to_class(rank)?,
                text: body.chars().take(MAX_PASSAGE_CHARS).collect(),
                bm25,
            });
        }
        let (kept, dropped) = retrieval::enforce(principal, &principal.tenant, out);
        if dropped > 0 {
            return Err(PortError::new(
                PortErrorKind::ContractViolation,
                format!("storage returned {dropped} row(s) above clearance"),
            ));
        }
        Ok(kept)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(t: &str, id: &str, c: Classification, body: &str) -> Document {
        Document {
            tenant: Ident::new(t).unwrap(),
            doc_id: Ident::new(id).unwrap(),
            title: id.to_string(),
            classification: c,
            body: body.to_string(),
        }
    }

    fn principal(t: &str, c: Classification) -> Principal {
        Principal {
            tenant: Ident::new(t).unwrap(),
            clearance: c,
        }
    }

    fn corpus() -> SqliteCorpus {
        let mut c = SqliteCorpus::in_memory().unwrap();
        c.ingest(&doc(
            "acme",
            "pump-manual",
            Classification::Internal,
            "hydraulic pump pressure limit 210 bar",
        ))
        .unwrap();
        c.ingest(&doc(
            "acme",
            "pump-secret",
            Classification::Restricted,
            "hydraulic pump vendor key",
        ))
        .unwrap();
        c.ingest(&doc(
            "globex",
            "pump-rival",
            Classification::Public,
            "hydraulic pump rival design",
        ))
        .unwrap();
        c
    }

    #[test]
    fn fts5_is_compiled_in() {
        // If the bundled SQLite lacked FTS5, schema creation would fail.
        assert!(SqliteCorpus::in_memory().is_ok());
    }

    #[test]
    fn retrieval_respects_clearance() {
        let c = corpus();
        let hits = c
            .search(
                &principal("acme", Classification::Internal),
                "hydraulic pump",
                10,
            )
            .unwrap();
        let ids: Vec<&str> = hits.iter().map(|h| h.doc_id.as_str()).collect();
        assert_eq!(ids, vec!["pump-manual"]);
    }

    #[test]
    fn retrieval_never_crosses_tenants() {
        let c = corpus();
        let hits = c
            .search(
                &principal("acme", Classification::Restricted),
                "rival design",
                10,
            )
            .unwrap();
        assert!(
            hits.iter().all(|h| h.doc_id.as_str() != "pump-rival"),
            "{hits:?}"
        );
        let hits = c
            .search(
                &principal("globex", Classification::Restricted),
                "hydraulic",
                10,
            )
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].doc_id.as_str(), "pump-rival");
    }

    #[test]
    fn fts_operators_in_user_text_are_neutralised() {
        let c = corpus();
        // Column filter / NEAR / prefix / quote injection must not error or widen.
        for q in [
            "title:pump",
            "NEAR(pump vendor)",
            "pum*",
            "\"pump\" OR body:key",
            "'; DROP TABLE documents; --",
        ] {
            let r = c.search(&principal("acme", Classification::Public), q, 10);
            // Public clearance: only Public acme docs (none) may ever appear.
            assert!(r.unwrap().is_empty(), "{q} widened retrieval");
        }
        // Table survived.
        assert_eq!(
            c.search(&principal("acme", Classification::Internal), "pressure", 10)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn reingest_increments_version_and_replaces_index() {
        let mut c = corpus();
        c.ingest(&doc(
            "acme",
            "pump-manual",
            Classification::Internal,
            "valve torque 45 Nm",
        ))
        .unwrap();
        let v: i64 = c
            .conn
            .query_row(
                "SELECT version FROM documents WHERE doc_id='pump-manual'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(v, 2);
        let p = principal("acme", Classification::Internal);
        assert!(
            c.search(&p, "pressure", 10).unwrap().is_empty(),
            "stale index entry survived"
        );
        assert_eq!(c.search(&p, "torque", 10).unwrap().len(), 1);
    }

    #[test]
    fn empty_or_symbol_only_query_returns_nothing() {
        let c = corpus();
        assert!(c
            .search(&principal("acme", Classification::Restricted), "?!* ", 10)
            .unwrap()
            .is_empty());
    }
}
