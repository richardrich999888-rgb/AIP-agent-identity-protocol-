"""Bounded, read-only diagnostics for disposable synthetic gateway trials.

This unsigned, gateway-local journal is never execution or authorization proof.
Do not export framework logs, raw SQLite files, arguments, credentials or keys.
"""
from contextlib import closing
import hashlib
from pathlib import Path
import sqlite3
import stat


def journal_snapshot(path: Path) -> dict:
    result = {
        "version": 1,
        "source_authority": "gateway_local_replay_journal",
        "evidence_status": "UNSIGNED_DIAGNOSTIC_NOT_EXECUTION_PROOF",
        "identifier_encoding": "sha256_of_utf8_exact_identifier",
        "status": "UNAVAILABLE",
        "rows": [],
    }
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            result["reason"] = "not_regular_file"
            return result
        # URI encoding also handles a literal '?' or '#' in the path. Read-only
        # mode must not create a missing journal or alter the original evidence.
        with closing(sqlite3.connect(path.absolute().as_uri() + "?mode=ro", uri=True, timeout=1)) as connection:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            if connection.execute("SELECT type FROM sqlite_schema WHERE name='requests'").fetchone() != ("table",):
                result["reason"] = "requests_table_missing"
                return result
            rows = connection.execute(
                "SELECT request_id, decision_id, state FROM requests ORDER BY rowid LIMIT 1001"
            ).fetchall()
        if len(rows) > 1000:
            result["reason"] = "row_limit"
            return result
        for request_id, decision_id, state in rows:
            if any(not isinstance(value, str) or len(value) > 128 for value in (request_id, decision_id, state)):
                result["reason"] = "invalid_row"
                result["rows"] = []
                return result
            # Hash even identifiers: a corrupt journal may contain arbitrary
            # sensitive strings. Never echo unrecognized state text either.
            result["rows"].append({
                "request_id_sha256": hashlib.sha256(request_id.encode()).hexdigest(),
                "decision_id_sha256": hashlib.sha256(decision_id.encode()).hexdigest(),
                "state": state if state in {"pending", "Forwarded", "Failed", "receipt_error"} else "UNKNOWN",
            })
        result["status"] = "CAPTURED"
        result["row_count"] = len(rows)
    except (OSError, sqlite3.Error, ValueError, UnicodeError) as error:
        result["rows"] = []
        result["reason"] = type(error).__name__
    return result
