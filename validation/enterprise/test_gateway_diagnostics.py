"""Actual temporary SQLite archives; no gateway or execution qualification."""
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from gateway_diagnostics import journal_snapshot


class GatewayDiagnostics(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / 'journal?#.sqlite3'

    def database(self, rows):
        connection = sqlite3.connect(self.path)
        with connection:
            connection.execute('CREATE TABLE requests (request_id TEXT, decision_id TEXT, state TEXT, private_value TEXT)')
            connection.executemany('INSERT INTO requests VALUES (?, ?, ?, ?)', rows)
            connection.execute('CREATE TABLE private_keys (secret TEXT)')
            connection.execute('INSERT INTO private_keys VALUES (?)', ('private-key-canary',))
        connection.close()

    def test_actual_journal_states_are_exported_without_credentials_or_modification(self):
        self.database([(f'request-{index}', 'decision-canary', state, 'credential-canary')
                       for index, state in enumerate(('pending', 'Forwarded', 'Failed', 'receipt_error', 'secret-state-canary'))])
        original = self.path.read_bytes()
        result = journal_snapshot(self.path)
        self.assertEqual(result['status'], 'CAPTURED')
        self.assertEqual(result['row_count'], 5)
        self.assertEqual([r['state'] for r in result['rows']], ['pending', 'Forwarded', 'Failed', 'receipt_error', 'UNKNOWN'])
        self.assertEqual(result['rows'][0]['request_id_sha256'], hashlib.sha256(b'request-0').hexdigest())
        for private in ('request-0', 'decision-canary', 'credential-canary', 'private-key-canary', 'secret-state-canary'):
            self.assertNotIn(private, json.dumps(result))
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(result['evidence_status'], 'UNSIGNED_DIAGNOSTIC_NOT_EXECUTION_PROOF')

    def test_missing_and_symlink_journals_are_not_created_or_followed(self):
        self.assertEqual(journal_snapshot(self.path)['status'], 'UNAVAILABLE')
        self.assertFalse(self.path.exists())
        target = self.path.parent / 'target'
        self.path.symlink_to(target)
        self.assertEqual(journal_snapshot(self.path)['reason'], 'not_regular_file')
        self.assertFalse(target.exists())

    def test_corrupt_archive_preserves_bytes_and_emits_no_error_payload(self):
        self.path.write_bytes(b'private-corruption-canary')
        result = journal_snapshot(self.path)
        self.assertEqual(result['status'], 'UNAVAILABLE')
        self.assertEqual(result['rows'], [])
        self.assertNotIn('private-corruption-canary', json.dumps(result))
        self.assertEqual(self.path.read_bytes(), b'private-corruption-canary')

    def test_oversize_or_invalid_rows_never_publish_partial_success(self):
        self.database([('ok', 'ok', 'pending', 'private'), (None, 'ok', 'pending', 'private')])
        self.assertEqual(journal_snapshot(self.path)['reason'], 'invalid_row')
        self.assertEqual(journal_snapshot(self.path)['rows'], [])
        self.path.unlink()
        self.database([(str(index), 'ok', 'pending', 'private') for index in range(1001)])
        self.assertEqual(journal_snapshot(self.path)['reason'], 'row_limit')


if __name__ == '__main__':
    unittest.main()
