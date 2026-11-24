"""Portable boundary checks only; these never claim a genuine agent/kernel run."""
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from prepare_local_model import CPU_FILE, publish_runtime, verify_model

HERE = Path(__file__).resolve().parent


class SameRunControls(unittest.TestCase):
    def test_public_runtime_permissions_do_not_publish_bootstrap_home_or_logs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ('bin','lib/ollama','models/blobs','bootstrap-home'):
                (root/name).mkdir(parents=True,mode=0o700)
            executable=root/'bin/ollama'; executable.write_text('public runtime'); executable.chmod(0o700)
            blob=root/'models/blobs/public-model'; blob.write_text('public weights'); blob.chmod(0o600)
            private=root/'bootstrap-home/private-key'; private.write_text('private'); private.chmod(0o600)
            log=root/'bootstrap.log'; log.write_text('private diagnostics'); log.chmod(0o600)
            publish_runtime(root)
            self.assertEqual(executable.stat().st_mode & 0o777,0o755)
            self.assertEqual(blob.stat().st_mode & 0o777,0o644)
            self.assertEqual((root/'models/blobs').stat().st_mode & 0o777,0o755)
            self.assertEqual((root/'bootstrap-home').stat().st_mode & 0o777,0o700)
            self.assertEqual(private.stat().st_mode & 0o777,0o600)
            self.assertEqual(log.stat().st_mode & 0o777,0o600)

    def test_public_runtime_allowlist_excludes_accelerator_and_traversal_members(self):
        for member in ('lib/ollama/libggml-base.so', 'lib/ollama/libggml-cpu-haswell.so',
                       'lib/ollama/libggml-cpu.so', 'lib/ollama/libllama.so.0',
                       'lib/ollama/llama-server','lib/ollama/libggml.so','lib/ollama/libmtmd.so',
                       'lib/ollama/libllama-server-impl.so','lib/ollama/libgomp.so.1'):
            self.assertIsNotNone(CPU_FILE.fullmatch(member))
        for member in ('lib/ollama/cuda_v12/libggml-cuda.so', 'lib/ollama/libggml-cuda.so',
                       'lib/ollama/rocm/libggml-hip.so', 'lib/ollama/vulkan/libggml-vulkan.so',
                       '../../lib/ollama/libggml-cpu.so', '/lib/ollama/libggml-base.so'):
            self.assertIsNone(CPU_FILE.fullmatch(member))

    def test_mutable_model_tag_cannot_replace_reviewed_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            models = Path(temporary)
            manifest = models / 'manifests/registry.ollama.ai/library/llama3.2/1b'
            manifest.parent.mkdir(parents=True)
            manifest.write_text('{"config":{},"layers":[]}')
            with self.assertRaisesRegex(ValueError, 'model tag changed'):
                verify_model(models)

    def test_v2_model_reference_cannot_escape_content_addressed_store(self):
        with tempfile.TemporaryDirectory() as temporary:
            models = Path(temporary)
            current = models / 'manifests-v2/ollama.com/library/llama3.2/1b'
            current.parent.mkdir(parents=True)
            outside = models / 'unexpected.json'
            outside.write_text('{}')
            (models / 'blobs').mkdir()
            from prepare_local_model import MANIFEST_SHA256
            (models/'blobs'/('sha256-'+MANIFEST_SHA256)).write_text('{}')
            current.symlink_to(outside)
            with self.assertRaisesRegex(ValueError,'does not reference the reviewed'):
                verify_model(models)

    def test_actual_read_subprocess_preserves_database_and_returns_selected_document(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            database = work / 'synthetic.sqlite3'
            with sqlite3.connect(database) as connection:
                connection.execute('CREATE TABLE loan_documents (loan_id INTEGER PRIMARY KEY, document_status TEXT NOT NULL)')
                connection.executemany('INSERT INTO loan_documents VALUES (?, ?)', [(1, 'document-one'), (2, 'document-two')])
            before = hashlib.sha256(database.read_bytes()).hexdigest()
            child = subprocess.run([sys.executable, str(HERE/'same_run_upstream.py'), '--read',
                '--database',str(database),'--work',str(work),'--loan-id','1'],
                capture_output=True, text=True, timeout=10, check=True)
            actual = json.loads(child.stdout)
            self.assertEqual(actual['loan_id'],1)
            self.assertEqual(actual['document_status'],'document-one')
            self.assertFalse(actual['bank_record_modified'])
            self.assertEqual(json.loads((work/'loan-1-review.json').read_text()), actual)
            self.assertEqual(hashlib.sha256(database.read_bytes()).hexdigest(),before)
            self.assertFalse((work/'loan-2-review.json').exists())
            failure = subprocess.run([sys.executable,str(HERE/'same_run_upstream.py'),'--read',
                '--database',str(database),'--work',str(work),'--loan-id','3'],capture_output=True,timeout=5)
            self.assertNotEqual(failure.returncode,0)
            self.assertEqual(hashlib.sha256(database.read_bytes()).hexdigest(),before)


if __name__ == '__main__':
    unittest.main(verbosity=2)
