"""Portable boundary checks only; these never claim a genuine agent/kernel run."""
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from prepare_local_model import (CPU_FILE, MANIFEST_SHA256, MANIFEST_SIZE,
    publish_runtime, read_reviewed_manifest, validate_manifest_bytes,
    verify_model, verify_model_blob)

HERE = Path(__file__).resolve().parent
MODEL_REVIEW = HERE.parent / 'final_acceptance/model-review'


class SameRunControls(unittest.TestCase):
    def test_synthetic_database_bootstrap_closes_its_mount_handle(self):
        import same_run_validation as validation
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / 'loans.sqlite3'
            connection = sqlite3.connect(database)
            with patch.object(validation.sqlite3, 'connect', return_value=connection):
                validation.create_synthetic_database(database)
            # sqlite3.Connection's transaction context manager does not close
            # the connection; leaving it live prevents the Linux mount cleanup.
            with self.assertRaises(sqlite3.ProgrammingError):
                connection.execute('SELECT 1')
            with sqlite3.connect(database) as reader:
                self.assertEqual(reader.execute('SELECT count(*) FROM loan_documents').fetchone()[0], 2)
            reader.close()

    def test_original_reviewed_manifest_exact_bytes_are_accepted(self):
        # Authentic public metadata only; this test does not substitute fake
        # weights or claim that a model/runtime was provisioned or executed.
        original = (MODEL_REVIEW/'llama3.2-1b.manifest.json').read_bytes()
        self.assertEqual(len(original), MANIFEST_SIZE)
        self.assertEqual(hashlib.sha256(original).hexdigest(), MANIFEST_SHA256)
        value = validate_manifest_bytes(original)
        self.assertEqual(value['config']['size'], 485)
        self.assertEqual(value['layers'][0]['size'], 1321082688)
        with tempfile.TemporaryDirectory() as temporary:
            models = Path(temporary)
            legacy = models/'manifests/registry.ollama.ai/library/llama3.2/1b'
            legacy.parent.mkdir(parents=True)
            legacy.write_bytes(original)
            self.assertEqual(read_reviewed_manifest(models), value)
            with self.assertRaises(FileNotFoundError):
                # Metadata acceptance alone must never pass full blob checks.
                verify_model(models)

    def test_v2_original_is_selected_instead_of_rewritten_legacy_gc_anchor(self):
        original = (MODEL_REVIEW/'llama3.2-1b.manifest.json').read_bytes()
        value = validate_manifest_bytes(original)
        anchor = json.loads(original)
        anchor['layers'].append({'mediaType':value['mediaType'],
            'digest':'sha256:'+MANIFEST_SHA256, 'size':MANIFEST_SIZE})
        rewritten = json.dumps(anchor, separators=(',', ':')).encode()
        self.assertEqual(len(rewritten), 1023)
        self.assertEqual(hashlib.sha256(rewritten).hexdigest(),
            '728ac54eed40c4c447b407828c1f1c633033657245fe8fd42931efc7eab30743')
        with tempfile.TemporaryDirectory() as temporary:
            models = Path(temporary)
            legacy = models/'manifests/registry.ollama.ai/library/llama3.2/1b'
            legacy.parent.mkdir(parents=True)
            legacy.write_bytes(rewritten)
            with self.assertRaisesRegex(ValueError, 'model tag changed'):
                read_reviewed_manifest(models)
            blob = models/'blobs'/('sha256-'+MANIFEST_SHA256)
            blob.parent.mkdir()
            blob.write_bytes(original)
            current = models/'manifests-v2/ollama.com/library/llama3.2/1b'
            current.parent.mkdir(parents=True)
            current.symlink_to(blob)
            self.assertEqual(read_reviewed_manifest(models), value)

    def test_changed_v2_manifest_bytes_are_refused_even_at_the_reviewed_blob_path(self):
        original = (MODEL_REVIEW/'llama3.2-1b.manifest.json').read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            models = Path(temporary)
            blob = models/'blobs'/('sha256-'+MANIFEST_SHA256)
            blob.parent.mkdir()
            current = models/'manifests-v2/ollama.com/library/llama3.2/1b'
            current.parent.mkdir(parents=True)
            current.symlink_to(blob)
            for changed in (original.replace(b'"schemaVersion":2', b'"schemaVersion":3'),
                            original+b'\n', original[:-1]):
                blob.write_bytes(changed)
                with self.assertRaisesRegex(ValueError, 'model tag changed'):
                    read_reviewed_manifest(models)

    def test_v2_reference_to_unreviewed_digest_is_refused_even_with_original_bytes(self):
        original = (MODEL_REVIEW/'llama3.2-1b.manifest.json').read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            models = Path(temporary)
            blobs = models/'blobs'
            blobs.mkdir()
            (blobs/('sha256-'+MANIFEST_SHA256)).write_bytes(original)
            unreviewed = blobs/('sha256-'+'0'*64)
            unreviewed.write_bytes(original)
            current = models/'manifests-v2/ollama.com/library/llama3.2/1b'
            current.parent.mkdir(parents=True)
            current.symlink_to(unreviewed)
            with self.assertRaisesRegex(ValueError, 'does not reference the reviewed'):
                read_reviewed_manifest(models)

    def test_original_config_blob_requires_exact_size_and_full_content_hash(self):
        # This is the actual 485-byte public config, not fake model weights.
        original = (MODEL_REVIEW/'llama3.2-1b.config.json').read_bytes()
        descriptor = validate_manifest_bytes((MODEL_REVIEW/'llama3.2-1b.manifest.json').read_bytes())['config']
        with tempfile.TemporaryDirectory() as temporary:
            models = Path(temporary)
            blob = models/'blobs'/descriptor['digest'].replace(':', '-')
            blob.parent.mkdir()
            blob.write_bytes(original)
            verify_model_blob(models, descriptor)
            for changed in (original+b' ', bytes([original[0]^1])+original[1:]):
                blob.write_bytes(changed)
                with self.assertRaisesRegex(ValueError, 'content/size mismatch'):
                    verify_model_blob(models, descriptor)

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
