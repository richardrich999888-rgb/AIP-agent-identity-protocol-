"""Controlled Linux bootstrap fixtures only; no binary/model is executed.

Real Linux archive download, CPU startup and inference are separate runner gates.
These temporary tiny archives/blobs are never presented as real model evidence.
"""
from pathlib import Path
import copy
import hashlib
import importlib.util
import io
import json
import os
import tarfile
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('linux_model_runtime_under_test', HERE / 'linux_model_runtime.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


def fixture_archive(path, extra=()):
    import zstandard
    payload=io.BytesIO()
    with tarfile.open(fileobj=payload,mode='w') as package:
        for name,body in (('bin/ollama',b'controlled binary fixture'),
                ('lib/ollama/llama-server',b'controlled runner fixture'),
                ('lib/ollama/libggml-cpu-x64.so',b'controlled CPU library fixture'),
                ('lib/ollama/libggml-base.so.1',b'controlled base library fixture'),
                ('lib/ollama/libggml-cuda.so',b'must not extract GPU fixture')):
            info=tarfile.TarInfo(name);info.size=len(body);package.addfile(info,io.BytesIO(body))
        link=tarfile.TarInfo('lib/ollama/libggml-base.so');link.type=tarfile.SYMTYPE
        link.linkname='libggml-base.so.1';package.addfile(link)
        for item in extra:
            package.addfile(item,io.BytesIO(b'X') if item.isfile() else None)
    path.write_bytes(zstandard.ZstdCompressor().compress(payload.getvalue()))


class ControlledLinuxBootstrap(unittest.TestCase):
    def test_reuses_reviewed_distribution_and_identical_official_hf_weight_pin(self):
        selected=runtime._reviewed_runtime_source()
        self.assertEqual(selected.pattern,runtime.pins()['runtime']['cpu_member_regex'])
        mac=json.loads((HERE/'model.lock.json').read_text())
        for field in ('repository','revision','sha256','bytes','license','license_sha256'):
            self.assertEqual(runtime.pins()['model'][field],mac['model'][field])
        self.assertEqual(runtime.pins()['runtime']['context_length'],8192)
        self.assertEqual(runtime.sha(HERE/'requirements.lock'),runtime.pins()['python']['requirements_sha256'])

    def test_environment_is_loopback_only_and_does_not_inherit_credentials(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ,{
                'HF_TOKEN':'controlled-private-canary','OLLAMA_API_KEY':'controlled-private-canary',
                'HTTP_PROXY':'http://controlled-private-canary.invalid','HOME':'/unrelated-global-home'}):
            root=Path(tmp);home=root/'owned-home';temporary=root/'owned-tmp'
            env=runtime.runtime_environment(root,11436,home=home,tmpdir=temporary)
            self.assertEqual(env['OLLAMA_HOST'],'127.0.0.1:11436')
            self.assertEqual(env['HOME'],str(home));self.assertEqual(env['TMPDIR'],str(temporary))
            self.assertEqual(env['OLLAMA_CONTEXT_LENGTH'],'8192')
            self.assertEqual(env['OLLAMA_NO_CLOUD'],'1')
            self.assertEqual(env['OLLAMA_MODELS'],str(root.resolve()/'models'))
            self.assertNotIn('controlled-private-canary',json.dumps(env))
            for field in ('HTTP_PROXY','HTTPS_PROXY','HF_TOKEN','OLLAMA_API_KEY'):
                self.assertNotIn(field,env)
            with self.assertRaises(ValueError):runtime.runtime_environment(root,True)
            with self.assertRaises(ValueError):runtime.runtime_environment(root,80)

    def test_controlled_cpu_archive_retains_safe_links_and_excludes_gpu_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'assets';root.mkdir();archive=Path(tmp)/'fixture.tar.zst'
            fixture_archive(archive);inventory=runtime._extract_cpu_archive(archive,root)
            self.assertFalse((root/'lib/ollama/libggml-cuda.so').exists())
            self.assertEqual((root/'lib/ollama/libggml-base.so').read_bytes(),b'controlled base library fixture')
            self.assertEqual(runtime._verify_runtime(root,inventory)['sha256'],runtime.sha(root/'bin/ollama'))
            (root/'bin/ollama').chmod(0o777)
            with self.assertRaises(ValueError):runtime._runtime_inventory(root)
            (root/'bin/ollama').chmod(0o755)
            (root/'bin/ollama').write_bytes(b'changed controlled fixture')
            with self.assertRaises(ValueError):runtime._verify_runtime(root,inventory)

    def test_archive_rejects_escape_duplicate_and_unsafe_selected_symlink(self):
        cases=[]
        escape=tarfile.TarInfo('../outside');escape.size=1;cases.append(escape)
        duplicate=tarfile.TarInfo('bin/ollama');duplicate.size=1;cases.append(duplicate)
        link=tarfile.TarInfo('lib/ollama/libggml-blas.so');link.type=tarfile.SYMTYPE
        link.linkname='../../outside';cases.append(link)
        for item in cases:
            with self.subTest(name=item.name),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)/'assets';root.mkdir();archive=Path(tmp)/'fixture.tar.zst'
                fixture_archive(archive,[item])
                with self.assertRaises(ValueError):runtime._extract_cpu_archive(archive,root)
                self.assertFalse((Path(tmp)/'outside').exists())

    def test_actual_service_summary_uses_only_checked_version_tag_and_manifest(self):
        # Controlled HTTP fixtures, not a model service or inference claim.
        identity={'binary':{'version':'0.40.11'},'model':{'model':'vanian-qwen-local','manifest_sha256':'a'*64}}
        tag={'name':'vanian-qwen-local:latest','digest':'a'*64,'unapproved':'private-canary'}
        with mock.patch.object(runtime,'request',side_effect=[{'version':'0.40.11','unapproved':'private-canary'},{'models':[tag]}]) as http:
            summary=runtime.verify_service('http://127.0.0.1:11436',identity)
        self.assertEqual(summary['status'],'PASS')
        self.assertEqual(summary['model'],'vanian-qwen-local:latest')
        self.assertEqual(summary['manifest_sha256'],'a'*64)
        self.assertFalse(summary['kernel_observation_claimed'])
        self.assertNotIn('private-canary',json.dumps(summary))
        self.assertEqual(http.call_count,2)
        self.assertTrue(all(call.kwargs=={'timeout':2}for call in http.call_args_list))
        for bad in ({'models':[]},{'models':[tag,tag]}, {'models':[dict(tag,digest='b'*64)]}):
            with self.subTest(bad=bad),mock.patch.object(runtime,'request',side_effect=[{'version':'0.40.11'},bad]):
                with self.assertRaises(ValueError):runtime.verify_service('http://127.0.0.1:11436',identity)
        with mock.patch.object(runtime,'request',return_value={'version':'wrong'}):
            with self.assertRaises(ValueError):runtime.verify_service('http://127.0.0.1:11436',identity)

    def test_runtime_inventory_refuses_symlink_outside_asset_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'assets';(root/'lib').mkdir(parents=True);(root/'bin').mkdir()
            outside=Path(tmp)/'outside';outside.write_bytes(b'controlled outside fixture')
            (root/'lib/escape.so').symlink_to(outside)
            with self.assertRaises(ValueError):runtime._runtime_inventory(root)

    def test_controlled_model_blob_verification_and_store_escape_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'assets';blobs=root/'models/blobs';blobs.mkdir(parents=True)
            fixture=copy.deepcopy(runtime.pins());weight=b'controlled tiny fixture, not model weights'
            weight_sha=hashlib.sha256(weight).hexdigest();fixture['model']['sha256']=weight_sha
            fixture['model']['bytes']=len(weight)
            (blobs/('sha256-'+weight_sha)).write_bytes(weight)
            config=b'{}';config_sha=hashlib.sha256(config).hexdigest();(blobs/('sha256-'+config_sha)).write_bytes(config)
            parameters=json.dumps({'num_ctx':8192,'temperature':0}).encode()
            params_sha=hashlib.sha256(parameters).hexdigest();(blobs/('sha256-'+params_sha)).write_bytes(parameters)
            manifest={'config':{'digest':'sha256:'+config_sha,'size':len(config)},'layers':[{
                'mediaType':'application/vnd.ollama.image.model','digest':'sha256:'+weight_sha,'size':len(weight)},
                {'mediaType':'application/vnd.ollama.image.params','digest':'sha256:'+params_sha,'size':len(parameters)}]}
            raw=json.dumps(manifest).encode();digest=hashlib.sha256(raw).hexdigest();(blobs/('sha256-'+digest)).write_bytes(raw)
            named=root/'models/manifests-v2/ollama.com/library/vanian-qwen-local/latest';named.parent.mkdir(parents=True)
            named.symlink_to(blobs/('sha256-'+digest))
            with mock.patch.object(runtime,'pins',return_value=fixture):
                self.assertEqual(runtime._model_identity(root)['weight_sha256'],weight_sha)
                self.assertEqual(runtime._model_identity(root)['serving_context_length'],8192)
                # Re-hash every changed byte so this exercises parameter truth,
                # rather than merely rejecting a broken content hash.
                wrong=json.dumps({'num_ctx':4096,'temperature':0}).encode()
                wrong_sha=hashlib.sha256(wrong).hexdigest();(blobs/('sha256-'+wrong_sha)).write_bytes(wrong)
                altered=copy.deepcopy(manifest);altered['layers'][1].update(digest='sha256:'+wrong_sha,size=len(wrong))
                altered_raw=json.dumps(altered).encode();altered_sha=hashlib.sha256(altered_raw).hexdigest()
                (blobs/('sha256-'+altered_sha)).write_bytes(altered_raw)
                named.unlink();named.symlink_to(blobs/('sha256-'+altered_sha))
                with self.assertRaises(ValueError):runtime._model_identity(root)
                named.unlink();named.symlink_to(blobs/('sha256-'+digest))
                (blobs/('sha256-'+weight_sha)).write_bytes(b'controlled mutation')
                with self.assertRaises(ValueError):runtime._model_identity(root)
                named.unlink();outside=Path(tmp)/'outside';outside.write_bytes(raw);named.symlink_to(outside)
                with self.assertRaises(ValueError):runtime._model_identity(root)


if __name__=='__main__':unittest.main(verbosity=2)
