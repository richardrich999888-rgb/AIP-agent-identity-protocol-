#!/usr/bin/env python3
"""Verified Linux CPU bootstrap for the same public Qwen evidence agent.

Preparation needs public networking and runs before workload keys/capture.
Verification is offline. Runtime assets are public/readable; isolated HOME,
temporary directories and bootstrap logs are private, never publication data.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import signal
import socket
import stat
import subprocess
import tarfile
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
DEFAULT_PORT = 11436
MAX_RUNTIME_FILE = 512 * 1024 * 1024
MAX_RUNTIME_TOTAL = 2 * 1024 * 1024 * 1024


def _module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Reuse byte hashing, public download bounds, loopback HTTP and no-overwrite
# JSON writing. Importing this stdlib module does not call a Mac model/service.
_io = _module('vanian_shared_model_io', HERE / 'model_runtime.py')
sha, save, request = _io.sha, _io.save, _io.request


def pins():
    return json.loads((HERE / 'linux_model.lock.json').read_text())


def _require_linux():
    if platform.system() + '-' + platform.machine() != pins()['runtime']['platform']:
        raise ValueError('this runtime pin requires Linux x86_64')


def _reviewed_runtime_source():
    existing = _module('vanian_reviewed_linux_cpu_bootstrap', REPO / 'validation/enterprise/prepare_local_model.py')
    runtime = pins()['runtime']
    if (existing.VERSION != runtime['version'] or existing.URL != runtime['archive_url'] or
            existing.ARCHIVE_SHA256 != runtime['archive_sha256'] or existing.ARCHIVE_SIZE != runtime['archive_bytes'] or
            existing.CPU_FILE.pattern != runtime['cpu_member_regex']):
        raise ValueError('Linux CPU distribution pin differs from the existing reviewed bootstrap')
    return existing.CPU_FILE


def _safe_relative(name):
    normalized = name.removeprefix('./')
    parts = PurePosixPath(normalized)
    if not normalized or parts.is_absolute() or '..' in parts.parts or '\\' in normalized:
        raise ValueError('unsafe runtime archive member')
    return Path(*parts.parts)


def _extract_cpu_archive(archive, root):
    """Stream the hash-verified archive, copying only reviewed CPU members."""
    import zstandard
    if importlib.metadata.version('zstandard') != pins()['python']['zstandard']:
        raise ValueError('requires the locked zstandard decompressor')
    cpu_pattern = _reviewed_runtime_source()
    seen, links, total = set(), [], 0
    with Path(archive).open('rb') as compressed:
        with zstandard.ZstdDecompressor().stream_reader(compressed) as decompressed:
            with tarfile.open(fileobj=decompressed, mode='r|') as package:
                for member in package:
                    if member.isdir() and member.name in ('.', './'):
                        continue
                    relative = _safe_relative(member.name)
                    name = relative.as_posix()
                    if name != 'bin/ollama' and cpu_pattern.fullmatch(name) is None:
                        continue
                    if name in seen:
                        raise ValueError('duplicate selected runtime archive member')
                    seen.add(name)
                    path = root / relative
                    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                    if member.issym():
                        target = PurePosixPath(member.linkname)
                        if (target.is_absolute() or len(target.parts) != 1 or target.parts[0] in ('.', '..') or
                                cpu_pattern.fullmatch((PurePosixPath(name).parent / target).as_posix()) is None):
                            raise ValueError('runtime symlink target leaves the reviewed CPU files')
                        links.append((path, member.linkname))
                        continue
                    if not member.isfile() or not 0 <= member.size <= MAX_RUNTIME_FILE:
                        raise ValueError('unexpected runtime member type or size')
                    total += member.size
                    if total > MAX_RUNTIME_TOTAL:
                        raise ValueError('selected CPU runtime exceeds its bound')
                    source = package.extractfile(member)
                    with path.open('xb') as output:
                        shutil.copyfileobj(source, output, length=1024 * 1024)
                    if path.stat().st_size != member.size:
                        raise ValueError('runtime member length changed during extraction')
                    path.chmod(0o755 if name == 'bin/ollama' or path.name == 'llama-server' else 0o444)
    # Resolve internal versioned .so chains after all original file bytes exist.
    while links:
        pending = []
        for path, target in links:
            destination = path.parent / target
            if not destination.exists():
                pending.append((path, target))
                continue
            if not destination.resolve(strict=True).is_relative_to((root / 'lib/ollama').resolve()):
                raise ValueError('runtime link target escapes its CPU library directory')
            path.symlink_to(target)
        if len(pending) == len(links):
            raise ValueError('unresolved or cyclic CPU runtime symlink')
        links = pending
    if 'bin/ollama' not in seen or not any('libggml-cpu' in name for name in seen) or not any(name.endswith('/llama-server') for name in seen):
        raise ValueError('required CPU runtime members are missing')
    return _runtime_inventory(root)


def _runtime_inventory(root):
    result = []
    for tree in ('bin', 'lib'):
        tree_path = root / tree
        if not tree_path.is_dir() or tree_path.is_symlink() or tree_path.stat().st_mode & 0o022:
            raise ValueError('runtime public directory is unsafe')
        for path in sorted(tree_path.rglob('*')):
            if not path.is_symlink() and path.lstat().st_mode & 0o022:
                raise ValueError('runtime asset is writable by another account')
            if path.is_symlink():
                target = path.resolve(strict=True)
                if not target.is_file() or not target.is_relative_to((root / tree).resolve()):
                    raise ValueError('runtime symlink escapes its public asset tree')
                result.append({'path':path.relative_to(root).as_posix(), 'kind':'symlink', 'target':os.readlink(path)})
            elif path.is_file():
                result.append({'path':path.relative_to(root).as_posix(), 'kind':'file', 'bytes':path.stat().st_size, 'sha256':sha(path)})
            elif not path.is_dir():
                raise ValueError('special runtime file refused')
    return result


def _verify_runtime(root, expected):
    if _runtime_inventory(root) != expected:
        raise ValueError('Linux binary/library bytes or symlinks changed')
    binary = root / 'bin/ollama'
    if binary.is_symlink() or not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError('Linux Ollama executable is unavailable')
    return {'path':str(binary), 'version':pins()['runtime']['version'], 'sha256':sha(binary)}


def _model_identity(root):
    lock = pins()
    models = root / 'models'
    if models.resolve(strict=True) != root.resolve() / 'models' or (models / 'blobs').resolve(strict=True) != root.resolve() / 'models/blobs':
        raise ValueError('model store must remain inside the owned asset root')
    suffix = Path('library') / lock['runtime']['model_name'] / 'latest'
    current = models / 'manifests-v2/ollama.com' / suffix
    legacy = models / 'manifests/registry.ollama.ai' / suffix
    manifest = current if current.exists() or current.is_symlink() else legacy
    if manifest.is_symlink():
        target = manifest.resolve(strict=True)
        if (target.parent != (models / 'blobs').resolve(strict=True) or not re.fullmatch('sha256-[0-9a-f]{64}', target.name) or
                sha(target) != target.name[7:]):
            raise ValueError('model manifest link is not its content-addressed blob')
    elif not manifest.is_file():
        raise ValueError('local model manifest is missing')
    data = json.loads(manifest.read_text())
    weights, parameters = [], []
    for layer in [data['config'], *data['layers']]:
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', layer['digest']):
            raise ValueError('invalid model layer digest')
        blob = models / 'blobs' / layer['digest'].replace(':', '-')
        if blob.is_symlink() or not blob.is_file() or blob.stat().st_mode & 0o022 or blob.stat().st_size != layer['size'] or sha(blob) != layer['digest'][7:]:
            raise ValueError('model layer content/length mismatch')
        if layer.get('mediaType') == 'application/vnd.ollama.image.model':
            weights.append(layer)
        if layer.get('mediaType') == 'application/vnd.ollama.image.params':
            if layer['size'] > 1024:
                raise ValueError('model parameter layer exceeds its reviewed bound')
            def unique_fields(pairs):
                values = {}
                for key, value in pairs:
                    if key in values:
                        raise ValueError('duplicate model parameter field')
                    values[key] = value
                return values
            parameters.append(json.loads(blob.read_text(), object_pairs_hook=unique_fields))
    if (len(parameters) != 1 or type(parameters[0]) is not dict or set(parameters[0]) != {'num_ctx', 'temperature'} or
            type(parameters[0]['num_ctx']) is not int or parameters[0]['num_ctx'] != lock['runtime']['context_length'] or
            type(parameters[0]['temperature']) not in (int, float) or parameters[0]['temperature'] != 0):
        raise ValueError('verified model parameters differ from the reviewed serving profile')
    if (len(weights) != 1 or weights[0]['digest'] != 'sha256:' + lock['model']['sha256'] or
            weights[0]['size'] != lock['model']['bytes']):
        raise ValueError('model does not use the exact official HF weights')
    return {'model':lock['runtime']['model_name'], 'manifest_sha256':sha(manifest),
        'weight_sha256':lock['model']['sha256'], 'weight_bytes':lock['model']['bytes'],
        'serving_context_length':parameters[0]['num_ctx']}


def runtime_environment(root, port=DEFAULT_PORT, *, home=None, tmpdir=None):
    root = Path(root).resolve(strict=True)
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError('requires an unprivileged local model port')
    private = root / 'runtime-private'
    home = Path(home).absolute() if home is not None else private / 'home'
    temporary = Path(tmpdir).absolute() if tmpdir is not None else private / 'tmp'
    return {'PATH':os.defpath, 'HOME':str(home), 'TMPDIR':str(temporary),
        'OLLAMA_MODELS':str(root / 'models'), 'LD_LIBRARY_PATH':str(root / 'lib/ollama'),
        'OLLAMA_HOST':f'127.0.0.1:{port}', 'OLLAMA_NO_CLOUD':'1', 'OLLAMA_NOPRUNE':'1',
        'OLLAMA_NUM_PARALLEL':'1', 'OLLAMA_MAX_LOADED_MODELS':'1', 'OLLAMA_MAX_QUEUE':'1',
        'OLLAMA_CONTEXT_LENGTH':str(pins()['runtime']['context_length']),
        'OLLAMA_KEEP_ALIVE':'10m', 'LANG':'C.UTF-8', 'NETRC':os.devnull}


class _Server:
    def __init__(self, root, port, *, home=None, tmpdir=None):
        self.root, self.port = root, port
        self.environment = runtime_environment(root, port, home=home, tmpdir=tmpdir)
        self.base_url = f'http://127.0.0.1:{port}'
        self.model = pins()['runtime']['model_name']
        self.process = None

    def __enter__(self):
        for key in ('HOME','TMPDIR'):
            Path(self.environment[key]).mkdir(mode=0o700, parents=True, exist_ok=True)
        with socket.socket() as available:
            available.bind(('127.0.0.1',self.port))
        log_root = Path(self.environment['HOME'])
        self.log = (log_root / ('ollama-' + str(time.time_ns()) + '.log')).open('xb')
        self.process = subprocess.Popen([str(self.root / 'bin/ollama'),'serve'], env=self.environment,
            cwd=self.environment['HOME'], stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + 30
        try:
            while True:
                if self.process.poll() is not None:
                    raise RuntimeError('owned Linux model service exited before readiness')
                try:
                    if request(self.base_url,'/api/version',timeout=1)['version'] == pins()['runtime']['version']:
                        return self
                except (OSError,ValueError,KeyError):
                    pass
                if time.monotonic() >= deadline:
                    raise TimeoutError('owned Linux CPU model readiness timed out')
                time.sleep(0.1)
        except BaseException:
            self.close();raise

    @property
    def pid(self):
        return self.process.pid if self.process is not None else None

    def close(self):
        if self.process is not None and self.process.poll() is None:
            os.killpg(self.process.pid,signal.SIGTERM)
            try:self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid,signal.SIGKILL);self.process.wait(timeout=10)
        if getattr(self,'log',None) is not None:self.log.close()

    def __exit__(self,*_):self.close()


class ModelProcess(_Server):
    def __init__(self, root, port=DEFAULT_PORT, *, home=None, tmpdir=None):
        super().__init__(Path(root).resolve(strict=True),port,home=home,tmpdir=tmpdir)

    def __enter__(self):
        self.identity = verify(self.root)
        super().__enter__()
        try:
            verify_service(self.base_url,self.identity)
        except BaseException:
            self.close();raise
        return self


def verify_service(base_url, identity):
    version = request(base_url,'/api/version',timeout=2)['version']
    if version != identity['binary']['version']:
        raise ValueError('actual model service version differs')
    matches = [item for item in request(base_url,'/api/tags',timeout=2)['models']
               if item['name']==identity['model']['model']+':latest' and item['digest']==identity['model']['manifest_sha256']]
    if len(matches) != 1:
        raise ValueError('actual model service tag/manifest differs')
    return {'classification':'ROOT_CONTROLLER_MODEL_SERVICE_CHECK','status':'PASS',
        'version':version,'model':matches[0]['name'],'manifest_sha256':matches[0]['digest'],
        'matches_offline_verified_assets':True,'source_authority':'UNSIGNED_CONTROLLER_HTTP_RESPONSE_CHECK',
        'kernel_observation_claimed':False}


def _publish_public_assets(root):
    root.chmod(0o755)
    for name in ('bin','lib','models'):
        tree=root/name
        for path in [tree,*tree.rglob('*')]:
            if path.is_symlink():
                if not path.resolve(strict=True).is_relative_to(tree.resolve()):
                    raise ValueError('public asset link leaves its tree')
            else:
                path.chmod(0o755 if path.is_dir() or name=='bin' or path.name=='llama-server' else 0o444)
    for name in ('MODEL-LICENSE.txt','identity.json'):(root/name).chmod(0o444)


def verify(root):
    """Offline hashes only: does not execute a binary or contact any service."""
    _require_linux();root=Path(root).resolve(strict=True);identity=json.loads((root/'identity.json').read_text())
    if identity['lock_sha256'] != sha(HERE/'linux_model.lock.json'):
        raise ValueError('prepared Linux assets use another lock')
    _reviewed_runtime_source()
    binary=_verify_runtime(root,identity['runtime_files']);model=_model_identity(root)
    if model != identity['model'] or sha(root/'MODEL-LICENSE.txt') != pins()['model']['license_sha256']:
        raise ValueError('prepared HF model/license identity changed')
    if sha(HERE/'requirements.lock') != pins()['python']['requirements_sha256']:
        raise ValueError('Python dependency lock changed')
    return {'status':'PASS','classification':'PUBLIC_PINNED_LOCAL_CPU_MODEL_ASSETS',
        'root':str(root),'models':str(root/'models'),'binary':binary,'model':model,
        'repository':pins()['model']['repository'],'revision':pins()['model']['revision'],
        'license':pins()['model']['license'],'runtime_archive_sha256':pins()['runtime']['archive_sha256'],
        'model_api_credentials_used':False,'paid_inference_used':False,'verification_network_used':False}


def prepare(root):
    _require_linux();root=Path(root).absolute();root.mkdir(mode=0o700,parents=True,exist_ok=True)
    with (root/'.prepare.lock').open('a') as guard:
        fcntl.flock(guard,fcntl.LOCK_EX)
        if (root/'identity.json').exists():return verify(root)
        lock=pins();private=root/'bootstrap-private';private.mkdir(mode=0o700,exist_ok=True)
        archive=private/'ollama-linux-amd64.tar.zst'
        _io._download(lock['runtime']['archive_url'],archive,lock['runtime']['archive_bytes'],lock['runtime']['archive_sha256'])
        runtime_files=_extract_cpu_archive(archive,root)
        _verify_runtime(root,runtime_files)
        _io._download(lock['model']['license_url'],root/'MODEL-LICENSE.txt',lock['model']['license_bytes'],lock['model']['license_sha256'])
        downloaded=private/'model-download.gguf'
        _io._download(lock['model']['url'],downloaded,lock['model']['bytes'],lock['model']['sha256'])
        modelfile=private/'Modelfile'
        with modelfile.open('x') as stream:
            stream.write('FROM '+str(downloaded)+'\nPARAMETER num_ctx '+str(lock['runtime']['context_length'])+'\nPARAMETER temperature 0\n')
        with _Server(root,lock['runtime']['bootstrap_port'],home=private/'home',tmpdir=private/'tmp') as service:
            subprocess.run([str(root/'bin/ollama'),'create',lock['runtime']['model_name'],'-f',str(modelfile)],
                env=service.environment,stdout=service.log,stderr=subprocess.STDOUT,check=True,timeout=240)
            model=_model_identity(root)
            identity={'schema':'vanian-linux-cpu-model-assets-v1','lock_sha256':sha(HERE/'linux_model.lock.json'),
                'runtime_files':runtime_files,'model':model,'actual_bootstrap_version':lock['runtime']['version'],
                'complete_runtime_archive_hash_checked':True,'complete_HF_weight_hash_checked':True,
                'model_api_credentials_used':False,'paid_inference_used':False}
            verify_service(service.base_url,{'binary':{'version':lock['runtime']['version']},'model':model})
        save(root/'identity.json',identity)
        _publish_public_assets(root)
        verified=verify(root)
        # Delete only our two verified duplicate bootstrap downloads. Preserve
        # private logs/home and all canonical runtime/model bytes for diagnosis.
        if sha(downloaded)!=model['weight_sha256'] or sha(archive)!=lock['runtime']['archive_sha256']:
            raise ValueError('owned bootstrap downloads changed before duplicate cleanup')
        downloaded.unlink();archive.unlink()
        return verified


def inference_smoke(root):
    with ModelProcess(root) as service:
        began=time.monotonic()
        response=request(service.base_url,'/api/chat',{'model':service.model,
            'messages':[{'role':'user','content':'Answer briefly: why keep an audit trail?'}],
            'format':{'type':'object','properties':{'answer':{'type':'string'}},'required':['answer'],'additionalProperties':False},
            'stream':False,'options':{'num_ctx':8192,'num_predict':64,'num_thread':2,'temperature':0}},timeout=180)
        if response.get('model') != service.model or response.get('message',{}).get('role') != 'assistant':
            raise ValueError('actual Linux model response identity/role differs')
        content=json.loads(response.get('message',{}).get('content',''))
        resident=request(service.base_url,'/api/ps')['models']
        matches=[item for item in resident if item.get('name')==service.model+':latest' and item.get('digest')==service.identity['model']['manifest_sha256']]
        if len(matches)!=1 or matches[0].get('context_length')!=8192:
            raise ValueError('actual Linux model context is not the requested8192 tokens')
        if (response.get('done') is not True or response.get('done_reason')=='length' or type(content) is not dict or
                set(content)!={'answer'} or not isinstance(content['answer'],str) or not content['answer'].strip()):
            raise ValueError('actual Linux CPU inference did not complete its JSON answer')
        return {'classification':'ACTUAL_LINUX_LOCAL_MODEL_INFERENCE_ONLY','status':'PASS','answer':content['answer'],
            'request_options':{'num_ctx':8192,'num_predict':64,'num_thread':2,'temperature':0},
            'actual_service_context_length':matches[0]['context_length'],
            'actual_service_vram_bytes':matches[0].get('size_vram'),
            'wall_seconds':time.monotonic()-began,'model_identity':service.identity['model'],'binary':service.identity['binary'],
            'metrics':{key:response.get(key) for key in ('done_reason','prompt_eval_count','eval_count','total_duration','load_duration')},
            'paid_inference_used':False,'model_api_credentials_used':False,'kernel_observation_claimed':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=('prepare','verify','smoke'))
    parser.add_argument('--root',required=True,type=Path);parser.add_argument('--out',type=Path)
    args=parser.parse_args();result={'prepare':prepare,'verify':verify,'smoke':inference_smoke}[args.action](args.root)
    if args.out:save(args.out,result)
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
