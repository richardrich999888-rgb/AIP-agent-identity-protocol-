#!/usr/bin/env python3
"""Pinned public Hugging Face model and an owned loopback Ollama process.

Assets stay outside Git. This Mac application demo does not claim Linux kernel
observation, independent custody or authoritative business outcomes.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import socket
import subprocess
import sys
import time
from urllib.request import ProxyHandler, Request, build_opener

HERE = Path(__file__).resolve().parent
DEFAULT_ROOT = Path('/private/tmp/vanian-local-evidence-agent-assets')
MAX_JSON = 2 * 1024 * 1024


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def pins():
    return json.loads((HERE / 'model.lock.json').read_text())


def save(path, value):
    path = Path(path)
    if path.exists():
        if json.loads(path.read_text()) == value:
            return
        raise ValueError('existing model metadata differs; no automatic overwrite')
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write('\n')
    path.chmod(0o600)


def environment(root, port):
    return {'PATH': os.defpath, 'HOME': str(root / 'home'), 'TMPDIR': str(root / 'tmp'),
        'OLLAMA_MODELS': str(root / 'models'), 'OLLAMA_HOST': f'127.0.0.1:{port}',
        'OLLAMA_NO_CLOUD': '1', 'OLLAMA_NOPRUNE': '1', 'OLLAMA_NUM_PARALLEL': '1',
        'OLLAMA_MAX_LOADED_MODELS': '1', 'OLLAMA_MAX_QUEUE': '1',
        'OLLAMA_CONTEXT_LENGTH': str(pins()['runtime']['context_length']),
        'OLLAMA_KEEP_ALIVE': '5m', 'LANG': 'en_US.UTF-8', 'NETRC': os.devnull}


def request(base_url, route, body=None, timeout=120):
    if not base_url.startswith('http://127.0.0.1:') or not route.startswith('/api/'):
        raise ValueError('only the owned local model service is supported')
    raw = None if body is None else json.dumps(body, allow_nan=False).encode()
    req = Request(base_url + route, data=raw, headers={'Content-Type': 'application/json'})
    with build_opener(ProxyHandler({})).open(req, timeout=timeout) as response:
        data = response.read(MAX_JSON + 1)
    if len(data) > MAX_JSON:
        raise ValueError('model API response exceeds its bound')
    return json.loads(data)


def verify_binary(root=DEFAULT_ROOT):
    lock = pins()['runtime']
    binary = Path(lock['binary'])
    if platform.system() + '-' + platform.machine() != lock['platform']:
        raise ValueError('this reviewed local model profile requires macOS arm64')
    if not binary.is_file() or sha(binary) != lock['sha256']:
        raise ValueError('installed Ollama binary differs from the reviewed pin')
    version = subprocess.run([str(binary), '--version'], check=True, capture_output=True,
        text=True, timeout=15, env={'PATH': os.defpath, 'HOME': str(Path(root) / 'home'),
            'OLLAMA_MODELS': str(Path(root) / 'models'), 'OLLAMA_NO_CLOUD': '1'}).stdout.strip()
    if version != 'ollama version is ' + lock['version']:
        raise ValueError('installed Ollama version differs from the reviewed pin')
    return {'path': str(binary), 'sha256': lock['sha256'], 'version': lock['version']}


def verify_python(root):
    python = root / 'venv/bin/python'
    requirements = HERE / 'requirements.lock'
    if sha(requirements) != pins()['python']['requirements_sha256']:
        raise ValueError('Python requirements differ from the reviewed lock')
    expected = {}
    for line in requirements.read_text().splitlines():
        if line and not line.startswith('#'):
            name, version = line.split('==', 1)
            expected[name] = version
    program = ('import sys,json,importlib.metadata as m;'
        'print(json.dumps({"python":list(sys.version_info[:2]),"prefix":sys.prefix,'
        '"base":sys.base_prefix,"versions":{n:m.version(n) for n in ' + repr(sorted(expected)) + '}}))')
    result = subprocess.run([str(python), '-I', '-B', '-c', program], check=True,
        capture_output=True, text=True, timeout=20, env={'PATH': os.defpath})
    actual = json.loads(result.stdout)
    if (actual['python'] != [3, 12] or actual['versions'] != expected or
            Path(actual['prefix']).resolve() != (root / 'venv').resolve() or actual['prefix'] == actual['base']):
        raise ValueError('requires the exact isolated Python 3.12 dependency environment')
    return str(python)


def model_identity(root):
    lock = pins()
    manifest = root / 'models/manifests-v2/ollama.com/library' / lock['runtime']['model_name'] / 'latest'
    # Ollama0.40 uses a manifests-v2 link to its content-addressed manifest.
    # Accept only this owned-store link; never follow a model reference outside it.
    if not manifest.is_symlink():
        raise ValueError('verified local model manifest link is missing')
    target = manifest.resolve(strict=True)
    blobs = (root / 'models/blobs').resolve(strict=True)
    if (blobs != root.resolve() / 'models/blobs' or target.parent != blobs or
            not target.is_file() or len(target.name) != 71 or not target.name.startswith('sha256-') or
            sha(target) != target.name[7:]):
        raise ValueError('model manifest link escapes its verified content-addressed store')
    data = json.loads(target.read_text())
    layers = [*data['layers'], data['config']]
    weights = []
    for layer in layers:
        digest = layer['digest']
        if not isinstance(digest, str) or len(digest) != 71 or not digest.startswith('sha256:'):
            raise ValueError('unexpected model layer digest')
        blob = root / 'models/blobs' / digest.replace(':', '-')
        if blob.is_symlink() or not blob.is_file() or blob.stat().st_size != layer['size'] or sha(blob) != digest[7:]:
            raise ValueError('model layer bytes do not match the import manifest')
        if layer.get('mediaType') == 'application/vnd.ollama.image.model':
            weights.append(layer)
    if len(weights) != 1 or weights[0]['digest'] != 'sha256:' + lock['model']['sha256'] or weights[0]['size'] != lock['model']['bytes']:
        raise ValueError('imported model differs from the exact public Hugging Face weights')
    return {'model': lock['runtime']['model_name'], 'manifest_sha256': sha(manifest),
        'weight_sha256': lock['model']['sha256'], 'weight_bytes': lock['model']['bytes']}


class _Server:
    def __init__(self, root, port):
        if type(port) is not int or not 1024 <= port <= 65535:
            raise ValueError('invalid local model port')
        self.root, self.port = root, port
        self.base_url = f'http://127.0.0.1:{port}'
        self.process = None

    def __enter__(self):
        identity = verify_binary(self.root)
        for name in ('home', 'tmp', 'models'):
            (self.root / name).mkdir(mode=0o700, parents=True, exist_ok=True)
        with socket.socket() as available:
            available.bind(('127.0.0.1', self.port))  # Never attach to or kill another service.
        log_path = self.root / ('ollama-' + str(time.time_ns()) + '.log')
        self.log = log_path.open('xb')
        self.process = subprocess.Popen([identity['path'], 'serve'], cwd=self.root,
            env=environment(self.root, self.port), stdout=self.log, stderr=subprocess.STDOUT,
            start_new_session=True)
        deadline = time.monotonic() + 30
        try:
            while True:
                if self.process.poll() is not None:
                    raise RuntimeError('owned Ollama process exited before readiness')
                try:
                    if request(self.base_url, '/api/version', timeout=1)['version'] == identity['version']:
                        return self
                except (OSError, ValueError, KeyError):
                    pass
                if time.monotonic() >= deadline:
                    raise TimeoutError('owned local model service startup timed out')
                time.sleep(0.1)
        except BaseException:
            self.close()
            raise

    @property
    def pid(self):
        return self.process.pid if self.process is not None else None

    def close(self):
        if self.process is not None and self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=8)
        if getattr(self, 'log', None) is not None:
            self.log.close()

    def __exit__(self, *_):
        self.close()


class ModelProcess(_Server):
    """Start and stop only this context's pinned, isolated model service."""
    def __init__(self, root=DEFAULT_ROOT, port=11436):
        super().__init__(Path(root).resolve(strict=True), port)
        self.model = pins()['runtime']['model_name']

    def __enter__(self):
        self.identity = verify(self.root)
        super().__enter__()
        try:
            tags = request(self.base_url, '/api/tags')['models']
            if not any(tag['name'] == self.model + ':latest' and tag['digest'] == self.identity['model']['manifest_sha256'] for tag in tags):
                raise ValueError('actual local service does not expose the verified model')
        except BaseException:
            self.close()
            raise
        return self


def verify(root):
    root = Path(root).resolve(strict=True)
    identity = json.loads((root / 'identity.json').read_text())
    if identity['lock_sha256'] != sha(HERE / 'model.lock.json'):
        raise ValueError('prepared assets use another model lock')
    actual = model_identity(root)
    if identity['model'] != actual:
        raise ValueError('prepared model identity changed')
    if sha(root / 'MODEL-LICENSE.txt') != pins()['model']['license_sha256']:
        raise ValueError('prepared model license differs from the official pin')
    return {**identity, 'root': str(root), 'python': verify_python(root), 'binary': verify_binary(root)}


def _download(url, target, size, digest):
    if target.exists():
        if target.is_symlink() or target.stat().st_size != size or sha(target) != digest:
            raise ValueError('existing downloaded asset differs from its pin')
        return
    partial = target.with_suffix(target.suffix + '.part')
    if partial.exists():
        if partial.stat().st_size == size and sha(partial) == digest:
            partial.rename(target)
            return
        raise ValueError('incomplete owned download retained; inspect it before retrying')
    with build_opener(ProxyHandler({})).open(url, timeout=60) as source, partial.open('xb') as output:
        count = 0
        while chunk := source.read(1024 * 1024):
            count += len(chunk)
            if count > size:
                raise ValueError('public asset download exceeds its pinned size')
            output.write(chunk)
    if partial.stat().st_size != size or sha(partial) != digest:
        raise ValueError('public downloaded asset hash mismatch')
    partial.rename(target)


def prepare(root=DEFAULT_ROOT):
    """Bootstrap pinned public assets, or verify/reuse an already prepared root."""
    root = Path(root).absolute()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (root / '.prepare.lock').open('a') as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        if (root / 'identity.json').exists():
            return verify(root)
        lock = pins()
        verify_binary(root)
        if not (root / 'venv/bin/python').exists():
            subprocess.run([sys.executable, '-I', '-m', 'venv', str(root / 'venv')], check=True, timeout=60)
        # An interrupted first pip install leaves a valid but incomplete venv.
        # Until identity.json exists, retry the same exact locked installation.
        subprocess.run([str(root / 'venv/bin/python'), '-I', '-m', 'pip', '--isolated',
            '--disable-pip-version-check', 'install', '--no-cache-dir', '--index-url', 'https://pypi.org/simple',
            '--keyring-provider', 'disabled', '-r', str(HERE / 'requirements.lock')], check=True, timeout=240)
        python = verify_python(root)
        _download(lock['model']['license_url'], root / 'MODEL-LICENSE.txt', lock['model']['license_bytes'], lock['model']['license_sha256'])
        model_path = root / 'model-download.gguf'
        try:
            imported = model_identity(root)
        except (OSError, ValueError):
            import shutil
            needed = lock['model']['bytes'] + 256 * 1024 * 1024
            if not model_path.exists():
                needed += lock['model']['bytes']
            if shutil.disk_usage(root).free < needed:
                raise ValueError('insufficient disk space for bounded local model import')
            _download(lock['model']['url'], model_path, lock['model']['bytes'], lock['model']['sha256'])
            modelfile = root / 'Modelfile'
            content = ('FROM ' + str(model_path) + '\nPARAMETER num_ctx ' + str(lock['runtime']['context_length']) + '\nPARAMETER temperature 0\n')
            if modelfile.exists() and modelfile.read_text() != content:
                raise ValueError('existing import configuration differs')
            if not modelfile.exists():
                modelfile.write_text(content)
            with _Server(root, lock['runtime']['default_port']) as service:
                subprocess.run([lock['runtime']['binary'], 'create', lock['runtime']['model_name'], '-f', str(modelfile)],
                    env=environment(root, service.port), check=True, timeout=180)
                imported = model_identity(root)
                tags = request(service.base_url, '/api/tags')['models']
                if not any(tag['digest'] == imported['manifest_sha256'] for tag in tags):
                    raise ValueError('actual imported model digest does not match its verified manifest')
        identity = {'schema': 'vanian-local-model-assets-v1', 'lock_sha256': sha(HERE / 'model.lock.json'),
            'repository': lock['model']['repository'], 'revision': lock['model']['revision'],
            'license': lock['model']['license'], 'model': imported,
            'model_api_credentials_used': False, 'paid_inference_used': False}
        save(root / 'identity.json', identity)
        if model_path.exists():
            if model_path.is_symlink() or sha(model_path) != imported['weight_sha256']:
                raise ValueError('owned source download changed after import')
            model_path.unlink()  # Only our duplicate, after the stored import's full hash verified.
        return {**verify(root), 'python': python}


def inference_smoke(root=DEFAULT_ROOT, question='In one sentence, why should an AI agent keep an audit trail?'):
    prepare(root)
    with ModelProcess(root) as service:
        began = time.monotonic()
        response = request(service.base_url, '/api/generate', {'model': service.model,
            'prompt': question, 'stream': False, 'options': {'num_ctx': 4096, 'num_predict': 64, 'num_thread': 2, 'temperature': 0}}, timeout=180)
        if response.get('done') is not True or not isinstance(response.get('response'), str) or not response['response'].strip():
            raise ValueError('actual inference did not return a completed nonempty answer')
        result = {'classification': 'ACTUAL_LOCAL_MODEL_INFERENCE_ONLY', 'question': question,
            'response': response['response'], 'wall_seconds': time.monotonic() - began,
            'pid': service.pid, 'binary': service.identity['binary'], 'model_identity': service.identity['model'],
            'metrics': {k: response.get(k) for k in ('total_duration', 'load_duration', 'prompt_eval_count', 'prompt_eval_duration', 'eval_count', 'eval_duration', 'done_reason')},
            'model_api_credentials_used': False, 'paid_inference_used': False,
            'kernel_observation_claimed': False}
    save(Path(root) / 'inference-smoke.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'verify', 'smoke'))
    parser.add_argument('--root', type=Path, default=DEFAULT_ROOT)
    args = parser.parse_args()
    function = {'prepare': prepare, 'verify': verify, 'smoke': inference_smoke}[args.action]
    print(json.dumps(function(args.root), indent=2))


if __name__ == '__main__':
    main()
