#!/usr/bin/env python3
"""Download pinned public CPU inference runtime/model; never reads account credentials."""
import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import time
import urllib.request
from pathlib import Path

VERSION = '0.40.11'
ARCHIVE_SHA256 = '7bedab90dd122661be78798e9f0edf37fccf0cccf2699d2c58ea1a3afdc04b6d'
ARCHIVE_SIZE = 1508659610
MODEL = 'llama3.2:1b'
MANIFEST_SHA256 = 'baf6a787fdffd633537aa2eb51cfd54cb93ff08e28040095462bb63daf552878'
URL = f'https://github.com/ollama/ollama/releases/download/v{VERSION}/ollama-linux-amd64.tar.zst'
CPU_FILE = re.compile(r'lib/ollama/(?:llama-server|lib(?:ggml(?:-(?:base|cpu[^/]*|blas))?|llama(?:-common|-server-impl)?|mtmd|gomp|omp|stdc\+\+|gcc_s)\.so(?:\.[0-9.]+)?)\Z')


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify_model(models):
    manifest = models / 'manifests/registry.ollama.ai/library/llama3.2/1b'
    if sha(manifest) != MANIFEST_SHA256:
        raise ValueError('model tag changed; reviewed manifest digest required')
    value = json.loads(manifest.read_bytes())
    for layer in [value['config'], *value['layers']]:
        digest = layer['digest']
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
            raise ValueError('invalid model layer digest')
        blob = models / 'blobs' / digest.replace(':', '-')
        if blob.stat().st_size != layer['size'] or sha(blob) != digest.split(':')[1]:
            raise ValueError('model layer content/size mismatch')
    return value


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    args = p.parse_args()
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise ValueError('this pin is Linux x86_64 only')
    root = args.root.resolve(); root.mkdir(parents=True, exist_ok=False)
    archive = root / 'ollama-linux-amd64.tar.zst'
    digest = hashlib.sha256(); total = 0
    with urllib.request.urlopen(URL, timeout=90) as response, archive.open('wb') as output:
        while data := response.read(2 * 1024 * 1024):
            total += len(data)
            if total > ARCHIVE_SIZE:
                raise ValueError('download exceeds pinned archive length')
            digest.update(data); output.write(data)
    if total != ARCHIVE_SIZE or digest.hexdigest() != ARCHIVE_SHA256:
        raise ValueError('official runtime archive digest/length mismatch')
    names = subprocess.check_output(['tar', '--zstd', '-tf', str(archive)], text=True).splitlines()
    selected = []
    for name in names:
        normalized = name.removeprefix('./')
        if normalized == 'bin/ollama' or CPU_FILE.fullmatch(normalized):
            if '..' in Path(normalized).parts or normalized.startswith('/'):
                raise ValueError('unsafe runtime member')
            selected.append(name)
    if not any(x.removeprefix('./') == 'bin/ollama' for x in selected) or not any('libggml-cpu' in x for x in selected):
        raise ValueError('reviewed CPU archive layout unavailable')
    subprocess.run(['tar', '--zstd', '-xf', str(archive), '-C', str(root), '--', *selected], check=True)
    archive.unlink()  # Do not retain unused GPU libraries or the 1.5 GB archive.
    models = root / 'models'; models.mkdir()
    home = root / 'bootstrap-home'; home.mkdir(mode=0o700)
    environment = {'PATH': os.defpath, 'HOME': str(home), 'OLLAMA_MODELS': str(models),
        'LD_LIBRARY_PATH': str(root / 'lib/ollama'), 'OLLAMA_HOST': '127.0.0.1:11435',
        'OLLAMA_NO_CLOUD': '1', 'OLLAMA_NUM_PARALLEL': '1', 'OLLAMA_MAX_LOADED_MODELS': '1',
        'OLLAMA_MAX_QUEUE': '1', 'OLLAMA_CONTEXT_LENGTH': '2048'}
    with (root / 'bootstrap.log').open('wb') as log:
        server = subprocess.Popen([str(root / 'bin/ollama'), 'serve'], env=environment, stdout=log, stderr=log)
        try:
            for _ in range(100):
                if server.poll() is not None:
                    raise ValueError('public CPU runtime failed startup; inspect bootstrap.log')
                try:
                    with urllib.request.urlopen('http://127.0.0.1:11435/api/version', timeout=1):
                        break
                except OSError:
                    time.sleep(0.2)
            else:
                raise TimeoutError('local CPU runtime readiness timeout')
            subprocess.run([str(root / 'bin/ollama'), 'pull', MODEL], env=environment,
                           stdout=log, stderr=log, check=True, timeout=600)
            manifest = verify_model(models)
        finally:
            server.terminate()
            try:
                server.wait(timeout=20)
            except subprocess.TimeoutExpired:
                server.kill(); server.wait()
    pin = {'ollama_version': VERSION, 'archive_url': URL, 'archive_sha256': ARCHIVE_SHA256,
           'archive_bytes': ARCHIVE_SIZE, 'extracted_cpu_members': selected, 'model': MODEL,
           'manifest_sha256': MANIFEST_SHA256, 'manifest': manifest, 'every_blob_hash_verified': True,
           'cloud_inference': 'disabled', 'api_credentials_used': False, 'model_api_spend_cap': 0,
           'source_authority': 'operator_verified_public_distribution'}
    (root / 'model-pin.json').write_text(json.dumps(pin, indent=2) + '\n')
    print(json.dumps({'status': 'PASS', 'model_pin': str(root / 'model-pin.json')}))

if __name__ == '__main__':
    main()
