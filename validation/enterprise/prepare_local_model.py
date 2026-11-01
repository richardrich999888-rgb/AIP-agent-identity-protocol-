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
# Reviewed choices only. The default and exported constants retain the
# existing LangGraph/loan profile; Agent Zero opts in explicitly.
DEFAULT_MODEL_PROFILE = 'llama32-1b'
MODEL_PROFILES = {
    DEFAULT_MODEL_PROFILE: {'model': MODEL, 'manifest_sha256': MANIFEST_SHA256,
        'family': 'llama3.2', 'tag': '1b', 'license': 'Llama 3.2 Community License'},
    'agent-zero-qwen25-coder-15b': {
        'model': 'qwen2.5-coder:1.5b-instruct',
        'manifest_sha256': 'd7372fd828518a4d38b1eb196c673c31a85f2ed302b3d1e406c4c2d1b64a0668',
        'family': 'qwen2.5-coder', 'tag': '1.5b-instruct', 'license': 'Apache-2.0'},
    'agent-zero-qwen3-4b-instruct-2507': {
        'model': 'qwen3:4b-instruct-2507-q4_K_M',
        'manifest_sha256': '0edcdef34593eac1aa2be9c7d06c432dcf81945adca5eca2f27662c18f168ba0',
        'family': 'qwen3', 'tag': '4b-instruct-2507-q4_K_M', 'license': 'Apache-2.0',
        'model_blob_sha256': '85e4a5b7b8ef0e48af0e8658f5aaab9c2324c76c1641493f4d1e25fce54b18b9',
        'model_blob_bytes': 2497280480},
}


def model_profile(name=DEFAULT_MODEL_PROFILE):
    try:
        return dict(MODEL_PROFILES[name])
    except (KeyError, TypeError) as error:
        raise ValueError('unknown reviewed public model profile') from error


def manifest_paths(profile):
    suffix = '/library/' + profile['family'] + '/' + profile['tag']
    return ('manifests/registry.ollama.ai' + suffix,
            'manifests-v2/ollama.com' + suffix)

URL = f'https://github.com/ollama/ollama/releases/download/v{VERSION}/ollama-linux-amd64.tar.zst'
CPU_FILE = re.compile(r'lib/ollama/(?:llama-server|lib(?:ggml(?:-(?:base|cpu[^/]*|blas))?|llama(?:-common|-server-impl)?|mtmd|gomp|omp|stdc\+\+|gcc_s)\.so(?:\.[0-9.]+)?)\Z')


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify_model(models, profile_name=DEFAULT_MODEL_PROFILE):
    profile = model_profile(profile_name)
    legacy_path, current_path = manifest_paths(profile)
    legacy = models / legacy_path
    current = models / current_path
    if current.exists() or current.is_symlink():
        # Ollama 0.40 stores the original registry document as a blob and
        # links its v2 name to it. The legacy file is a DIFFERENT downgrade
        # anchor with extra GC-reference layers, not the running manifest.
        expected_blob = models / 'blobs' / ('sha256-' + profile['manifest_sha256'])
        if current.resolve(strict=True) != expected_blob.resolve(strict=True):
            raise ValueError('v2 model name does not reference the reviewed content-addressed blob')
        manifest = current
    else:
        manifest = legacy
    if sha(manifest) != profile['manifest_sha256']:
        raise ValueError('model tag changed; reviewed manifest digest required')
    value = json.loads(manifest.read_bytes())
    if 'model_blob_sha256' in profile:
        weights = [layer for layer in value['layers']
                   if layer.get('mediaType') == 'application/vnd.ollama.image.model']
        if (len(weights) != 1 or weights[0]['digest'] != 'sha256:' + profile['model_blob_sha256']
                or weights[0]['size'] != profile['model_blob_bytes']):
            raise ValueError('model weight layer differs from the explicit reviewed asset pin')
    for layer in [value['config'], *value['layers']]:
        digest = layer['digest']
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
            raise ValueError('invalid model layer digest')
        blob = models / 'blobs' / digest.replace(':', '-')
        if blob.stat().st_size != layer['size'] or sha(blob) != digest.split(':')[1]:
            raise ValueError('model layer content/size mismatch')
    return value


def publish_runtime(root):
    """Expose verified public assets; keep bootstrap HOME and logs private."""
    root.chmod(0o755)
    for name in ('bin', 'lib', 'models'):
        tree = root / name
        tree.chmod(0o755)
        for path in tree.rglob('*'):
            if path.is_symlink():
                if not path.resolve(strict=True).is_relative_to(tree.resolve()):
                    raise ValueError('public runtime symlink escapes its asset tree')
                continue
            path.chmod(0o755 if path.is_dir() or name == 'bin' or path.name == 'llama-server' else 0o644)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--model-profile', choices=sorted(MODEL_PROFILES), default=DEFAULT_MODEL_PROFILE)
    args = p.parse_args()
    profile = model_profile(args.model_profile)
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
            subprocess.run([str(root / 'bin/ollama'), 'pull', profile['model']], env=environment,
                           stdout=log, stderr=log, check=True, timeout=600)
            layout = []
            for relative in manifest_paths(profile):
                candidate = models / relative
                if candidate.exists():
                    layout.append({'path':relative,'target':str(candidate.resolve().relative_to(models)),
                                   'sha256':sha(candidate),'bytes':candidate.stat().st_size,
                                   'public_manifest':json.loads(candidate.read_text())})
            (root / 'model-manifest-layout.json').write_text(json.dumps(layout,indent=2)+'\n')
            manifest = verify_model(models, args.model_profile)
        finally:
            server.terminate()
            try:
                server.wait(timeout=20)
            except subprocess.TimeoutExpired:
                server.kill(); server.wait()
    pin = {'ollama_version': VERSION, 'archive_url': URL, 'archive_sha256': ARCHIVE_SHA256,
           'archive_bytes': ARCHIVE_SIZE, 'extracted_cpu_members': selected, 'model': profile['model'],
           'model_profile': args.model_profile, 'model_license': profile['license'],
           'manifest_sha256': profile['manifest_sha256'], 'manifest': manifest, 'every_blob_hash_verified': True,
           'cloud_inference': 'disabled', 'api_credentials_used': False, 'model_api_spend_cap': 0,
           'source_authority': 'operator_verified_public_distribution'}
    publish_runtime(root)
    (root / 'model-pin.json').write_text(json.dumps(pin, indent=2) + '\n')
    print(json.dumps({'status': 'PASS', 'model_pin': str(root / 'model-pin.json')}))

if __name__ == '__main__':
    main()
