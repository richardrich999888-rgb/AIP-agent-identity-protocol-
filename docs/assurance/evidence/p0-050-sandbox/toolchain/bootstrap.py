import concurrent.futures
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import tomllib
import urllib.request

root = Path(__file__).parent
manifest = tomllib.loads((root / 'channel-rust-1.99.1.toml').read_text())
packages = ['rustc', 'cargo', 'rust-std', 'rustfmt-preview', 'clippy-preview']

def download(name):
    pin = manifest['pkg'][name]['target']['x86_64-unknown-linux-gnu']
    url, expected = pin['xz_url'], pin['xz_hash']
    archive = root / url.rsplit('/', 1)[-1]
    raw = urllib.request.urlopen(url, timeout=60).read()
    assert hashlib.sha256(raw).hexdigest() == expected, name
    archive.write_bytes(raw)
    print(json.dumps({'package': name, 'sha256': expected, 'bytes': len(raw)}), flush=True)
    return name, archive, url, expected

with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
    downloads = list(pool.map(download, packages))
records = []
for name, archive, url, expected in downloads:
    with tarfile.open(archive) as tar:
        directory = tar.getmembers()[0].name.split('/')[0]
        tar.extractall(root / 'unpacked', filter='data')
    source = root / 'unpacked' / directory
    subprocess.run(['bash', str(source / 'install.sh'), '--prefix=' + str(root / 'rust'),
                    '--disable-ldconfig'], check=True, stdout=subprocess.DEVNULL)
    records.append({'package': name, 'version': manifest['pkg'][name]['version'],
                    'url': url, 'sha256': expected,
                    'licences': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                 for p in source.glob('LICENSE*') if p.is_file()}})
(root / 'toolchain-provenance.json').write_text(json.dumps(records, indent=2) + '\n')
print(subprocess.check_output([str(root / 'rust/bin/rustc'), '--version'], text=True), flush=True)
