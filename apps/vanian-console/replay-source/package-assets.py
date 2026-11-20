"""Stage public research assets from the exact upstream checkout and freshly built WASM binaries."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import subprocess
import zipfile
import gzip

PIN = 'd8ea36255d311b10b9b5b6e844336058622d45c6'
SAME_RUN_DIGEST = 'bc5c9882c37fcd4039bb4f3db082329fffbc74a6624125dccd7660766d678c0a'
NATIVE_DIGEST = 'f6859f1235aa10755df8949ceb6b4d055d9d452512a15194f1a7026497d21996'
root = Path(__file__).resolve().parent.parent
cli = argparse.ArgumentParser(description=__doc__)
cli.add_argument('checkout', type=Path)
cli.add_argument('wasm_directory', type=Path)
cli.add_argument('--public-directory', type=Path, default=root/'public'/'upstream-replay')
args = cli.parse_args()
head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=args.checkout, text=True).strip()
dirty = subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=args.checkout, text=True)
if head != PIN or dirty:
    raise SystemExit('Use a clean source checkout at the pinned revision.')
base = args.checkout/'validation/p0_057/iteration-002/hosted'
out = args.public_directory
fixtures = out/'fixtures'
fixtures.mkdir(exist_ok=True, parents=True)
for path, expected in [(base/'native-original.zip', NATIVE_DIGEST), (base/'same-run-failure-original.zip', SAME_RUN_DIGEST)]:
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise SystemExit('Upstream archive fingerprint differs from the accepted release.')
assets = []
for name in ['aip-execution-assurance', 'aip-observe-verify']:
    p = out/(name+'.wasm')
    shutil.copyfile(args.wasm_directory/(name+'.wasm'), p)
    assets.append(p)
for name in ['t09','t15']:
    source=base/'native/p0-native-evidence/originals'/name
    for kind in ['batches','health']:
        p=fixtures/(name+'-'+kind+'.jsonl')
        shutil.copyfile(source/(kind+'.jsonl'), p)
        assets.append(p)
    anchor=json.loads((source/'scope-and-anchor.json').read_text())
    p=fixtures/(name+'-trust.json')
    p.write_text(json.dumps({'observerId':anchor['observer_id'],'keyVersion':anchor['key_version'],'publicKey':bytes(anchor['public_key']).hex()},indent=2)+'\n')
    assets.append(p)
with zipfile.ZipFile(base/'same-run-failure-original.zip') as archive:
    for name in ['same-run','same-run-interruption']:
        p=fixtures/(name+'-bundle.json.gz')
        p.write_bytes(gzip.compress(archive.read(name+'/public/run-bundle.json'),compresslevel=9,mtime=0))
        assets.append(p)
        p=fixtures/(name+'-trust.json')
        p.write_bytes(archive.read(name+'/run-trust.json'))
        assets.append(p)
pins = {str(path.relative_to(out)):hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(assets)}
(Path(__file__).parent/'digests.mjs').write_text('export const pins='+json.dumps(pins,indent=2)+';\n')
