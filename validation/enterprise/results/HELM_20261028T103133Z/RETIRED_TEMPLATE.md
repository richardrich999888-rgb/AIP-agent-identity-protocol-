# Retired, unvalidated host-probe render

`template-enabled.yaml` is preserved byte for byte inside
`retired-template-enabled.zip`. It is historical evidence, not a deployable
manifest. The active chart now refuses Kubernetes host-probe enablement.

The original static report, commands, structural assertions and scanner findings
remain unchanged. Their PASS statuses describe the historical static checks;
they do not mean that node privileges were safe or runtime qualified. The four
HIGH findings KSV-0009, KSV-0010, KSV-0118 and KSV-0121 still apply to the archived
render. No finding was dismissed and no scanner path exclusion was added.

`retired-template-provenance.json` records both SHA-256 digests, the original
path, member, byte count and source revision. Verify and restore the original
bytes into a separate temporary directory for historical reproduction:

```sh
python3 - <<'PY'
from pathlib import Path
import hashlib, json, tempfile, zipfile
root = Path('validation/enterprise/results/HELM_20261028T103133Z')
meta = json.loads((root / 'retired-template-provenance.json').read_text())
archive = root / meta['archive']
assert hashlib.sha256(archive.read_bytes()).hexdigest() == meta['archive_sha256']
with zipfile.ZipFile(archive) as z:
    original = z.read(meta['member'])
assert len(original) == meta['original_bytes']
assert hashlib.sha256(original).hexdigest() == meta['original_sha256']
target = Path(tempfile.mkdtemp(prefix='retired-helm-evidence-')) / meta['member']
target.write_bytes(original)
print(target)
PY
```

The same original bytes remain available through Git at
`9c78d29710eccc3b6b18b1345593bd737b1c2bee:validation/enterprise/results/HELM_20261028T103133Z/template-enabled.yaml`.
Reproducing the old chart requires its original source revision from `report.json`,
not the current chart. No signed evidence verifier consumes this static manifest.
