"""Derived offline replay of exact public originals; never writes originals."""
import hashlib
import json
import os
import platform
from pathlib import Path
import shutil
import subprocess
import time
import zipfile

REPO=Path('/Users/richardrich/.codex/worktrees/snifferdog-complete-enterprise-validation/AIP')
ROOT=Path('/private/tmp/snifferdog-gov-3e6c179-41432473155/original')
ZIP=Path('/private/tmp/snifferdog-gov-3e6c179-41432473155/original-artifact.zip')
OUT=Path('/private/tmp/snifferdog-gov-3e6c179-41432473155/independent-offline')
OUT.mkdir(exist_ok=False)
BIN=REPO/'target/debug'
def sha(p):
    with Path(p).open('rb') as f:
        return hashlib.file_digest(f,'sha256').hexdigest()
def save(p,x):
    p.write_text(json.dumps(x,indent=2)+'\n')
command_receipts=[]
def run(args,request=None,env=None):
    started=time.monotonic()
    r=subprocess.run([str(a) for a in args], input=json.dumps(request) if request is not None else None,
                     text=True,capture_output=True,timeout=120,env=env or {'PATH':os.defpath})
    index=len(command_receipts)+1
    (OUT/f'command-{index:02d}.stdout.json').write_text(r.stdout)
    (OUT/f'command-{index:02d}.stderr.txt').write_text(r.stderr)
    command_receipts.append({'arguments':[str(a) for a in args],'environment_keys':sorted((env or {'PATH':os.defpath}).keys()),'exit_code':r.returncode,'seconds':time.monotonic()-started,'stdin_sha256':hashlib.sha256(json.dumps(request).encode()).hexdigest() if request is not None else None,'stdout_sha256':hashlib.sha256(r.stdout.encode()).hexdigest(),'stderr_sha256':hashlib.sha256(r.stderr.encode()).hexdigest()})
    save(OUT/'command-receipts.json',command_receipts)
    if r.returncode:
        raise RuntimeError({'returncode':r.returncode,'stderr':r.stderr,'command':str(args[0])})
    return json.loads(r.stdout)
inventory=[]
with zipfile.ZipFile(ZIP) as z:
    for name in z.namelist():
        if name.endswith('/'):
            continue
        raw=z.read(name)
        assert raw==(ROOT/name).read_bytes()
        inventory.append({'path':name,'size_bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
save(OUT/'original-zip-inventory.json',inventory)
summary={'classification':'DERIVED_INDEPENDENT_OFFLINE_VERIFICATION_OF_ORIGINAL_GITHUB_ZIP',
 'source_run_id':41432473155,'source_commit':'3e6c1794000fa23006ef623722e37700e49582b7',
 'artifact_id':13136100222,'artifact_zip_sha256':sha(ZIP),'original_file_count':len(inventory),
 'workflow_conclusion':'success','platform':platform.platform(),
 'environment':'PATH only; evaluator additionally receives separately supplied AIP_RUN_TRUST_FILE.',
 'additional_agent_or_model_execution':False,
 'binaries_sha256':{n:sha(BIN/n) for n in ('aip-observe-verify','aip-execution-assurance','aip-tool-receipt')},
 'profiles':{}}
for name in ('same-run','same-run-interruption','same-run-recovery'):
    src=ROOT/name
    public=src/'public'
    dst=OUT/name
    dst.mkdir()
    trustdir=dst/'separately-supplied-public-trust'
    trustdir.mkdir()
    for n in ('run-trust.json','observer-anchor.json','checkpoint.json'):
        shutil.copyfile(src/n,trustdir/n)
    anchor=json.loads((trustdir/'observer-anchor.json').read_text())
    cp=json.loads((trustdir/'checkpoint.json').read_text())
    trust=json.loads((trustdir/'run-trust.json').read_text())
    manifest=json.loads((public/'run-manifest.json').read_text())
    archive=run([BIN/'aip-observe-verify','--observer-id',anchor['observer_id'],
        '--key-version',anchor['key_version'],'--pubkey',anchor['public_key'],
        '--batches',public/'attested.archive.jsonl','--health',public/'health.archive.jsonl','--json'])
    save(dst/'independent-archive-verification.json',archive)
    cp_ok=all(sha(public/n)==h for n,h in cp['sha256'].items())
    assert cp_ok and not archive['findings']
    profile={'manifest_status':manifest['status'],'archive_verification':'PASS',
      'run_id':manifest['run_id'],'actual_model_calls':manifest['model_calls'],
      'signed_batches':archive['batches']['records'],'kernel_events':archive['batches']['kernel_events'],
      'health_records':archive['health']['records'],'checkpoint_bytes_match':cp_ok,
      'archive_findings':archive['findings'],'cleanup_errors':manifest['cleanup_errors']}
    receipts=[json.loads(s) for s in (public/'receipts.jsonl').read_text().splitlines()]
    env={'PATH':os.defpath,'AIP_GATEWAY_ID':trust['gateway_id'],
      'AIP_GATEWAY_PUBLIC_KEY':trust['gateway_public_key_hex'],
      'AIP_GATEWAY_KEY_VERSION':str(trust['gateway_key_version'])}
    verified_receipts=[run([BIN/'aip-tool-receipt','verify'],r,env) for r in receipts]
    save(dst/'independent-receipt-verification.json',verified_receipts)
    profile['verified_gateway_receipt_dispositions']=[r['receipt']['disposition'] for r in verified_receipts]
    if (public/'run-bundle.json').exists():
        bundle=json.loads((public/'run-bundle.json').read_text())
        original=json.loads((public/'evaluation.json').read_text())
        evaluation=run([BIN/'aip-execution-assurance','evaluate'],bundle,
            {'PATH':os.defpath,'AIP_RUN_TRUST_FILE':str(trustdir/'run-trust.json')})
        save(dst/'independent-run-evaluation.json',evaluation)
        assert evaluation==original
        assert all(evaluation[k] for k in ('archive_integrity_verified','authorization_verified',
             'checkpoint_verified','gateway_receipt_verified','signed_reconciliation_verified'))
        profile.update(bundle_sha256=sha(public/'run-bundle.json'),
          independent_evaluation_matches_original=True,kernel_identity=evaluation['reconciliation']['identity'],
          kernel_result=evaluation['reconciliation']['result'],kernel_reason=evaluation['reconciliation']['reason'],
          kernel_availability=evaluation['reconciliation']['availability'],
          original_forwarded_tool_boundary=evaluation['tool_boundary'])
        refused=json.loads((public/'parameter-mismatch-receipt.json').read_text())
        changed={**bundle,'signed_receipt':refused}
        negative=run([BIN/'aip-execution-assurance','evaluate'],changed,
            {'PATH':os.defpath,'AIP_RUN_TRUST_FILE':str(trustdir/'run-trust.json')})
        save(dst/'derived-refused-receipt-evaluation.json',negative)
        assert negative['gateway_receipt_verified'] and 'Diverges' in negative['tool_boundary']
        profile['derived_actual_refused_tool_boundary']=negative['tool_boundary']
    else:
        profile.update(bundle_verification='UNAVAILABLE_NO_ORIGINAL_BUNDLE',failure=manifest.get('failure'),
          limitation='Successful raw tool result is retained but original Forwarded receipt is absent. No receipt or signed reconciliation was reconstructed.')
    summary['profiles'][name]=profile
save(OUT/'summary.json',summary)
print(json.dumps({'derived_directory':str(OUT),'summary':summary},indent=2))
