#!/usr/bin/env python3
"""Replay retained genuine trials without private keys; never upgrade CannotProve."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import zipfile

ROOT = Path(__file__).resolve().parents[2]
ARCHIVE = ROOT / 'validation/p0_057/iteration-002/hosted/same-run-failure-original.zip'
DIGEST = 'bc5c9882c37fcd4039bb4f3db082329fffbc74a6624125dccd7660766d678c0a'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verifier', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    binary = args.verifier.resolve()
    if hashlib.sha256(ARCHIVE.read_bytes()).hexdigest() != DIGEST:
        raise ValueError('original hosted artifact digest mismatch')
    args.out.mkdir(parents=True, exist_ok=False)
    summary = {'artifact_sha256': DIGEST, 'verifier_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
               'scope': 'Separate local verifier process, same reviewer administration; no private keys. Original recovery failure remains unresolved.',
               'cases': []}
    with zipfile.ZipFile(ARCHIVE) as archive, tempfile.TemporaryDirectory() as temporary:
        for scene, reason in [('same-run', 'ActionEvidenceUnavailable'), ('same-run-interruption', 'WindowNotCovered')]:
            bundle = json.loads(archive.read(scene + '/public/run-bundle.json'))
            trust = json.loads(archive.read(scene + '/run-trust.json'))
            expected = json.loads(archive.read(scene + '/public/evaluation.json'))
            for case in ('original', 'missing-receipt', 'wrong-gateway-anchor'):
                request, anchor = copy.deepcopy(bundle), copy.deepcopy(trust)
                if case == 'missing-receipt':
                    request['signed_receipt'] = None
                if case == 'wrong-gateway-anchor':
                    anchor['gateway_public_key_hex'] = '00' * 32
                trust_file = Path(temporary) / 'public-trust.json'
                trust_file.write_text(json.dumps(anchor))
                payload = json.dumps(request).encode()
                started = time.monotonic()
                result = subprocess.run([str(binary), 'evaluate'], input=payload,
                    env={'PATH': os.defpath, 'AIP_RUN_TRUST_FILE': str(trust_file)},
                    capture_output=True, timeout=60)
                prefix = args.out / (scene + '-' + case)
                prefix.with_suffix('.stdout.json').write_bytes(result.stdout)
                prefix.with_suffix('.stderr.txt').write_bytes(result.stderr)
                value = json.loads(result.stdout) if result.returncode == 0 else None
                if case == 'original':
                    passed = (result.returncode == 0 and value == expected
                        and value['reconciliation']['result'] == 'CannotProve'
                        and value['reconciliation']['reason'] == reason
                        and value['signed_reconciliation_verified'] is True)
                else:
                    # Refusal can be returned as an error or a verified negative
                    # evaluation, but must not accept an unverified receipt.
                    passed = result.returncode != 0 or (
                        value['gateway_receipt_verified'] is False
                        and value['reconciliation']['result'] == 'CannotProve')
                summary['cases'].append({'scene': scene, 'case': case, 'exit_code': result.returncode,
                    'elapsed_seconds': time.monotonic() - started, 'status': 'PASS' if passed else 'FAIL',
                    'input_sha256': hashlib.sha256(payload).hexdigest(),
                    'public_trust_sha256': hashlib.sha256(trust_file.read_bytes()).hexdigest(),
                    'mutation': case if case != 'original' else None})
    summary['status'] = 'PASS' if all(c['status'] == 'PASS' for c in summary['cases']) else 'FAIL'
    (args.out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({'status': summary['status'], 'checks': len(summary['cases'])}))
    return 0 if summary['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
