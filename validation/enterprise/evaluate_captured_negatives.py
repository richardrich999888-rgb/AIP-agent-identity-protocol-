#!/usr/bin/env python3
"""Negative verification of original captured same-run records; no new execution claims."""
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--trust', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    bundle = json.loads(args.bundle.read_text())
    if not bundle.get('expectation') or not bundle.get('signed_receipt') or not bundle.get('signed_reconciliation'):
        raise ValueError('requires actual signed authorization, receipt and reconciliation')
    environment = {'PATH':os.environ.get('PATH', os.defpath), 'AIP_RUN_TRUST_FILE':str(args.trust.resolve())}
    checks = {}

    def evaluate(name, value, reject=False):
        process = subprocess.run([str(args.binary.resolve()), 'evaluate'], input=json.dumps(value),
            text=True, capture_output=True, timeout=30, env=environment)
        if reject:
            assert process.returncode == 1, (name, process.returncode)
            checks[name] = {'status':'PASS', 'rejected':True, 'exit_code':process.returncode}
            return None
        assert process.returncode == 0, (name, process.returncode, process.stderr)
        return json.loads(process.stdout)

    original = evaluate('original', bundle)
    assert original['authorization_verified'] and original['gateway_receipt_verified']
    assert original['signed_reconciliation_verified']
    checks['original'] = {'status':'PASS', 'source':'unaltered captured records'}
    missing_auth = copy.deepcopy(bundle)
    missing_auth['expectation'] = None
    missing_auth['signed_reconciliation'] = None
    result = evaluate('missing_authorization', missing_auth)
    assert result['authorization_verified'] is False and result['reconciliation'] is None
    assert any('CANNOT_PROVE' in line for line in result['limitations'])
    checks['missing_authorization'] = {'status':'PASS', 'verdict':'CANNOT_PROVE',
        'expected_side_completeness':'UNKNOWN', 'unauthorized_execution_claimed':False}
    missing_receipt = copy.deepcopy(bundle)
    missing_receipt['signed_receipt'] = None
    result = evaluate('missing_gateway_receipt', missing_receipt)
    assert result['gateway_receipt_verified'] is False
    assert 'NoReceipt' in json.dumps(result['tool_boundary'])
    assert result['reconciliation'] == original['reconciliation']
    checks['missing_gateway_receipt'] = {'status':'PASS', 'tool_boundary':'NotEvaluated/NoReceipt',
        'kernel_finding_not_upgraded':True}
    for name, path in [('authorization_signature',('expectation','decision_sig')),
                       ('gateway_signature',('signed_receipt','attestation')),
                       ('reconciler_signature',('signed_reconciliation','attestation'))]:
        altered = copy.deepcopy(bundle)
        signature = altered[path[0]][path[1]]['signature_bytes']
        signature[0] ^= 1
        evaluate(name, altered, reject=True)
    injected = copy.deepcopy(bundle)
    injected['trust'] = json.loads(args.trust.read_text())
    evaluate('caller_supplied_trust_rejected', injected, reject=True)
    for edge in ('prefix','suffix'):
        altered = copy.deepcopy(bundle)
        lines = altered['batches_jsonl'].splitlines(keepends=True)
        if len(lines) < 3:
            raise ValueError('actual archive too short for truncation test')
        altered['batches_jsonl'] = ''.join(lines[1:] if edge == 'prefix' else lines[:-1])
        evaluate(edge+'_truncation_checkpoint', altered, reject=True)
    report = {'classification':'CONTROLLED_NEGATIVE_VERIFICATION_OF_CAPTURED_RECORDS',
        'source_bundle':args.bundle.name, 'run_id':bundle['run_id'], 'status':'PASS', 'checks':checks,
        'no_additional_agent_execution_claimed':True,
        'live_observer_interruption':'NOT_EXERCISED_BY_THIS_OFFLINE_CHECK',
        'wrong_instance_trust_prerequisites':'separate typed reconciler regression; no fabricated kernel claims'}
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':'PASS','checks':len(checks),'classification':report['classification']}))


if __name__ == '__main__':
    main()
