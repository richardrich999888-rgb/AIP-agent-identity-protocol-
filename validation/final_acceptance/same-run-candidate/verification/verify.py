#!/usr/bin/env python3
"""Independently verify original public captures; write only derived results."""
import argparse
from contextlib import contextmanager
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[4]
OUTPUT = Path(__file__).resolve().parent
DEFAULT_CAPTURE_ROOT = OUTPUT.parent / 'originals'
SOURCE = '42d0d96c9cc9d3075c792a195cc74e4171b0e817'
ARCHIVES = ('attested.archive.jsonl', 'health.archive.jsonl')
MECHANISMS = {'SchedTracepoint', 'Fanotify', 'SockSendTracepoint'}
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_CAPTURE_BYTES = 512 * 1024 * 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    return json.loads(path.read_text())


def lines(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def write(name, value):
    (OUTPUT / name).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def safe_relative(value):
    if not isinstance(value, str) or not value or '\\' in value:
        raise ValueError('invalid retained relative path')
    path = PurePosixPath(value)
    if path.is_absolute() or '..' in path.parts or path.as_posix() != value or value == '.':
        raise ValueError('retained paths must be canonical relative paths without traversal')
    return path


def materialize_retained(capture_root, destination):
    """Validate every declared original byte, without modifying retained files."""
    manifest_path = capture_root / 'files.json'
    entries = read(manifest_path)
    if not isinstance(entries, list) or not entries:
        raise ValueError('retained files manifest must be a nonempty list')
    original_names, retained_names = set(), set()
    declared_total = 0
    gzip_count = 0
    for entry in entries:
        original = safe_relative(entry['original'])
        retained = safe_relative(entry['retained'])
        if original in original_names or retained in retained_names:
            raise ValueError('duplicate retained or original path')
        original_names.add(original)
        retained_names.add(retained)
        expected_size = entry['bytes']
        if type(expected_size) is not int or not 0 <= expected_size <= MAX_FILE_BYTES:
            raise ValueError('invalid or excessive original size')
        declared_total += expected_size
        if declared_total > MAX_CAPTURE_BYTES:
            raise ValueError('retained capture exceeds materialization limit')
        expected_hash = entry['sha256']
        if (not isinstance(expected_hash, str) or len(expected_hash) != 64
                or any(character not in '0123456789abcdef' for character in expected_hash)):
            raise ValueError('invalid original SHA256')
        source = capture_root.joinpath(*retained.parts)
        if source.is_symlink() or not source.is_file():
            raise ValueError('retained source must be a regular file')
        source.resolve(strict=True).relative_to(capture_root.resolve(strict=True))
        compression = entry['compression']
        if compression not in ('none', 'gzip-mtime-zero'):
            raise ValueError('unsupported retained compression')
        if compression == 'gzip-mtime-zero':
            gzip_count += 1
            with source.open('rb') as raw:
                header = raw.read(10)
            if len(header) != 10 or header[:3] != b'\x1f\x8b\x08' or header[4:8] != b'\x00' * 4:
                raise ValueError('retained gzip header is not the declared deterministic format')
        target = destination.joinpath(*original.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        actual_hash = hashlib.sha256()
        count = 0
        opener = gzip.open if compression == 'gzip-mtime-zero' else open
        with opener(source, 'rb') as incoming, target.open('xb') as outgoing:
            while True:
                chunk = incoming.read(min(65536, expected_size - count + 1))
                if not chunk:
                    break
                count += len(chunk)
                if count > expected_size:
                    raise ValueError('retained file exceeds declared original size')
                actual_hash.update(chunk)
                outgoing.write(chunk)
        if count != expected_size or actual_hash.hexdigest() != expected_hash:
            raise ValueError('retained file does not match original byte count and SHA256')
    return {'kind': 'MANIFEST_VALIDATED_TEMPORARY_MATERIALIZATION',
            'files_manifest_sha256': digest(manifest_path.read_bytes()),
            'validated_original_files': len(entries), 'gzip_original_files': gzip_count,
            'validated_original_bytes': declared_total,
            'source': 'tracked originals/files.json (default)' if capture_root == DEFAULT_CAPTURE_ROOT
                      else 'explicit --capture-root manifest',
            'originals_modified': False}


@contextmanager
def prepared_capture(capture_root, explicit_override=False):
    if (capture_root / 'files.json').is_file():
        with tempfile.TemporaryDirectory(prefix='aip-same-run-verification-') as temporary:
            destination = Path(temporary)
            metadata = materialize_retained(capture_root, destination)
            yield destination, metadata
    elif explicit_override:
        yield capture_root, {'kind': 'EXPLICIT_UNCOMPRESSED_CAPTURE_ROOT',
                             'files_manifest_sha256': None, 'originals_modified': False,
                             'source': 'explicit --capture-root; parent checkpoint and trust validation still required'}
    else:
        raise ValueError('tracked originals/files.json is required for default reproduction')


def covered(health, start, end):
    if any(start <= h['emitted_at_ms'] <= end and h['state'] != 'Active' for h in health):
        return False
    for h in health:
        window, clock = h.get('attested_coverage'), h.get('clock')
        if (h['state'] == 'Active' and h['continuity'] == 'Verified' and window
                and window['from_ms'] <= start and window['to_ms'] >= end
                and MECHANISMS <= set(h['covered_by']) and clock
                and clock['synchronized'] and 0 <= clock['max_error_us'] <= 1_000_000):
            return True
    return False


def verify_capture(input_root, input_metadata):
    results, commands = {}, []
    verifier = ROOT / 'target/debug/aip-observe-verify'
    evaluator = ROOT / 'target/debug/aip-execution-assurance'
    if not verifier.is_file() or not evaluator.is_file():
        raise RuntimeError('build native verification tools first: cargo build --locked -p aip-observe-verify '
                           '-p aip-mcp-gateway --bin aip-observe-verify --bin aip-execution-assurance')
    for profile in ('same-run', 'same-run-interruption', 'same-run-recovery'):
        parent = input_root / profile
        public = parent / 'public'
        anchor, checkpoint, trust = [read(parent / name) for name in
                                       ('observer-anchor.json', 'checkpoint.json', 'run-trust.json')]
        manifest, bundle = read(public / 'run-manifest.json'), read(public / 'run-bundle.json')
        assert manifest['source_commit'] == SOURCE
        assert manifest['status'] == 'PASS' and manifest['cleanup_errors'] == []
        assert manifest['autonomous_workload_executed'] and manifest['model_calls'] == 2
        assert 'trust' not in bundle, 'caller-provided trust is not an independent anchor'
        hashes = {name: digest((public / name).read_bytes()) for name in ARCHIVES}
        assert hashes == checkpoint['sha256']
        assert trust['checkpoints'][bundle['run_id']] == {
            'batches_sha256': hashes[ARCHIVES[0]], 'health_sha256': hashes[ARCHIVES[1]]}
        assert trust['observer_id'] == anchor['observer_id']
        assert trust['observer_key_version'] == anchor['key_version']
        assert trust['observer_public_key_hex'] == anchor['public_key']

        command = [str(verifier), '--observer-id', anchor['observer_id'], '--key-version',
                   str(anchor['key_version']), '--pubkey', anchor['public_key'],
                   '--batches', str(public / ARCHIVES[0]), '--health', str(public / ARCHIVES[1]), '--json']
        process = subprocess.run(command, capture_output=True, text=True, check=False)
        assert process.returncode == 0, (profile, 'native archive verifier', process.returncode)
        verification = json.loads(process.stdout)
        assert not verification['findings']
        assert verification['batches']['records'] and verification['health']['records']
        write(profile + '-archive-verification.json', verification)
        commands.append({'profile': profile, 'input_preparation': input_metadata['kind'], 'command':
            'target/debug/aip-observe-verify --observer-id <parent anchor observer_id> '
            '--key-version <parent anchor key_version> --pubkey <parent anchor public_key> '
            '--batches <profile>/public/attested.archive.jsonl '
            '--health <profile>/public/health.archive.jsonl --json', 'exit_code': process.returncode})

        process = subprocess.run([str(evaluator), 'evaluate'], input=(public / 'run-bundle.json').read_bytes(),
            capture_output=True, env={'PATH': os.defpath, 'AIP_RUN_TRUST_FILE': str(parent / 'run-trust.json')})
        assert process.returncode == 0, (profile, 'native bundle evaluator', process.returncode)
        evaluation = json.loads(process.stdout)
        assert evaluation == read(public / 'evaluation.json'), 'local evaluation differs from retained evaluation'
        assert evaluation['authorization_verified'] and evaluation['gateway_receipt_verified']
        assert evaluation['signed_reconciliation_verified']
        assert evaluation['receipt_within_authorization'] is True
        assert evaluation['gateway_disposition'] == 'Forwarded' and 'Agrees' in evaluation['tool_boundary']
        finding = evaluation['reconciliation']
        selected = {key: evaluation.get(key) for key in (
            'authorization_verified', 'gateway_receipt_verified', 'signed_reconciliation_verified',
            'receipt_within_authorization', 'gateway_disposition', 'tool_boundary')}
        selected['reconciliation'] = {key: finding.get(key) for key in
            ('result', 'reason', 'availability', 'identity', 'temporal', 'action', 'lineage', 'wire')}
        write(profile + '-evaluation-summary.json', selected)
        commands.append({'profile': profile, 'input_preparation': input_metadata['kind'], 'command':
            'AIP_RUN_TRUST_FILE=<separately retained profile parent>/run-trust.json '
            'target/debug/aip-execution-assurance evaluate < <profile>/public/run-bundle.json',
            'exit_code': process.returncode, 'matches_original_evaluation': True})

        health = [record['health'] for record in lines(public / ARCHIVES[1])]
        batches = lines(public / ARCHIVES[0])
        task_covered = covered(health, manifest['from_ms'], manifest['to_ms'])
        assert health[-1]['sequence'] == batches[-1]['sequence']
        assert health[-1]['head'] == batches[-1]['attestation']['payload_hash']
        instances = read(public / 'kernel-bound-instances.json')['instances']
        expectation = read(public / 'expectation.json')
        reconstructed = {}
        target_pids = {manifest['agent_pid'], manifest['tool_child_pid']}
        for signed in batches:
            batch = signed['batch']
            for event in batch['kernel_events']:
                bound, clock = event.get('bound'), batch.get('clock_anchor')
                if not bound or not clock or bound['process']['pid'] not in target_pids:
                    continue
                delta = event['kernel_timestamp_ns'] - clock['monotonic_ns']
                millis = (abs(delta) // 1_000_000) * (-1 if delta < 0 else 1)
                when = clock['realtime_ms'] + millis
                if not manifest['from_ms'] <= when <= manifest['to_ms']:
                    continue
                if bound['process']['pid'] == manifest['agent_pid'] and when < expectation['execution_binding']['bound_at_ms']:
                    continue
                reconstructed[str(bound['process']['pid'])] = bound
        assert reconstructed == instances, 'retained process summary differs from original signed events'
        if profile == 'same-run-interruption':
            assert not task_covered and not instances
            assert finding['reason'] == 'WindowNotCovered' and finding['identity'] == 'NoReference'
            assert finding['temporal'] == 'Indeterminate'
            interruption = read(public / 'observer-interruption.json')
            assert interruption['status'] == 'PASS' and interruption['coverage_backfilled'] is False
            assert health[-1]['attested_coverage']['to_ms'] < manifest['from_ms']
            assert interruption['frozen_batches_sha256'] == hashes[ARCHIVES[0]]
        else:
            assert task_covered
            assert set(instances) == {str(manifest['agent_pid']), str(manifest['tool_child_pid'])}
            expected = expectation['execution_binding']
            agent = instances[str(manifest['agent_pid'])]
            assert agent['process'] == expected['process']
            assert agent['exe_content_sha256'] == expected['exe_content_sha256']
            assert finding['reason'] == 'ActionEvidenceUnavailable'
            assert finding['temporal'] == 'WithinWindow' and finding['identity'] == {'Match': {'observations': 7}}
        assert finding['result'] == 'CannotProve'
        results[profile] = {
            'status': 'PASS', 'task_window': {'from_ms': manifest['from_ms'], 'to_ms': manifest['to_ms']},
            'task_has_single_signed_active_coverage': task_covered,
            'final_signed_health': {key: health[-1].get(key) for key in
                ('state', 'continuity', 'emitted_at_ms', 'attested_coverage', 'covered_by', 'clock', 'sequence')},
            'archive_records': {'batches': len(batches), 'health': len(health)},
            'kernel_events': sum(len(row['batch']['kernel_events']) for row in batches),
            'kernel_bound_instance_count': len(instances), 'model_calls': manifest['model_calls'],
            'cleanup_errors': manifest['cleanup_errors'],
            'authorization_window': {'issued_at': expectation['issued_at'], 'valid_until': expectation['valid_until']},
            'reconciliation': selected['reconciliation'],
            'source_hashes': {name: digest((parent / name).read_bytes()) for name in
                              ('observer-anchor.json', 'checkpoint.json', 'run-trust.json')},
            'public_input_sha256': {name: digest((public / name).read_bytes()) for name in
                (*ARCHIVES, 'run-manifest.json', 'run-bundle.json', 'evaluation.json', 'expectation.json', 'kernel-bound-instances.json')},
        }
    write('commands.json', commands)
    source_paths = [
        '.github/workflows/same-run-validation.yml', 'validation/enterprise/same_run_validation.py',
        'aip-standalone/aip-observe-verify/src/main.rs', 'aip-standalone/aip-observe-verify/src/lib.rs',
        'aip-standalone/aip-observe-verify/src/cli.rs', 'aip-standalone/aip-mcp-gateway/src/assurance.rs',
        'aip-standalone/aip-mcp-gateway/src/bin/aip-execution-assurance.rs',
        'aip-standalone/aip-reconcile/src/reconcile.rs', 'aip-standalone/aip-observe/src/probe.rs',
        'aip-standalone/aip-probe/src/sensors.rs', 'aip-standalone/aip-probe/src/main.rs',
        'aip-standalone/aip-collector/src/sink.rs']
    write('verification-results.json', {
        'status': 'PASS', 'workflow_run_id': 40850559136, 'capture_source_commit': SOURCE,
        'capture_source_sha256': {path: digest(subprocess.check_output(['git', 'show', SOURCE + ':' + path], cwd=ROOT))
                                  for path in source_paths},
        'verification_script_sha256': digest(Path(__file__).read_bytes()),
        'verification_input': input_metadata,
        'verification_host': {'system': platform.system(), 'machine': platform.machine()},
        'profiles': results, 'native_binary_sha256': {
            verifier.name: digest(verifier.read_bytes()), evaluator.name: digest(evaluator.read_bytes())},
        'limits': ['Offline verification uses native local binaries identified by SHA256; host platform is recorded separately.',
            'Separately retained parent public anchors/checkpoints/trust were used; original archives were not rewritten.',
            'Checksums identify bytes; they do not authenticate the artifact download origin by themselves.',
            'Positive captures verify identity and time coverage, but retain CannotProve/ActionEvidenceUnavailable.',
            'Interruption capture retains CannotProve/WindowNotCovered and is not backfilled by fresh recovery.',
            'Local isolation shares kernel/root; separate administrative custody and logical tool-to-kernel causality are not established.']})
    print(json.dumps({profile: {'status': row['status'], 'coverage': row['task_has_single_signed_active_coverage'],
        'batches': row['archive_records']['batches'], 'kernel_events': row['kernel_events'],
        'reason': row['reconciliation']['reason']} for profile, row in results.items()}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture-root', type=Path,
        help='optional retained-manifest or uncompressed capture root; default is tracked sibling originals/')
    args = parser.parse_args()
    capture_root = args.capture_root.resolve() if args.capture_root else DEFAULT_CAPTURE_ROOT
    with prepared_capture(capture_root, explicit_override=args.capture_root is not None) as (root, metadata):
        verify_capture(root, metadata)


if __name__ == '__main__':
    main()
