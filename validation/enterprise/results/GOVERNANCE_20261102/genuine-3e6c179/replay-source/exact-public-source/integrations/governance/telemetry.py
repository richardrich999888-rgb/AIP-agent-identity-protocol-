"""Isolated actual SDK/Collector round trip for controller metadata only.

This module is stdlib-only. Telemetry never supplies kernel observations,
cryptographic verification, authorization, independent custody or production
approval. Remote endpoints and credentials are outside this local profile.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.request import urlopen

HERE = Path(__file__).resolve().parent
SOURCE = 'ROOT_CONTROLLER_APPLICATION_TELEMETRY'
MODE = 'DELAYED_BATCH_AFTER_WORKLOAD_CLEANUP'
PHASES = frozenset(('aip.governance.policy', 'aip.authorization.issue', 'aip.agent.execution',
    'aip.evidence.verify', 'aip.enterprise.clients', 'aip.run'))
ATTRIBUTES = frozenset(('aip.run_id', 'aip.source_authority', 'aip.policy.allowed',
    'aip.policy.sha256', 'aip.policy.engine.sha256', 'aip.authorization.decision_id',
    'aip.authorization.expectation_sha256', 'aip.evidence.bundle_sha256',
    'aip.evidence.signed_reconciliation_sha256', 'aip.kernel.coverage_status',
    'aip.controller.status', 'aip.error.type'))
COVERAGE = frozenset(('SIGNED_ACTIVE_FOR_WINDOW', 'UNAVAILABLE_OBSERVER_INTERRUPTED', 'NOT_ESTABLISHED'))
MAX_RECORDS = 64
MAX_JSON_BYTES = 1024 * 1024
MAX_COLLECTOR_BYTES = 8 * 1024 * 1024


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read_regular_bytes(path, limit=MAX_JSON_BYTES):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        raise ValueError('requires a bounded regular telemetry file')
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(descriptor, 'rb') as stream:
        actual = os.fstat(stream.fileno())
        if (actual.st_dev, actual.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError('telemetry file changed before reading')
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('telemetry input exceeds its bound')
    return raw


def strict_json(raw):
    # Preserve the original bytes only after checking every object field.
    # Default last-key-wins parsing would hide unapproved duplicate content.
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate telemetry JSON object key')
            result[key] = value
        return result
    def reject_constant(_value):
        raise ValueError('non-finite telemetry JSON number')
    return json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)


def read_json(path, limit=MAX_JSON_BYTES):
    return strict_json(read_regular_bytes(path, limit))


def save(path, value):
    raw = json.dumps(value, indent=2, allow_nan=False).encode() + b'\n'
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError('telemetry metadata exceeds its bound')
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def validate_records(records):
    if type(records) is not list or not 1 <= len(records) <= MAX_RECORDS:
        raise ValueError('invalid controller telemetry record count')
    result = []
    for record in records:
        if type(record) is not dict or set(record) != {'phase', 'start_time_unix_nano', 'end_time_unix_nano', 'attributes'}:
            raise ValueError('unreviewed controller telemetry record fields')
        phase, start, end, attributes = (record[k] for k in ('phase', 'start_time_unix_nano', 'end_time_unix_nano', 'attributes'))
        if type(phase) is not str or phase not in PHASES or type(start) is not int or type(end) is not int or not 0 < start <= end < 2**63:
            raise ValueError('invalid controller phase or chronology')
        if end > time.time_ns():
            raise ValueError('controller telemetry cannot describe future operations')
        if type(attributes) is not dict or set(attributes) - ATTRIBUTES or not {'aip.run_id', 'aip.source_authority'} <= set(attributes):
            raise ValueError('unreviewed controller telemetry attributes')
        values = {}
        for key, value in attributes.items():
            valid = False
            if key == 'aip.source_authority': valid = type(value) is str and value == SOURCE
            elif key == 'aip.run_id': valid = type(value) is str and re.fullmatch(r'same-run-[0-9a-f]{24}', value) is not None
            elif key == 'aip.authorization.decision_id': valid = type(value) is str and re.fullmatch(r'[0-9a-f]{32}', value) is not None
            elif key.endswith('.sha256') or key.endswith('_sha256'): valid = type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None
            elif key == 'aip.policy.allowed': valid = type(value) is bool
            elif key == 'aip.kernel.coverage_status': valid = type(value) is str and value in COVERAGE
            elif key == 'aip.controller.status': valid = type(value) is str and value in ('PASS', 'FAIL', 'ERROR')
            elif key == 'aip.error.type': valid = type(value) is str and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,79}', value) is not None
            if not valid: raise ValueError('invalid controller telemetry attribute value')
            values[key] = value
        result.append({'phase': phase, 'start_time_unix_nano': start, 'end_time_unix_nano': end, 'attributes': values})
    roots = [r for r in result if r['phase'] == 'aip.run']
    if len(roots) != 1 or len({r['attributes']['aip.run_id'] for r in result}) != 1:
        raise ValueError('requires one actual controller run and a single run correlation')
    whole = roots[0]
    if any(r['start_time_unix_nano'] < whole['start_time_unix_nano'] or r['end_time_unix_nano'] > whole['end_time_unix_nano'] for r in result):
        raise ValueError('controller phases escape the recorded run interval')
    if len(json.dumps(result, allow_nan=False).encode()) > MAX_JSON_BYTES:
        raise ValueError('controller telemetry exceeds its byte bound')
    return result


def clean_environment():
    # No caller OTEL headers, proxies, baggage, Python paths or model secrets.
    return {'PATH': os.defpath, 'NETRC': os.devnull, 'LANG': 'C.UTF-8'}


def _pins():
    return read_json(HERE / 'otel.lock.json')


def _platform_pin():
    key = platform.system() + '-' + platform.machine()
    pin = _pins()
    try: return pin, key, pin['collector']['platforms'][key]
    except KeyError as error: raise ValueError('unsupported pinned Collector platform') from error


def prepare_telemetry(root):
    """Network bootstrap into a new isolated asset directory, never core pip."""
    root = Path(root).absolute()
    if root.exists(): return verify_telemetry(root)
    root.mkdir(mode=0o700, parents=True)
    pin, key, asset = _platform_pin()
    archive = root / asset['filename']
    with urlopen(asset['url'], timeout=60) as source, archive.open('xb') as target:
        count = 0
        while chunk := source.read(1024 * 1024):
            count += len(chunk)
            if count > asset['bytes']: raise ValueError('Collector download exceeds the reviewed size')
            target.write(chunk)
    if archive.stat().st_size != asset['bytes'] or sha(archive) != asset['sha256']:
        raise ValueError('Collector archive does not match the official pin')
    binary = root / 'otelcol-contrib'
    with tarfile.open(archive) as package:
        members = package.getmembers()
        if any(not m.isfile() or m.name not in ('README.md', 'otelcol-contrib') for m in members):
            raise ValueError('unexpected Collector archive member')
        member = package.getmember('otelcol-contrib')
        if member.size != asset['binary_bytes']: raise ValueError('unexpected Collector binary size')
        with package.extractfile(member) as source, binary.open('xb') as target:
            shutil.copyfileobj(source, target, length=1024 * 1024)
    binary.chmod(0o700)
    if sha(binary) != asset['binary_sha256']: raise ValueError('Collector binary pin mismatch')
    requirements = HERE / 'requirements-otel.lock'
    if sha(requirements) != pin['sdk']['requirements_sha256']: raise ValueError('SDK requirement pin mismatch')
    subprocess.run([sys.executable, '-I', '-m', 'venv', str(root / 'sdk-venv')], env=clean_environment(), check=True, timeout=60, capture_output=True)
    python = root / 'sdk-venv/bin/python'
    subprocess.run([str(python), '-I', '-m', 'pip', '--isolated', '--disable-pip-version-check', 'install',
        '--no-cache-dir', '--require-hashes', '--only-binary=:all:', '--index-url', 'https://pypi.org/simple', '--keyring-provider', 'disabled',
        '-r', str(requirements)], env=clean_environment(), check=True, timeout=180, capture_output=True)
    save(root / 'manifest.json', {'schema': 'aip-controller-otel-assets-v1', 'platform': key,
        'lock_sha256': sha(HERE / 'otel.lock.json'), 'worker_sha256': sha(HERE / 'otel_worker.py'),
        'requirements_sha256': sha(requirements)})
    return verify_telemetry(root)


def verify_telemetry(root):
    """Read-only/offline checks; no dependency imports into the controller."""
    root = Path(root).resolve(strict=True)
    pin, key, asset = _platform_pin()
    manifest = read_json(root / 'manifest.json')
    if manifest != {'schema': 'aip-controller-otel-assets-v1', 'platform': key,
            'lock_sha256': sha(HERE / 'otel.lock.json'), 'worker_sha256': sha(HERE / 'otel_worker.py'),
            'requirements_sha256': sha(HERE / 'requirements-otel.lock')}:
        raise ValueError('telemetry asset/source manifest mismatch')
    binary = root / 'otelcol-contrib'
    if binary.is_symlink() or not binary.is_file() or binary.stat().st_size != asset['binary_bytes'] or sha(binary) != asset['binary_sha256']:
        raise ValueError('verified Collector binary unavailable')
    archive = root / asset['filename']
    if archive.is_symlink() or not archive.is_file() or sha(archive) != asset['sha256']:
        raise ValueError('verified original Collector archive unavailable')
    python = root / 'sdk-venv/bin/python'
    script = 'import importlib.metadata,json,sys;print(json.dumps({"prefix":sys.prefix,"base_prefix":sys.base_prefix,"versions":{n:importlib.metadata.version(n) for n in '+repr(sorted(pin['sdk']['packages']))+'}}))'
    result = subprocess.run([str(python), '-I', '-B', '-c', script], env=clean_environment(), capture_output=True, text=True, check=True, timeout=15)
    metadata = json.loads(result.stdout)
    if Path(metadata['prefix']).resolve() != root / 'sdk-venv' or metadata['prefix'] == metadata['base_prefix'] or metadata['versions'] != pin['sdk']['packages']:
        raise ValueError('requires the exact SDK packages in the isolated telemetry environment')
    return {'status': 'PASS', 'classification': SOURCE, 'collector_version': pin['collector']['version'],
        'collector_archive_sha256': asset['sha256'], 'collector_binary_sha256': asset['binary_sha256'],
        'sdk_version': pin['sdk']['version'], 'sdk_isolated': True, 'root': str(root),
        'binary': str(binary), 'python': str(python), 'production_or_remote_export': 'UNVALIDATED'}


def _attribute_values(items):
    if type(items) is not list or len(items) > len(ATTRIBUTES) + 3:
        raise ValueError('unreviewed received telemetry attribute collection')
    values = {}
    for item in items:
        if type(item) is not dict or set(item) != {'key', 'value'} or type(item['key']) is not str:
            raise ValueError('unreviewed received telemetry attribute fields')
        key, value = item['key'], item['value']
        if key in values or type(value) is not dict or len(value) != 1: raise ValueError('invalid received telemetry attributes')
        kind, raw = next(iter(value.items()))
        if kind == 'stringValue' and type(raw) is str: values[key] = raw
        elif kind == 'boolValue' and type(raw) is bool: values[key] = raw
        elif kind == 'intValue' and (type(raw) is int or type(raw) is str and re.fullmatch('[0-9]+', raw)): values[key] = int(raw)
        else: raise ValueError('unreviewed received telemetry attribute type')
    return values


def verify_collector_file(path, records, nonce, expected_trace_id):
    records = validate_records(records)
    raw = read_regular_bytes(path, MAX_COLLECTOR_BYTES)
    spans = []
    for line in raw.decode().splitlines():
        document = strict_json(line)
        if type(document) is not dict or set(document) != {'resourceSpans'}:
            raise ValueError('unreviewed Collector document fields')
        resources = document['resourceSpans']
        if type(resources) is not list or not resources:
            raise ValueError('unreviewed Collector resource collection')
        for resource in resources:
            if type(resource) is not dict or set(resource) != {'resource', 'scopeSpans'}:
                raise ValueError('unreviewed Collector resource fields')
            if type(resource['resource']) is not dict or set(resource['resource']) != {'attributes'}:
                raise ValueError('unreviewed Collector resource metadata')
            values = _attribute_values(resource['resource']['attributes'])
            if values != {'service.name': 'aip-validation-controller', 'aip.source_authority': SOURCE}:
                raise ValueError('unexpected Collector resource attributes')
            scopes = resource['scopeSpans']
            if type(scopes) is not list or not scopes:
                raise ValueError('unreviewed Collector scope collection')
            for scope in scopes:
                if type(scope) is not dict or set(scope) != {'scope', 'spans'}:
                    raise ValueError('unreviewed Collector scope fields')
                if scope['scope'] != {'name': 'aip.controller.governance', 'version': '1.0'}:
                    raise ValueError('unexpected telemetry scope')
                if type(scope['spans']) is not list or not scope['spans']:
                    raise ValueError('unreviewed Collector span collection')
                spans.extend(scope['spans'])
    if len(spans) != len(records): raise ValueError('Collector has not received every controller phase')
    if type(expected_trace_id) is not str or not re.fullmatch('[0-9a-f]{32}', expected_trace_id) or int(expected_trace_id,16)==0:
        raise ValueError('invalid actual trace identifier')
    if type(nonce) is not str or not re.fullmatch('[0-9a-f]{32}', nonce):
        raise ValueError('invalid export correlation nonce')
    root_index = next(i for i,r in enumerate(records) if r['phase']=='aip.run')
    seen, span_ids, parents = {}, set(), {}
    required = {'traceId','spanId','flags','name','kind','startTimeUnixNano','endTimeUnixNano','attributes','status'}
    for span in spans:
        if type(span) is not dict or not required <= set(span) or set(span) - required - {'parentSpanId'}:
            raise ValueError('unreviewed Collector span fields')
        if type(span['flags']) is not int or not 0 <= span['flags'] < 2**32 or type(span['kind']) is not int or span['kind'] != 1:
            raise ValueError('unreviewed Collector span metadata')
        attributes = _attribute_values(span['attributes'])
        index = attributes.pop('aip.telemetry.record_index', None)
        if type(index) is not int or not 0 <= index < len(records) or index in seen: raise ValueError('invalid received phase correlation')
        if attributes.pop('aip.telemetry.export_nonce', None) != nonce or attributes.pop('aip.telemetry.export_mode', None) != MODE:
            raise ValueError('Collector correlation nonce or export scope mismatch')
        record = records[index]
        for key in ('startTimeUnixNano', 'endTimeUnixNano'):
            if type(span[key]) is not str or re.fullmatch('[0-9]+', span[key]) is None:
                raise ValueError('unreviewed Collector timestamp encoding')
        expected_status = {'code': 2} if record['attributes'].get('aip.controller.status') in ('FAIL','ERROR') else {}
        if (span['name'] != record['phase'] or int(span['startTimeUnixNano']) != record['start_time_unix_nano']
                or int(span['endTimeUnixNano']) != record['end_time_unix_nano'] or attributes != record['attributes']
                or span['traceId'] != expected_trace_id or span['status'] != expected_status):
            raise ValueError('received span differs from its actual controller record')
        span_id = span['spanId']
        if type(span_id) is not str or not re.fullmatch('[0-9a-f]{16}', span_id) or int(span_id, 16) == 0 or span_id in span_ids:
            raise ValueError('invalid actual span identifier')
        parents[index] = span.get('parentSpanId','')
        span_ids.add(span_id);seen[index]=span_id
    if any((index==root_index and parent) or (index!=root_index and parent!=seen[root_index]) for index,parent in parents.items()):
        raise ValueError('received phases do not share the actual run parent')
    return {'span_count': len(spans), 'trace_id': expected_trace_id, 'phase_correlations_verified': True,
            'actual_timestamps_preserved': True, 'original_collector_file_sha256': hashlib.sha256(raw).hexdigest()}


def export_records(root, records, output_dir, *, private_dir=None):
    """Stop/reap the actual Collector before verifying and publishing its file.

    Raw originals, including every failed output and the free-form Collector
    log, remain in a fresh mode-0700 directory outside the public destination.
    Publication is an atomic directory rename on the same filesystem. A caller
    supplying private_dir should place it in its existing private run storage.
    """
    records = validate_records(records)
    assets = verify_telemetry(root)
    output = Path(output_dir).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError('telemetry publication destination already exists')
    if private_dir is None:
        private = Path(tempfile.mkdtemp(prefix='aip-controller-otel-private-'))
    else:
        private = Path(private_dir).absolute()
        if private.resolve().is_relative_to(output.resolve()) or output.resolve().is_relative_to(private.resolve()):
            raise ValueError('private telemetry originals must stay outside the public destination')
        private.mkdir(mode=0o700, parents=True, exist_ok=False)
        private.chmod(0o700)
    nonce = secrets.token_hex(16)
    save(private / 'records.json', {'nonce': nonce, 'records': records})
    listener = socket.socket();listener.bind(('127.0.0.1', 0));port = listener.getsockname()[1];listener.close()
    config = read_json(HERE / 'otel-collector.json')
    config['receivers']['otlp']['protocols']['http']['endpoint'] = '127.0.0.1:' + str(port)
    config['exporters']['file']['path'] = str(private / 'collector-spans.jsonl')
    save(private / 'collector-config.json', config)
    collector, receipt = None, None
    result = {'status': 'FAIL', 'classification': SOURCE, 'export_mode': MODE,
        'signed_kernel_evidence': False, 'independent_custody': False,
        'collector_version': assets['collector_version'], 'collector_binary_sha256': assets['collector_binary_sha256'],
        'sdk_version': assets['sdk_version'], 'sdk_isolated': True, 'nonce': nonce,
        'private_originals_retained': True, 'raw_collector_log_published': False,
        'final_file_verified_after_collector_stop': False}
    try:
        descriptor = os.open(private / 'collector.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as log:
            collector = subprocess.Popen([assets['binary'], '--config', str(private / 'collector-config.json')],
                env=clean_environment(), cwd=private, stdout=log, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 10
            while True:
                if collector.poll() is not None: raise RuntimeError('Collector exited before startup')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.2): break
                except OSError:
                    if time.monotonic() >= deadline: raise TimeoutError('Collector startup exceeded its bound')
                    time.sleep(0.05)
            worker = subprocess.run([assets['python'], '-I', '-B', str(HERE / 'otel_worker.py'),
                '--input', str(private / 'records.json'), '--endpoint', f'http://127.0.0.1:{port}/v1/traces'],
                env=clean_environment(), capture_output=True, text=True, timeout=25)
            if worker.returncode or len(worker.stdout.encode()) > 65536: raise RuntimeError('actual SDK export failed')
            receipt = json.loads(worker.stdout)
            if receipt.get('status') != 'PASS' or receipt.get('nonce') != nonce: raise ValueError('actual SDK receipt mismatch')
    except Exception as error:
        result['failure_type'] = type(error).__name__
    finally:
        if collector is not None:
            try:
                collector.terminate()
            except Exception as error:
                result['cleanup_failure'] = type(error).__name__
            try:
                result['collector_exit_code'] = collector.wait(timeout=5)
            except subprocess.TimeoutExpired:
                result['cleanup_failure'] = 'CollectorForcedKill'
                try:
                    collector.kill()
                    result['collector_exit_code'] = collector.wait(timeout=5)
                except Exception as error:
                    result['cleanup_failure'] = type(error).__name__
            except Exception as error:
                result['cleanup_failure'] = type(error).__name__
    # The child has exited and been reaped. There is no live-file success path.
    if (receipt is not None and 'failure_type' not in result and 'cleanup_failure' not in result
            and result.get('collector_exit_code') == 0):
        try:
            verified = verify_collector_file(private / 'collector-spans.jsonl', records, nonce, receipt['trace_id'])
            result.update(verified, status='PASS', actual_collector_receipt=True,
                worker_sdk_export_success=True, final_file_verified_after_collector_stop=True)
        except Exception as error:
            result['failure_type'] = type(error).__name__
    elif 'failure_type' not in result:
        result['failure_type'] = 'CollectorDidNotExitCleanly'
    save(private / 'telemetry-report.json', result)
    if result['status'] != 'PASS':
        return result
    try:
        # Every public byte was validated above. Retain original source bytes;
        # never copy the free-form Collector log, on success or failure.
        payloads = {name: read_regular_bytes(private / name,
            MAX_COLLECTOR_BYTES if name == 'collector-spans.jsonl' else MAX_JSON_BYTES)
            for name in ('records.json', 'collector-config.json', 'collector-spans.jsonl', 'telemetry-report.json')}
        if hashlib.sha256(payloads['collector-spans.jsonl']).hexdigest() != result['original_collector_file_sha256']:
            raise ValueError('stopped Collector output changed before publication')
        publication = private / 'verified-publication'
        publication.mkdir(mode=0o700)
        for name, raw in payloads.items():
            descriptor = os.open(publication / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(raw);stream.flush();os.fsync(stream.fileno())
            (publication / name).chmod(0o644)
        output.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        if output.exists() or output.is_symlink():
            raise ValueError('telemetry publication destination appeared during export')
        publication.chmod(0o755)
        # Cross-filesystem publication fails closed; private originals survive.
        os.rename(publication, output)
    except Exception as error:
        result.update(status='FAIL', failure_type=type(error).__name__)
        save(private / 'publication-failure.json', result)
    return result
