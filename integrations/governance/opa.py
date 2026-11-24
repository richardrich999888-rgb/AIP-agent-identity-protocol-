"""Pinned real OPA CLI gate; never an AIP authorization or kernel observation.

Only the trusted controller calls evaluate(), supplying actual SO_PEERCRED and
its separately configured expected peer/agent/allowlist. This adapter does not
measure those credentials. The existing Rust signer must still authorize the
same proposal. Returned hashes are unsigned correlation data, not receipts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import tempfile
import urllib.request

HERE = Path(__file__).resolve().parent
LOCK_PATH = HERE / 'opa.lock.json'
POLICY_PATH = HERE / 'opa.rego'
MAX_INPUT_BYTES = 65536
MAX_OUTPUT_BYTES = 4096


class OPAError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def asset_for_platform(platform_key=None):
    lock = json.loads(LOCK_PATH.read_bytes())
    if platform_key is None:
        architecture = {'x86_64': 'amd64', 'arm64': 'arm64', 'aarch64': 'arm64'}.get(platform.machine())
        platform_key = platform.system().lower() + '_' + str(architecture)
    if platform_key not in lock['assets']:
        raise OPAError('unsupported pinned OPA platform')
    return {**lock['assets'][platform_key], 'platform': platform_key,
            'version': lock['version'], 'source_commit': lock['source_commit']}


def _verified_file(path, expected):
    path = Path(path)
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_size != expected['bytes']
            or info.st_mode & 0o022):
        raise OPAError('asset must be a protected regular file of the pinned size')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        actual = os.fstat(stream.fileno())
        if (info.st_dev, info.st_ino) != (actual.st_dev, actual.st_ino):
            raise OPAError('asset changed before verification')
        actual_digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if actual_digest != expected['sha256']:
        raise OPAError('asset hash differs from the immutable upstream pin')
    return actual_digest


def verify_engine(path, platform_key=None):
    """Offline verification only; never downloads or repairs a missing asset."""
    asset = asset_for_platform(platform_key)
    actual = _verified_file(path, asset)
    if not os.access(path, os.X_OK):
        raise OPAError('verified OPA asset is not executable')
    return {'version': asset['version'], 'platform': asset['platform'],
            'sha256': actual, 'source_commit': asset['source_commit'],
            'verification': 'FULL_FILE_SHA256_AND_SIZE', 'network_used': False}


def _download(root, name, asset, mode):
    destination = root / name
    if destination.exists() or destination.is_symlink():
        _verified_file(destination, asset)
        return destination
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=root, prefix='.opa-download-', delete=False) as stream:
            temporary = Path(stream.name)
            total = 0
            with urllib.request.urlopen(asset['url'], timeout=60) as response:
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > asset['bytes']:
                        raise OPAError('asset download exceeds the pinned size')
                    stream.write(chunk)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(mode)
        _verified_file(temporary, asset)
        # No overwrite of an existing asset, including under concurrent bootstrap.
        try:
            os.link(temporary, destination)
        except FileExistsError:
            _verified_file(destination, asset)
        return destination
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def prepare_engine(root, platform_key=None):
    """Explicit network bootstrap, before private keys/workload isolation exist."""
    root = Path(root)
    root.mkdir(mode=0o755, parents=True, exist_ok=True)
    info = root.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o022):
        raise OPAError('asset directory must be owned and protected by the controller')
    lock = json.loads(LOCK_PATH.read_bytes())
    asset = asset_for_platform(platform_key)
    path = _download(root, 'opa-' + asset['version'] + '-' + asset['platform'], asset, 0o555)
    _download(root, 'OPA-LICENSE.txt', lock['license'], 0o444)
    verify_engine(path, asset['platform'])
    return path


def _request(proposal, agent_id, peer, expected, allowed_calls):
    def valid_peer(value):
        return (type(value) is dict and set(value) == {'pid', 'uid', 'gid'}
                and all(type(value[key]) is int and 0 <= value[key] <= 2**32-1 for key in value)
                and value['pid'] > 0)
    def valid_call(value):
        return (type(value) is dict and set(value) == {'tool_id', 'arguments'}
                and type(value['tool_id']) is str and 0 < len(value['tool_id']) <= 256
                and value['tool_id'].isprintable() and type(value['arguments']) is dict
                and set(value['arguments']) == {'loan_id', 'amount'}
                and all(type(value['arguments'][key]) is int for key in value['arguments']))
    if (type(agent_id) is not str or not 0 < len(agent_id) <= 512 or not agent_id.isprintable()
            or not valid_peer(peer) or not valid_peer(expected) or not valid_call(proposal)
            or type(allowed_calls) is not list or len(allowed_calls) != 1
            or not all(valid_call(call) for call in allowed_calls)):
        raise OPAError('malformed controller policy context or proposal')
    value = {'agent_id': agent_id, 'peer': {'source': 'ROOT_SO_PEERCRED', **peer}, 'proposal': proposal}
    data = {'aip_context': {'agent_id': agent_id, 'expected_peer': expected, 'allowed_calls': allowed_calls}}
    raw, data_raw = canonical(value), canonical(data)
    if max(len(raw), len(data_raw)) > MAX_INPUT_BYTES:
        raise OPAError('policy input exceeds its fixed bound')
    return raw, data_raw


def _invoke(engine, raw, data_raw):
    with tempfile.TemporaryDirectory(prefix='aip-opa-') as directory:
        data = Path(directory) / 'controller-data.json'
        data.write_bytes(data_raw)
        data.chmod(0o600)
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            process = subprocess.run([str(engine), 'eval', '--stdin-input', '--format=raw',
                '--strict', '--strict-builtin-errors', '--fail', '--timeout=1s',
                '--data', str(POLICY_PATH), '--data', str(data), 'data.aip.loan_read.allow'],
                input=raw, stdout=stdout, stderr=stderr, timeout=3,
                cwd=directory, env={'PATH': os.defpath, 'HOME': directory})
            if any(os.fstat(stream.fileno()).st_size > MAX_OUTPUT_BYTES for stream in (stdout, stderr)):
                raise OPAError('policy engine output exceeds its fixed bound')
            stdout.seek(0)
            return process.returncode, stdout.read(MAX_OUTPUT_BYTES + 1)


def evaluate(engine, *, proposal, agent_id, peer_pid, peer_uid, peer_gid,
             expected_pid, expected_uid, expected_gid, allowed_calls):
    """Always returns an exact bool and fail-closed status; never downloads.

    The caller binds an allowed result to the subsequent unchanged Rust decision
    ID, not before authorization. No raw proposal/peer/config or engine errors
    are included in this bounded unsigned audit projection.
    """
    result = {'allowed': False, 'status': 'INVALID_INPUT',
              'source_authority': 'OPA_POLICY_EVALUATION_OF_CONTROLLER_SUPPLIED_CONTEXT',
              'not_signed': True, 'aip_authorization': False}
    try:
        raw, data_raw = _request(proposal, agent_id,
            {'pid': peer_pid, 'uid': peer_uid, 'gid': peer_gid},
            {'pid': expected_pid, 'uid': expected_uid, 'gid': expected_gid}, allowed_calls)
        result.update(input_sha256=digest(raw), policy_data_sha256=digest(data_raw),
                      proposal_sha256=digest(canonical(proposal)))
    except (OPAError, ValueError, TypeError, OverflowError):
        return result
    result['status'] = 'ENGINE_ERROR'
    try:
        identity = verify_engine(engine)
        lock = json.loads(LOCK_PATH.read_bytes())
        policy = POLICY_PATH.read_bytes()
        if len(policy) > 32768 or digest(policy) != lock['policy_sha256']:
            raise OPAError('policy content differs from its reviewed pin')
        result.update(engine_version=identity['version'], engine_sha256=identity['sha256'],
                      policy_sha256=digest(policy))
        code, output = _invoke(engine, raw, data_raw)
        if type(code) is not int or code != 0 or type(output) is not bytes or len(output) > MAX_OUTPUT_BYTES:
            return result
        result['output_sha256'] = digest(output)
        allowed = json.loads(output)
        if type(allowed) is not bool:
            raise OPAError('policy result is not an exact boolean')
        result.update(allowed=allowed, status='ALLOW' if allowed else 'DENY')
    except (OPAError, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        pass
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    prepare = sub.add_parser('prepare'); prepare.add_argument('--root', type=Path, required=True)
    verify = sub.add_parser('verify'); verify.add_argument('--binary', type=Path, required=True)
    args = parser.parse_args()
    path = prepare_engine(args.root) if args.command == 'prepare' else args.binary
    print(json.dumps({'binary': str(path), 'action': args.command,
        'bootstrap_network': 'EXPLICIT_PREPARE_ONLY' if args.command == 'prepare' else 'NOT_USED',
        'verification': verify_engine(path)}))


if __name__ == '__main__':
    main()
