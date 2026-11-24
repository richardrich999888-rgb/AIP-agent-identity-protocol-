#!/usr/bin/env python3
"""Qualify the explicitly approved full-sensor service on a disposable runner.

This runs controlled OS actions, not an autonomous AI task or a customer pilot.
A collector under a different UID on the same host is not independent custody.
Environment markers guard accidental use; they do not authenticate this host.
Private keys, raw queued bytes and command logs never enter the public allowlist.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import secrets
import select
import shutil
import socket
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'integrations/real_agents'))
from evidence import ARCHIVES, Refused, covered, records, verify  # noqa: E402
from harness import save, tamper, terminate  # noqa: E402

MECHANISMS = {'SchedTracepoint', 'CgroupTracepoint', 'SockStateTracepoint',
              'SockSendTracepoint', 'ProcConnector', 'Fanotify', 'WireTapAfPacket'}
WORK = Path('/srv/aip-pilot-workspace')
ALTERNATE = Path('/srv/aip-pilot-alternate')
PROBE_STATE = Path('/var/lib/aip-probe')
COLLECTOR = Path('/var/lib/aip-validation-collector')
INSTALLED = Path('/opt/vanian/snifferdog/bin/aip-probe')
UNIT = Path('/etc/systemd/system/aip-probe.service')
FILTER = Path('/etc/aip/agent-filter.json')
CONFIG = Path('/etc/aip/probe.env')
CGROUP = Path('/sys/fs/cgroup/aip-pilot-validation')
TOOLS = Path('/opt/aip-pilot-tools')
SPOOL = PROBE_STATE / 'spool'
PROBE_ID = 'probe.full-sensor.disposable'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def batch_key(batch):
    return (batch['probe_id'], tuple(batch['probe_run_id']), tuple(batch['batch_id']))


def read_live(path):
    """Only complete records are candidates; final verification refuses tails."""
    if not path.exists():
        return []
    data = path.read_bytes()
    return [json.loads(line) for line in data.split(b'\n')[:-1] if line]


def same_selection(observed, target):
    if not observed or observed['process'] != target['process']:
        return False
    if observed['exe_content_sha256'] != target['exe_content_sha256']:
        return False
    actual, wanted = observed.get('container'), target.get('container')
    if wanted is None:
        return True
    return bool(actual and all(actual.get(key) == value for key, value in wanted.items()
                               if value is not None))


class Proxy:
    """Forward real transport bytes; fault injection never synthesizes a reply.

    Arming requires an already established connection that forwarded responses.
    The next server response is discarded, both sockets close, and all new
    connections are blocked until resume. Thus a queued accepted batch can be
    captured before its exact authenticated retry. Handshake bytes are never
    counted as a lost ACK: the caller proves a newly signed batch is still queued.
    """
    def __init__(self, port):
        self.port = port
        self.lock = threading.RLock()
        self.enabled = True
        self.stopping = False
        self.armed = False
        self.dropped = 0
        self.serial = 0
        self.connections = {}
        self.server = socket.socket()
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(('192.0.2.1', 24680))
        self.server.listen(16)
        self.server.settimeout(0.2)
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    @staticmethod
    def close_sockets(pair):
        for sock in pair:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()

    def accept(self):
        while not self.stopping:
            try:
                client, _ = self.server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self.lock:
                if not self.enabled:
                    client.close()
                    continue
                try:
                    upstream = socket.create_connection(('127.0.0.1', self.port), timeout=1)
                except OSError:
                    client.close()
                    continue
                self.serial += 1
                serial = self.serial
                self.connections[serial] = {'pair': (client, upstream), 'responses': 0}
            threading.Thread(target=self.forward, args=(serial,), daemon=True).start()

    def forward(self, serial):
        with self.lock:
            pair = self.connections[serial]['pair']
        try:
            while not self.stopping:
                ready, _, _ = select.select(pair, [], [], 0.2)
                for source in ready:
                    data = source.recv(65536)
                    if not data:
                        return
                    with self.lock:
                        if not self.enabled:
                            return
                        if source is pair[1] and self.armed:
                            self.armed = False
                            self.dropped += 1
                            self.enabled = False
                            return
                        if source is pair[1]:
                            self.connections[serial]['responses'] += 1
                        pair[1 if source is pair[0] else 0].sendall(data)
        except (OSError, ValueError):
            return
        finally:
            with self.lock:
                self.connections.pop(serial, None)
                self.close_sockets(pair)

    def outage(self):
        with self.lock:
            self.enabled = False
            for item in self.connections.values():
                self.close_sockets(item['pair'])

    def resume(self):
        with self.lock:
            self.enabled = True

    def arm(self):
        with self.lock:
            if (not self.enabled or self.armed or len(self.connections) != 1
                    or next(iter(self.connections.values()))['responses'] < 3):
                raise Refused('lost-ACK injection requires one established authenticated session')
            self.armed = True

    def established(self):
        with self.lock:
            return len(self.connections) == 1 and next(iter(self.connections.values()))['responses'] >= 3

    def close(self):
        self.stopping = True
        self.outage()
        self.server.close()
        self.thread.join(timeout=2)


class Runner:
    def __init__(self, args):
        self.args = args
        self.out = args.out
        self.public, self.private = self.out / 'public', self.out / 'private'
        self.public.mkdir(parents=True, mode=0o755)
        self.private.mkdir(mode=0o700)
        self.report = {'status': 'FAIL', 'failures': [], 'checks': {},
                       'workload': 'CONTROLLED_OS_ACTIONS_NOT_AN_AI_AGENT',
                       'deployment': 'DISPOSABLE_GITHUB_HOSTED_VALIDATION_ONLY',
                       'independent_administrative_custody_established': False,
                       'customer_pilot_ready': False,
                       'environment_markers_are_authentication': False}
        self.logs, self.processes, self.workers = [], [], {}
        self.mounts = []
        self.network_created = False
        self.installation_owned = False
        self.installation_attempted = False
        self.negative_owned = False
        self.collector = self.proxy = None
        self.anchor = None
        self.env = None
        self.queued = {}
        self.receipts = []
        self.step = 0
        self.unit_text = None
        self.started = time.monotonic()

    def cmd(self, argv, *, timeout=30, check=True, **kwargs):
        self.step += 1
        stem = self.private / f'command-{self.step:03d}'
        result = subprocess.run([str(x) for x in argv], capture_output=True,
                                timeout=timeout, **kwargs)
        stem.with_suffix('.stdout').write_bytes(result.stdout)
        stem.with_suffix('.stderr').write_bytes(result.stderr)
        if check and result.returncode:
            raise Refused(f'{Path(str(argv[0])).name} failed with exit {result.returncode}; private log {stem.name}')
        return result

    def wait(self, label, predicate, seconds=30):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if time.monotonic() - self.started > 780:
                raise Refused('qualification exceeded its 13-minute work budget')
            value = predicate()
            if value:
                return value
            if self.collector and self.collector.poll() is not None:
                raise Refused('collector exited while waiting for ' + label)
            time.sleep(0.2)
        raise Refused('timed out waiting for ' + label)

    def account(self, name, home):
        try:
            pwd.getpwnam(name)
        except KeyError:
            self.cmd(['useradd', '--system', '--user-group', '--no-create-home',
                      '--home-dir', home, '--shell', '/usr/sbin/nologin', name])
        account = pwd.getpwnam(name)
        if account.pw_uid == 0 or account.pw_gid == 0:
            raise Refused('dedicated validation account unexpectedly uses root')
        return account

    def owned_dir(self, path, account, mode=0o700):
        path.mkdir(parents=True, mode=mode)
        path.chmod(mode)
        os.chown(path, account.pw_uid, account.pw_gid)

    def spawn(self, name, argv, account=None, **kwargs):
        stdout = (self.private / (name + '.stdout')).open('ab')
        stderr = (self.private / (name + '.stderr')).open('ab')
        self.logs += [stdout, stderr]
        if account:
            kwargs.update(user=account.pw_uid, group=account.pw_gid, extra_groups=[])
        process = subprocess.Popen([str(x) for x in argv], stdin=subprocess.DEVNULL,
                                   stdout=stdout, stderr=stderr, **kwargs)
        self.processes.append(process)
        return process

    def line(self, process, seconds=15):
        # Unbuffered pipes keep select and readline in the same buffering domain.
        if not select.select([process.stdout], [], [], seconds)[0]:
            raise Refused('controlled helper did not return a bounded response')
        line = process.stdout.readline(65537)
        if not line or len(line) > 65536 or not line.endswith(b'\n'):
            raise Refused('controlled helper returned an incomplete or oversized response')
        return json.loads(line)

    def setup(self):
        if (platform.system() != 'Linux' or os.geteuid() != 0
                or os.environ.get('GITHUB_ACTIONS') != 'true'
                or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'):
            raise Refused('requires explicitly approved root execution on a disposable GitHub-hosted Linux runner')
        if not Path('/run/systemd/system').is_dir():
            raise Refused('actual systemd host required')
        if any(path.exists() for path in (WORK, ALTERNATE, COLLECTOR, TOOLS, CGROUP, CONFIG, UNIT, PROBE_STATE)):
            raise Refused('validation paths already exist; refusing to overwrite a prior installation')
        if not re.fullmatch('[a-fA-F0-9]{64}', self.args.expected_sha256):
            raise Refused('invalid expected archive digest')
        if digest(self.args.archive.read_bytes()) != self.args.expected_sha256.lower():
            raise Refused('package hash mismatch')
        verified = self.cmd(['/usr/bin/python3', ROOT / 'deploy/enterprise/linux/package.py',
            'verify', '--archive', self.args.archive, '--expected-sha256', self.args.expected_sha256])
        manifest = json.loads(verified.stdout)['manifest']
        for name in ('aip-probe', 'aip-collector', 'aip-observe-verify'):
            if digest((self.args.tools / name).read_bytes()) != manifest['files']['bin/' + name]['sha256']:
                raise Refused('tool binary does not match the verified runtime package: ' + name)
        self.report['package'] = {'archive_sha256': self.args.expected_sha256.lower(),
                                  'source_commit': manifest['source_commit']}
        version = self.cmd(['systemctl', '--version']).stdout.decode('ascii', errors='replace').splitlines()[0]
        if not re.match(r'^systemd [0-9]+', version):
            raise Refused('systemd version could not be measured')
        clock = self.cmd(['timedatectl', 'show', '--property=NTPSynchronized', '--value']).stdout.strip()
        self.report['platform'] = {'kernel_release': platform.release(), 'machine': platform.machine(),
            'systemd_version': re.match(r'^systemd [0-9]+', version).group(),
            'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'controller_clock_synchronized': clock == b'yes',
            'clock_check_is_independent_collector_proof': False}
        self.probe_user = self.account('aip-probe', str(PROBE_STATE))
        self.collector_user = self.account('aip-validation-collector', str(COLLECTOR))
        self.selected_user = self.account('aip-pilot-selected', str(WORK))
        self.unselected_user = self.account('aip-pilot-unselected', str(ALTERNATE))
        users = [self.probe_user, self.collector_user, self.selected_user, self.unselected_user]
        if len({user.pw_uid for user in users}) != 4:
            raise Refused('probe, collector and both workload users must be distinct')
        self.report['accounts'] = {user.pw_name: {'uid': user.pw_uid, 'gid': user.pw_gid} for user in users}
        TOOLS.mkdir(mode=0o755)
        for name in ('aip-probe', 'aip-collector', 'aip-observe-verify'):
            source = self.args.tools / name
            shutil.copyfile(source, TOOLS / name)
            (TOOLS / name).chmod(0o755)
        for name in ('full_sensor_workload.py', 'full_sensor_privilege_check.py'):
            shutil.copyfile(Path(__file__).parent / name, TOOLS / name)
            (TOOLS / name).chmod(0o644)
        for path in (WORK, ALTERNATE):
            path.mkdir(mode=0o755)
            self.cmd(['mount', '-t', 'tmpfs', '-o', 'size=32m,nodev,nosuid,mode=0755', 'aip-pilot', path])
            self.mounts.append(path)
        if not Path('/sys/kernel/tracing/available_events').exists():
            self.cmd(['mount', '-t', 'tracefs', 'nodev', '/sys/kernel/tracing'])
        if not Path('/sys/fs/cgroup/cgroup.controllers').exists():
            raise Refused('cgroup v2 required')
        CGROUP.mkdir()
        self.cmd(['ip', 'netns', 'add', 'aip-pilot-peer'])
        self.network_created = True
        self.cmd(['ip', 'link', 'add', 'aip-pilot0', 'type', 'veth', 'peer', 'name', 'aip-pilot1'])
        self.cmd(['ip', 'link', 'set', 'aip-pilot1', 'netns', 'aip-pilot-peer'])
        self.cmd(['ip', 'addr', 'add', '192.0.2.1/30', 'dev', 'aip-pilot0'])
        self.cmd(['ip', 'link', 'set', 'aip-pilot0', 'up'])
        self.cmd(['ip', '-n', 'aip-pilot-peer', 'addr', 'add', '192.0.2.2/30', 'dev', 'aip-pilot1'])
        self.cmd(['ip', '-n', 'aip-pilot-peer', 'link', 'set', 'aip-pilot1', 'up'])
        self.cmd(['ip', '-n', 'aip-pilot-peer', 'link', 'set', 'lo', 'up'])
        self.ifindex = int(Path('/sys/class/net/aip-pilot0/ifindex').read_text())
        echo = self.spawn('echo', ['ip', 'netns', 'exec', 'aip-pilot-peer', 'setpriv',
            '--reuid', str(self.unselected_user.pw_uid), '--regid', str(self.unselected_user.pw_gid),
            '--clear-groups', '/usr/bin/python3', TOOLS / 'full_sensor_workload.py',
            'echo', '--host', '192.0.2.2', '--port', '24681'])
        self.wait('peer echo server', lambda: b'"READY"' in (self.private / 'echo.stdout').read_bytes())
        if echo.poll() is not None:
            raise Refused('peer echo server exited')
        self.owned_dir(PROBE_STATE, self.probe_user)
        self.cmd([TOOLS / 'aip-probe', 'init-transport-key', PROBE_STATE / 'transport.key.json'])
        os.chown(PROBE_STATE / 'transport.key.json', self.probe_user.pw_uid, self.probe_user.pw_gid)
        self.owned_dir(COLLECTOR, self.collector_user)
        self.state = COLLECTOR / 'state'
        self.owned_dir(self.state, self.collector_user)
        passphrase = COLLECTOR / 'passphrase'
        passphrase.write_text(secrets.token_urlsafe(48))
        passphrase.chmod(0o600)
        os.chown(passphrase, self.collector_user.pw_uid, self.collector_user.pw_gid)
        allowlist = COLLECTOR / 'probes.json'
        save(allowlist, [{'probe_id': PROBE_ID, 'transport_pubkey_hex':
                         json.loads((PROBE_STATE / 'transport.key.json').read_text())['public_hex']}])
        allowlist.chmod(0o600)
        os.chown(allowlist, self.collector_user.pw_uid, self.collector_user.pw_gid)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            self.port = sock.getsockname()[1]
        self.env = {'PATH': '/usr/bin:/bin', 'AIP_COLLECTOR_OBSERVER_ID': 'collector.full-sensor.disposable',
            'AIP_COLLECTOR_KEY_VERSION': '1', 'AIP_COLLECTOR_KEY_PATH': str(COLLECTOR / 'signing.key.wrapped'),
            'AIP_COLLECTOR_PASSPHRASE_FILE': str(passphrase), 'AIP_COLLECTOR_STATE_DIR': str(self.state),
            'AIP_COLLECTOR_LISTEN': f'127.0.0.1:{self.port}', 'AIP_COLLECTOR_PROBES_PATH': str(allowlist),
            'AIP_COLLECTOR_NOISE_KEY_PATH': str(COLLECTOR / 'noise.key.json'),
            'AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK': '1', 'AIP_COLLECTOR_CONTINUITY': 'strict'}
        self.start_collector()
        self.anchor = {'observer_id': self.env['AIP_COLLECTOR_OBSERVER_ID'], 'key_version': 1,
                       'public_key': (self.state / 'observer.pub').read_text().strip()}
        save(self.public / 'anchor.json', self.anchor)
        self.proxy = Proxy(self.port)
        for name, account in (('selected', self.selected_user), ('unselected', self.unselected_user)):
            for base in (WORK, ALTERNATE, CGROUP):
                self.owned_dir(base / name, account)
            stderr = (self.private / (name + '.stderr')).open('wb')
            self.logs.append(stderr)
            process = subprocess.Popen(['/usr/bin/python3', str(TOOLS / 'full_sensor_workload.py'),
                'worker', '--work-dir', str(WORK / name), '--alternate-dir', str(ALTERNATE / name),
                '--cgroup-dir', str(CGROUP / name), '--host', '192.0.2.2', '--port', '24681'],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, bufsize=0,
                user=account.pw_uid, group=account.pw_gid, extra_groups=[])
            self.processes.append(process)
            ready = self.line(process)
            if ready != {'status': 'READY', 'pid': process.pid, 'uid': account.pw_uid}:
                raise Refused('controlled workload identity mismatch')
            (CGROUP / name / 'cgroup.procs').write_text(str(process.pid))
            self.workers[name] = process
        self.report['checks']['disposable_setup'] = 'PASS'

    def start_collector(self):
        self.collector = self.spawn('collector', [TOOLS / 'aip-collector'], self.collector_user, env=self.env)
        def ready():
            if not all((self.state / name).exists() for name in ('noise.pub', 'observer.pub')):
                return False
            try:
                with socket.create_connection(('127.0.0.1', self.port), timeout=0.2):
                    return True
            except OSError:
                return False
        self.wait('strict collector startup', ready)
        if self.anchor and (self.state / 'observer.pub').read_text().strip() != self.anchor['public_key']:
            raise Refused('collector restart changed retained signing anchor')

    def stop_collector(self):
        terminate(self.collector)
        self.collector = None

    def configuration(self, scoped):
        value = {'AIP_PROBE_ID': PROBE_ID, 'AIP_PROBE_COLLECTOR_ENDPOINT': '192.0.2.1:24680',
            'AIP_PROBE_COLLECTOR_NOISE_PUBKEY': (self.state / 'noise.pub').read_text().strip(),
            'AIP_PROBE_KEY_PATH': str(PROBE_STATE / 'transport.key.json'),
            'AIP_PROBE_SENSORS': 'sched,cgroup,sockstate,socksend,connector,fanotify,afpacket',
            'AIP_PROBE_FANOTIFY_PATH': str(WORK), 'AIP_PROBE_AFPACKET_INTERFACE': 'aip-pilot0',
            'AIP_PROBE_SPOOL_DIR': str(SPOOL), 'AIP_PROBE_SPOOL_MAX_BYTES': '268435456',
            'AIP_PROBE_SPOOL_MAX_BATCHES': '10000', 'AIP_PROBE_BATCH_INTERVAL_MS': '1000'}
        if scoped:
            value['AIP_PROBE_FILTER_PATH'] = str(FILTER)
        config = self.private / ('scoped.env' if scoped else 'baseline.env')
        config.write_text(''.join(key + '=' + item + '\n' for key, item in value.items()))
        config.chmod(0o600)
        return config

    def install(self, config, label):
        package = ROOT / 'deploy/enterprise/linux/package.py'
        review_path = self.private / (label + '-review.json')
        common = ['--archive', self.args.archive, '--expected-sha256', self.args.expected_sha256]
        self.cmd(['/usr/bin/python3', package, 'review-probe-unit', *common,
                  '--config', config, '--output', review_path])
        review = json.loads(review_path.read_text())
        self.installation_attempted = True
        self.cmd(['/usr/bin/python3', package, 'install', *common, '--role', 'probe',
            '--config', config, '--approved-probe-unit-sha256', review['unit_sha256'],
            '--approved-probe-config-sha256', review['config_sha256'],
            '--approved-probe-apparmor-sha256', review['apparmor_sha256'], '--disposable-runner-validation'])
        self.installation_owned = True
        if UNIT.read_bytes() != review['unit'].encode() or CONFIG.read_bytes() != config.read_bytes():
            raise Refused('installed unit/config differs from exact reviewed bytes')
        receipt = json.loads(Path('/etc/aip/vanian-runtime-install.json').read_text())
        if (receipt['unit_sha256'] != review['unit_sha256']
                or receipt['config_sha256'] != review['config_sha256']
                or receipt['apparmor_sha256'] != review['apparmor_sha256']
                or not receipt['apparmor_enforcing_checked']
                or not receipt['live_installation'] or not receipt['disposable_runner_validation']
                or receipt['operator_separate_host_assertion']
                or receipt['independent_administrative_custody_established']):
            raise Refused('installation receipt does not match disposable exact approval')
        self.receipts.append({'phase': label, **receipt})
        save(self.public / 'installation-receipts.json', self.receipts)
        if Path('/etc/apparmor.d/aip-probe-full-sensor').read_text() != review['apparmor_policy']:
            raise Refused('installed AppArmor policy differs from approved bytes')
        (self.public / 'effective-apparmor.profile').write_text(review['apparmor_policy'])
        self.unit_text = review['unit']
        (self.public / 'effective-probe.service').write_text(self.unit_text)
        # Capture effective properties after systemd's actual parser, not only template bytes.
        effective = self.cmd(['systemctl', 'show', 'aip-probe.service',
            '--property=AppArmorProfile,User,Group,NoNewPrivileges,ProtectSystem,ProtectHome,PrivateTmp,ReadWritePaths,RestrictNamespaces,RestrictSUIDSGID,MemoryDenyWriteExecute,AmbientCapabilities,CapabilityBoundingSet,SystemCallFilter,RestrictAddressFamilies,FragmentPath'])
        (self.public / 'effective-systemd-properties.txt').write_bytes(effective.stdout)
        if self.cmd(['systemctl', 'is-active', 'aip-probe.service'], check=False).returncode == 0:
            raise Refused('installer unexpectedly started the probe')

    def start_probe(self):
        before = len(self.batches())
        self.cmd(['systemctl', 'start', 'aip-probe.service'])
        self.wait('actual systemd probe to attest a new batch', lambda: len(self.batches()) > before, 35)
        self.check_probe_identity()

    def check_probe_identity(self):
        main = int(self.cmd(['systemctl', 'show', 'aip-probe.service', '--property=MainPID', '--value']).stdout)
        if Path(f'/proc/{main}/attr/current').read_text().strip() != 'aip-probe-full-sensor (enforce)':
            raise Refused('actual probe process is not running in its enforcing AppArmor profile')
        uid = Path(f'/proc/{main}/status').read_text().split('Uid:', 1)[1].splitlines()[0].split()
        if any(int(value) != self.probe_user.pw_uid for value in uid):
            raise Refused('probe did not run under the dedicated nonroot service identity')

    def stop_probe(self):
        self.cmd(['systemctl', 'stop', 'aip-probe.service'])

    def batches(self):
        return read_live(self.state / ARCHIVES[0])

    def health(self):
        return read_live(self.state / ARCHIVES[1])

    def exercise(self, name, phase):
        process = self.workers[name]
        process.stdin.write((json.dumps({'op': 'exercise', 'phase': phase}) + '\n').encode())
        process.stdin.flush()
        result = self.line(process, 20)
        if (result.get('status') != 'DONE' or result.get('phase') != phase
                or result.get('pid') != process.pid
                or result.get('counts') != {'watched_files': 3, 'alternate_files': 3, 'tcp_echoes': 3,
                    'child_processes': 3, 'cgroups_created_and_removed': 3}):
            raise Refused('controlled real workload did not complete all actions')
        self.report.setdefault('controlled_actions', []).append(result)

    def drain(self):
        self.wait('durable queue to drain', lambda: SPOOL.exists() and not list(SPOOL.glob('*.batch')), 40)
        time.sleep(0.3)

    def freeze(self, destination):
        destination.mkdir(parents=True, exist_ok=True)
        for name in ARCHIVES:
            shutil.copyfile(self.state / name, destination / name)
        save(destination / 'anchor.json', self.anchor)
        checkpoint = {'sha256': {name: digest((destination / name).read_bytes()) for name in ARCHIVES},
                      'custody': 'SAME_ADMINISTRATOR_CONTROLLER_CHECKPOINT_NOT_INDEPENDENT_CUSTODY'}
        save(destination / 'checkpoint.json', checkpoint)
        raw = self.cmd([TOOLS / 'aip-observe-verify', '--observer-id', self.anchor['observer_id'],
            '--key-version', str(self.anchor['key_version']), '--pubkey', self.anchor['public_key'],
            '--batches', destination / ARCHIVES[0], '--health', destination / ARCHIVES[1], '--json'], check=False)
        (destination / 'offline-verifier.stdout.json').write_bytes(raw.stdout)
        (destination / 'offline-verifier.stderr.txt').write_bytes(raw.stderr)
        report = verify(destination, TOOLS, self.anchor, checkpoint)
        save(destination / 'verification.json', report)
        return checkpoint

    def baseline(self):
        self.install(self.configuration(False), 'baseline')
        self.start_probe()
        start = time.time_ns() // 1_000_000
        self.exercise('selected', 'baseline')
        self.exercise('unselected', 'baseline')
        end = time.time_ns() // 1_000_000
        self.wait('all-seven signed Active baseline coverage',
                  lambda: covered(self.health(), start, end, MECHANISMS), 30)
        self.drain()
        self.stop_probe()
        self.stop_collector()
        baseline = self.public / 'baseline'
        self.freeze(baseline)
        events = [event for item in records(baseline / ARCHIVES[0]) for event in item['batch']['kernel_events']]
        batches = [item['batch'] for item in records(baseline / ARCHIVES[0])]
        if not batches or any(set(batch['active_mechanisms']) != MECHANISMS for batch in batches):
            raise Refused('baseline does not declare all seven opened sensors in every batch')
        controlled_pids = {process.pid for process in self.workers.values()}
        positive = Counter()
        for event in events:
            kind, details = next(iter(event['kind'].items()))
            related = any(details.get(key) in controlled_pids for key in
                          ('parent_pid', 'pid', 'current_pid', 'creator_pid', 'remover_pid'))
            if kind == 'WireSegment':
                related = details['ifindex'] == self.ifindex and any(
                    details[endpoint]['port'] == 24681 for endpoint in ('src', 'dst'))
            elif kind == 'SocketState':
                related = details['remote']['port'] == 24681
            if related:
                positive[event['mechanism']] += 1
            if kind == 'FileEvent' and details['pid'] in controlled_pids:
                observed_path = details['path']
                if observed_path.startswith('/proc/1/root/'):
                    observed_path = observed_path[len('/proc/1/root'):]
                if not observed_path.startswith(str(WORK) + '/'):
                    raise Refused('fanotify included controlled files outside its approved mount')
                metadata = Path(observed_path).stat()
                if (details['dev'], details['ino']) != (metadata.st_dev, metadata.st_ino) or metadata.st_dev != WORK.stat().st_dev:
                    raise Refused('fanotify event device/inode differs from the controlled workspace file')
        if set(positive) != MECHANISMS:
            raise Refused('controlled workload lacks positive events for: ' + ','.join(sorted(MECHANISMS - set(positive))))
        if not covered(records(baseline / ARCHIVES[1]), start, end, MECHANISMS):
            raise Refused('frozen baseline lost its complete signed coverage')
        self.report['checks']['baseline_full_sensor'] = {'status': 'PASS',
            'controlled_positive_events_by_mechanism': dict(positive), 'start_ms': start, 'end_ms': end,
            'signed_coverage': 'COVERED', 'fanotify_alternate_mount_excluded': True,
            'afpacket_ifindex': self.ifindex}
        self.start_collector()

    def enroll_and_scope(self):
        self.cmd(['/usr/bin/python3', ROOT / 'deploy/enterprise/linux/package.py', 'uninstall'])
        self.installation_owned = False
        shutil.move(CONFIG, self.private / 'installed-baseline.env')
        enrolled = self.cmd([TOOLS / 'aip-probe', 'enroll-filter', 'disposable-selected',
                             str(self.workers['selected'].pid)])
        self.scope = json.loads(enrolled.stdout)
        FILTER.write_bytes(enrolled.stdout)
        os.chown(FILTER, 0, self.probe_user.pw_gid)
        FILTER.chmod(0o640)
        self.cmd([TOOLS / 'aip-probe', 'validate-filter', FILTER])
        save(self.public / 'enrolled-scope.json', self.scope)
        self.scoped_config = self.configuration(True)
        self.install(self.scoped_config, 'scoped')
        self.start_probe()
        self.exercise('selected', 'scoped')
        self.exercise('unselected', 'scoped')
        self.wait('scoped work export', lambda: any(item['batch'].get('filter_report') and
            any(event['kind'].get('FileEvent', {}).get('path', '').endswith('scoped-6.txt')
                for event in item['batch']['kernel_events']) for item in self.batches()), 20)
        self.wait('scoped health withdraws aggregate coverage', lambda: self.health() and
            self.health()[-1]['health'].get('attested_coverage') is None and
            not self.health()[-1]['health'].get('covered_by'), 15)
        self.check_scoped()

    def check_scoped(self):
        batches = [item['batch'] for item in self.batches() if item['batch'].get('filter_report')]
        if not batches:
            raise Refused('no signed filtered batches')
        target = self.scope['targets'][0]
        counts, exclusions, unassigned = Counter(), 0, 0
        for batch in batches:
            report = batch['filter_report']
            if report['scope'] != self.scope or set(batch['active_mechanisms']) != MECHANISMS:
                raise Refused('scoped batch changed target enrollment or sensor declarations')
            if batch['dropped_events'] != 0:
                raise Refused('scoped batch reports observation loss or an unknown loss counter')
            exclusions += report['excluded_records']
            unassigned += report['unassigned_records']
            for observed in batch['observations']:
                if not same_selection(observed['observed'], target):
                    raise Refused('an out-of-scope execution observation was retained')
            for event in batch['kernel_events']:
                if not same_selection(event.get('bound'), target):
                    raise Refused('an unselected or unbound kernel event was retained')
                kind = next(iter(event['kind']))
                if kind == 'WireSegment':
                    raise Refused('unassignable wire event was retained under a process filter')
                counts[kind] += 1
        if not exclusions or not unassigned or any(not counts[name] for name in
                                                  ('FileEvent', 'SocketSend', 'ProcessSpawn', 'CgroupCreated')):
            raise Refused('scoped run lacks selected positive events or measured exclusions')
        latest = self.health()[-1]['health']
        if latest.get('attested_coverage') is not None or latest.get('covered_by'):
            raise Refused('scoped run incorrectly asserted aggregate coverage')
        self.report['checks']['per_agent_retention'] = {'status': 'PASS', 'selected_event_counts': dict(counts),
            'excluded_records': exclusions, 'unassigned_records': unassigned,
            'aggregate_coverage': 'CANNOT_PROVE', 'logical_agent_identity': 'CANNOT_PROVE'}

    def snapshot_queue(self, label):
        destination = self.private / ('queue-' + label)
        destination.mkdir()
        captured, captured_keys = [], set()
        for path in sorted(SPOOL.glob('*.batch')):
            data = path.read_bytes()
            expected = path.stem.split('-', 1)[1]
            if digest(data) != expected:
                raise Refused('durable queue filename hash does not match original payload bytes')
            batch = json.loads(data)
            key = batch_key(batch)
            if key in self.queued and self.queued[key] != data:
                raise Refused('same queued batch identity changed its original bytes')
            self.queued[key] = data
            captured_keys.add(key)
            (destination / path.name).write_bytes(data)
            captured.append({'probe_id': batch['probe_id'], 'probe_run_id': batch['probe_run_id'],
                'batch_id': batch['batch_id'], 'sha256': digest(data),
                'claimed_from_ms': batch['claimed_from_ms'], 'claimed_to_ms': batch['claimed_to_ms']})
        if not captured:
            raise Refused('fault injection did not retain any durable queued batch')
        self.report.setdefault('queue_snapshots', []).append({'phase': label, 'batches': captured})
        return captured_keys

    def state_hashes(self):
        return {str(path.relative_to(PROBE_STATE)): digest(path.read_bytes())
                for path in PROBE_STATE.rglob('*') if path.is_file() and path.name != '.lock'}

    def queue_at_least(self, count=3):
        return self.wait('durable queue growth', lambda: len(list(SPOOL.glob('*.batch'))) >= count, 20)

    def lifecycle(self):
        self.drain()
        original_key = digest((PROBE_STATE / 'transport.key.json').read_bytes())
        self.proxy.outage()
        self.exercise('selected', 'route-outage')
        self.queue_at_least()
        self.snapshot_queue('route-outage')
        self.stop_probe()
        before = self.state_hashes()
        self.cmd(['/usr/bin/python3', ROOT / 'deploy/enterprise/linux/package.py', 'uninstall'])
        self.installation_owned = False
        if before != self.state_hashes():
            raise Refused('uninstall changed credentials or durable queued state')
        self.install(self.scoped_config, 'queued-reinstall')
        if before != self.state_hashes():
            raise Refused('reinstallation changed credentials or durable queued state')
        # While disconnected start without waiting for an attestation. New run
        # identity must later appear in signed evidence, never inferred from PID.
        self.cmd(['systemctl', 'start', 'aip-probe.service'])
        self.exercise('selected', 'probe-restart')
        self.check_probe_identity()
        self.queue_at_least(len([key for key in before if key.endswith('.batch')]) + 2)
        self.snapshot_queue('probe-restart')
        self.proxy.resume()
        self.drain()
        self.wait('queued batches to appear in signed archive',
                  lambda: set(self.queued) <= {batch_key(item['batch']) for item in self.batches()}, 20)
        # Wait for an authenticated established session after the queue drain.
        self.wait('established session for lost ACK', self.proxy.established, 15)
        prior = {batch_key(item['batch']) for item in self.batches()}
        self.proxy.arm()
        self.exercise('selected', 'lost-ack')
        self.wait('real server response discarded', lambda: self.proxy.dropped == 1, 15)
        captured = self.snapshot_queue('lost-ack')
        accepted = {batch_key(item['batch']) for item in self.batches()} - prior
        if not captured & accepted:
            raise Refused('lost response was not proven to be an accepted still-queued batch ACK')
        self.proxy.resume()
        self.drain()
        self.report['checks']['lost_authenticated_ack'] = {'status': 'PASS', 'responses_discarded': 1,
            'accepted_still_queued_batch_count': len(captured & accepted), 'reply_fabrication': False}
        self.proxy.outage()
        self.exercise('selected', 'collector-restart')
        self.queue_at_least()
        self.snapshot_queue('collector-restart')
        self.stop_collector()
        original_archives = {name: (self.state / name).read_bytes() for name in ARCHIVES}
        self.start_collector()
        for name, prefix in original_archives.items():
            if not (self.state / name).read_bytes().startswith(prefix):
                raise Refused('strict collector restart rewrote or truncated signed history')
        self.proxy.resume()
        self.drain()
        self.wait('all queued original batches in signed history',
                  lambda: set(self.queued) <= {batch_key(item['batch']) for item in self.batches()}, 20)
        if digest((PROBE_STATE / 'transport.key.json').read_bytes()) != original_key:
            raise Refused('probe lifecycle rotated or lost original transport credentials')
        self.report['checks']['lifecycle_preservation'] = {'status': 'PASS',
            'uninstall_reinstall_preserved_stopped_spool_and_credentials': True,
            'collector_restart_preserved_archive_prefix_and_signing_anchor': True,
            'collector_continuity_mode': 'strict'}
        self.check_scoped()
        self.drain()
        self.stop_probe()
        self.stop_collector()
        checkpoint = self.freeze(self.public)
        self.compare_queue()
        save(self.public / 'tamper.json', tamper(self.public, TOOLS, self.anchor, checkpoint))
        self.report['checks']['offline_signatures_and_tampering'] = 'PASS'

    def compare_queue(self):
        archive = records(self.public / ARCHIVES[0])
        identities = [batch_key(item['batch']) for item in archive]
        if len(identities) != len(set(identities)):
            raise Refused('replay produced duplicate signed batch identities')
        indexed = {batch_key(item['batch']): item['batch'] for item in archive}
        enriched = 0
        for key, data in self.queued.items():
            original = json.loads(data)
            actual = dict(indexed.get(key, {}))
            before = original.pop('mechanism_integrity', [])
            after = actual.pop('mechanism_integrity', [])
            if original != actual:
                raise Refused('collector changed original buffered payload fields or collection window')
            enriched += before != after
        runs = {tuple(batch['probe_run_id']) for batch in indexed.values() if batch.get('filter_report')}
        if len(runs) < 2:
            raise Refused('probe restart did not produce a new signed run identity')
        self.report['checks']['original_batch_replay'] = {'status': 'PASS',
            'original_private_byte_snapshots': len(self.queued), 'duplicate_batch_identities': 0,
            'signed_filtered_probe_runs': len(runs), 'collector_integrity_enriched_batches': enriched,
            'comparison': 'Exact original queued SHA256 bytes retained privately; every signed JSON batch field equals original except mechanism_integrity, which the existing collector enriches. Rust verifier checks signed canonical bytes, signatures and continuity without exceptions.'}

    def privileges(self):
        if not self.unit_text or not UNIT.exists():
            raise Refused('privilege checks require a successfully installed reviewed service')
        outside = Path('/srv/aip-pilot-external-canary')
        private = Path('/etc/aip-pilot-private-canary')
        for path, mode in ((outside, 0o666), (private, 0o600)):
            if path.exists():
                raise Refused('negative privilege canary already exists')
            path.write_bytes(b'DISPOSABLE NONSECRET CANARY\n')
            path.chmod(mode)
        # Make the outside link target service-owned so the policy's owner
        # qualifier cannot hide a broken source/target path restriction.
        os.chown(outside, self.probe_user.pw_uid, self.probe_user.pw_gid)
        if outside.stat().st_dev != PROBE_STATE.stat().st_dev:
            raise Refused('outside hardlink canary must share the host state filesystem')
        target = PROBE_STATE / 'negative-mount'
        self.owned_dir(target, self.probe_user)
        state_link = PROBE_STATE / 'outside-link'
        state_link.symlink_to(outside)
        output = PROBE_STATE / 'privilege-check.json'
        argv = ['/usr/bin/python3', str(TOOLS / 'full_sensor_privilege_check.py'),
                '--output', str(output), '--outside-writable', str(outside),
                '--outside-private', str(private), '--mount-target', str(target),
                '--outside-pid', str(self.workers['selected'].pid), '--state-symlink', str(state_link)]
        text = re.sub(r'(?m)^ExecStart=.*$', 'ExecStart=' + ' '.join(argv), self.unit_text)
        text = re.sub(r'(?m)^Restart=.*$', 'Restart=no', text)
        # Copy every other security directive byte-for-byte from the approved unit.
        negative_unit = Path('/etc/systemd/system/aip-pilot-negative.service')
        if negative_unit.exists():
            raise Refused('negative privilege service already exists')
        negative_unit.write_text(text)
        self.negative_owned = True
        self.cmd(['systemctl', 'daemon-reload'])
        self.cmd(['systemctl', 'start', 'aip-pilot-negative.service'], check=False)
        self.wait('exact-profile negative privilege results', output.exists, 75)
        result = json.loads(output.read_text())
        result['source_unit_sha256'] = digest(self.unit_text.encode())
        result['negative_unit_sha256'] = digest(text.encode())
        result['only_unit_changes'] = ['ExecStart', 'Restart']
        save(self.public / 'privilege-check.json', result)
        (self.public / 'effective-negative.service').write_text(text)
        if result.get('lsm_label') != 'aip-probe-full-sensor (enforce)':
            raise Refused('negative helper did not run under the exact enforcing AppArmor profile')
        if result.get('status') != 'PASS':
            raise Refused('exact service profile allowed forbidden negative controls: ' +
                          ','.join(result.get('failed_negative_controls', [])))
        self.report['checks']['negative_privileges'] = 'PASS'

    def probe_diagnostics(self):
        last_stderr = self.private / f'command-{self.step:03d}.stderr'
        previous_error = last_stderr.read_text(errors='replace') if last_stderr.exists() else ''
        journal = self.cmd(['journalctl', '--unit=aip-probe.service', '--no-pager',
                            '--output=cat', '--lines=150'], check=False)
        # Raw daemon text remains private. Public diagnostics are an allowlist
        # of fixed sensor labels, recognized errors, and constrained unit states.
        raw = journal.stdout.decode('utf-8', errors='replace')
        sensors = {'sched': 'open sched tracer', 'cgroup': 'open cgroup tracer',
                   'sockstate': 'open sockstate tracer', 'socksend': 'open socksend tracer',
                   'connector': 'open netlink process connector', 'fanotify': 'open fanotify',
                   'afpacket': 'open AF_PACKET'}
        errors = {'Operation not permitted': 'EPERM', 'Permission denied': 'EACCES',
                  'Read-only file system': 'EROFS', 'No such file or directory': 'ENOENT',
                  'Connection refused': 'ECONNREFUSED', 'Address already in use': 'EADDRINUSE'}
        allowed = {'ActiveState', 'SubState', 'Result', 'ExecMainCode', 'ExecMainStatus', 'NRestarts'}
        status = self.cmd(['systemctl', 'show', 'aip-probe.service',
            '--property=' + ','.join(sorted(allowed))], check=False)
        states = {}
        for line in status.stdout.decode('ascii', errors='replace').splitlines():
            key, _, value = line.partition('=')
            if key in allowed and re.fullmatch('[A-Za-z0-9_-]{1,32}', value):
                states[key] = value
        kernel = self.cmd(['journalctl', '--dmesg', '--no-pager', '--output=cat', '--lines=300'], check=False)
        denials = []
        operations = {'open', 'file_mmap', 'file_inherit', 'file_lock', 'getattr', 'capable', 'ptrace', 'signal', 'exec', 'change_onexec', 'connect', 'create', 'sendmsg', 'recvmsg'}
        for line in kernel.stdout.decode('utf-8', errors='replace').splitlines():
            if 'apparmor="DENIED"' not in line or 'profile="aip-probe-full-sensor"' not in line:
                continue
            fields = {key: quoted or bare for key, quoted, bare in
                      re.findall(r'([a-z_]+)=(?:"([^"]*)"|([^\s]+))', line)}
            entry = {}
            if fields.get('operation') in operations:
                entry['operation'] = fields['operation']
            for key, values in (('family', {'inet', 'inet6', 'unix', 'netlink', 'packet'}),
                                ('sock_type', {'stream', 'dgram', 'raw', 'seqpacket', 'rdm', 'packet'}),
                                ('class', {'file', 'net', 'cap', 'ptrace', 'signal', 'mount', 'domain'})):
                if fields.get(key) in values:
                    entry[key] = fields[key]
            protocol = fields.get('protocol', '')
            if re.fullmatch('[0-9]{1,5}', protocol) and int(protocol) <= 65535:
                entry['protocol'] = int(protocol)
            for key in ('requested_mask', 'denied_mask'):
                if re.fullmatch('[a-z]{1,16}', fields.get(key, '')):
                    entry[key] = fields[key]
            if fields.get('capname') in {'dac_read_search', 'sys_ptrace', 'perfmon', 'net_admin', 'sys_admin', 'net_raw'}:
                entry['capability'] = fields['capname']
            value = fields.get('name', '')
            for prefix, category in (('/proc/', 'procfs'), ('/sys/', 'sysfs'), ('/usr/lib/', 'library'), ('/lib/', 'library'), ('/var/lib/aip-probe/', 'probe_state'), ('/srv/aip-pilot-', 'controlled_workspace'), ('/usr/bin/python', 'negative_python'), ('/opt/vanian/', 'probe_binary')):
                if value.startswith(prefix):
                    entry['path_category'] = category
                    break
            if fields.get('info') == 'Failed name lookup - disconnected path':
                entry['disconnected_path'] = True
            denials.append(entry)
        save(self.public / 'probe-diagnostics.json', {
            'apparmor_denials': denials,
            'parser_syntax_error': 'syntax error' in previous_error.lower(),
            'apparmor_disabled_refusal': 'AppArmor must be enabled' in previous_error,
            'apparmor_parser_unavailable': 'apparmor_parser is required' in previous_error,
            'preexisting_profile_refused': 'already loaded AppArmor profile' in previous_error,
            'source': 'SANITIZED_SYSTEMD_JOURNAL_RAW_RETAINED_PRIVATELY',
            'unit_states': states,
            'fatal_read_error_names': [name for name in (*sensors, 'exec-rendezvous') if 'sensor ' + name + ' acquisition failed:' in raw],
            'sensor_open_error_names': [name for name, marker in sensors.items() if marker in raw],
            'recognized_errors': sorted({code for message, code in errors.items() if message in raw}),
            'os_error_numbers': sorted({int(number) for number in re.findall(r'os error ([0-9]{1,4})', raw)}),
            'sensors_open_reported': 'aip-probe: sensors open;' in raw,
            'arbitrary_log_text_published': False})

    def cleanup(self):
        errors = []
        operations = []
        if self.installation_owned:
            operations.append(('stop probe', lambda: self.cmd(['systemctl', 'stop', 'aip-probe.service'])))
        if self.negative_owned:
            operations.append(('stop negative service', lambda: self.cmd(['systemctl', 'stop', 'aip-pilot-negative.service'], check=False)))
        for name, operation in operations:
            try:
                operation()
            except Exception as error:
                errors.append(name + ': ' + type(error).__name__)
        if self.proxy:
            self.proxy.close()
        for process in reversed(self.processes):
            try:
                terminate(process)
            except Exception as error:
                errors.append('terminate helper: ' + type(error).__name__)
        self.collector = None
        # Preserve failed-run signed archives and actual verifier output too.
        if self.anchor and not (self.public / 'checkpoint.json').exists():
            try:
                self.freeze(self.public)
            except Exception as error:
                errors.append('freeze incomplete run: ' + str(error))
        if self.installation_owned and Path('/etc/aip/vanian-runtime-install.json').exists():
            try:
                self.cmd(['/usr/bin/python3', ROOT / 'deploy/enterprise/linux/package.py', 'uninstall'])
            except Exception as error:
                errors.append('preserving uninstall: ' + str(error))
        if self.network_created:
            self.cmd(['ip', 'link', 'del', 'aip-pilot0'], check=False)
            self.cmd(['ip', 'netns', 'del', 'aip-pilot-peer'], check=False)
        for path in reversed(self.mounts):
            result = self.cmd(['umount', path], check=False)
            if result.returncode:
                errors.append('unmount failed: ' + str(path))
        for stream in self.logs:
            stream.close()
        if errors:
            self.report['failures'].extend(errors)
        self.report['cleanup'] = 'FAIL' if errors else 'PASS'

    def run(self):
        try:
            self.setup()
            self.baseline()
            self.enroll_and_scope()
            self.lifecycle()
        except Exception as error:
            self.report['failures'].append(type(error).__name__ + ': ' + str(error))
            if self.installation_attempted:
                try:
                    self.probe_diagnostics()
                except Exception as diagnostic_error:
                    self.report['failures'].append('probe diagnostic capture failed: ' + type(diagnostic_error).__name__)
        finally:
            if self.unit_text:
                try:
                    self.privileges()
                except Exception as error:
                    self.report['failures'].append(type(error).__name__ + ': ' + str(error))
            try:
                self.cleanup()
            except Exception as cleanup_error:
                self.report['cleanup'] = 'FAIL'
                self.report['failures'].append('unexpected cleanup failure: ' + type(cleanup_error).__name__)
        required = {'disposable_setup', 'baseline_full_sensor', 'per_agent_retention',
                    'lost_authenticated_ack', 'lifecycle_preservation', 'original_batch_replay',
                    'offline_signatures_and_tampering', 'negative_privileges'}
        missing = required - self.report['checks'].keys()
        if missing:
            self.report['failures'].append('unperformed required checks: ' + ','.join(sorted(missing)))
        self.report['status'] = 'FAIL' if self.report['failures'] else 'PASS'
        self.report['elapsed_seconds'] = round(time.monotonic() - self.started, 3)
        save(self.public / 'result.json', self.report)
        if self.args.github_output:
            with self.args.github_output.open('a') as stream:
                stream.write('public_ready=true\n')
        print(json.dumps({'status': self.report['status'], 'failures': self.report['failures'],
                          'public_evidence': str(self.public)}), flush=True)
        return int(bool(self.report['failures']))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tools', required=True, type=Path)
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--github-output', type=Path)
    args = parser.parse_args()
    if not args.out.is_absolute() or args.out.exists():
        parser.error('--out must be an absolute new directory')
    args.tools = args.tools.resolve(strict=True)
    args.archive = args.archive.resolve(strict=True)
    return Runner(args).run()


if __name__ == '__main__':
    raise SystemExit(main())
