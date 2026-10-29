#!/usr/bin/env python3
"""Real kernel/collector/audit compatibility test, NOT an autonomous agent run.

Only use on a disposable Linux runner. Private material stays in its own 0700
folder; the upload allowlist contains public evidence and verification only.
"""
import argparse
import json
import os
import secrets
import shutil
import socket
import subprocess
import time
from pathlib import Path
from audit_crosscheck import AuditCrosscheck
from evidence import ARCHIVES, Refused, command, covered, records, sha256, verify
from harness import now, save, tamper, terminate


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--tools', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    if os.geteuid() != 0 or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted':
        raise Refused('requires root on an explicitly disposable GitHub-hosted runner')
    args.tools = args.tools.resolve()
    out = args.out.resolve(); out.mkdir(mode=0o755)
    private = out / 'private'; private.mkdir(mode=0o700)
    state = private / 'state'; state.mkdir()
    public = out / 'public'; public.mkdir()
    workload = out / 'work'; workload.mkdir(); os.chown(workload, 10001, 10001)
    # A separate mount avoids observing every build/log write on the host.
    command(['mount', '-t', 'tmpfs', '-o', 'size=64m,uid=10001,gid=10001', 'tmpfs', workload])
    probe = collector = None
    audit = AuditCrosscheck()
    streams = []
    result = {'kind': 'kernel/collector/audit capability smoke', 'autonomous_workload_executed': False,
              'kernel': os.uname().release, 'status': 'FAILED',
              'trust': 'ephemeral key isolated from uid 10001; host kernel/root trusted; not institutional custody'}
    def spawn(binary, env):
        log = (private / (binary + '.log')).open('w'); streams.append(log)
        return subprocess.Popen([str(args.tools / binary)], env={'PATH': os.environ['PATH'], **env},
                                stdout=log, stderr=subprocess.STDOUT)
    def checkpoint():
        for name in ARCHIVES:
            shutil.copyfile(state / name, public / name)
        cp = {'sha256': {name: sha256(public / name) for name in ARCHIVES}}
        # Preserve the controller's actual snapshot even if a later gate refuses.
        save(out / 'checkpoint.json', cp)
        return cp
    try:
        if command(['timedatectl', 'show', '--property=NTPSynchronized', '--value']).strip() != 'yes':
            raise Refused('host clock not synchronized')
        trace = Path('/sys/kernel/tracing/available_events')
        if not trace.exists():
            command(['mount', '-t', 'tracefs', 'nodev', '/sys/kernel/tracing'])
        for event in ('sched:sched_process_exec', 'cgroup:cgroup_attach_task', 'sock:sock_send_length'):
            if event not in trace.read_text():
                raise Refused('required tracepoint unavailable: ' + event)
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]
        probe_env = {'AIP_PROBE_ID': 'probe.hosted.smoke', 'AIP_PROBE_COLLECTOR_ENDPOINT': '127.0.0.1:1',
                     'AIP_PROBE_COLLECTOR_NOISE_PUBKEY': '0' * 64,
                     'AIP_PROBE_KEY_PATH': str(private / 'probe.key.json'), 'AIP_PROBE_SENSORS': 'sched'}
        probe = spawn('aip-probe', probe_env)
        for _ in range(40):
            if (private / 'probe.key.json').exists():
                break
            time.sleep(0.1)
        terminate(probe); probe = None
        transport_key = json.loads((private / 'probe.key.json').read_text())['public_hex']
        save(private / 'probes.json', [{'probe_id': 'probe.hosted.smoke', 'transport_pubkey_hex': transport_key}])
        (private / 'pass').write_text(secrets.token_urlsafe(48)); os.chmod(private / 'pass', 0o600)
        collector = spawn('aip-collector', {
            'AIP_COLLECTOR_OBSERVER_ID': 'collector.hosted.smoke', 'AIP_COLLECTOR_KEY_VERSION': '1',
            'AIP_COLLECTOR_KEY_PATH': str(private / 'collector.key.wrapped'),
            'AIP_COLLECTOR_PASSPHRASE_FILE': str(private / 'pass'), 'AIP_COLLECTOR_STATE_DIR': str(state),
            'AIP_COLLECTOR_LISTEN': f'127.0.0.1:{port}',
            'AIP_COLLECTOR_PROBES_PATH': str(private / 'probes.json'),
            'AIP_COLLECTOR_NOISE_KEY_PATH': str(private / 'noise.key.json'),
            'AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK': '1', 'AIP_COLLECTOR_CONTINUITY': 'strict'})
        for _ in range(100):
            if (state / 'noise.pub').exists():
                break
            if collector.poll() is not None:
                raise Refused('collector failed startup')
            time.sleep(0.1)
        anchor = {'observer_id': 'collector.hosted.smoke', 'key_version': 1,
                  'public_key': (state / 'observer.pub').read_text().strip()}
        # Retained before any workload, outside the container's reach.
        save(out / 'anchor.json', anchor)
        probe_env.update(AIP_PROBE_COLLECTOR_ENDPOINT=f'127.0.0.1:{port}',
                         AIP_PROBE_COLLECTOR_NOISE_PUBKEY=(state / 'noise.pub').read_text().strip(),
                         AIP_PROBE_SENSORS='sched,cgroup,connector,fanotify,sockstate,socksend',
                         AIP_PROBE_FANOTIFY_PATH=str(workload), AIP_PROBE_BATCH_INTERVAL_MS='1000')
        probe = spawn('aip-probe', probe_env)
        save(public / 'audit-rules-before.json', {'rules': command(['auditctl', '-l'])})
        audit.start()
        ready = False
        for _ in range(40):
            if probe.poll() is not None or collector.poll() is not None:
                raise Refused('observer daemon exited')
            time.sleep(2)
            if not all((state / name).exists() for name in ARCHIVES):
                continue
            cp = checkpoint(); verify(public, args.tools, anchor, cp)
            h = records(public / ARCHIVES[1])
            last = h[-1]['health']
            w = last.get('attested_coverage')
            if w and covered(h, w['to_ms'] - 1, w['to_ms'], ['SchedTracepoint', 'Fanotify', 'SockSendTracepoint']):
                ready = True; break
        if not ready:
            raise Refused('signed Active coverage unavailable with audit cross-check running')
        start = now()
        result['coverage_requested_from_ms'] = start
        # Establish the window prospectively, before dispatch. Audit uses a
        # coarser clock than userspace; do not put the exec on the boundary.
        # Both observers remain active and signed coverage must include guards.
        time.sleep(1)
        # Real OS operations strictly labeled as component testing. No LLM,
        # generated agent response, or framework validation is asserted here.
        child = subprocess.Popen(['/bin/sleep', '2'], user=10001, group=10001, extra_groups=())
        workload_pid = child.pid
        result['component_child_pid'] = workload_pid
        result['component_child_exit_code'] = child.wait()
        if result['component_child_exit_code'] != 0:
            raise Refused('OS component test failed')
        time.sleep(1)
        end = now()
        result['coverage_requested_to_ms'] = end
        for _ in range(25):
            time.sleep(2)
            cp = checkpoint(); verify(public, args.tools, anchor, cp)
            if covered(records(public / ARCHIVES[1]), start, end,
                       ['SchedTracepoint', 'Fanotify', 'SockSendTracepoint']):
                break
        else:
            raise Refused('workload interval lacks signed coverage')
        save(public / 'audit-status.json', audit.export(public / 'auditd.log'))
        audit.close(); terminate(probe); probe = None
        terminate(collector); collector = None
        cp = checkpoint(); save(out / 'checkpoint.json', cp)
        save(public / 'verification.json', verify(public, args.tools, anchor, cp))
        save(public / 'tamper.json', tamper(public, args.tools, anchor, cp))
        (public / 'observer.pub').write_text(anchor['public_key'] + '\n')
        comparison = json.loads(command([args.tools / 'aip-corroborate',
            '--observer-id', anchor['observer_id'], '--key-version', '1',
            '--pubkey-file', public / 'observer.pub', '--batches', public / ARCHIVES[0],
            '--external', public / 'auditd.log', '--source', 'auditd',
            '--from-ms', start, '--to-ms', end, '--json']))
        save(public / 'corroboration.json', comparison)
        if (not any(x['aip']['pid'] == workload_pid for x in comparison['agreed'])
                or any(x['pid'] == workload_pid for x in comparison['aip_only'])
                or comparison['external_only'] or comparison['external_unparsed']):
            raise Refused('OS component exec did not corroborate without gaps')
        result.update(status='PASS', from_ms=start, to_ms=end,
                      signed_batches=len(records(public / ARCHIVES[0])))
    finally:
        audit.close(); terminate(probe); terminate(collector)
        for stream in streams:
            stream.close()
        command(['umount', workload])
        save(public / 'result.json', result)
        # Logs are daemon diagnostics only; no model ever runs in this test.
        for name in ('aip-probe.log', 'aip-collector.log'):
            if (private / name).exists():
                shutil.copyfile(private / name, public / name)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
