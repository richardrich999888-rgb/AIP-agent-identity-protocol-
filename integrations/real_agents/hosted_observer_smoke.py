#!/usr/bin/env python3
"""Real kernel/collector/audit compatibility test, NOT an autonomous agent run.

Only use on a disposable Linux runner. Private material stays in its own 0700
folder; the upload allowlist contains public evidence and verification only.
"""
import argparse
import json
import os
import re
from collections import Counter
import secrets
import shutil
import socket
import subprocess
import time
from pathlib import Path
from audit_crosscheck import AuditCrosscheck
from evidence import ARCHIVES, Refused, command, covered, records, sha256, summarize, verify
from harness import now, proc_identity, save, tamper, terminate
from build_image import runtime_python


FRAMEWORKS = ('agent_zero', 'deerflow', 'openhands')
ALL_COMPONENT_MECHANISMS = ['SchedTracepoint', 'CgroupTracepoint', 'ProcConnector',
                            'Fanotify', 'SockStateTracepoint', 'SockSendTracepoint']


def framework_options(framework, image):
    if bool(framework) != bool(image):
        raise Refused('--framework and --framework-image must be supplied together')
    if framework and (framework not in FRAMEWORKS or not re.fullmatch(r'sha256:[a-f0-9]{64}', image)):
        raise Refused('framework component requires a supported framework and immutable image ID')


def framework_image_metadata(framework, image, inspected, pin):
    labels = inspected.get('Config', {}).get('Labels') or {}
    if (inspected.get('Id') != image or labels.get('org.opencontainers.image.revision') != pin['commit']
            or labels.get('org.opencontainers.image.source') != pin['repository']):
        raise Refused('framework image does not match its immutable source pin')
    # Never publish a full docker inspect document/environment.
    return {'source_authority': 'ROOT_CONTROLLER_IMAGE_INSPECTION', 'framework': framework,
            'image_id': image, 'upstream_repository': pin['repository'], 'upstream_commit': pin['commit'],
            'image_os': inspected['Os'], 'image_architecture': inspected['Architecture'],
            'model_calls': 0, 'autonomous_workload_executed': False}


def prepare_framework(framework, image, workload, control, public, component):
    pins = json.loads((Path(__file__).parent / 'frameworks.lock.json').read_text())
    pin = pins[framework]
    inspected = json.loads(command(['docker', 'image', 'inspect', image], timeout=15))[0]
    metadata = framework_image_metadata(framework, image, inspected, pin)
    save(public / 'framework-image.json', metadata)
    control.mkdir(mode=0o755)
    name = 'sd-framework-component-' + secrets.token_hex(12)
    component.update(name=name, framework=framework, metadata=metadata, created=False, output_collected=False)
    create = ['docker', 'create', '--name', name, '--user', '10001:10001', '--cap-drop=ALL',
        '--security-opt=no-new-privileges', '--read-only', '--network', 'none', '--pids-limit', '256',
        '--memory', '4g', '--cpus', '2', '--log-opt', 'max-size=2m', '--log-opt', 'max-file=1',
        '--tmpfs', '/tmp:rw,nosuid,size=1g,mode=1777',
        '--mount', f'type=bind,src={control},dst=/input,readonly',
        '--mount', f'type=bind,src={workload},dst=/work',
        '--env', 'SNIFFERDOG_SMOKE_START_FILE=/input/start',
        '--env', 'SNIFFERDOG_SMOKE_CHILD_HOLD_SECONDS=2']
    if framework == 'agent_zero':
        create += ['--tmpfs', '/opt/framework/usr:rw,nosuid,size=1g,uid=10001,gid=10001']
    create += ['--entrypoint', runtime_python(framework), image, '/opt/snifferdog/smoke.py']
    command(create, timeout=30); component['created'] = True
    command(['docker', 'start', name], timeout=15)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        pid = int(command(['docker', 'inspect', '--format', '{{.State.Pid}}', name], timeout=10))
        try:
            argv = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
            executable = Path(f'/proc/{pid}/exe').readlink().name
            if (argv[:2] == [runtime_python(framework).encode(), b'/opt/snifferdog/smoke.py']
                    and executable.startswith('python')):
                launch = proc_identity(pid)
                launch['probe_id'] = 'probe.hosted.smoke'
                watch = Path(f'/proc/{pid}/root/work')
                host, mounted = workload.stat(), watch.stat()
                if (host.st_dev, host.st_ino) != (mounted.st_dev, mounted.st_ino):
                    raise Refused('framework /work is not the provisioned workspace mount')
                component.update(launch=launch, watch_path=str(watch), control=control)
                save(public / 'component-launch.json', launch)
                save(public / 'component-fanotify-watch.json', {
                    'source_authority': 'ROOT_CONTROLLER_CONTAINER_MOUNT_RESOLUTION',
                    'path': str(watch), 'workspace_device': host.st_dev, 'workspace_inode': host.st_ino,
                    'scope': 'FAN_MARK_MOUNT on actual container /work',
                    'framework_task_gate_released': False})
                return str(watch)
        except (FileNotFoundError, ProcessLookupError):
            pass
        time.sleep(0.1)
    raise Refused('framework waiting Python process could not be measured')


def collect_framework_output(component, public):
    output = subprocess.run(['docker', 'logs', '--tail', '500', component['name']],
                            capture_output=True, timeout=15, check=True)
    for stream, data in (('stdout', output.stdout), ('stderr', output.stderr)):
        if len(data) > 2 * 1024 * 1024:
            raise Refused('framework component output exceeds publication limit')
        (public / f'framework-component.{stream}.txt').write_bytes(data)
    component['output_collected'] = True
    return output.stdout.decode('utf-8')


def framework_report(stdout, framework, commit):
    report = None
    for line in stdout.splitlines():
        try:
            candidate = json.loads(line)
        except ValueError:
            continue
        if isinstance(candidate, dict) and candidate.get('framework') == framework:
            report = candidate
    if (report is None or report.get('status') != 'PASS' or type(report.get('model_calls')) is not int
            or report['model_calls'] != 0 or report.get('autonomous_workload_executed') is not False
            or report.get('upstream_source_commit') != commit
            or report.get('start_gate', {}).get('state') != 'RELEASED_CONTROLLER_READONLY_INPUT'
            or report.get('component_child_hold_seconds') != 2):
        raise Refused('framework component did not report the pinned gated no-model checks')
    return {'source_authority': 'COMPONENT_STDOUT_NOT_SIGNED_KERNEL_EVIDENCE', 'report': report}


def run_framework(component, public, probe, collector):
    measured = {k: v for k, v in component['launch'].items() if k != 'probe_id'}
    if proc_identity(measured['process']['pid']) != measured:
        raise Refused('framework waiting process changed before gate release')
    (component['control'] / 'start').touch()
    deadline = time.monotonic() + 120
    while command(['docker', 'inspect', '--format', '{{.State.Running}}', component['name']], timeout=10).strip() == 'true':
        if probe.poll() is not None or collector.poll() is not None:
            raise Refused('observer exited during framework component')
        if time.monotonic() >= deadline:
            raise Refused('framework component exceeded 120-second runtime budget')
        time.sleep(0.2)
    exit_code = int(command(['docker', 'inspect', '--format', '{{.State.ExitCode}}', component['name']], timeout=15))
    component['exit_code'] = exit_code
    stdout = collect_framework_output(component, public)
    if exit_code != 0:
        raise Refused('actual framework component exited unsuccessfully')
    report = framework_report(stdout, component['framework'], component['metadata']['upstream_commit'])
    save(public / 'framework-component.json', report)
    return exit_code


def framework_observation_failures(summary, comparison, exit_code):
    """Network-none component contract; never the genuine-agent acceptance gate."""
    failures = []
    if exit_code != 0:
        failures.append('framework component failed')
    if summary['coverage'] != 'COVERED' or summary.get('component_full_sensor_coverage') != 'COVERED':
        failures.append('framework interval lacks signed Active coverage')
    if not summary['launch_instance_events']:
        failures.append('measured framework launch instance was not observed')
    for kind in ('ProcessExec', 'FileEvent'):
        if not summary['workload_events_by_kind'].get(kind):
            failures.append('no workload-bound ' + kind)
    if summary['workload_events_by_kind'].get('SocketSend'):
        failures.append('unexpected workload-bound SocketSend in network-none component')
    if summary['probe_reported_drops'] or summary['events_without_clock_anchor']:
        failures.append('component observation reports loss or lacks clock anchors')
    observed = Counter((e['batch_sequence'], e['pid'], e['wall_ms'])
                       for e in summary.get('workload_executions', []))
    paired = Counter((e['aip']['batch_sequence'], e['aip']['pid'], e['aip']['wall_ms'])
                     for e in comparison.get('agreed', []))
    if not observed or observed - paired:
        failures.append('not every bound component exec was independently corroborated')
    if comparison.get('external_only') or comparison.get('external_unparsed'):
        failures.append('independent component comparison has unresolved gaps')
    return failures


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--tools', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--framework', choices=FRAMEWORKS)
    p.add_argument('--framework-image')
    args = p.parse_args()
    framework_options(args.framework, args.framework_image)
    mechanisms = (ALL_COMPONENT_MECHANISMS if args.framework else
                  ['SchedTracepoint', 'Fanotify', 'SockSendTracepoint'])
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
    component = {}
    anchor = None
    audit = AuditCrosscheck()
    streams = []
    result = {'kind': 'kernel/collector/audit capability smoke', 'autonomous_workload_executed': False,
              'kernel': os.uname().release, 'status': 'FAILED',
              'trust': 'ephemeral key isolated from uid 10001; host kernel/root trusted; not institutional custody'}
    if args.framework:
        result.update(framework=args.framework, model_calls=0, observation_validation='NOT_ESTABLISHED',
                      logical_agent_attribution='CANNOT_PROVE', delegation='UNVALIDATED')
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
        watch_path = (prepare_framework(args.framework, args.framework_image, workload,
                         out / 'component-input', public, component) if args.framework else str(workload))
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
                         AIP_PROBE_FANOTIFY_PATH=watch_path, AIP_PROBE_BATCH_INTERVAL_MS='1000')
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
            if w and covered(h, w['to_ms'] - 1, w['to_ms'], mechanisms):
                ready = True; break
        if not ready:
            raise Refused('signed Active coverage unavailable with audit cross-check running')
        start = now()
        result['coverage_requested_from_ms'] = start
        # Establish the window prospectively, before dispatch. Audit uses a
        # coarser clock than userspace; do not put the exec on the boundary.
        # Both observers remain active and signed coverage must include guards.
        time.sleep(1)
        # Real OS or installed-tool operations, never a model-chosen workload.
        if args.framework:
            result.update(kind='observed installed framework component; no model workload', framework=args.framework,
                          model_calls=0, logical_agent_attribution='CANNOT_PROVE', delegation='UNVALIDATED',
                          expected_workload_SocketSend=0, component_child_hold_seconds=2,
                          performance_measurement='NOT_ESTABLISHED_COMPONENT_HOLD_IS_EXPLICIT')
            result['component_child_pid'] = component['launch']['process']['pid']
            result['component_child_exit_code'] = run_framework(component, public, probe, collector)
        else:
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
            if covered(records(public / ARCHIVES[1]), start, end, mechanisms):
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
        if args.framework:
            summary = summarize(records(public / ARCHIVES[0]), records(public / ARCHIVES[1]),
                                component['launch'], start, end)
            summary['component_full_sensor_coverage'] = ('COVERED' if covered(
                records(public / ARCHIVES[1]), start, end, ALL_COMPONENT_MECHANISMS) else 'INTEGRITY_UNKNOWN')
            save(public / 'component-observation-summary.json', summary)
            failures = framework_observation_failures(summary, comparison, result['component_child_exit_code'])
            result['component_observation_failures'] = failures
            result['observation_validation'] = 'FAILED' if failures else 'PASSED'
            if failures:
                raise Refused('; '.join(failures))
        else:
            if (not any(x['aip']['pid'] == workload_pid for x in comparison['agreed'])
                    or any(x['pid'] == workload_pid for x in comparison['aip_only'])
                    or comparison['external_only'] or comparison['external_unparsed']):
                raise Refused('OS component exec did not corroborate without gaps')
        result.update(status='PASS', from_ms=start, to_ms=end,
                      signed_batches=len(records(public / ARCHIVES[0])))
    except Exception as error:
        result['failure'] = {'type': type(error).__name__, 'detail': str(error)}
        raise
    finally:
        cleanup_errors = []
        def cleanup(stage, operation):
            try:
                return operation()
            except Exception as error:
                cleanup_errors.append({'stage': stage, 'type': type(error).__name__, 'detail': str(error)})
                return None
        if component.get('created'):
            cleanup('stop framework', lambda: command(['docker', 'stop', '--time', '0', component['name']], timeout=15))
            if not component.get('output_collected'):
                cleanup('framework output', lambda: collect_framework_output(component, public))
        if audit.started:
            cleanup('failure audit export', lambda: save(public / 'audit-status.json', audit.export(public / 'auditd.log')))
        cleanup('audit close', audit.close)
        cleanup('probe stop', lambda: terminate(probe))
        cleanup('collector stop', lambda: terminate(collector))
        if anchor and all((state / name).exists() for name in ARCHIVES):
            cp = cleanup('final checkpoint', checkpoint)
            if cp:
                cleanup('final archive verification', lambda: save(public / 'verification.json', verify(public, args.tools, anchor, cp)))
        if component.get('created'):
            cleanup('remove framework', lambda: command(['docker', 'rm', '--force', component['name']], timeout=15))
        for stream in streams:
            cleanup('close diagnostic log', stream.close)
        cleanup('unmount workspace', lambda: command(['umount', workload]))
        if cleanup_errors:
            result.update(status='FAILED', cleanup_errors=cleanup_errors)
        save(public / 'result.json', result)
        # Only controlled no-credential component output and daemon diagnostics.
        for name in ('aip-probe.log', 'aip-collector.log'):
            if (private / name).exists():
                shutil.copyfile(private / name, public / name)
    print(json.dumps(result))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
