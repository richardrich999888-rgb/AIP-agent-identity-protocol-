"""Ordinary observer-component controls, never executed framework/kernel evidence."""
import copy
import json
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import hosted_observer_smoke as observer
from evidence import Refused
from hosted_observer_smoke import (framework_options, framework_image_metadata,
                                   framework_report, framework_observation_failures)


class ObservedFrameworkControls(unittest.TestCase):
    def setUp(self):
        self.image = 'sha256:' + 'a' * 64
        self.pin = {'commit': 'b' * 40, 'repository': 'https://github.com/example/framework'}
        self.report = {'framework': 'agent_zero', 'status': 'PASS', 'model_calls': 0,
            'autonomous_workload_executed': False, 'upstream_source_commit': self.pin['commit'],
            'start_gate': {'state': 'RELEASED_CONTROLLER_READONLY_INPUT'},
            'component_child_hold_seconds': 2, 'checks': {'actual_terminal': 'PASS'}}
        self.summary = {'coverage': 'COVERED', 'component_full_sensor_coverage': 'COVERED',
            'launch_instance_events': 2, 'workload_events_by_kind': {'ProcessExec': 1, 'FileEvent': 1},
            'probe_reported_drops': 0, 'events_without_clock_anchor': 0,
            'workload_executions': [{'batch_sequence': 3, 'pid': 17, 'wall_ms': 100}]}
        self.comparison = {'agreed': [{'aip': {'batch_sequence': 3, 'pid': 17, 'wall_ms': 100}}]}

    def test_framework_options_are_paired_and_immutable(self):
        framework_options(None, None)
        framework_options('agent_zero', self.image)
        for framework, image in [('agent_zero', None), (None, self.image), ('unknown', self.image),
                                 ('agent_zero', 'mutable:latest'), ('agent_zero', 'sha256:123')]:
            with self.subTest(framework=framework, image=image), self.assertRaises(Refused):
                framework_options(framework, image)

    def test_image_metadata_uses_exact_source_and_never_exports_environment(self):
        value = {'Id': self.image, 'Os': 'linux', 'Architecture': 'amd64', 'Config': {
            'Labels': {'org.opencontainers.image.revision': self.pin['commit'],
                       'org.opencontainers.image.source': self.pin['repository']},
            'Env': ['PRIVATE_TEST_VALUE=must-not-be-exported']}}
        metadata = framework_image_metadata('agent_zero', self.image, value, self.pin)
        self.assertNotIn('must-not-be-exported', json.dumps(metadata))
        self.assertFalse(metadata['autonomous_workload_executed'])
        self.assertEqual(metadata['model_calls'], 0)
        for mutate in ('image', 'commit', 'repository'):
            wrong = copy.deepcopy(value)
            if mutate == 'image': wrong['Id'] = 'sha256:' + 'c' * 64
            else: wrong['Config']['Labels']['org.opencontainers.image.' + ('revision' if mutate == 'commit' else 'source')] = 'wrong'
            with self.subTest(mutate=mutate), self.assertRaises(Refused):
                framework_image_metadata('agent_zero', self.image, wrong, self.pin)

    def test_report_requires_the_actual_gated_pinned_no_model_contract(self):
        result = framework_report('ordinary log\n' + json.dumps(self.report), 'agent_zero', self.pin['commit'])
        self.assertEqual(result['source_authority'], 'COMPONENT_STDOUT_NOT_SIGNED_KERNEL_EVIDENCE')
        for field, value in [('status', 'FAIL'), ('model_calls', 1), ('model_calls', False),
                             ('autonomous_workload_executed', True), ('upstream_source_commit', 'wrong'),
                             ('start_gate', {'state': 'NOT_REQUESTED'}), ('component_child_hold_seconds', 0)]:
            wrong = {**self.report, field: value}
            with self.subTest(field=field, value=value), self.assertRaises(Refused):
                framework_report(json.dumps(wrong), 'agent_zero', self.pin['commit'])

    def test_network_none_component_passes_without_any_socket_send(self):
        self.assertEqual(framework_observation_failures(self.summary, self.comparison, 0), [])

    def test_host_or_unbound_counts_cannot_satisfy_bound_component_effects(self):
        summary = copy.deepcopy(self.summary)
        summary['workload_events_by_kind'] = {}
        summary['host_events_by_kind'] = {'ProcessExec': 99, 'FileEvent': 99}
        summary['unbound_host_events'] = 198
        failures = framework_observation_failures(summary, self.comparison, 0)
        self.assertIn('no workload-bound ProcessExec', failures)
        self.assertIn('no workload-bound FileEvent', failures)

    def test_launch_instance_other_sensors_and_loss_remain_required(self):
        for field, value in [('launch_instance_events', 0), ('coverage', 'INTEGRITY_UNKNOWN'),
                             ('component_full_sensor_coverage', 'INTEGRITY_UNKNOWN'),
                             ('probe_reported_drops', 1), ('events_without_clock_anchor', 1)]:
            with self.subTest(field=field):
                self.assertTrue(framework_observation_failures({**self.summary, field: value}, self.comparison, 0))

    def test_unexpected_socket_send_or_nonzero_exit_is_a_failure(self):
        summary = copy.deepcopy(self.summary); summary['workload_events_by_kind']['SocketSend'] = 1
        self.assertTrue(framework_observation_failures(summary, self.comparison, 0))
        self.assertTrue(framework_observation_failures(self.summary, self.comparison, 7))

    def test_pid_only_or_reused_batch_agreement_cannot_satisfy_exact_exec_reference(self):
        for changes in ({'pid': 18}, {'batch_sequence': 4}, {'wall_ms': 101}):
            with self.subTest(changes=changes):
                comparison = {'agreed': [{'aip': {**self.comparison['agreed'][0]['aip'], **changes}}]}
                self.assertTrue(framework_observation_failures(self.summary, comparison, 0))
        summary = copy.deepcopy(self.summary)
        summary['workload_executions'] *= 2
        self.assertTrue(framework_observation_failures(summary, self.comparison, 0))

    def test_prepare_uses_restricted_gated_container_and_actual_mount(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); work = root / 'work'; work.mkdir(); public = root / 'public'; public.mkdir()
            control = root / 'input'; component = {}; calls = []
            pins = {'agent_zero': self.pin}
            image = {'Id': self.image, 'Os': 'linux', 'Architecture': 'amd64', 'Config': {'Labels': {
                'org.opencontainers.image.revision': self.pin['commit'],
                'org.opencontainers.image.source': self.pin['repository']}}}
            actual_stat, actual_read = Path.stat, Path.read_text
            launch = {'process': {'pid': 123, 'pid_start_time_ticks': 7, 'boot_id': [1] * 16},
                      'container': {'pid_ns_inode': 11, 'mnt_ns_inode': 22, 'net_ns_inode': 33}}
            def command(args, **kwargs):
                calls.append(args)
                if args[:3] == ['docker', 'image', 'inspect']: return json.dumps([image])
                if args[:2] == ['docker', 'inspect']: return '123\n'
                return ''
            def stat(path, *args, **kwargs):
                return actual_stat(work if str(path) == '/proc/123/root/work' else path, *args, **kwargs)
            def read(path, *args, **kwargs):
                return json.dumps(pins) if path.name == 'frameworks.lock.json' else actual_read(path, *args, **kwargs)
            with patch.object(observer, 'command', side_effect=command), \
                    patch.object(observer, 'proc_identity', return_value=copy.deepcopy(launch)), \
                    patch.object(Path, 'stat', new=stat), patch.object(Path, 'read_text', new=read), \
                    patch.object(Path, 'read_bytes', return_value=b'/opt/framework/.venv/bin/python\0/opt/snifferdog/smoke.py\0'), \
                    patch.object(Path, 'readlink', return_value=Path('/usr/local/bin/python3.12')):
                watch = observer.prepare_framework('agent_zero', self.image, work, control, public, component)
            self.assertEqual(watch, '/proc/123/root/work')
            create = next(args for args in calls if args[:2] == ['docker', 'create'])
            for flag in ('--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only'):
                self.assertIn(flag, create)
            self.assertEqual(create[create.index('--network') + 1], 'none')
            self.assertEqual(create[create.index('--user') + 1], '10001:10001')
            self.assertIn('SNIFFERDOG_SMOKE_START_FILE=/input/start', create)
            self.assertIn('SNIFFERDOG_SMOKE_CHILD_HOLD_SECONDS=2', create)
            self.assertIn(f'type=bind,src={control},dst=/input,readonly', create)
            self.assertNotIn('--env-file', create)
            self.assertTrue(component['created'])
            self.assertFalse((control / 'start').exists())
            self.assertEqual(component['launch']['process'], launch['process'])

    def test_changed_waiting_process_is_refused_before_gate_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            component = {'control': Path(tmp), 'launch': {'process': {'pid': 123, 'pid_start_time_ticks': 7}}}
            with patch.object(observer, 'proc_identity', return_value={'process': {'pid': 123, 'pid_start_time_ticks': 8}}), \
                    patch.object(observer, 'command') as command:
                with self.assertRaises(Refused):
                    observer.run_framework(component, Path(tmp), None, None)
            command.assert_not_called()
            self.assertFalse((Path(tmp) / 'start').exists())

    def test_component_runtime_budget_stops_waiting_and_does_not_publish_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            measured = {'process': {'pid': 123}}
            component = {'control': Path(tmp), 'name': 'fixture', 'launch': measured}
            process = Mock(); process.poll.return_value = None
            with patch.object(observer, 'proc_identity', return_value=measured), \
                    patch.object(observer, 'command', return_value='true\n'), \
                    patch.object(observer.subprocess, 'Popen', return_value=Mock(poll=Mock(return_value=None))), \
                    patch.object(observer.time, 'monotonic', side_effect=[0, 121]), \
                    patch.object(observer, 'collect_framework_output') as collect:
                with self.assertRaisesRegex(Refused, 'runtime budget'):
                    observer.run_framework(component, Path(tmp), process, process)
            collect.assert_not_called()
            self.assertNotIn('exit_code', component)

    def test_output_limit_refuses_unbounded_component_publication(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Mock(stdout=b'x' * (2 * 1024 * 1024 + 1), stderr=b'')
            with patch.object(observer.subprocess, 'run', return_value=output):
                with self.assertRaisesRegex(Refused, 'publication limit'):
                    observer.collect_framework_output({'name': 'fixture'}, Path(tmp))
            self.assertFalse((Path(tmp) / 'framework-component.stdout.txt').exists())

    def invoke_waiter(self, *, output=b'0\n', cli_exit=0, state=None,
                      observer_exit=None, finish_after=3):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        root = Path(tmp.name); control = root / 'input'; control.mkdir()
        public = root / 'public'; public.mkdir()
        measured = {'process': {'pid': 123}}
        component = {'control': control, 'name': 'fixture-container', 'launch': measured,
                     'framework': 'agent_zero', 'metadata': {'upstream_commit': self.pin['commit']}}
        events = []
        class Waiter:
            def __init__(self):
                self.polls = 0
                self.returncode = None
            def poll(self):
                self.polls += 1
                if self.returncode is None and self.polls >= finish_after:
                    self.returncode = cli_exit
                return self.returncode
            def terminate(self):
                events.append('terminate_waiter')
                self.returncode = -15
            def kill(self):
                events.append('kill_waiter')
                self.returncode = -9
            def wait(self, timeout):
                events.append('reap_waiter')
                return self.returncode
        waiter = Waiter()
        def popen(args, **kwargs):
            self.assertEqual(args, ['docker', 'wait', 'fixture-container'])
            self.assertNotEqual(kwargs['stdout'], observer.subprocess.PIPE)
            self.assertNotEqual(kwargs['stderr'], observer.subprocess.PIPE)
            kwargs['stdout'].write(output); kwargs['stdout'].flush()
            return waiter
        def command(args, **kwargs):
            events.append('stop_workload' if args[:2] == ['docker', 'stop'] else 'inspect_state')
            self.assertEqual(kwargs['timeout'], 15)
            return json.dumps({'Running': False, 'ExitCode': 0} if state is None else state)
        probe, collector = Mock(), Mock()
        probe.poll.return_value = observer_exit; collector.poll.return_value = None
        error, code = None, None
        with patch.object(observer, 'proc_identity', return_value=measured), \
                patch.object(observer.subprocess, 'Popen', side_effect=popen) as started, \
                patch.object(observer, 'command', side_effect=command) as commands, \
                patch.object(observer, 'collect_framework_output', return_value=json.dumps(self.report)) as collect, \
                patch.object(observer.time, 'monotonic', return_value=0), \
                patch.object(observer.time, 'sleep'):
            try:
                code = observer.run_framework(component, public, probe, collector)
            except Exception as caught:
                error = caught
        return {'error': error, 'code': code, 'component': component, 'events': events,
                'popen_calls': started.call_count, 'commands': commands.call_args_list,
                'collect_calls': collect.call_count, 'gate_released': (control / 'start').exists()}

    def test_one_waiter_and_one_final_state_inspect_replace_running_cli_polling(self):
        result = self.invoke_waiter()
        self.assertIsNone(result['error'])
        self.assertEqual(result['code'], 0)
        self.assertEqual(result['popen_calls'], 1)
        self.assertEqual(len(result['commands']), 1)
        self.assertEqual(result['commands'][0].args[0][3], '{{json .State}}')
        self.assertEqual(result['collect_calls'], 1)
        self.assertTrue(result['gate_released'])
        self.assertIn('reap_waiter', result['events'])
        self.assertNotIn('stop_workload', result['events'])

    def test_waiter_cli_error_or_malformed_output_cannot_supply_exit_zero(self):
        for kwargs in ({'cli_exit': 1}, {'output': b''}, {'output': b'0\n0\n'}, {'output': b'256\n'}):
            with self.subTest(kwargs=kwargs):
                result = self.invoke_waiter(**kwargs)
                self.assertIsInstance(result['error'], Refused)
                self.assertIsNone(result['code'])
                self.assertEqual(result['collect_calls'], 0)
                self.assertIn('stop_workload', result['events'])

    def test_stale_zero_waiter_requires_actual_stopped_container_state(self):
        for state in ({'Running': True, 'ExitCode': 0}, {'Running': False, 'ExitCode': 7},
                      {'Running': False, 'ExitCode': False}):
            with self.subTest(state=state):
                result = self.invoke_waiter(state=state)
                self.assertIsInstance(result['error'], Refused)
                self.assertNotIn('exit_code', result['component'])
                self.assertEqual(result['collect_calls'], 0)

    def test_observer_failure_stops_workload_before_terminating_and_reaping_waiter(self):
        result = self.invoke_waiter(observer_exit=1, finish_after=100)
        self.assertIsInstance(result['error'], Refused)
        self.assertEqual(result['events'], ['stop_workload', 'terminate_waiter', 'reap_waiter'])
        self.assertEqual(result['collect_calls'], 0)

    def test_waiter_output_limit_fails_and_always_reaps_child(self):
        result = self.invoke_waiter(output=b'0' * 4097, finish_after=100)
        self.assertIsInstance(result['error'], Refused)
        self.assertIn('status limit', str(result['error']))
        self.assertEqual(result['events'], ['stop_workload', 'terminate_waiter', 'reap_waiter'])

    def test_waiter_completed_before_release_does_not_start_framework(self):
        result = self.invoke_waiter(finish_after=1)
        self.assertIsInstance(result['error'], Refused)
        self.assertFalse(result['gate_released'])
        self.assertEqual(result['collect_calls'], 0)

    def test_waiter_ignoring_termination_is_killed_and_reaped_with_short_bounds(self):
        waiter = Mock()
        waiter.poll.return_value = None
        waiter.wait.side_effect = [observer.subprocess.TimeoutExpired('docker wait', 1), -9]
        observer._reap_framework_waiter(waiter)
        waiter.terminate.assert_called_once()
        waiter.kill.assert_called_once()
        self.assertEqual([call.kwargs['timeout'] for call in waiter.wait.call_args_list], [1, 1])

    def invoke_default_main(self, *, primary_failure=False):
        """Drive actual main() control flow; every OS/crypto effect is a fixture."""
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        root = Path(tmp.name); out = root / 'run'; tools = root / 'tools'; tools.mkdir()
        args = SimpleNamespace(tools=tools, out=out, framework=None, framework_image=None)
        audit = Mock(); audit.started = False
        audit.start.side_effect = lambda: setattr(audit, 'started', True)
        audit.close.side_effect = lambda: setattr(audit, 'started', False)
        audit.export.return_value = {'fixture': True}
        actual_read = Path.read_text
        actual_exists = Path.exists
        def exists(path, *args, **kwargs):
            if str(path) == '/sys/kernel/tracing/available_events':
                return True
            return actual_exists(path, *args, **kwargs)
        def read(path, *args, **kwargs):
            if str(path) == '/sys/kernel/tracing/available_events':
                return 'sched:sched_process_exec\ncgroup:cgroup_attach_task\nsock:sock_send_length\n'
            return actual_read(path, *args, **kwargs)
        def command(args, **kwargs):
            if str(args[0]) == 'timedatectl':
                if primary_failure:
                    raise Refused('fixture primary failure')
                return 'yes\n'
            if str(args[0]) == 'umount':
                raise Refused('fixture cleanup failure')
            if Path(args[0]).name == 'aip-corroborate':
                return json.dumps({'agreed': [{'aip': {'pid': 777}}], 'aip_only': [],
                                   'external_only': [], 'external_unparsed': []})
            return ''
        def popen(args, **kwargs):
            name = Path(args[0]).name
            if name == 'aip-probe':
                (out / 'private/probe.key.json').write_text(json.dumps({'public_hex': '11' * 32}))
            elif name == 'aip-collector':
                state = out / 'private/state'
                (state / 'noise.pub').write_text('22' * 32)
                (state / 'observer.pub').write_text('33' * 32)
                for filename in observer.ARCHIVES:
                    (state / filename).write_text('{}\n')
            process = Mock(pid=777)
            process.poll.return_value = None
            process.wait.return_value = 0
            return process
        with patch.object(observer.argparse.ArgumentParser, 'parse_args', return_value=args), \
                patch.object(observer.os, 'geteuid', return_value=0), patch.object(observer.os, 'chown'), \
                patch.dict(observer.os.environ, {'RUNNER_ENVIRONMENT': 'github-hosted'}), \
                patch.object(observer, 'command', side_effect=command), \
                patch.object(observer.subprocess, 'Popen', side_effect=popen), \
                patch.object(observer, 'AuditCrosscheck', return_value=audit), \
                patch.object(observer, 'terminate'), patch.object(observer.time, 'sleep'), \
                patch.object(observer, 'records', return_value=[{'health': {'attested_coverage': {'to_ms': 100}}}]), \
                patch.object(observer, 'covered', return_value=True), patch.object(observer, 'verify', return_value={}), \
                patch.object(observer, 'tamper', return_value={}), patch.object(observer, 'now', return_value=20), \
                patch.object(Path, 'exists', new=exists), \
                patch.object(Path, 'read_text', new=read), patch('builtins.print'):
            if primary_failure:
                with self.assertRaisesRegex(Refused, 'fixture primary failure'):
                    observer.main()
                code = None
            else:
                code = observer.main()
        return code, json.loads((out / 'public/result.json').read_text())

    def test_cleanup_only_failure_is_preserved_and_returns_nonzero(self):
        code, result = self.invoke_default_main()
        self.assertEqual(code, 1)
        self.assertEqual(result['status'], 'FAILED')
        self.assertNotIn('failure', result)  # all primary component stages passed
        self.assertTrue(any(e['stage'] == 'unmount workspace' for e in result['cleanup_errors']))

    def test_cleanup_fixture_is_independent_of_unreadable_host_tracefs(self):
        actual_exists = Path.exists
        trace_queries = []
        def denied_tracefs(path, *args, **kwargs):
            if str(path) == '/sys/kernel/tracing/available_events':
                trace_queries.append(path)
                raise PermissionError(13, 'controlled inaccessible host tracefs')
            return actual_exists(path, *args, **kwargs)
        with patch.object(Path, 'exists', new=denied_tracefs):
            code, result = self.invoke_default_main()
        self.assertEqual(trace_queries, [])
        self.assertEqual(code, 1)
        self.assertEqual(result['status'], 'FAILED')
        self.assertNotIn('failure', result)
        self.assertTrue(result['cleanup_errors'])

    def test_primary_failure_is_not_replaced_by_cleanup_or_return_code(self):
        code, result = self.invoke_default_main(primary_failure=True)
        self.assertIsNone(code)
        self.assertEqual(result['failure']['detail'], 'fixture primary failure')
        self.assertEqual(result['status'], 'FAILED')
        self.assertTrue(result['cleanup_errors'])

    def test_unresolved_external_or_unparsed_execs_are_not_silently_dropped(self):
        for field in ('external_only', 'external_unparsed'):
            with self.subTest(field=field):
                self.assertTrue(framework_observation_failures(self.summary, {**self.comparison, field: [{}]}, 0))


if __name__ == '__main__':
    unittest.main()
