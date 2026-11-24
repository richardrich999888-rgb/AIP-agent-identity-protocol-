"""Optional policy gate and controller telemetry; never a new evidence authority."""
from contextlib import contextmanager
import hashlib
import json
import re
from pathlib import Path
import threading
import time

PHASES = frozenset(('aip.governance.policy', 'aip.authorization.issue',
    'aip.agent.execution', 'aip.evidence.verify', 'aip.enterprise.clients', 'aip.run'))
ATTRIBUTES = frozenset(('aip.run_id', 'aip.source_authority', 'aip.policy.allowed',
    'aip.policy.sha256', 'aip.policy.engine.sha256', 'aip.authorization.decision_id',
    'aip.authorization.expectation_sha256', 'aip.evidence.bundle_sha256',
    'aip.evidence.signed_reconciliation_sha256', 'aip.kernel.coverage_status',
    'aip.controller.status', 'aip.error.type'))
SOURCE = 'ROOT_CONTROLLER_APPLICATION_TELEMETRY'


def save(path, value):
    path = Path(path)
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')
    path.chmod(0o644)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


class GovernanceRun:
    def __init__(self, assets, public, run_id):
        from . import opa, telemetry
        if type(run_id) is not str or re.fullmatch(r'same-run-[0-9a-f]{24}', run_id) is None:
            raise ValueError('requires the fixed controlled-run identifier format')
        self.assets = Path(assets).resolve(strict=True)
        manifest = json.loads((self.assets / 'assets-manifest.json').read_text())
        relative = Path(manifest['opa_engine'])
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('governance binary reference must stay inside prepared assets')
        self.engine = (self.assets / relative).resolve(strict=True)
        if not self.engine.is_relative_to(self.assets):
            raise ValueError('governance binary reference escapes prepared assets')
        opa.verify_engine(self.engine)
        telemetry.verify_telemetry(self.assets / 'otel')
        self.public = Path(public)
        self.public.mkdir(mode=0o755)
        self.run_id = run_id
        self.records = []
        self.lock = threading.Lock()
        self.policy_result = None
        self.started = time.time_ns()

    @contextmanager
    def phase(self, name, attributes=None):
        if name not in PHASES:
            raise ValueError('unreviewed governance trace phase')
        values = dict(attributes or {})
        if set(values) - ATTRIBUTES:
            raise ValueError('unreviewed governance trace attribute')
        values.update({'aip.run_id': self.run_id, 'aip.source_authority': SOURCE})
        start = time.time_ns()
        try:
            yield values
        except BaseException as error:
            values['aip.error.type'] = type(error).__name__
            values['aip.controller.status'] = 'ERROR'
            raise
        finally:
            end = time.time_ns()
            if set(values) - ATTRIBUTES or end < start:
                raise ValueError('invalid controller phase record')
            record = {'phase': name, 'start_time_unix_nano': start,
                      'end_time_unix_nano': end, 'attributes': values}
            with self.lock:
                if len(self.records) >= 32:
                    raise ValueError('controller phase record bound exceeded')
                self.records.append(record)

    def evaluate_policy(self, *, proposal, agent_id, peer_pid, peer_uid, peer_gid,
                        expected_pid, allowed_calls):
        from . import opa
        with self.phase('aip.governance.policy') as attributes:
            result = opa.evaluate(self.engine, proposal=proposal, agent_id=agent_id,
                peer_pid=peer_pid, peer_uid=peer_uid, peer_gid=peer_gid,
                expected_pid=expected_pid, expected_uid=10001, expected_gid=10001,
                allowed_calls=allowed_calls)
            if type(result) is not dict or type(result.get('allowed')) is not bool:
                raise ValueError('policy engine did not return a strict boolean decision')
            if result['allowed'] is True and result.get('status') != 'ALLOW':
                raise ValueError('policy approval requires a completed OPA evaluation')
            self.policy_result = dict(result)
            self.policy_result.update({'source_authority': 'ROOT_CONTROLLER_GATE_WITH_PINNED_OPA',
                'policy_engine_completed': result.get('status') in ('ALLOW', 'DENY'),
                'run_id': self.run_id, 'signed_authorization': False,
                'kernel_observation': False})
            save(self.public / 'opa-decision.json', self.policy_result)
            attributes['aip.policy.allowed'] = result['allowed']
            if 'policy_sha256' in result:
                attributes['aip.policy.sha256'] = result['policy_sha256']
            if 'engine_sha256' in result:
                attributes['aip.policy.engine.sha256'] = result['engine_sha256']
            return result['allowed']

    def link_authorization(self, decision_id, expectation_path):
        if type(decision_id) is not str or re.fullmatch(r'[0-9a-f]{32}', decision_id) is None:
            raise ValueError('requires the existing AIP decision identifier format')
        if not self.policy_result or self.policy_result['allowed'] is not True:
            raise ValueError('cannot link authorization without a permitted policy result')
        self.policy_result.update({'aip_decision_id': decision_id,
            'aip_expectation_file_sha256': digest(expectation_path),
            'link_authority': 'ROOT_CONTROLLER_CORRELATION_NOT_A_NEW_SIGNATURE'})
        save(self.public / 'opa-decision.json', self.policy_result)
        with self.lock:
            for record in reversed(self.records):
                if record['phase'] == 'aip.authorization.issue':
                    record['attributes'].update({
                        'aip.authorization.decision_id': decision_id,
                        'aip.authorization.expectation_sha256': self.policy_result['aip_expectation_file_sha256']})
                    break

    def finalize(self, result):
        from . import telemetry
        end = time.time_ns()
        with self.lock:
            records = [*self.records, {'phase': 'aip.run',
                'start_time_unix_nano': self.started, 'end_time_unix_nano': end,
                'attributes': {'aip.run_id': self.run_id, 'aip.source_authority': SOURCE,
                    'aip.controller.status': result['status'],
                    'aip.kernel.coverage_status': result.get('observation_coverage', 'NOT_ESTABLISHED')}}]
        records = telemetry.validate_records(records)
        save(self.public / 'controller-phase-records.json', {
            'classification': SOURCE, 'capture': 'ACTUAL_CONTROLLER_OPERATION_TIMESTAMPS',
            'export': 'DELAYED_BATCH_AFTER_WORKLOAD_CLEANUP',
            'kernel_evidence': False, 'records': records})
        exported = telemetry.export_records(self.assets / 'otel', records, self.public / 'otel',
            private_dir=self.public.parent.parent / 'private/governance-telemetry')
        if type(exported) is not dict or exported.get('status') != 'PASS':
            raise ValueError('actual OpenTelemetry collector round trip did not pass')
        report = {'classification': 'OPEN_SOURCE_POLICY_AND_OBSERVABILITY_INTEGRATION',
            'run_id': self.run_id, 'controller_result': result['status'],
            'policy_allowed': bool(self.policy_result and self.policy_result.get('allowed') is True),
            'policy_linked_to_aip_decision': bool(self.policy_result and self.policy_result.get('aip_decision_id')),
            'telemetry': exported, 'aip_verification_rules': 'UNCHANGED',
            'telemetry_is_kernel_evidence': False, 'policy_audit_is_signed_authorization': False,
            'independent_administrative_custody': 'NOT_ESTABLISHED',
            'regulatory_or_production_approval': 'NOT_ESTABLISHED'}
        save(self.public / 'integration-report.json', report)
        return report
