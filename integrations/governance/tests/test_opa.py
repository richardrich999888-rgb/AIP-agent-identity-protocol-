"""Policy controls; real-engine tests require an explicitly prepared pinned binary.

Controlled policy inputs here are not a live SO_PEERCRED observation or AIP
signed authorization. No unit fixture result is used as engine validation.
"""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from integrations.governance import opa

PROPOSAL = {'tool_id': 'same-run-loan-read', 'arguments': {'loan_id': 1, 'amount': 0}}


def context():
    return dict(proposal=copy.deepcopy(PROPOSAL), agent_id='AID:controlled-policy-component',
        peer_pid=1234, peer_uid=10001, peer_gid=10001,
        expected_pid=1234, expected_uid=10001, expected_gid=10001,
        allowed_calls=[copy.deepcopy(PROPOSAL)])


class FailClosedControls(unittest.TestCase):
    def test_bool_numeric_extra_arguments_and_identity_injection_are_denied_before_engine(self):
        for change in ({'loan_id': True, 'amount': 0}, {'loan_id': 1.0, 'amount': 0},
                       {'loan_id': 1, 'amount': False}, {'loan_id': 1, 'amount': 0, 'extra': 1}, {}):
            request = context(); request['proposal']['arguments'] = change
            with self.subTest(arguments=change), patch.object(opa, '_invoke') as run:
                result = opa.evaluate('/does-not-exist', **request)
                self.assertIs(result['allowed'], False)
                self.assertEqual(result['status'], 'INVALID_INPUT')
                run.assert_not_called()
        request = context(); request['proposal']['agent_id'] = 'injected'
        self.assertEqual(opa.evaluate('/does-not-exist', **request)['status'], 'INVALID_INPUT')
        for key, value in (('peer_pid', True), ('peer_uid', 10001.0), ('agent_id', ''), ('allowed_calls', [])):
            request = context(); request[key] = value
            self.assertIs(opa.evaluate('/does-not-exist', **request)['allowed'], False)

    def test_missing_mismatched_or_symlink_engine_cannot_allow(self):
        self.assertEqual(opa.evaluate('/does-not-exist', **context())['status'], 'ENGINE_ERROR')
        with tempfile.TemporaryDirectory() as tmp:
            wrong = Path(tmp) / 'wrong'; wrong.write_bytes(b'not an OPA binary'); wrong.chmod(0o555)
            link = Path(tmp) / 'link'; link.symlink_to(wrong)
            for path in (wrong, link):
                with self.subTest(path=path):
                    with self.assertRaises((opa.OPAError, OSError)): opa.verify_engine(path)
                    self.assertIs(opa.evaluate(path, **context())['allowed'], False)

    def test_nonboolean_undefined_error_and_oversized_outputs_never_allow(self):
        # Deliberate negative subprocess fixtures, not actual engine evidence.
        identity = {'version': 'fixture-only', 'sha256': '0'*64}
        for code, output in ((0, b'1'), (0, b'"true"'), (0, b'[true]'), (0, b'null'),
                             (0, b''), (0, b'true\nfalse'), (0, b'true' + b' '*4096), (1, b'true'), (False, b'true'), (2, b'{}')):
            with self.subTest(code=code, output=output), patch.object(opa, 'verify_engine', return_value=identity), \
                    patch.object(opa, '_invoke', return_value=(code, output)):
                result = opa.evaluate('fixture-only', **context())
                self.assertIs(result['allowed'], False)
                self.assertEqual(result['status'], 'ENGINE_ERROR')
        for error in (subprocess.TimeoutExpired('fixture', 3), OSError('fixture'), opa.OPAError('fixture')):
            with self.subTest(error=type(error).__name__), patch.object(opa, 'verify_engine', return_value=identity), \
                    patch.object(opa, '_invoke', side_effect=error):
                self.assertIs(opa.evaluate('fixture-only', **context())['allowed'], False)

    def test_changed_policy_is_refused_even_with_valid_asset_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = Path(tmp) / 'policy.rego'; policy.write_text('package injected\nallow := true\n')
            with patch.object(opa, 'POLICY_PATH', policy), \
                    patch.object(opa, 'verify_engine', return_value={'version': 'fixture', 'sha256': '0'*64}), \
                    patch.object(opa, '_invoke') as run:
                result = opa.evaluate('fixture-only', **context())
            self.assertIs(result['allowed'], False); run.assert_not_called()


@unittest.skipUnless(os.environ.get('AIP_OPA_BINARY'), 'actual pinned OPA binary not supplied; real engine gate NOT EXERCISED')
class RealOPAComponent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = Path(os.environ['AIP_OPA_BINARY'])
        cls.identity = opa.verify_engine(cls.engine)

    def test_real_engine_allows_exact_configured_call_only(self):
        result = opa.evaluate(self.engine, **context())
        self.assertIs(result['allowed'], True); self.assertEqual(result['status'], 'ALLOW')
        self.assertTrue(result['not_signed']); self.assertIs(result['aip_authorization'], False)
        for field in ('engine_sha256', 'policy_sha256', 'input_sha256', 'policy_data_sha256', 'output_sha256'):
            self.assertRegex(result[field], r'^[0-9a-f]{64}$')
        self.assertNotIn('proposal', result); self.assertNotIn('agent_id', result)

    def test_real_engine_denies_wrong_record_tool_amount_and_peer(self):
        variants = []
        for key, value in (('loan_id', 2), ('amount', 1)):
            request = context(); request['proposal']['arguments'][key] = value; variants.append(request)
        request = context(); request['proposal']['tool_id'] = 'unconfigured-tool'; variants.append(request)
        for key in ('peer_pid', 'peer_uid', 'peer_gid'):
            request = context(); request[key] += 1; variants.append(request)
        request = context(); request['allowed_calls'][0]['tool_id'] = 'different-root-tool'; variants.append(request)
        for request in variants:
            with self.subTest(request=request):
                result = opa.evaluate(self.engine, **request)
                self.assertIs(result['allowed'], False); self.assertEqual(result['status'], 'DENY')
                self.assertIn('output_sha256', result)  # Actual engine executed, not a local precheck.

    def test_actual_rego_default_denies_bool_and_extra_arguments_too(self):
        # Exercise Rego directly as well as the stricter integer-only adapter.
        request = context()
        raw, data = opa._request(request['proposal'], request['agent_id'],
            {'pid':1234,'uid':10001,'gid':10001}, {'pid':1234,'uid':10001,'gid':10001}, request['allowed_calls'])
        for arguments in ({'loan_id':True,'amount':0}, {'loan_id':1,'amount':False},
                          {'loan_id':1,'amount':0,'extra':1}):
            value = json.loads(raw); value['proposal']['arguments'] = arguments
            code, output = opa._invoke(self.engine, opa.canonical(value), data)
            self.assertEqual(code, 0); self.assertIs(json.loads(output), False)
        value = json.loads(raw); value['agent_id'] = 'unconfigured-agent'
        code, output = opa._invoke(self.engine, opa.canonical(value), data)
        self.assertEqual(code, 0); self.assertIs(json.loads(output), False)

    def test_cached_preparation_verifies_real_binary_and_license_without_network(self):
        license_source = self.engine.parent / 'OPA-LICENSE.txt'
        self.assertTrue(license_source.is_file(), 'real prepared asset directory must retain its license')
        asset = opa.asset_for_platform()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / ('opa-' + asset['version'] + '-' + asset['platform'])
            os.link(self.engine, path)
            license_target = root / 'OPA-LICENSE.txt'
            license_target.write_bytes(license_source.read_bytes()); license_target.chmod(0o444)
            with patch.object(opa.urllib.request, 'urlopen', side_effect=AssertionError('cached bootstrap must stay offline')):
                self.assertEqual(opa.prepare_engine(root), path)
                self.assertEqual(opa.verify_engine(path)['sha256'], self.identity['sha256'])

    def test_offline_verify_and_evaluate_do_not_download(self):
        with patch.object(opa.urllib.request, 'urlopen', side_effect=AssertionError('runtime download forbidden')):
            self.assertFalse(opa.verify_engine(self.engine)['network_used'])
            self.assertIs(opa.evaluate(self.engine, **context())['allowed'], True)


if __name__ == '__main__':
    unittest.main()
