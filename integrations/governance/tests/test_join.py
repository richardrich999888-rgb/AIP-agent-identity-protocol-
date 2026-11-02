"""Controlled broker fixtures, not live peer, policy-engine or signing evidence."""
import json
from pathlib import Path
import socket
import struct
import tempfile
import threading
import time
import sys
from unittest.mock import Mock, patch
import unittest
from contextlib import nullcontext

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'validation/enterprise'))
from same_run_validation import AuthorityBroker


class PolicySigningBoundary(unittest.TestCase):
    def broker(self, allowed):
        broker = object.__new__(AuthorityBroker)
        broker.process = Mock(pid=1234)
        broker.process.poll.return_value = None
        broker.binary = Path('/trusted/signer')
        broker.config = {'agent_id': 'controlled-agent', 'authority_config_path': '/private/config'}
        broker.allowed_calls = [{'tool_id': 'same-run-loan-read', 'arguments': {'loan_id': 1, 'amount': 0}}]
        broker.governance = Mock()
        broker.governance.evaluate_policy.return_value = allowed
        broker.governance.phase.side_effect = lambda *_: nullcontext({})
        peer = Mock()
        peer.getsockopt.return_value = struct.pack('3i', 1234, 10001, 10001)
        peer.recv.return_value = json.dumps(broker.allowed_calls[0]).encode() + b'\n'
        context = Mock()
        context.__enter__ = Mock(return_value=peer)
        context.__exit__ = Mock(return_value=False)
        broker.connection = Mock()
        broker.connection.accept.return_value = (context, None)
        broker.failure = None
        broker.expectation = None
        return broker, peer

    def test_policy_denial_never_reaches_the_aip_signer(self):
        broker, peer = self.broker(False)
        with patch.object(socket, 'SO_PEERCRED', 17, create=True), \
                patch('same_run_validation.subprocess.run') as signer:
            broker.run()
        signer.assert_not_called()
        peer.sendall.assert_called_once_with(b'{"authorized":false}\n')
        self.assertIsNone(broker.expectation)
        self.assertIn('policy engine denied', broker.failure)
        broker.governance.link_authorization.assert_not_called()

    def test_policy_allow_does_not_override_an_aip_signer_denial(self):
        broker, peer = self.broker(True)
        with patch.object(socket, 'SO_PEERCRED', 17, create=True), \
                patch('same_run_validation.subprocess.run', return_value=Mock(returncode=1)) as signer:
            broker.run()
        signer.assert_called_once()
        peer.sendall.assert_called_once_with(b'{"authorized":false}\n')
        self.assertIsNone(broker.expectation)
        self.assertIn('authority denied', broker.failure)
        broker.governance.link_authorization.assert_not_called()


class ControllerPublicationBoundary(unittest.TestCase):
    def test_privacy_veto_precedes_controller_record_publication(self):
        sys.path.insert(0, str(ROOT))
        from integrations.governance.run import GovernanceRun
        from integrations.governance import telemetry
        with tempfile.TemporaryDirectory() as directory:
            run = object.__new__(GovernanceRun)
            run.public = Path(directory)
            run.assets = Path(directory)
            run.run_id = 'same-run-' + 'a' * 24
            run.lock = threading.Lock()
            now = time.time_ns()
            run.started = now - 10000
            run.records = [{'phase': 'aip.agent.execution',
                'start_time_unix_nano': now - 9000, 'end_time_unix_nano': now - 8000,
                'attributes': {'aip.run_id': run.run_id,
                    'aip.source_authority': 'ROOT_CONTROLLER_APPLICATION_TELEMETRY',
                    'aip.error.type': 'private-value-must-not-be-published'}}]
            with patch.object(telemetry, 'export_records') as export, self.assertRaises(ValueError):
                run.finalize({'status': 'FAIL'})
            export.assert_not_called()
            self.assertEqual(list(run.public.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
