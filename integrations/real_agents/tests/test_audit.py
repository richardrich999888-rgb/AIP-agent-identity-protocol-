"""Unit fixtures only; live audit acceptance is a separate Linux gate."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from audit_crosscheck import AuditCrosscheck, parse_status
from evidence import Refused

ACTIVE = 'enabled 1\npid 20\nlost 0\nbacklog 0\n'

class AuditTests(unittest.TestCase):
    def test_disabled_locked_or_incomplete_audit_refused(self):
        for text in ('', ACTIVE.replace('enabled 1', 'enabled 0'),
                     ACTIVE.replace('enabled 1', 'enabled 2'), ACTIVE.replace('pid 20', 'pid 0')):
            with self.assertRaises(Refused):
                parse_status(text)

    def test_own_rule_only_is_removed(self):
        audit = AuditCrosscheck()
        with patch('audit_crosscheck.command', side_effect=[ACTIVE, '', audit.key, '']) as cmd:
            audit.start()
            audit.close()
        calls = [x.args[0] for x in cmd.call_args_list]
        self.assertEqual(calls[1][2:], calls[-1][2:])
        self.assertEqual(calls[-1][:2], ['auditctl', '-d'])
        self.assertNotIn('-D', sum(calls, []))

    def test_loss_or_daemon_restart_refuses_export(self):
        for final in (ACTIVE.replace('lost 0','lost 1'), ACTIVE.replace('pid 20','pid 21')):
            audit = AuditCrosscheck(); audit.initial = parse_status(ACTIVE)
            with patch('audit_crosscheck.command', return_value=final), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(Refused):
                    audit.export(Path(tmp, 'audit.log'))
                self.assertFalse(Path(tmp, 'audit.log').exists())

    def test_no_syscalls_is_not_success(self):
        audit = AuditCrosscheck(); audit.initial = parse_status(ACTIVE)
        with patch('audit_crosscheck.command', side_effect=[ACTIVE, '<no matches>']):
            with self.assertRaises(Refused):
                audit.export('/not-written')
