"""Browser diagnostic boundaries; these mocks establish no browser execution."""
import json
from pathlib import Path
import sys
import tempfile
from types import ModuleType
import unittest
from unittest import mock

from run_client_smoke import BROWSER_TIMEOUT_MS, check_console, write_progress


class ConsoleProgressTests(unittest.TestCase):
    def exercise(self, failure_stage=None, *, mismatched_json=False):
        parent = ModuleType('playwright'); parent.__path__ = []
        api = ModuleType('playwright.sync_api')
        runtime = mock.Mock()
        context = mock.MagicMock()
        context.__enter__.return_value = runtime
        api.sync_playwright = mock.Mock(return_value=context)
        page = runtime.chromium.launch.return_value.new_page.return_value
        locators = {}
        page.locator.side_effect = lambda selector: locators.setdefault(selector, mock.Mock())
        credential = locators.setdefault('#credential', mock.Mock())
        credential.input_value.return_value = ''
        status = locators.setdefault('#status', mock.Mock())
        run = locators.setdefault('#run', mock.Mock())
        status_expect, run_expect = mock.Mock(), mock.Mock()
        api.expect = mock.Mock(side_effect=lambda locator: status_expect if locator is status else run_expect)
        secret = 'reader-secret-response-body-must-stay-private'
        if failure_stage == 'connect':
            status_expect.to_have_text.side_effect = TimeoutError(secret)
        elif failure_stage == 'query':
            run_expect.to_contain_text.side_effect = TimeoutError(secret)
        admitted = {'run_artifact_id': 'actual-artifact', 'evaluation': {'result': 'CannotProve'}}
        displayed = {'metadata': admitted, 'evaluation': admitted['evaluation'], 'signed_verdict': None}
        if mismatched_json:
            displayed['evaluation'] = {'result': 'unsupported-upgrade'}
        run.inner_text.return_value = json.dumps(displayed)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'client-progress.json'
            def progress(stage, *, error=None):
                write_progress(path, stage, error=error)
            expected = AssertionError if mismatched_json else TimeoutError
            with mock.patch.dict(sys.modules, {'playwright': parent, 'playwright.sync_api': api}):
                with self.assertRaises(expected):
                    check_console('http://127.0.0.1:1', secret, 'actual-artifact', admitted, {}, None, progress)
            record = json.loads(path.read_text())
            self.assertNotIn(secret, path.read_text())
            self.assertNotIn('message', record)
            self.assertEqual(record['status'], 'FAIL')
            self.assertEqual(record['configured_browser_timeout_ms'], BROWSER_TIMEOUT_MS)
        return record, status_expect, run_expect

    def test_connect_timeout_retains_fixed_location_without_credentials_or_body(self):
        record, status, _ = self.exercise('connect')
        self.assertEqual(record['stage'], 'CONSOLE_BROWSER_CONNECT_READY')
        self.assertEqual(record['error_class'], 'TimeoutError')
        self.assertEqual(status.to_have_text.call_args.kwargs['timeout'], 30_000)

    def test_query_timeout_is_distinct_and_retains_no_exception_message(self):
        record, _, run = self.exercise('query')
        self.assertEqual(record['stage'], 'CONSOLE_BROWSER_QUERY_READY')
        self.assertEqual(record['error_class'], 'TimeoutError')
        self.assertEqual(run.to_contain_text.call_args.kwargs['timeout'], 30_000)

    def test_artifact_id_presence_cannot_hide_changed_rendered_evaluation(self):
        record, _, _ = self.exercise(mismatched_json=True)
        self.assertEqual(record['stage'], 'CONSOLE_BROWSER_EXACT_MATCH')
        self.assertEqual(record['error_class'], 'AssertionError')

    def test_arbitrary_exception_class_names_and_progress_stages_are_not_published(self):
        secret = 'credential-material'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'progress.json'
            write_progress(path, 'CONSOLE_BROWSER_QUERY_READY', error=type(secret, (Exception,), {})(secret))
            self.assertEqual(json.loads(path.read_text())['error_class'], 'OtherError')
            self.assertNotIn(secret, path.read_text())
            original = path.read_bytes()
            with self.assertRaisesRegex(ValueError, '^unknown client progress stage$'):
                write_progress(path, secret)
            self.assertEqual(path.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
