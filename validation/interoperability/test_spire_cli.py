#!/usr/bin/env python3
"""Portable regressions for the exact pinned SPIRE 1.15.3 CLI response."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import traceback
import unittest
from unittest.mock import Mock, patch


SCRIPT = Path(__file__).resolve().parents[2] / "integrations/interoperability/examples/spire_jwt_live.py"
SPEC = importlib.util.spec_from_file_location("spire_jwt_live", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SpireTokenResponseTests(unittest.TestCase):
    def test_missing_spiffe_id_warning_is_not_part_of_the_join_token(self):
        # Exact upstream v1.15.3 generate_test.go fixture, not a live credential.
        response = "Token: token\nWarning: Missing SPIFFE ID.\n"
        self.assertEqual(MODULE.parse_join_token(response), "token")

    def test_token_line_without_a_warning_is_accepted(self):
        self.assertEqual(MODULE.parse_join_token("Token: token\n"), "token")

    def test_missing_duplicate_or_malformed_token_is_refused_without_echo(self):
        responses = [
            "",
            "Warning: Missing SPIFFE ID.\n",
            "Token: \n",
            "Token: token\nToken: other\n",
            "Token: token\nToken: \n",
            "Token: token with spaces\n",
            "Token: token\tvalue\n",
            "Token: token\x00value\n",
            "Token: tokené\n",
            "Token: " + "a" * 1025 + "\n",
        ]
        for index, response in enumerate(responses):
            with self.subTest(case=index):
                output = io.StringIO()
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                    with self.assertRaisesRegex(ValueError, "^invalid SPIRE join-token response$"):
                        MODULE.parse_join_token(response)
                self.assertEqual(output.getvalue(), "")


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, duration):
        # Assert the deadline property on every sleep, including the last one.
        assert self.now < 60.0
        assert 0 < duration <= 60.0 - self.now
        self.sleeps.append((self.now, duration))
        self.now += duration


class SpireReadinessTests(unittest.TestCase):
    def await_with(self, clock, call, processes=None):
        if processes is None:
            processes = [Mock(poll=Mock(return_value=None)), Mock(poll=Mock(return_value=None))]
        with patch.object(MODULE.time, "monotonic", clock.monotonic), \
                patch.object(MODULE.time, "sleep", clock.sleep), \
                patch.object(MODULE.subprocess, "run", side_effect=call):
            return MODULE.await_jwt_svid("/synthetic/spire-agent", "/synthetic/api.sock", processes)

    def check_call_bound(self, clock, kwargs):
        self.assertGreater(kwargs["timeout"], 0)
        self.assertLessEqual(kwargs["timeout"], 15.0)
        self.assertLessEqual(kwargs["timeout"], 60.0 - clock.now)
        self.assertEqual(kwargs["stderr"], subprocess.PIPE)
        self.assertFalse(kwargs["check"])

    def test_delayed_readiness_after_old_six_second_window_is_accepted(self):
        clock = FakeClock()
        # This exercises polling only, never JWT signature/trust verification.
        response = [{"svids": [{"svid": "not-a-real-jwt"}]}, {}]
        def call(arguments, **kwargs):
            self.check_call_bound(clock, kwargs)
            clock.now += min(0.05, kwargs["timeout"])
            ready = clock.now >= 8.0
            return subprocess.CompletedProcess(arguments, 0 if ready else 1,
                stdout=json.dumps(response) if ready else "", stderr="discarded synthetic diagnostic")
        fetched, diagnostics = self.await_with(clock, call)
        self.assertEqual(fetched, response)
        self.assertGreaterEqual(diagnostics["elapsed_ms"], 8000)
        self.assertLess(diagnostics["elapsed_ms"], 60000)
        self.assertEqual(diagnostics["result_class"], "cli_json_ready")
        self.assertEqual(diagnostics["last_error_class"], "none")
        self.assertEqual(diagnostics["last_returncode"], 0)
        self.assertEqual(diagnostics["process_returncodes"], [None, None])
        self.assertGreater(diagnostics["attempts"], 30)

    def test_permanent_cli_failure_times_out_without_sleeping_past_deadline(self):
        clock = FakeClock()
        calls = []
        def call(arguments, **kwargs):
            self.check_call_bound(clock, kwargs)
            calls.append(kwargs["timeout"])
            clock.now += min(0.05, kwargs["timeout"])
            return subprocess.CompletedProcess(arguments, 7, stdout="",
                stderr="rpc error: code = PermissionDenied desc = no identity issued\n")
        with self.assertRaises(MODULE.SpireReadinessError) as caught:
            self.await_with(clock, call)
        diagnostics = caught.exception.diagnostics
        self.assertEqual(clock.now, 60.0)
        self.assertEqual(diagnostics["elapsed_ms"], 60000)
        self.assertEqual(diagnostics["result_class"], "readiness_timeout")
        self.assertEqual(diagnostics["last_error_class"], "no_identity_issued")
        self.assertEqual(diagnostics["last_returncode"], 7)
        self.assertEqual(diagnostics["attempts"], len(calls))

    def test_individual_call_timeouts_use_only_remaining_deadline(self):
        clock = FakeClock()
        calls = []
        def call(arguments, **kwargs):
            self.check_call_bound(clock, kwargs)
            calls.append(kwargs["timeout"])
            clock.now += kwargs["timeout"]
            raise subprocess.TimeoutExpired(arguments, kwargs["timeout"], output="not retained", stderr="not retained")
        with self.assertRaises(MODULE.SpireReadinessError) as caught:
            self.await_with(clock, call)
        self.assertEqual(clock.now, 60.0)
        self.assertEqual(len(calls), 4)
        self.assertLess(calls[-1], 15.0)
        self.assertEqual(len(clock.sleeps), 3)
        self.assertEqual(caught.exception.diagnostics["last_error_class"], "fetch_timeout")
        self.assertIsNone(caught.exception.diagnostics["last_returncode"])

    def test_process_death_is_refused_before_call_or_before_returning_success(self):
        for initially_dead in (True, False):
            with self.subTest(initially_dead=initially_dead):
                clock = FakeClock()
                process = Mock(poll=Mock(side_effect=lambda: 9 if initially_dead or clock.now else None))
                call = Mock(side_effect=lambda arguments, **kwargs: self.success_after_call(clock, arguments))
                with self.assertRaises(MODULE.SpireReadinessError) as caught:
                    self.await_with(clock, call, [process])
                self.assertEqual(caught.exception.diagnostics["result_class"], "process_exited")
                self.assertEqual(caught.exception.diagnostics["process_returncodes"], [9])
                self.assertEqual(caught.exception.diagnostics["attempts"], 0 if initially_dead else 1)
                self.assertEqual(call.call_count, 0 if initially_dead else 1)
                self.assertEqual(clock.sleeps, [])

    @staticmethod
    def success_after_call(clock, arguments):
        clock.now += 0.1
        return subprocess.CompletedProcess(arguments, 0, stdout="[]")

    def test_failure_diagnostics_and_tracebacks_never_retain_cli_secrets(self):
        secret = "synthetic-sensitive-jwt-join-token-and-private-log-marker"
        for failure in ("nonzero", "timeout", "invalid_json", "execution_error"):
            with self.subTest(failure=failure):
                clock, output = FakeClock(), io.StringIO()
                def call(arguments, **kwargs):
                    self.check_call_bound(clock, kwargs)
                    clock.now += kwargs["timeout"]
                    if failure == "timeout":
                        raise subprocess.TimeoutExpired(arguments, kwargs["timeout"], output=secret, stderr=secret)
                    if failure == "execution_error":
                        raise OSError(secret)
                    return subprocess.CompletedProcess(arguments, 3 if failure == "nonzero" else 0,
                        stdout=secret, stderr=secret)
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                    try:
                        self.await_with(clock, call)
                    except MODULE.SpireReadinessError as error:
                        retained = json.dumps(error.diagnostics) + str(error) + traceback.format_exc()
                        if failure == "nonzero":
                            self.assertEqual(error.diagnostics["last_error_class"], "unclassified_cli_failure")
                    else:
                        self.fail("sensitive invalid output was accepted")
                self.assertNotIn(secret, retained)
                self.assertEqual(output.getvalue(), "")

    def test_stderr_classifier_retains_only_allowlisted_categories(self):
        secret = "synthetic-sensitive-jwt-join-token-and-private-log-marker"
        cases = [
            ("rpc error: code = PermissionDenied desc = no identity issued\n" + secret,
             "no_identity_issued"),
            ("rpc error: code = Unavailable desc = workload attestation failed\n" + secret,
             "connection_refused_or_unavailable"),
            ("dial unix /synthetic/api.sock: connect: connection refused\n" + secret,
             "connection_refused_or_unavailable"),
            ("rpc error: code = PermissionDenied desc = " + secret, "permission_denied"),
            ("open /synthetic/api.sock: permission denied\n" + secret, "permission_denied"),
            (secret, "unclassified_cli_failure"),
            ("", "unclassified_cli_failure"),
            (None, "unclassified_cli_failure"),
            ("x" * 4096 + "rpc error: code = PermissionDenied desc = no identity issued",
             "unclassified_cli_failure"),
            ("é" * 2048 + "rpc error: code = PermissionDenied desc = no identity issued",
             "unclassified_cli_failure"),
        ]
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            for stderr, expected in cases:
                self.assertEqual(MODULE.classify_cli_stderr(stderr), expected)
        self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
