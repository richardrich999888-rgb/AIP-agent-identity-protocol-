"""Ordinary unit fixtures. These are NEVER real-agent execution evidence."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from evidence import (Refused, acceptance, covered, event_time, mutations,
                      records, summarize, verify)
from harness import preflight, read_env, remote, validate_collector_boundary


def health(start=10, end=100):
    return [{"health": {"state": "Active", "continuity": "Verified",
            "attested_coverage": {"from_ms": start, "to_ms": end},
            "emitted_at_ms": end,
            "covered_by": ["SchedTracepoint", "Fanotify", "SockSendTracepoint"],
            "clock": {"synchronized": True, "max_error_us": 100}}}]


def launch():
    return {"probe_id": "unit-fixture", "process": {"pid": 12, "pid_start_time_ticks": 1, "boot_id": [1] * 16},
            "container": {"pid_ns_inode": 100, "mnt_ns_inode": 200, "net_ns_inode": 300}}


def batch():
    return [{"sequence": 1, "batch": {
        "probe_id": "unit-fixture",
        "claimed_from_ms": 10, "claimed_to_ms": 100, "dropped_events": 0,
        "clock_anchor": {"realtime_ms": 10, "monotonic_ns": 0},
        "kernel_events": [{"kind": {"ProcessExec": {"pid": 12}},
            "kernel_timestamp_ns": 10_000_000, "bound": launch(), "probe_seq": 1}]}}]


class EvidencePolicyTests(unittest.TestCase):
    def test_covered_requires_one_complete_epoch(self):
        self.assertTrue(covered(health(), 20, 90, ["SchedTracepoint"]))
        self.assertFalse(covered(health(10, 40) + health(60, 100), 20, 90, ["SchedTracepoint"]))

    def test_bad_health_vetoes_overlapping_claim(self):
        h = health()
        bad = copy.deepcopy(h[0]); bad["health"].update(state="IntegrityUnknown", emitted_at_ms=50)
        self.assertFalse(covered([bad, *h], 20, 90, []))

    def test_later_adverse_health_cannot_reuse_historical_active(self):
        h = health()
        bad = copy.deepcopy(h[0]); bad["health"].update(state="IntegrityUnknown", emitted_at_ms=150)
        self.assertFalse(covered([*h, bad], 20, 90, ["SchedTracepoint"]))

    def test_backwards_health_emission_is_rejected_even_when_both_active(self):
        h = health()
        backwards = copy.deepcopy(h[0]); backwards["health"]["emitted_at_ms"] = 99
        self.assertFalse(covered([*h, backwards], 20, 90, ["SchedTracepoint"]))

    def test_equal_ms_last_adverse_record_wins(self):
        h = health()
        bad = copy.deepcopy(h[0]); bad["health"]["state"] = "IntegrityUnknown"
        self.assertFalse(covered([*h, bad], 20, 90, ["SchedTracepoint"]))
        # With both emissions outside the task interval, a final recovery at
        # the same timestamp is authoritative; max(timestamp) is not enough.
        self.assertTrue(covered([bad, *h], 20, 90, ["SchedTracepoint"]))

    def test_final_active_health_with_stale_coverage_cannot_reuse_old_epoch(self):
        h = health()
        stale = health(10, 80)[0]; stale["health"]["emitted_at_ms"] = 150
        self.assertFalse(covered([*h, stale], 20, 90, ["SchedTracepoint"]))

    def test_final_health_must_itself_have_verified_continuity_sensors_and_clock(self):
        for changes in ({"continuity":"Unverified"}, {"covered_by":[]},
                        {"clock":None}, {"clock":{"synchronized":False,"max_error_us":0}},
                        {"clock":{"synchronized":True,"max_error_us":1_000_001}}):
            with self.subTest(changes=changes):
                h = health()
                latest = copy.deepcopy(h[0]); latest["health"].update(emitted_at_ms=150, **changes)
                self.assertFalse(covered([*h, latest], 20, 90, ["SchedTracepoint"]))

    def test_empty_health_is_not_coverage(self):
        self.assertFalse(covered([], 20, 90, []))

    def test_missing_or_unsynchronized_clock_is_not_coverage(self):
        for clock in (None, {"synchronized": False, "max_error_us": 0},
                      {"synchronized": True, "max_error_us": 1_000_001},
                      {"synchronized": True, "max_error_us": -1}):
            h = health(); h[0]["health"]["clock"] = clock
            self.assertFalse(covered(h, 20, 90, []))

    def test_absent_sensor_is_not_coverage(self):
        self.assertFalse(covered(health(), 20, 90, ["WireTapAfPacket"]))

    def test_matching_observed_namespace_does_not_prove_logical_agent(self):
        report = summarize(batch(), health(), launch(), 10, 100)
        self.assertEqual(report["process_instances"], 1)
        self.assertEqual(report["launch_instance_events"], 1)
        for k in ("authority", "logical_agent_attribution", "reconciliation"):
            self.assertEqual(report[k], "CANNOT_PROVE")
        self.assertIsNone(report["coverage_percent"])

    def test_other_host_boot_is_not_workload(self):
        b = batch(); b[0]["batch"]["kernel_events"][0]["bound"]["process"]["boot_id"] = [2] * 16
        self.assertEqual(summarize(b, health(), launch(), 10, 100)["process_instances"], 0)

    def test_other_probe_is_excluded(self):
        b = batch(); b[0]["batch"]["probe_id"] = "different-probe"
        self.assertEqual(summarize(b, health(), launch(), 10, 100)["process_instances"], 0)

    def test_reused_pid_is_not_original_instance(self):
        b = batch(); b[0]["batch"]["kernel_events"][0]["bound"]["process"]["pid_start_time_ticks"] = 2
        r = summarize(b, health(), launch(), 10, 100)
        self.assertEqual(r["launch_instance_events"], 0)

    def test_other_container_is_excluded(self):
        b = batch(); b[0]["batch"]["kernel_events"][0]["bound"]["container"]["pid_ns_inode"] = 999
        r = summarize(b, health(), launch(), 10, 100)
        self.assertEqual(r["process_instances"], 0)
        self.assertEqual(r["outside_workload_bound_events"], 1)

    def test_unbound_events_are_visible_never_pid_attributed(self):
        b = batch(); b[0]["batch"]["kernel_events"][0]["bound"] = None
        r = summarize(b, health(), launch(), 10, 100)
        self.assertEqual(r["unbound_host_events"], 1)
        self.assertEqual(r["process_instances"], 0)

    def test_unclocked_events_are_visible(self):
        b = batch(); b[0]["batch"]["clock_anchor"] = None
        r = summarize(b, health(), launch(), 10, 100)
        self.assertEqual(r["events_without_clock_anchor"], 1)
        self.assertEqual(r["process_instances"], 0)

    def test_loss_is_visible_even_when_events_bind(self):
        b = batch(); b[0]["batch"]["dropped_events"] = 12
        self.assertEqual(summarize(b, health(), launch(), 10, 100)["probe_reported_drops"], 12)

    def test_out_of_window_host_activity_does_not_count(self):
        r = summarize(batch(), health(), launch(), 50, 100)
        self.assertEqual(r["process_instances"], 0)

    def test_monotonic_anchor_not_boottime_places_event(self):
        b = batch()[0]["batch"]
        b["clock_anchor"]["boottime_ns"] = 9_000_000_000
        self.assertEqual(event_time(b, b["kernel_events"][0]), 20)

    def test_pre_anchor_fractional_timestamp_matches_rust_truncation(self):
        b = batch()[0]["batch"]
        b["clock_anchor"]["monotonic_ns"] = 11_500_000
        self.assertEqual(event_time(b, b["kernel_events"][0]), 9)

    def test_clock_conversion_saturates_like_rust(self):
        b = batch()[0]["batch"]
        b["clock_anchor"]["realtime_ms"] = 2**64 - 1
        self.assertEqual(event_time(b, b["kernel_events"][0]), 2**63 - 1)

    def test_crosscheck_references_use_each_signed_batch_clock(self):
        b = batch()
        second = copy.deepcopy(b[0]); second["sequence"] = 2
        second["batch"]["clock_anchor"]["realtime_ms"] = 11
        b.append(second)
        r = summarize(b, health(), launch(), 10, 100)
        # aip-corroborate::aip_executions converts each event with its own
        # batch anchor. A one-ms anchor change must retain two exact refs.
        self.assertEqual([e["wall_ms"] for e in r["workload_executions"]], [20, 21])
        self.assertEqual([e["time_ms"] for e in r["events"]], [20, 21])
        canonical = {"agreed": [{"aip": {"pid":12,"batch_sequence":1,"wall_ms":20}},
                                 {"aip": {"pid":12,"batch_sequence":2,"wall_ms":21}}]}
        self.assertNotIn("not every bound workload exec was independently corroborated",
                         acceptance(r,canonical,0))
        # A single agreement cannot cover both distinct signed references.
        canonical["agreed"].pop()
        self.assertIn("not every bound workload exec was independently corroborated",
                      acceptance(r,canonical,0))

    def test_host_only_crosscheck_is_not_workload_corroboration(self):
        s = summarize(batch(), health(), launch(), 10, 100)
        c = {"agreed": [{"aip": {"pid": 99, "batch_sequence": 1, "wall_ms": 20}}]}
        self.assertIn("not every bound workload exec was independently corroborated", acceptance(s, c, 0))

    def test_one_agreement_cannot_cover_repeated_execs_in_same_millisecond(self):
        s = summarize(batch(), health(), launch(), 10, 100)
        e = s["workload_executions"][0]
        s["workload_executions"].append(dict(e))
        c = {"agreed": [{"aip": e}]}
        self.assertIn("not every bound workload exec was independently corroborated", acceptance(s, c, 0))

    def test_zero_exit_is_not_workload_acceptance(self):
        s = summarize(batch(), health(), launch(), 10, 100)
        failures = acceptance(s, {"agreed": []}, 0)
        self.assertIn("no workload-bound FileEvent", failures)
        self.assertIn("no workload-bound SocketSend", failures)

    def test_checkpoint_mismatch_precedes_external_verifier(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "attested.archive.jsonl").write_text("{}\n")
            with patch("evidence.command") as called:
                with self.assertRaises(Refused):
                    verify(tmp, "/missing", {}, {"sha256": {}})
                called.assert_not_called()

    def test_empty_and_partial_archives_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp, "archive")
            for value in (b"", b"{}"):
                p.write_bytes(value)
                with self.assertRaises(Refused):
                    records(p)

    def test_mutations_cover_edge_deletions(self):
        data = b''.join(json.dumps({"attested_at_ms": i}).encode() + b'\n' for i in range(3))
        m = mutations(data)
        self.assertEqual(len(m), 7)
        self.assertEqual(len(m["remove_suffix"].splitlines()), 2)
        self.assertTrue(all(value != data for value in m.values()))

    def test_small_mutation_input_is_blocked_not_passed(self):
        with self.assertRaises(Refused):
            mutations(b"{}\n")


class ControllerTests(unittest.TestCase):
    def test_non_linux_preflight_fails_before_any_launch(self):
        with patch("platform.system", return_value="Darwin"), patch("harness.command") as called:
            with self.assertRaisesRegex(Refused, "Linux"):
                preflight({})
            called.assert_not_called()

    def test_remote_shell_metacharacters_refused(self):
        c = {"collector": {"ssh": "host;touch /tmp/x", "helper": "/a", "config": "/b"}}
        with patch("harness.command") as called:
            with self.assertRaises(Refused):
                remote(c, "status", "sd-" + "0" * 32)
            called.assert_not_called()

    def test_off_host_mode_still_refuses_same_machine(self):
        with self.assertRaisesRegex(Refused, "distinct host"):
            validate_collector_boundary({"collector": {}},
                {"machine_id": "one", "clock_synchronized": True}, "one")

    def test_isolated_mode_is_explicit_and_keeps_trust_limit(self):
        value = validate_collector_boundary({"collector": {"mode": "local-isolated"}},
            {"machine_id": "one", "clock_synchronized": True}, "one")
        self.assertIn("not off-host custody", value)
        self.assertIn("host root trusted", value)

    def test_isolated_mode_never_waives_clock_checks(self):
        with self.assertRaisesRegex(Refused, "not synchronized"):
            validate_collector_boundary({"collector": {"mode": "local-isolated"}},
                {"machine_id": "one", "clock_synchronized": False}, "one")

    def test_unknown_isolation_mode_fails_before_helper(self):
        with patch("harness.command") as called:
            with self.assertRaises(Refused):
                remote({"collector": {"mode": "anything"}}, "status", "sd-" + "0" * 32)
            called.assert_not_called()

    def test_environment_is_data_not_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp, "env")
            p.write_text("AIP_PROBE_ID=$(touch /tmp/must-not-execute)\n")
            self.assertEqual(read_env(p)["AIP_PROBE_ID"], "$(touch /tmp/must-not-execute)")
            p.write_text("LD_PRELOAD=/untrusted.so\n")
            with self.assertRaises(Refused):
                read_env(p)


if __name__ == "__main__":
    unittest.main()
