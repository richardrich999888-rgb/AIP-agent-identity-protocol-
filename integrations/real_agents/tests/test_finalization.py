"""Lifecycle control fixtures only; never genuine-agent or signed-kernel evidence."""
import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import harness
from evidence import ARCHIVES, Refused


class FinalizationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = Path(self.tmp.name) / "run"
        (self.out / "evidence").mkdir(parents=True)
        self.checkpoint = Path(self.tmp.name) / "outside-checkpoint.json"
        self.config = {"tools": "/fixture-tools", "anchor": {
            "observer_id": "fixture", "key_version": 1, "public_key": "00" * 32}}
        self.launch = {"probe_id": "fixture", "process": {
            "pid": 12, "pid_start_time_ticks": 1, "boot_id": [1] * 16},
            "container": {"pid_ns_inode": 100, "mnt_ns_inode": 200, "net_ns_inode": 300}}
        self.batches = [{"sequence": 1, "batch": {
            "probe_id": "fixture", "claimed_from_ms": 10, "claimed_to_ms": 2000,
            "dropped_events": 0, "clock_anchor": {"realtime_ms": 10, "monotonic_ns": 0},
            "kernel_events": [{"kind": {kind: {}}, "bound": self.launch,
                               "kernel_timestamp_ns": 20_000_000, "probe_seq": index}
                              for index, kind in enumerate(("ProcessExec", "FileEvent", "SocketSend"), 1)]}}]
        self.health = [{"health": {"state": "Active", "continuity": "Verified",
            "attested_coverage": {"from_ms": 10, "to_ms": 2000}, "emitted_at_ms": 2000,
            "covered_by": harness.REQUIRED_MECHANISMS,
            "clock": {"synchronized": True, "max_error_us": 100}}}]
        self.events = []
        self.clock = 0
        self.frozen = False
        self.stop_fails = self.freeze_fails = self.audit_fails = self.final_verify_fails = False
        self.resources = {"collector": True, "container": True}
        self.status = {"status": "FAILED", "assignment_complete": False,
            "workload_from_ms": 10, "failures": ["workload exceeded runtime budget"],
            "summary": {"coverage": "COVERED", "source": "STALE_LIVE_SNAPSHOT"}}

        owner = self
        class Audit:
            def export(self, path):
                owner.events.append("audit_export")
                if owner.audit_fails:
                    raise Refused("fixture audit unavailable")
                Path(path).write_text("fixture audit only\n")
                return {"fixture": True}
            def close(self):
                owner.events.append("audit_close")
        class Probe:
            def poll(self):
                return None
        self.audit, self.probe = Audit(), Probe()

    def command(self, args, **kwargs):
        if args[:3] == ["docker", "rm", "--force"]:
            self.events.append("workload_stop")
            self.assertEqual(kwargs["timeout"], 15)
            if self.stop_fails:
                raise Refused("fixture Docker stop failed")
            return "fixture\n"
        if Path(args[0]).name == "aip-corroborate":
            self.events.append("corroborate")
            return json.dumps({"agreed": [{"aip": {"pid": 12, "batch_sequence": 1, "wall_ms": 30}}]})
        self.events.append(Path(args[0]).name)
        return "fixture output\n"

    def snapshot(self, config, archive, token, *, stop=False):
        self.events.append("freeze" if stop else "snapshot")
        if stop and self.freeze_fails:
            raise Refused("fixture freeze unavailable")
        self.frozen = stop
        for name, values in zip(ARCHIVES, (self.batches, self.health)):
            (Path(archive) / name).write_text("".join(json.dumps(v) + "\n" for v in values))
        return {"sha256": {name: hashlib.sha256((Path(archive) / name).read_bytes()).hexdigest()
                           for name in ARCHIVES}}

    def verify(self, archive, tools, anchor, checkpoint):
        self.events.append("verify_frozen" if self.frozen else "verify_snapshot")
        for name in ARCHIVES:
            self.assertEqual(checkpoint["sha256"][name],
                             hashlib.sha256((Path(archive) / name).read_bytes()).hexdigest())
        if self.frozen and self.final_verify_fails:
            raise Refused("fixture frozen signature rejected")
        return {"fixture_verifier": True, "findings": []}

    def sleep(self, seconds):
        self.events.append("sleep")
        self.clock += seconds

    def finish(self):
        with patch.multiple(harness, command=self.command, snapshot=self.snapshot, verify=self.verify,
                            terminate=lambda probe: self.events.append("observer_stop"),
                            tamper=lambda *args: {"fixture_mutations": True},
                            now=lambda: 100 + int(self.clock * 1000)), \
                patch.object(harness.time, "monotonic", side_effect=lambda: self.clock), \
                patch.object(harness.time, "sleep", side_effect=self.sleep):
            harness.finalize_released_workload(self.config, self.out, self.checkpoint, "fixture-token",
                self.probe, self.audit, self.status, self.launch, self.resources)

    def test_timeout_stops_before_wait_exports_and_verifies_but_remains_failed(self):
        self.finish()
        self.assertEqual(self.events[0], "workload_stop")
        self.assertLess(self.events.index("workload_stop"), self.events.index("sleep"))
        self.assertLess(self.events.index("audit_export"), self.events.index("audit_close"))
        self.assertLess(self.events.index("audit_export"), self.events.index("observer_stop"))
        self.assertLess(self.events.index("observer_stop"), self.events.index("freeze"))
        self.assertLess(self.events.index("freeze"), self.events.index("verify_frozen"))
        self.assertLess(self.events.index("verify_frozen"), self.events.index("corroborate"))
        self.assertFalse(self.resources["container"])
        self.assertFalse(self.resources["collector"])
        self.assertTrue(self.checkpoint.is_file())
        self.assertTrue((self.out / "verification.json").is_file())
        self.assertTrue((self.out / "corroboration.json").is_file())
        self.assertEqual(self.status["summary"]["coverage"], "COVERED")
        self.assertEqual(self.status["task_end_boundary"]["kind"], "FORCED_CONTAINER_REMOVAL_RETURNED")
        self.assertEqual(self.status["task_end_boundary"]["to_ms"], self.status["workload_to_ms"])
        self.assertEqual(self.status["failures"][0], "workload exceeded runtime budget")
        self.assertEqual(self.status["status"], "FAILED")
        self.assertEqual(self.status["observation_validation"], "FAILED")
        self.assertEqual(self.status["task_acceptance"], "FAILED_WORKLOAD")
        self.assertFalse(self.status["assignment_complete"])

    def test_normal_exit_preserves_review_requirement_and_existing_checks(self):
        self.status.update(status="VERIFYING", failures=[], workload_exit=0, workload_to_ms=90)
        self.finish()
        self.assertNotIn("workload_stop", self.events)
        self.assertEqual(self.status["status"], "REVIEW_REQUIRED")
        self.assertEqual(self.status["observation_validation"], "PASSED")
        self.assertEqual(self.status["task_acceptance"], "PENDING_INDEPENDENT_REVIEW")
        self.assertTrue((self.out / "tamper.json").is_file())
        self.assertIn("aip-lineage", self.events)
        self.assertIn("aip-sentinel-feed", self.events)

    def test_nonzero_exit_cannot_be_promoted_by_complete_evidence(self):
        self.status.update(status="VERIFYING", failures=[], workload_exit=7, workload_to_ms=90)
        self.finish()
        self.assertEqual(self.status["status"], "FAILED")
        self.assertIn("framework process failed", self.status["failures"])

    def test_failed_stop_leaves_end_unknown_and_never_waits_or_uses_live_summary(self):
        self.stop_fails = True
        self.finish()
        self.assertNotIn("sleep", self.events)
        self.assertNotIn("snapshot", self.events)
        self.assertNotIn("workload_to_ms", self.status)
        self.assertNotIn("summary", self.status)
        self.assertNotIn("corroborate", self.events)
        self.assertIn("verify_frozen", self.events)
        self.assertEqual(self.status["finalization"]["coverage_wait"]["status"], "NOT_ATTEMPTED_END_UNKNOWN")
        self.assertTrue(self.resources["container"])  # outer cleanup must retry

    def test_later_adverse_health_never_borrows_old_active_coverage(self):
        bad = copy.deepcopy(self.health[0]); bad["health"].update(
            state="IntegrityUnknown", emitted_at_ms=3000, attested_coverage=None)
        self.health.append(bad)
        self.finish()
        self.assertLessEqual(self.status["finalization"]["coverage_wait"]["attempts"], 15)
        self.assertLessEqual(self.clock, 46)
        self.assertEqual(self.status["summary"]["coverage"], "INTEGRITY_UNKNOWN")
        self.assertIn("no signed Active epoch encloses the workload", self.status["failures"])

    def test_audit_failure_preserves_original_error_and_archive_verification(self):
        self.audit_fails = True
        self.finish()
        self.assertIn("verify_frozen", self.events)
        self.assertNotIn("corroborate", self.events)
        self.assertEqual(self.status["finalization"]["archive_verification"], "VERIFIED")
        self.assertEqual(self.status["failures"][0], "workload exceeded runtime budget")
        self.assertEqual(self.status["status"], "FAILED")

    def test_freeze_failure_does_not_verify_a_previous_live_prefix_as_final(self):
        self.freeze_fails = True
        self.finish()
        self.assertIn("verify_snapshot", self.events)
        self.assertNotIn("verify_frozen", self.events)
        self.assertFalse(self.checkpoint.exists())
        self.assertNotIn("summary", self.status)
        self.assertTrue(self.resources["collector"])  # outer cleanup must retry

    def test_final_signature_rejection_prevents_summary_and_corroboration(self):
        self.final_verify_fails = True
        self.finish()
        self.assertNotIn("summary", self.status)
        self.assertNotIn("corroborate", self.events)
        self.assertEqual(self.status["finalization"]["archive_verification"], "NOT_ESTABLISHED")
        self.assertEqual(self.status["status"], "FAILED")

    def run_timeout(self, finalizer_failure=None):
        run_out = Path(self.tmp.name) / "actual-run-control"
        task_path = Path(self.tmp.name) / "task.txt"
        task_path.write_text("fixture workload; not genuine execution evidence\n")
        config = {**self.config, "framework": "agent_zero", "model": "fixture", "task": str(task_path),
            "image": "fixture-image", "model_env": "/fixture-env", "model_config": "/fixture-config",
            "probe_env": "/fixture-probe", "network": "fixture-network", "pids_limit": 256,
            "memory_mb": 4096, "cpus": 2, "timeout_s": 900, "collector": {"mode": "local-isolated"}}
        original_stat, original_read = Path.stat, Path.read_text
        measured = {k: v for k, v in self.launch.items() if k != "probe_id"}
        def stat(path, *args, **kwargs):
            if str(path) == "/proc/12/root/work":
                return original_stat(run_out / "work", *args, **kwargs)
            return original_stat(path, *args, **kwargs)
        def read(path, *args, **kwargs):
            return "fixture-machine" if str(path) == "/etc/machine-id" else original_read(path, *args, **kwargs)
        def command(args, **kwargs):
            if args[:2] == ["docker", "inspect"]:
                if args[3] == "{{.State.Pid}}":
                    return "12\n"
                if args[3] == "{{json .NetworkSettings.Networks}}":
                    return json.dumps({"fixture-network": {"IPAddress": "172.30.0.2"}})
                if args[3] == "{{.State.Running}}":
                    self.clock += 901  # real run() takes its unchanged timeout branch
                    return "true\n"
                self.fail("timeout must not invent a container exit code")
            return self.command(args, **kwargs)
        self.audit.start = lambda: self.events.append("audit_start")
        original_finalizer = harness.finalize_released_workload
        def finalize(*args):
            if finalizer_failure:
                raise finalizer_failure
            return original_finalizer(*args)
        with patch.multiple(harness, preflight=lambda cfg: {"commit": "fixture"}, command=command,
                            read_env=lambda path: {"AIP_PROBE_ID": "fixture"},
                            proc_identity=lambda pid: copy.deepcopy(measured),
                            remote=lambda *args: {"clock_synchronized": True, "state": "inactive",
                                                  "machine_id": "fixture-machine"},
                            snapshot=self.snapshot, verify=self.verify,
                            terminate=lambda probe: self.events.append("observer_stop"),
                            now=lambda: 100 + int(self.clock * 1000)), \
                patch.object(harness, "AuditCrosscheck", return_value=self.audit), \
                patch.object(harness, "finalize_released_workload", side_effect=finalize), \
                patch.object(harness.subprocess, "Popen", return_value=self.probe), \
                patch.object(harness.os, "chown"), patch.object(Path, "stat", new=stat), \
                patch.object(Path, "read_text", new=read), \
                patch.object(harness.time, "monotonic", side_effect=lambda: self.clock), \
                patch.object(harness.time, "sleep", side_effect=self.sleep):
            code = harness.run(config, run_out, self.checkpoint)
        status = json.loads((run_out / "status.json").read_text())
        self.assertEqual(config["timeout_s"], 900)
        return code, status, run_out

    def test_run_timeout_invokes_common_finalizer_and_keeps_failed_return(self):
        code, status, run_out = self.run_timeout()
        self.assertEqual(code, 1)
        self.assertEqual(status["workload_network"], {"source_authority": "ROOT_CONTROLLER_DOCKER_INSPECT",
            "network": "fixture-network", "ipv4_address": "172.30.0.2"})
        self.assertEqual(status["status"], "FAILED")
        self.assertEqual(status["failures"][0], "workload exceeded runtime budget")
        self.assertEqual(self.events.count("workload_stop"), 1)
        self.assertEqual(self.events.count("freeze"), 1)
        self.assertIn("audit_export", self.events)
        self.assertTrue((run_out / "verification.json").is_file())
        self.assertTrue((run_out / "finalization.json").is_file())
        self.assertEqual(status["task_end_boundary"]["kind"], "FORCED_CONTAINER_REMOVAL_RETURNED")
        self.assertFalse(status["assignment_complete"])

    def test_unexpected_finalizer_fault_still_cleans_every_resource(self):
        code, status, run_out = self.run_timeout(RuntimeError("fixture finalizer failure"))
        self.assertEqual(code, 1)
        self.assertEqual(status["failures"][0], "workload exceeded runtime budget")
        self.assertTrue(any("final evidence collection" in x for x in status["failures"]))
        self.assertEqual(status["status"], "FAILED")
        self.assertFalse(any("container cleanup:" in x for x in status["failures"]))
        for event in ("workload_stop", "audit_close", "observer_stop", "freeze"):
            self.assertIn(event, self.events)
        self.assertTrue(self.checkpoint.is_file())
        self.assertFalse((run_out / "verification.json").exists())

    def test_network_inventory_is_controller_measured_and_rejects_missing_or_malformed_ipv4(self):
        with patch.object(harness, "command", return_value=json.dumps({"isolated": {"IPAddress": "172.31.0.2"}})) as called:
            measured = harness.measure_workload_network("container-fixture", "isolated")
        self.assertEqual(measured["ipv4_address"], "172.31.0.2")
        self.assertEqual(measured["source_authority"], "ROOT_CONTROLLER_DOCKER_INSPECT")
        self.assertEqual(called.call_args.kwargs["timeout"], 15)
        for value in ({}, {"isolated": {}}, {"isolated": {"IPAddress": ""}},
                      {"isolated": {"IPAddress": "not-an-ip"}}, {"isolated": {"IPAddress": "::1"}},
                      {"isolated": {"IPAddress": 1}}, {"isolated": {"IPAddress": "0.0.0.0"}}):
            with self.subTest(value=value), patch.object(harness, "command", return_value=json.dumps(value)):
                with self.assertRaises(Refused):
                    harness.measure_workload_network("container-fixture", "isolated")

    def test_preflight_failure_never_invokes_released_workload_finalization(self):
        with patch.object(harness, "preflight", side_effect=Refused("fixture preflight")), \
                patch.object(harness, "finalize_released_workload") as finalize:
            code = harness.run({"framework": "agent_zero", "model": "fixture"},
                               self.out / "blocked", self.checkpoint)
        self.assertEqual(code, 2)
        finalize.assert_not_called()
        status = json.loads((self.out / "blocked/status.json").read_text())
        self.assertEqual(status["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
