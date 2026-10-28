"""Offline kit/security contracts; fixture ELF bytes are never executed."""
import argparse
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import onboarding_bundle as kit


class OnboardingBundle(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="vanian-kit-test-")
        self.addCleanup(self.directory.cleanup)
        self.work = Path(self.directory.name)
        self.manifest = self.work / "manifest.json"
        self.value = json.loads((HERE / "example.json").read_text())
        self.manifest.write_text(json.dumps(self.value))
        binaries = self.work / "bin"
        binaries.mkdir()
        for name in kit.runtime.BINARIES:
            data = bytearray(64)
            data[:6] = b"\x7fELF\x02\x01"
            data[18:20] = (62).to_bytes(2, "little")
            p = binaries / name
            p.write_bytes(data)
            p.chmod(0o755)
        self.archive = self.work / "runtime.tar"
        with contextlib.redirect_stdout(io.StringIO()):
            kit.runtime.build(argparse.Namespace(bin_dir=str(binaries), source_commit="a"*40,
                target="x86_64-unknown-linux-gnu", output=str(self.archive)))
        self.probe = self.work / "probe.env"
        self.probe.write_text("\n".join(["AIP_PROBE_ID=agent-linux-01",
            "AIP_PROBE_COLLECTOR_ENDPOINT=collector.bank.example:8443",
            "AIP_PROBE_COLLECTOR_NOISE_PUBKEY=" + "ab"*32,
            "AIP_PROBE_KEY_PATH=/var/lib/aip-probe/transport.key.json", "AIP_PROBE_SENSORS=sched,connector", ""]))
        self.collector = self.work / "collector.env"
        self.collector.write_text("\n".join(["AIP_COLLECTOR_OBSERVER_ID=evidence-linux-01",
            "AIP_COLLECTOR_KEY_PATH=/var/lib/aip-collector/collector.key.wrapped",
            "AIP_COLLECTOR_STATE_DIR=/var/lib/aip-collector/state", "AIP_COLLECTOR_LISTEN=0.0.0.0:8443",
            "AIP_COLLECTOR_PROBES_PATH=/etc/aip/probes.json", "AIP_COLLECTOR_NOISE_KEY_PATH=/var/lib/aip-collector/noise.key.json", ""]))
        self.enrollment = self.work / "enrollment.json"
        self.record = {"schema": "vanian.probe-enrollment.v1", "probe_id": "agent-linux-01",
            "transport_pubkey_hex": "cd"*32, "status": "PUBLIC_KEY_READY", "observation": "NOT_STARTED",
            "workload_identity_binding": "NOT_ESTABLISHED"}
        self.enrollment.write_text(json.dumps(self.record))

    def args(self):
        return argparse.Namespace(manifest=str(self.manifest), runtime_archive=str(self.archive),
            expected_sha256=kit.runtime.digest(self.archive.read_bytes()), collector_config=str(self.collector),
            probe_config=["agent-linux-01=" + str(self.probe)], enrollment=[str(self.enrollment)],
            retention_days=90, output=str(self.work / "output"))

    def prepare(self, args=None):
        with contextlib.redirect_stdout(io.StringIO()):
            return kit.prepare(args or self.args())

    def test_only_configuration_status_can_be_established(self):
        result = self.prepare()
        self.assertEqual(result["stages"]["CONFIGURATION_VALID"], "CONFIGURATION_VALID")
        self.assertEqual(set(result["stages"].values()), {"CONFIGURATION_VALID", "NOT_ASSESSED"})
        self.assertEqual(result["live_coverage"], "UNAVAILABLE")
        self.assertEqual(result["transport_key_possession"], "REQUIRES_AUTHENTICATED_HANDSHAKE")

    def test_collector_allowlist_matches_actual_native_format(self):
        self.prepare()
        result = json.loads((self.work / "output/collector/probes.json").read_text())
        self.assertEqual(result, [{"probe_id": "agent-linux-01", "transport_pubkey_hex": "cd"*32}])

    def test_every_output_has_integrity_digest_and_retention_is_only_requested(self):
        self.prepare()
        out = self.work / "output"
        for name, digest in json.loads((out / "SHA256SUMS.json").read_text()).items():
            self.assertEqual(kit.runtime.digest((out / name).read_bytes()), digest)
        policy = json.loads((out / "requested-retention.json").read_text())
        self.assertEqual(policy["enforcement"], "NOT_CONFIGURED_BY_THIS_TOOL")
        self.assertFalse(any("private_hex" in p.read_text() for p in out.rglob("*") if p.is_file()))

    def test_missing_or_duplicate_host_config_refused(self):
        for values in ([], self.args().probe_config * 2):
            args = self.args()
            args.probe_config = values
            with self.assertRaises(ValueError):
                self.prepare(args)

    def test_unknown_probe_and_false_runtime_claim_refused(self):
        for field, value in [("probe_id", "another-host"), ("status", "OBSERVER_ACTIVE"),
            ("observation", "VERIFIED"), ("workload_identity_binding", "VERIFIED")]:
            record = {**self.record, field: value}
            self.enrollment.write_text(json.dumps(record))
            with self.assertRaises(ValueError):
                self.prepare()

    def test_private_material_and_unknown_fields_refused(self):
        self.enrollment.write_text(json.dumps({**self.record, "private_hex": "test-secret"}))
        with self.assertRaisesRegex(ValueError, "exact public"):
            self.prepare()

    def test_probe_and_collector_identity_mismatch_refused(self):
        self.probe.write_text(self.probe.read_text().replace("agent-linux-01", "another-host"))
        with self.assertRaisesRegex(ValueError, "probe ID"):
            self.prepare()
        self.probe.write_text(self.probe.read_text().replace("another-host", "agent-linux-01"))
        self.collector.write_text(self.collector.read_text().replace("evidence-linux-01", "another-collector"))
        with self.assertRaisesRegex(ValueError, "collector ID"):
            self.prepare()

    def test_bad_archive_digest_and_no_overwrite(self):
        args = self.args()
        args.expected_sha256 = "00"*32
        with self.assertRaises(ValueError):
            self.prepare(args)
        self.prepare()
        with self.assertRaisesRegex(ValueError, "overwrite"):
            self.prepare()

    def test_unknown_retention_and_capture_modes_refused(self):
        args = self.args()
        args.retention_days = 0
        with self.assertRaises(ValueError):
            self.prepare(args)
        self.value["data_policy"]["capture_prompts"] = True
        self.manifest.write_text(json.dumps(self.value))
        with self.assertRaises(ValueError):
            self.prepare()

    def test_duplicate_json_keys_refused(self):
        self.manifest.write_text('{"schema_version": "a", "schema_version": "b"}')
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.prepare()

    def test_colliding_probe_keys_refused(self):
        self.value["agent_hosts"].append({"host_id": "agent-linux-02", "admin_group": "agent-platform", "os": "linux"})
        self.manifest.write_text(json.dumps(self.value))
        second = self.work / "probe-two.env"
        second.write_text(self.probe.read_text().replace("agent-linux-01", "agent-linux-02"))
        other = self.work / "enrollment-two.json"
        other.write_text(json.dumps({**self.record, "probe_id": "agent-linux-02"}))
        args = self.args()
        args.probe_config.append("agent-linux-02=" + str(second))
        args.enrollment.append(str(other))
        with self.assertRaisesRegex(ValueError, "colliding"):
            self.prepare(args)


if __name__ == "__main__":
    unittest.main(verbosity=2)
