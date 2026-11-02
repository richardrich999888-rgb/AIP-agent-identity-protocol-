#!/usr/bin/env python3
"""Packaging/control-flow regressions; fixture ELF headers are not Linux tests."""

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("runtime_package", ROOT / "deploy/enterprise/linux/package.py")
PACKAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGE)


class Packaging(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name).resolve()
        self.bins = self.work / "bin"
        self.bins.mkdir()
        for name in PACKAGE.BINARIES:
            data = bytearray(64)
            data[:6] = b"\x7fELF\x02\x01"
            data[18:20] = (62).to_bytes(2, "little")
            path = self.bins / name
            path.write_bytes(data)
            path.chmod(0o755)
        self.archive = self.work / "runtime.tar"
        self.build(self.archive)
        self.expected = PACKAGE.digest(self.archive.read_bytes())
        self.probe = self.work / "probe.env"
        self.probe.write_text("\n".join([
            "AIP_PROBE_ID=approved-host.example", "AIP_PROBE_COLLECTOR_ENDPOINT=collector.bank.example:8443",
            "AIP_PROBE_COLLECTOR_NOISE_PUBKEY=" + "ab" * 32,
            "AIP_PROBE_KEY_PATH=/var/lib/aip-probe/transport.key.json",
            "AIP_PROBE_SENSORS=sched,connector", "AIP_PROBE_BATCH_INTERVAL_MS=2000", ""]))
        self.collector = self.work / "collector.env"
        self.collector.write_text("\n".join([
            "AIP_COLLECTOR_OBSERVER_ID=collector.bank.example",
            "AIP_COLLECTOR_KEY_PATH=/var/lib/aip-collector/collector.key.wrapped",
            "AIP_COLLECTOR_STATE_DIR=/var/lib/aip-collector/state",
            "AIP_COLLECTOR_LISTEN=0.0.0.0:8443", "AIP_COLLECTOR_PROBES_PATH=/etc/aip/probes.json",
            "AIP_COLLECTOR_NOISE_KEY_PATH=/var/lib/aip-collector/noise.key.json", ""]))

    def build(self, output):
        with contextlib.redirect_stdout(io.StringIO()):
            PACKAGE.build(argparse.Namespace(bin_dir=str(self.bins), source_commit="a" * 40,
                target="x86_64-unknown-linux-gnu", output=str(output)))

    def verify(self, archive=None, expected=None):
        return PACKAGE.verified_package(archive or self.archive, expected or self.expected)

    def args(self, role="probe"):
        root = self.work / (role + "-root")
        root.mkdir(exist_ok=True)
        return argparse.Namespace(archive=str(self.archive), expected_sha256=self.expected,
            role=role, root=str(root), config=str(self.probe if role == "probe" else self.collector),
            confirm_separate_host=False)

    def install(self, args):
        with contextlib.redirect_stdout(io.StringIO()):
            PACKAGE.install(args)

    def replace_tar(self, mutate):
        with tarfile.open(self.archive) as archive:
            members = [(member, archive.extractfile(member).read()) for member in archive]
        output = self.work / "changed.tar"
        mutate(members)
        with tarfile.open(output, "w") as archive:
            for member, data in members:
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data) if member.isfile() else None)
        return output, PACKAGE.digest(output.read_bytes())

    def test_reproducible_archive_manifest_and_exact_members(self):
        other = self.work / "second.tar"
        self.build(other)
        self.assertEqual(self.archive.read_bytes(), other.read_bytes())
        manifest, files = self.verify()
        self.assertEqual(manifest["mode"], "OBSERVER_ONLY")
        self.assertEqual(manifest["source_commit"], "a" * 40)
        self.assertEqual(set(files), set(manifest["files"]) | {"manifest.json"})

    def test_wrong_or_absent_trusted_hash_refused(self):
        for anchor in (None, "", "0" * 64, "oops"):
            with self.subTest(anchor=anchor), self.assertRaises(ValueError):
                PACKAGE.verified_package(self.archive, anchor)

    def test_altered_binary_refused_even_with_new_archive_digest(self):
        def mutate(members):
            index = next(i for i, (member, _) in enumerate(members) if member.name == "bin/aip-probe")
            member, data = members[index]
            members[index] = member, data + b"tampered"
        archive, expected = self.replace_tar(mutate)
        with self.assertRaisesRegex(ValueError, "integrity"):
            self.verify(archive, expected)

    def test_unsafe_paths_symlinks_duplicates_extra_files_and_modes_refused(self):
        for attack in ("traversal", "symlink", "duplicate", "extra", "mode"):
            with self.subTest(attack=attack):
                def mutate(members):
                    member, data = members[0]
                    if attack == "traversal":
                        member.name = "../escape"
                    elif attack == "symlink":
                        member.type, member.linkname = tarfile.SYMTYPE, "/etc/passwd"
                    elif attack == "duplicate":
                        members.append((member, data))
                    elif attack == "mode":
                        member.mode |= 0o4000
                    else:
                        members.append((tarfile.TarInfo("unexpected"), b""))
                archive, expected = self.replace_tar(mutate)
                with self.assertRaises(ValueError):
                    self.verify(archive, expected)

    def test_macos_or_wrong_arch_binary_and_invalid_commit_refused(self):
        with self.assertRaises(ValueError):
            PACKAGE.elf_check(b"macho" * 20, "x86_64-unknown-linux-gnu")
        with self.assertRaises(ValueError):
            PACKAGE.elf_check((self.bins / "aip-probe").read_bytes(), "aarch64-unknown-linux-gnu")
        with self.assertRaises(ValueError):
            PACKAGE.build(argparse.Namespace(bin_dir=str(self.bins), source_commit="HEAD",
                target="x86_64-unknown-linux-gnu", output=str(self.work / "bad.tar")))

    def test_valid_probe_and_collector_config(self):
        with mock.patch.object(PACKAGE.socket, "getfqdn", side_effect=AssertionError("offline validation attempted DNS")):
            self.assertEqual(PACKAGE.parse_config(self.probe, "probe")["AIP_PROBE_SENSORS"], "sched,connector")
        self.assertIn("AIP_COLLECTOR_KEY_PATH", PACKAGE.parse_config(self.collector, "collector"))

    def test_config_placeholders_shell_expansion_duplicates_and_cross_role_refused(self):
        original = self.probe.read_text()
        for extra in ("AIP_PROBE_ID=again", "AIP_PROBE_NOT_REAL=1", "AIP_COLLECTOR_KEY_PATH=/tmp/key",
                      "RUST_LOG=$(id)", "RUST_LOG=info # comment"):
            with self.subTest(extra=extra):
                self.probe.write_text(original + extra + "\n")
                with self.assertRaises(ValueError):
                    PACKAGE.parse_config(self.probe, "probe")
        self.probe.write_text(original.replace("ab" * 32, "<PIN_PUBLIC_KEY>"))
        with self.assertRaises(ValueError):
            PACKAGE.parse_config(self.probe, "probe")

    def test_no_loopback_collector_or_silent_sensor_fallback(self):
        original = self.probe.read_text()
        for endpoint in ("localhost:8443", "127.0.0.1:8443", "[::1]:8443", "0.0.0.0:8443", "host:99999"):
            self.probe.write_text(original.replace("collector.bank.example:8443", endpoint))
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                PACKAGE.parse_config(self.probe, "probe")
        for sensors in ("sched,bogus", "", "sched,sched", "fanotify", "sched,afpacket,"):
            self.probe.write_text(original.replace("sched,connector", sensors))
            with self.subTest(sensors=sensors), self.assertRaises(ValueError):
                PACKAGE.parse_config(self.probe, "probe")

    def test_strict_clock_continuity_key_separation_and_unit_paths_enforced(self):
        original = self.collector.read_text()
        for extra in ("AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK=0", "AIP_COLLECTOR_CONTINUITY=advisory",
                      "AIP_COLLECTOR_KEY_VERSION=0", "AIP_COLLECTOR_ATTESTED_ARCHIVE_PATH=/tmp/archive",
                      "AIP_COLLECTOR_PASSPHRASE_FILE=/run/secrets/unprovisioned"):
            self.collector.write_text(original + extra + "\n")
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                PACKAGE.parse_config(self.collector, "collector")
        self.collector.write_text(original.replace("noise.key.json", "collector.key.wrapped"))
        with self.assertRaisesRegex(ValueError, "separate"):
            PACKAGE.parse_config(self.collector, "collector")

    def test_preflight_never_reports_runtime_pass_on_darwin(self):
        args = argparse.Namespace(config=str(self.probe), role="probe", config_only=False)
        with mock.patch.object(PACKAGE.platform, "system", return_value="Darwin"):
            with self.assertRaisesRegex(ValueError, "BLOCKED"):
                PACKAGE.preflight(args)

    def test_staged_install_is_role_separate_bounded_and_no_service_start(self):
        for role in ("probe", "collector"):
            args = self.args(role)
            with mock.patch.object(PACKAGE.subprocess, "run") as run:
                self.install(args)
                run.assert_not_called()
            root = Path(args.root)
            unit = (root / f"etc/systemd/system/aip-{role}.service").read_text()
            self.assertIn("MemoryMax=512M", unit)
            self.assertIn("TasksMax=128", unit)
            self.assertIn("UMask=0077", unit)
            self.assertIn(f"ExecStart=/opt/vanian/snifferdog/bin/aip-{role}", unit)
            self.assertFalse((root / f"opt/vanian/snifferdog/bin/aip-{'collector' if role == 'probe' else 'probe'}").exists())
            if role == "probe":
                self.assertIn("AmbientCapabilities=CAP_PERFMON CAP_NET_ADMIN\n", unit)
                self.assertNotIn("AmbientCapabilities=CAP_PERFMON CAP_NET_ADMIN CAP_NET_RAW\n", unit)
            with self.assertRaisesRegex(ValueError, "already installed"):
                self.install(args)

    def test_symlink_and_existing_file_are_refused_before_writes(self):
        args = self.args()
        root = Path(args.root)
        (root / "opt").symlink_to(self.work, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symbolic link"):
            self.install(args)
        self.assertFalse((root / "var").exists())
        (root / "opt").unlink()
        target = root / "etc/systemd/system/aip-probe.service"
        target.parent.mkdir(parents=True)
        target.write_text("existing operator unit")
        with self.assertRaisesRegex(ValueError, "overwrite"):
            self.install(args)
        self.assertEqual(target.read_text(), "existing operator unit")
        self.assertFalse((root / "opt").exists())

    def test_other_role_configuration_refused(self):
        args = self.args()
        path = Path(args.root) / "etc/aip/collector.env"
        path.parent.mkdir(parents=True)
        path.write_text("preserved collector config")
        with self.assertRaisesRegex(ValueError, "separate hosts"):
            self.install(args)

    def test_uninstall_retains_keys_evidence_config_and_service_account(self):
        args = self.args()
        self.install(args)
        root = Path(args.root)
        state = root / "var/lib/aip-probe"
        (state / "transport.key.json").write_text("test key placeholder")
        (state / "archive.jsonl").write_text("test evidence placeholder")
        with contextlib.redirect_stdout(io.StringIO()):
            PACKAGE.uninstall(args)
        self.assertEqual((state / "transport.key.json").read_text(), "test key placeholder")
        self.assertTrue((state / "archive.jsonl").exists())
        self.assertEqual((root / "etc/aip/probe.env").read_text(), self.probe.read_text())
        self.assertFalse((root / "opt/vanian/snifferdog/bin/aip-probe").exists())
        # A reviewed replacement package can now install over the retained,
        # identical configuration without touching continuity or key files.
        self.install(args)
        self.assertTrue((state / "archive.jsonl").exists())

    def test_uninstall_refuses_locally_modified_software_and_forged_paths(self):
        args = self.args()
        self.install(args)
        root = Path(args.root)
        unit = root / "etc/systemd/system/aip-probe.service"
        unit.write_text(unit.read_text() + "# local override\n")
        with self.assertRaisesRegex(ValueError, "local change"):
            PACKAGE.uninstall(args)
        self.assertTrue((root / "opt/vanian/snifferdog/bin/aip-probe").exists())
        path = root / "etc/aip/vanian-runtime-install.json"
        receipt = json.loads(path.read_text())
        receipt["installed"]["/etc/passwd"] = hashlib.sha256(b"anything").hexdigest()
        path.write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, "unexpected paths"):
            PACKAGE.uninstall(args)

    def test_kubernetes_template_requires_opt_in_and_retains_collector_state(self):
        # Static safety assertions only. Helm rendering and cluster behavior
        # still require their separate tools/infrastructure acceptance.
        chart = ROOT / "deploy/enterprise/kubernetes/chart"
        values = (chart / "values.yaml").read_text()
        template = (chart / "templates/runtime.yaml").read_text()
        self.assertEqual(values.count("enabled: false"), 2)
        self.assertIn("confirmSeparateAdministration: false", values)
        self.assertIn("helm.sh/resource-policy: keep", template)
        self.assertIn("must use an institution-approved immutable sha256 digest", template)
        self.assertNotIn("privileged: true", template)
        self.assertNotIn("SYS_ADMIN", template)
        self.assertIn("automountServiceAccountToken: false", template)


if __name__ == "__main__":
    unittest.main(verbosity=2)
