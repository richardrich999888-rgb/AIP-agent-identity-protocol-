#!/usr/bin/env python3
"""DEB construction/extraction and staged configuration; no service installation.

Requires real release ELF binaries. Missing binaries/tools fail rather than
silently substituting fixture headers for a native package validation.
"""
import argparse
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("vanian_deb", ROOT / "deploy/enterprise/linux/deb.py")
deb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deb)


class DebianPackage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="vanian-deb-test-")
        cls.work = Path(cls.temp.name)
        cls.archive = cls.work / "runtime.tar"
        with contextlib.redirect_stdout(io.StringIO()):
            deb.runtime.build(argparse.Namespace(bin_dir=str(ROOT / "target/release"),
                source_commit="a"*40, target="x86_64-unknown-linux-gnu", output=str(cls.archive)))
        cls.digest = deb.runtime.digest(cls.archive.read_bytes())
        cls.packages = {}
        for role in deb.PRODUCTS:
            path = cls.work / f"{role}.deb"
            with contextlib.redirect_stdout(io.StringIO()):
                deb.build(cls.build_args(role, path))
            cls.packages[role] = path

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @classmethod
    def build_args(cls, role, output):
        return argparse.Namespace(archive=str(cls.archive), expected_sha256=cls.digest,
            role=role, version="0.4.0~eval.1", output=str(output))

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="vanian-config-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.config = self.root / "input.env"
        self.config.write_text("\n".join(["AIP_PROBE_ID=host-one",
            "AIP_PROBE_COLLECTOR_ENDPOINT=collector.bank.example:8443",
            "AIP_PROBE_COLLECTOR_NOISE_PUBKEY=" + "ab"*32,
            "AIP_PROBE_KEY_PATH=/var/lib/aip-probe/transport.key.json",
            "AIP_PROBE_SENSORS=sched,connector", ""]))

    def args(self):
        return argparse.Namespace(config=str(self.config), root=str(self.root),
            confirm_separate_host=True, replace_config=False)

    def configure(self, args=None):
        with contextlib.redirect_stdout(io.StringIO()):
            deb.configure(args or self.args(), "probe")

    def test_real_role_payloads_and_native_dependencies(self):
        for role, path in self.packages.items():
            data = self.root / role
            subprocess.run(["dpkg-deb", "--extract", str(path), str(data)], check=True)
            names = {p.name for p in (data / "opt/vanian/snifferdog/bin").iterdir()}
            self.assertEqual(names, {f"aip-{role}", "aip-observe-verify"})
            self.assertTrue((data / f"usr/sbin/{deb.PRODUCTS[role]}").is_file())
            control = subprocess.check_output(["dpkg-deb", "--field", str(path)], text=True)
            self.assertIn("Architecture: amd64", control)
            self.assertIn("libc6 (>= ", control)
            self.assertIn("systemd (>= 247)", control)

    def test_reproducible_artifact_with_identical_inputs(self):
        other = self.root / "same.deb"
        with contextlib.redirect_stdout(io.StringIO()):
            deb.build(self.build_args("probe", other))
        self.assertEqual(self.packages["probe"].read_bytes(), other.read_bytes())

    def test_unapproved_archive_and_unsafe_version_refused(self):
        args = self.build_args("probe", self.root / "bad.deb")
        args.expected_sha256 = "00"*32
        with self.assertRaises(ValueError):
            deb.build(args)
        args.expected_sha256 = self.digest
        args.version = "0.4.0\nDepends: attacker"
        with self.assertRaises(ValueError):
            deb.build(args)

    def test_installed_units_fail_closed_before_configuration(self):
        for role, path in self.packages.items():
            data = self.root / role
            subprocess.run(["dpkg-deb", "--extract", str(path), str(data)], check=True)
            unit = (data / f"lib/systemd/system/aip-{role}.service").read_text()
            self.assertIn(f"ConditionPathExists=/etc/aip/{role}.configured.json", unit)
            self.assertIn(f"ExecStartPre=/usr/sbin/{deb.PRODUCTS[role]} check", unit)
            self.assertIn("MemoryMax=512M", unit)
            self.assertNotIn("CAP_SYS_ADMIN", "\n".join(line for line in unit.splitlines() if not line.startswith("#")))
            self.assertIn("AmbientCapabilities=\n", unit)

    def test_maintainer_scripts_preserve_data_and_do_not_start_services(self):
        for role, path in self.packages.items():
            control = self.root / role
            subprocess.run(["dpkg-deb", "--control", str(path), str(control)], check=True)
            for name in ("preinst", "postinst", "prerm", "postrm"):
                text = (control / name).read_text()
                subprocess.run(["sh", "-n", str(control / name)], check=True)
                self.assertNotIn("systemctl start", text)
                self.assertNotIn("systemctl enable", text)
                self.assertNotIn("rm ", text)
            self.assertIn("systemctl stop", (control / "prerm").read_text())

    def test_configuration_is_not_observation_and_hash_changes_fail_startup(self):
        self.configure()
        record = json.loads((self.root / "etc/aip/probe.configured.json").read_text())
        self.assertEqual(record["mode"], "OBSERVER_ONLY")
        self.assertNotIn("coverage", record)
        self.assertEqual(deb.check_configuration(self.root, "probe")["AIP_PROBE_ID"], "host-one")
        path = self.root / "etc/aip/probe.env"
        path.write_text(path.read_text().replace("host-one", "host-two"))
        with self.assertRaisesRegex(ValueError, "configuration changed"):
            deb.check_configuration(self.root, "probe")

    def test_capabilities_match_selected_sensors(self):
        self.configure()
        override = (self.root / "etc/systemd/system/aip-probe.service.d/10-vanian-capabilities.conf").read_text()
        self.assertIn("AmbientCapabilities=CAP_PERFMON CAP_NET_ADMIN\n", override)
        self.assertNotIn("CAP_NET_RAW", override)

    def test_configuration_replacement_requires_explicit_approval(self):
        self.configure()
        self.config.write_text(self.config.read_text().replace("sched,connector", "sched,connector,afpacket"))
        with self.assertRaisesRegex(ValueError, "replace-config"):
            self.configure()
        args = self.args()
        args.replace_config = True
        self.configure(args)
        self.assertIn("afpacket", deb.check_configuration(self.root, "probe")["AIP_PROBE_SENSORS"])

    def test_locally_modified_override_is_preserved(self):
        self.configure()
        override = self.root / "etc/systemd/system/aip-probe.service.d/10-vanian-capabilities.conf"
        override.write_text(override.read_text() + "# bank override\n")
        with self.assertRaisesRegex(ValueError, "locally modified"):
            self.configure()
        self.assertIn("# bank override", override.read_text())

    def test_symlink_and_colocation_are_refused(self):
        (self.root / "etc").symlink_to("/tmp")
        with self.assertRaisesRegex(ValueError, "symbolic link"):
            self.configure()
        (self.root / "etc").unlink()
        (self.root / "etc/aip").mkdir(parents=True)
        (self.root / "etc/aip/collector.env").write_text("retained")
        with self.assertRaisesRegex(ValueError, "separate hosts"):
            self.configure()

    def test_confirmation_and_sensor_permission_are_explicit(self):
        args = self.args()
        args.confirm_separate_host = False
        with self.assertRaises(ValueError):
            self.configure(args)
        self.config.write_text(self.config.read_text().replace("sched,connector", "fanotify"))
        with self.assertRaisesRegex(ValueError, "fanotify"):
            self.configure()

    def test_container_build_context_contains_one_role_and_no_credentials(self):
        output = self.root / "container"
        result = subprocess.run([sys.executable, str(ROOT / "deploy/enterprise/linux/container_context.py"),
            "--archive", str(self.archive), "--expected-sha256", self.digest, "--role", "collector",
            "--base-image", "registry.invalid/approved-base@sha256:" + "ab"*32,
            "--output", str(output)], capture_output=True, check=True, text=True)
        report = json.loads(result.stdout)
        self.assertFalse(report["image_built"])
        self.assertEqual(report["runtime_validation"], "NOT_EXECUTED")
        self.assertEqual({p.name for p in (output / "bin").iterdir()}, {"aip-collector", "aip-observe-verify"})
        self.assertIn("USER 10001:10001", (output / "Dockerfile").read_text())

    def test_unpinned_container_base_refused(self):
        result = subprocess.run([sys.executable, str(ROOT / "deploy/enterprise/linux/container_context.py"),
            "--archive", str(self.archive), "--expected-sha256", self.digest, "--role", "probe",
            "--base-image", "debian:latest", "--output", str(self.root / "bad-context")], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "bad-context").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
