#!/usr/bin/env python3
"""Tests for demos/common/harness.py. Run: python3 -m unittest demos/common/test_harness.py"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import harness  # noqa: E402

HARNESS = str(Path(harness.__file__))


def _netns_unavailable_reason() -> str | None:
    """Why `unshare --user --net` cannot run here, or None if it can.

    Namespace tests are SKIPPED (never passed) without it. CI runners commonly
    restrict unprivileged user namespaces (AppArmor), in which case the local
    run is the evidence for those tests.
    """
    try:
        r = subprocess.run(["unshare", "--user", "--map-root-user", "--net", "--", "true"],
                           capture_output=True, text=True, timeout=20)
    except FileNotFoundError:
        return "unshare is not installed"
    if r.returncode != 0:
        return "unshare --user --net refused here: " + (r.stderr.strip() or f"exit {r.returncode}")
    return None


NETNS_SKIP = _netns_unavailable_reason()


def fake_proc_net(tmp: Path, routes: list[str], devs: list[str]) -> Path:
    (tmp / "route").write_text("Iface\tDestination\tGateway\n" + "".join(r + "\n" for r in routes))
    (tmp / "ipv6_route").write_text("")
    hdr = "Inter-|   Receive\n face |bytes\n"
    (tmp / "dev").write_text(hdr + "".join(f"{d}: 10 1 0 0 0 0 0 0 20 2 0 0 0 0 0 0\n" for d in devs))
    return tmp


class Offline(unittest.TestCase):
    def test_loopback_only_is_offline(self):
        with tempfile.TemporaryDirectory() as t:
            s = harness.offline_status(fake_proc_net(Path(t), [], ["lo"]))
            self.assertTrue(s["offline"])
            self.assertEqual(s["tx_bytes_non_loopback"], 0)

    def test_a_default_route_is_not_offline(self):
        with tempfile.TemporaryDirectory() as t:
            s = harness.offline_status(fake_proc_net(Path(t), ["eth0\t00000000\t010200C0"], ["lo", "eth0"]))
            self.assertFalse(s["offline"])
            self.assertEqual(s["non_loopback_interfaces"], ["eth0"])

    def test_an_interface_without_a_route_is_still_not_offline(self):
        # A present interface can gain a route at any moment; fail closed.
        with tempfile.TemporaryDirectory() as t:
            self.assertFalse(harness.offline_status(fake_proc_net(Path(t), [], ["lo", "eth0"]))["offline"])

    def test_this_host_is_not_offline_and_the_check_says_so(self):
        # The sandbox has a default route via eth0: offline-check must refuse.
        r = subprocess.run([sys.executable, "-I", HARNESS, "offline-check"], capture_output=True, text=True)
        status = json.loads(r.stdout)
        if status["offline"]:
            self.skipTest("this host has no network route; the refusal path cannot be shown here")
        self.assertEqual(r.returncode, 1)

    @unittest.skipIf(NETNS_SKIP is not None, f"SKIPPED, not passed: {NETNS_SKIP}")
    def test_run_offline_runs_with_no_route_and_outbound_fails(self):
        probe = ("import socket,json,sys\n"
                 "sys.path.insert(0,%r)\n"
                 "import harness\n"
                 "s=socket.socket(); s.settimeout(2)\n"
                 "try:\n s.connect(('192.0.2.1',443)); r='connected'\n"
                 "except OSError as e: r=type(e).__name__\n"
                 "print(json.dumps({'status':harness.offline_status(),'connect':r}))\n"
                 % str(Path(HARNESS).parent))
        r = subprocess.run([sys.executable, "-I", HARNESS, "run-offline", "--", sys.executable, "-I", "-c", probe],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertTrue(out["status"]["offline"])
        self.assertNotEqual(out["connect"], "connected")
        # Loopback works inside: a demo can still serve its own local page.
        loop = ("import socket\nsrv=socket.socket(); srv.bind(('127.0.0.1',0)); srv.listen(1)\n"
                "c=socket.create_connection(srv.getsockname(),timeout=2); print('ok')\n")
        r = subprocess.run([sys.executable, "-I", HARNESS, "run-offline", "--", sys.executable, "-I", "-c", loop],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.stdout.strip(), "ok", r.stderr)


class Labels(unittest.TestCase):
    def test_live_label(self):
        self.assertTrue(harness.label("live", "answer")["banner"].startswith("[LIVE]"))

    def test_recorded_must_name_an_existing_source(self):
        with self.assertRaises(ValueError):
            harness.label("recorded", "draft")
        with self.assertRaises(FileNotFoundError):
            harness.label("recorded", "draft", "/nonexistent/round_1.json")
        with tempfile.NamedTemporaryFile() as f:
            b = harness.label("recorded", "draft", f.name)["banner"]
            self.assertIn("RECORDED", b)
            self.assertIn(f.name, b)

    def test_no_third_kind(self):
        with self.assertRaises(ValueError):
            harness.label("simulated", "x")


class Results(unittest.TestCase):
    def test_dirty_lists_files_and_ignores_only_the_tooling_output(self):
        with tempfile.TemporaryDirectory() as d:
            r = Path(d)
            for c in (["init", "-q"], ["config", "user.email", "t@t"], ["config", "user.name", "t"]):
                subprocess.run(["git", "-C", d, *c], check=True)
            (r / "docs/demos").mkdir(parents=True)
            (r / "docs/demos/REHEARSAL_LOG.md").write_text("a\n")
            (r / "code.py").write_text("x = 1\n")
            subprocess.run(["git", "-C", d, "add", "."], check=True)
            subprocess.run(["git", "-C", d, "commit", "-qm", "c"], check=True)
            self.assertFalse(harness.provenance(r)["dirty"])
            (r / "docs/demos/REHEARSAL_LOG.md").write_text("a\nb\n")
            p = harness.provenance(r)
            self.assertEqual((p["dirty"], p["changed_files"]), (False, ["docs/demos/REHEARSAL_LOG.md"]))
            (r / "code.py").write_text("x = 2\n")
            p = harness.provenance(r)
            self.assertTrue(p["dirty"])
            self.assertIn("code.py", p["changed_files"])

    def test_provenance_from_a_kit_reads_the_manifest_not_a_guess(self):
        with tempfile.TemporaryDirectory() as d:
            kit = Path(d) / "kit"
            (kit / "aip").mkdir(parents=True)
            self.assertEqual(harness.provenance(kit / "aip"), {"repo": "aip", "commit": None, "dirty": None})
            (kit / "MANIFEST.json").write_text(json.dumps({"commits": {"aip": "a" * 40}}))
            p = harness.provenance(kit / "aip")
            self.assertEqual((p["commit"], p["dirty"], p["source"]), ("a" * 40, None, "kit MANIFEST.json"))

    def test_result_file_carries_provenance_hardware_and_labels(self):
        with tempfile.TemporaryDirectory() as t:
            start = harness.now_utc()
            p = harness.write_result(Path(t), "unit", [harness.label("live", "step")], {"ms": 1}, start)
            r = json.loads(p.read_text())
            self.assertEqual(r["schema"], "syntriass.demo.result/v1")
            self.assertRegex(r["provenance"][0]["commit"] or "", r"^[0-9a-f]{40}$")
            self.assertIn("dirty", r["provenance"][0])
            self.assertGreater(r["hardware"]["vcpu"], 0)
            self.assertIn("vCPU", r["hardware"]["label"])
            self.assertLessEqual(r["started_utc"], r["finished_utc"])

    def test_an_unlabelled_step_is_refused(self):
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaises(ValueError):
                harness.write_result(Path(t), "unit", [{"text": "no label"}], {}, harness.now_utc())


class Hardware(unittest.TestCase):
    def test_read_live_not_typed(self):
        h = harness.hardware_report()
        self.assertEqual(h["vcpu"], __import__("os").cpu_count())
        self.assertTrue(h["label"].startswith(f"{h['vcpu']} vCPU"))

    def test_memory_is_never_rounded_up(self):
        kb = next(int(l.split()[1]) for l in Path("/proc/meminfo").read_text().splitlines()
                  if l.startswith("MemTotal:"))
        self.assertLessEqual(harness.hardware_report()["mem_gb"] * 1024 * 1024, kb)


if __name__ == "__main__":
    unittest.main()
