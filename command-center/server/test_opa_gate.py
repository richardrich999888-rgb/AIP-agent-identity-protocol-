"""Tests for opa_gate.py.

The live tests need the pinned OPA binary at VANIAN_OPA_BIN. Without it they
are SKIPPED, never passed. The fail-closed tests use fake `opa` scripts and
always run.
"""

import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

import opa_gate as g

POLICY = Path(__file__).resolve().parent.parent / "policy"
OPA = os.environ.get("VANIAN_OPA_BIN")
OK = {"agent_id": "recon-reporter", "server": "fs", "tool": "read_file",
      "authority_jtis": ["root-1", "hop-1"], "revoked_jtis": [], "delegation_depth": 1}


def fake_opa(tmp: Path, body: str) -> Path:
    p = tmp / "opa"
    p.write_text("#!/usr/bin/env python3\nimport sys, time\n" + body + "\n")
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return p


def eval_output(value) -> str:
    return json.dumps({"result": [{"expressions": [{"value": value, "text": g.QUERY}]}]})


class Bundle(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.pol = self.tmp / "policy"
        shutil.copytree(POLICY, self.pol)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_excludes_tests_includes_data(self):
        self.assertEqual(sorted(g.read_bundle(self.pol)), ["data.json", "gate.rego"])

    def test_hash_deterministic_and_content_sensitive(self):
        h = g.bundle_hash(g.read_bundle(self.pol))
        self.assertEqual(h, g.bundle_hash(g.read_bundle(self.pol)))
        (self.pol / "data.json").write_text((self.pol / "data.json").read_text() + " ")
        self.assertNotEqual(h, g.bundle_hash(g.read_bundle(self.pol)))

    def test_test_file_change_does_not_change_hash(self):
        h = g.bundle_hash(g.read_bundle(self.pol))
        (self.pol / "gate_test.rego").write_text("package x\n")
        self.assertEqual(h, g.bundle_hash(g.read_bundle(self.pol)))

    def test_rename_changes_hash(self):
        files = g.read_bundle(self.pol)
        moved = {("sub/" + k if k.endswith(".rego") else k): v for k, v in files.items()}
        self.assertNotEqual(g.bundle_hash(files), g.bundle_hash(moved))

    def test_missing_data_or_policy(self):
        (self.pol / "data.json").unlink()
        with self.assertRaises(g.BundleError):
            g.read_bundle(self.pol)
        with self.assertRaises(g.BundleError):
            g.read_bundle(self.tmp / "nope")


class Parse(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(g.parse_decision(eval_output({"outcome": "ALLOW", "reasons": []}).encode()), ("ALLOW", ()))
        self.assertEqual(g.parse_decision(eval_output({"outcome": "DENY", "reasons": ["x"]}).encode()), ("DENY", ("x",)))

    def test_rejections(self):
        cases = {
            b"not json": "policy output not JSON",
            b"{}": "policy result undefined",
            json.dumps({"result": []}).encode(): "policy result undefined",
            eval_output(True).encode(): "policy output malformed",
            eval_output({"outcome": "ALLOW"}).encode(): "policy output malformed",
            eval_output({"outcome": "allow", "reasons": []}).encode(): "policy output malformed",
            eval_output({"outcome": "ALLOW", "reasons": [1]}).encode(): "policy output malformed",
            eval_output({"outcome": "ALLOW", "reasons": [], "extra": 1}).encode(): "policy output malformed",
            eval_output({"outcome": "ALLOW", "reasons": ["x"]}).encode(): "policy output inconsistent: reasons without DENY",
            eval_output({"outcome": "PENDING_APPROVAL", "reasons": ["x"]}).encode(): "policy output inconsistent: reasons without DENY",
        }
        for out, err in cases.items():
            with self.subTest(out=out[:60]):
                self.assertEqual(g.parse_decision(out), err)


class FailClosed(unittest.TestCase):
    """Every engine failure is DENY with engine_ok False."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def assertFailClosed(self, d, reason):
        self.assertEqual((d.outcome, d.forward, d.engine_ok), ("DENY", False, False))
        self.assertTrue(d.reasons[0].startswith(reason), d.reasons)

    def test_binary_missing(self):
        d = g.OpaGate(self.tmp / "no-such-opa", POLICY).decide(OK)
        self.assertFailClosed(d, "policy engine unavailable: binary not found")
        self.assertIsNotNone(d.bundle_sha256)

    def test_timeout(self):
        d = g.OpaGate(fake_opa(self.tmp, "time.sleep(5)"), POLICY, timeout_s=0.5).decide(OK)
        self.assertFailClosed(d, "policy engine unavailable: timeout")

    def test_nonzero_exit(self):
        self.assertFailClosed(g.OpaGate(fake_opa(self.tmp, "sys.exit(3)"), POLICY).decide(OK), "policy engine failed: exit 3")

    def test_garbage_output(self):
        self.assertFailClosed(g.OpaGate(fake_opa(self.tmp, "print('hello')"), POLICY).decide(OK), "policy output not JSON")

    def test_engine_claims_allow_with_reasons(self):
        body = f"print({eval_output({'outcome': 'ALLOW', 'reasons': ['revoked']})!r})"
        self.assertFailClosed(g.OpaGate(fake_opa(self.tmp, body), POLICY).decide(OK), "policy output inconsistent")

    def test_undefined_result(self):
        self.assertFailClosed(g.OpaGate(fake_opa(self.tmp, "print('{}')"), POLICY).decide(OK), "policy result undefined")

    def test_unusable_bundle(self):
        d = g.OpaGate(fake_opa(self.tmp, "print('{}')"), self.tmp / "missing").decide(OK)
        self.assertFailClosed(d, "policy bundle unusable")
        self.assertIsNone(d.bundle_sha256)

    def test_non_json_request(self):
        self.assertFailClosed(g.OpaGate("opa", POLICY).decide({"x": object()}), "request is not JSON")
        self.assertFailClosed(g.OpaGate("opa", POLICY).decide({"x": float("nan")}), "request is not JSON")

    def test_engine_gets_exact_snapshot_not_source(self):
        # The engine must receive a private copy holding exactly the bundle
        # files (no *_test.rego), whose content hashes to bundle_sha256.
        body = ("import hashlib, json, pathlib, sys\n"
                "d = pathlib.Path(sys.argv[sys.argv.index('--data') + 1])\n"
                "names = sorted(p.relative_to(d).as_posix() for p in d.rglob('*') if p.is_file())\n"
                "sys.path.insert(0, %r)\n"
                "import opa_gate\n"
                "h = opa_gate.bundle_hash({n: (d / n).read_bytes() for n in names})\n"
                "print(json.dumps({'result': [{'expressions': [{'value': {'outcome': 'DENY', 'reasons': [str(d), h] + names}}]}]}))"
                ) % str(Path(g.__file__).parent)
        d = g.OpaGate(fake_opa(self.tmp, body), POLICY).decide(OK)
        engine_dir, engine_hash, *names = d.reasons
        self.assertNotEqual(Path(engine_dir).resolve(), POLICY.resolve())
        self.assertEqual(names, ["data.json", "gate.rego"])
        self.assertEqual(engine_hash, d.bundle_sha256)
        self.assertFalse(Path(engine_dir).exists())  # removed after the call


@unittest.skipUnless(OPA and Path(OPA).is_file(), "VANIAN_OPA_BIN not set: live OPA tests SKIPPED")
class Live(unittest.TestCase):
    def gate(self):
        return g.OpaGate(OPA, POLICY)

    def test_allow(self):
        d = self.gate().decide(OK)
        self.assertEqual((d.outcome, d.reasons, d.engine_ok, d.forward), ("ALLOW", (), True, True))
        self.assertEqual(d.bundle_sha256, g.bundle_hash(g.read_bundle(POLICY)))

    def test_revoked_denied(self):
        d = self.gate().decide({**OK, "revoked_jtis": ["hop-1"]})
        self.assertEqual((d.outcome, d.reasons, d.engine_ok), ("DENY", ("authority revoked",), True))

    def test_sensitive_pending_is_not_forwarded(self):
        d = self.gate().decide({**OK, "agent_id": "payments-agent", "server": "payments", "tool": "settle_batch"})
        self.assertEqual((d.outcome, d.forward), ("PENDING_APPROVAL", False))

    def test_explicit_deny(self):
        d = self.gate().decide({**OK, "server": "shell", "tool": "exec", "delegation_depth": 0})
        self.assertEqual(d.reasons, ("tool explicitly denied",))

    def test_malformed_request_is_policy_deny(self):
        d = self.gate().decide({"agent_id": "recon-reporter"})
        self.assertEqual((d.outcome, d.reasons, d.engine_ok), ("DENY", ("malformed input",), True))

    def test_input_hash_is_canonical(self):
        a = self.gate().decide(OK)
        b = self.gate().decide(dict(reversed(list(OK.items()))))
        self.assertEqual(a.input_sha256, b.input_sha256)

    def test_policy_change_changes_recorded_hash(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            pol = tmp / "policy"
            shutil.copytree(POLICY, pol)
            gate = g.OpaGate(OPA, pol)
            before = gate.decide(OK)
            data = json.loads((pol / "data.json").read_text())
            data["inventory"]["denied_tools"].append({"server": "fs", "tool": "read_file"})
            (pol / "data.json").write_text(json.dumps(data))
            after = gate.decide(OK)
            self.assertEqual((before.outcome, after.outcome), ("ALLOW", "DENY"))
            self.assertNotEqual(before.bundle_sha256, after.bundle_sha256)
        finally:
            shutil.rmtree(tmp)


if __name__ == "__main__":
    unittest.main()
