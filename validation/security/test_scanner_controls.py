#!/usr/bin/env python3
"""Exercise real scanners against exact false positives and credential controls.

Requires Python >=3.11, gitleaks and helm. No live credentials or cluster access.
Synthetic credential-shaped controls exist only in a disposable directory.
"""
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import string
import subprocess
import sys
import tempfile
import tomllib
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
GITLEAKS = os.environ.get("GITLEAKS", "gitleaks")
HELM = os.environ.get("HELM", "helm")
CHART = ROOT / "deploy/enterprise/kubernetes/chart"


def run(*args):
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True)


def literal(expression):
    assert expression.startswith(r"^\Q") and expression.endswith(r"\E$")
    return expression[3:-3]


class ScannerControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for binary in (GITLEAKS, HELM):
            if shutil.which(binary) is None:
                raise RuntimeError(f"Required scanner not installed: {binary}")
        config = tomllib.loads((ROOT / ".gitleaks.toml").read_text())
        rule = next(r for r in config["rules"] if r["id"] == "generic-api-key")
        cls.entries = []
        for entry in rule["allowlists"]:
            assert entry["condition"] == "AND" and entry["regexTarget"] == "match"
            assert len(entry["paths"]) == 1
            path = literal(entry["paths"][0])
            for expression in entry["regexes"]:
                cls.entries.append((path, literal(expression)))

    def scan(self, contents):
        with tempfile.TemporaryDirectory(prefix="scanner-controls-") as tmp:
            root = Path(tmp)
            for path, text in contents.items():
                target = root / "input" / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text)
            report = root / "report.json"
            result = subprocess.run(
                [GITLEAKS, "dir", "--no-banner", "--redact",
                 "--config", str(ROOT / ".gitleaks.toml"),
                 "--report-format", "json", "--report-path", str(report), "."],
                cwd=root / "input", capture_output=True, text=True)
            self.assertIn(result.returncode, (0, 1), "Scanner execution/config failed")
            self.assertTrue(report.exists(), "Scanner did not produce its report")
            return json.loads(report.read_text())

    def test_exact_nonsecret_matches_only(self):
        contents = {}
        for path, match in self.entries:
            contents[path] = contents.get(path, "") + match + "\n"
        self.assertEqual(len(self.scan(contents)), 0)

    def test_credentials_same_paths_and_same_lines_still_detected(self):
        rng = random.Random(728471)
        generic = "".join(rng.choices(string.ascii_letters + string.digits, k=48))
        provider = "gh" + "p_" + "".join(rng.choices(string.ascii_letters + string.digits, k=36))
        contents = {}
        expected = set()
        for path, match in self.entries:
            line = contents.get(path, "").count("\n") + 1
            contents[path] = contents.get(path, "") + match + ' api_key="' + generic + '"\n'
            expected.add((path, line, "generic-api-key"))
            contents[path] += match + ' access_token="' + provider + '"\n'
            expected.add((path, line + 1, "github-pat"))
        actual = {(x["File"], x["StartLine"], x["RuleID"]) for x in self.scan(contents)}
        # Other provider/generic detections may overlap; none of the expected
        # independent detections may be suppressed by the exact public match.
        self.assertTrue(expected <= actual, f"Missing detection locations: {sorted(expected - actual)}")

    def test_new_values_and_same_values_other_fields_and_paths_detected(self):
        rng = random.Random(162839)
        replacement = "".join(rng.choices(string.ascii_letters + string.digits, k=48))
        contents = {}
        expected = set()
        for index, (path, match) in enumerate(self.entries):
            import re
            public_value = re.findall(r"[A-Za-z0-9-]{20,}", match)[-1]
            line = contents.get(path, "").count("\n") + 1
            contents[path] = contents.get(path, "") + match.replace(public_value, replacement) + "\n"
            expected.add((path, line, "generic-api-key"))
            contents[path] += 'api_key="' + public_value + '"\n'
            expected.add((path, line + 1, "generic-api-key"))
            outsider = f"outside-evidence/{index}.txt"
            contents[outsider] = match + "\n"
            expected.add((outsider, 1, "generic-api-key"))
        actual = {(x["File"], x["StartLine"], x["RuleID"]) for x in self.scan(contents)}
        self.assertTrue(expected <= actual, f"Missing detection locations: {sorted(expected - actual)}")

    def test_future_audit_labels_need_no_exception(self):
        sys.path.insert(0, str(ROOT / "integrations/real_agents"))
        from audit_crosscheck import AuditCrosscheck
        labels = [AuditCrosscheck().key for _ in range(512)]
        self.assertEqual(len(labels), len(set(labels)))
        for label in labels:
            self.assertRegex(label, r"^audit-run-[a-p]{20}$")
            self.assertEqual(len(label.encode("ascii")), 30)
        contents = {
            "new-run/audit.log": "".join(f'type=SYSCALL key="{label}"\n' for label in labels),
            "new-run/audit-status.json": json.dumps([{"source": "Linux audit", "key": label} for label in labels])
        }
        self.assertEqual(self.scan(contents), [])

    def test_pr_scan_includes_late_history_and_checks_tree_after_failure(self):
        # Reproduce the pagination failure: a credential appears after commit 30,
        # then is removed. Both this historical exposure and an uncommitted
        # current-tree control must be detected independently.
        with tempfile.TemporaryDirectory(prefix="full-pr-scan-") as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()

            def git(*args):
                return subprocess.check_output(
                    ["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false",
                     "-c", "user.name=Scanner Control", "-c", "user.email=scanner@example.invalid",
                     "-C", str(repo), *args], stderr=subprocess.DEVNULL, text=True).strip()

            git("init")
            shutil.copyfile(ROOT / ".gitleaks.toml", repo / ".gitleaks.toml")
            (repo / ".gitleaksignore").write_text("")
            git("add", ".")
            git("commit", "-m", "base")
            base = git("rev-parse", "HEAD")
            rng = random.Random(374689)
            fake = "".join(rng.choices(string.ascii_letters + string.digits, k=48))
            for number in range(40):
                if number == 34:
                    (repo / "credential-control.txt").write_text('api_key="' + fake + '"\n')
                    git("add", "credential-control.txt")
                elif number == 35:
                    git("rm", "credential-control.txt")
                git("commit", "--allow-empty", "-m", f"control {number + 1}")
            head = git("rev-parse", "HEAD")
            env = dict(os.environ, GITHUB_EVENT_NAME="pull_request", PR_BASE_SHA=base, PR_HEAD_SHA=head)
            for tree_control in (False, True):
                if tree_control:
                    (repo / "current-control.txt").write_text('api_key="' + fake + '"\n')
                output = root / str(tree_control)
                result = subprocess.run(
                    [sys.executable, str(ROOT / "validation/security/run_secret_scan.py"),
                     "--repository", str(repo), "--output", str(output), "--gitleaks", GITLEAKS],
                    env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 1)
                scope = json.loads((output / "scope.json").read_text())
                self.assertEqual(scope["history_range"], base + ".." + head)
                self.assertEqual(scope["history_commits"], 40)
                self.assertEqual(scope["results"]["history"]["exit_code"], 1)
                self.assertEqual(scope["results"]["tree"]["exit_code"], int(tree_control))


class KubernetesControls(unittest.TestCase):
    @staticmethod
    def collector_options():
        return ["--set", "collector.enabled=true",
                "--set", "confirmSeparateAdministration=true",
                "--set-string", "collector.image=registry.example.invalid/collector@sha256:" + "1" * 64,
                "--set-string", "collector.configMap=collector-environment-fixture",
                "--set-string", "collector.allowListConfigMap=approved-probes-fixture",
                "--set-string", "collector.passphraseSecret=collector-passphrase-fixture"]

    def test_probe_enablement_is_refused_even_with_previous_opt_ins(self):
        for options in ([], self.collector_options()):
            result = run(HELM, "template", "security-check", str(CHART),
                         *options, "--set", "probe.enabled=true",
                         "--set-string", "probe.image=registry.example.invalid/probe@sha256:" + "0" * 64,
                         "--set-string", "probe.configMap=probe-environment-fixture")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Kubernetes host probe deployment is unavailable", result.stderr)
            self.assertNotIn("kind: DaemonSet", result.stdout)

    def test_collector_renders_without_host_access_and_retains_storage(self):
        result = run(HELM, "template", "security-check", str(CHART), *self.collector_options())
        self.assertEqual(result.returncode, 0, result.stderr)
        for forbidden in ("hostPID:", "hostNetwork:", "hostPath:", "kind: DaemonSet", "privileged: true"):
            self.assertNotIn(forbidden, result.stdout)
        for required in ("kind: Deployment", "kind: Service", "kind: PersistentVolumeClaim",
                         "helm.sh/resource-policy: keep", "runAsNonRoot: true",
                         "type: RuntimeDefault", "automountServiceAccountToken: false",
                         "allowPrivilegeEscalation: false", "readOnlyRootFilesystem: true"):
            self.assertIn(required, result.stdout)

    def test_collector_still_refuses_missing_administrative_boundary(self):
        options = self.collector_options()
        options[options.index("confirmSeparateAdministration=true")] = "confirmSeparateAdministration=false"
        result = run(HELM, "template", "security-check", str(CHART), *options)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("confirmSeparateAdministration is required", result.stderr)

    def test_historical_archive_preserves_exact_bytes_and_findings(self):
        root = ROOT / "validation/enterprise/results/HELM_20261028T103133Z"
        meta = json.loads((root / "retired-template-provenance.json").read_text())
        archive = root / meta["archive"]
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), meta["archive_sha256"])
        with zipfile.ZipFile(archive) as z:
            self.assertEqual(z.namelist(), ["template-enabled.yaml"])
            raw = z.read(meta["member"])
        self.assertEqual(len(raw), meta["original_bytes"])
        self.assertEqual(hashlib.sha256(raw).hexdigest(), meta["original_sha256"])
        self.assertIn(b"hostPID: true", raw)
        self.assertIn(b"hostNetwork: true", raw)
        self.assertIn(b"hostPath:", raw)
        self.assertEqual(meta["historical_findings"], ["KSV-0009", "KSV-0010", "KSV-0118", "KSV-0121"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
