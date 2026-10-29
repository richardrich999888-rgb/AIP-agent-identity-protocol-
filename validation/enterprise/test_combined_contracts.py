"""Portable integration regressions; no kernel or autonomous-workload claim."""
import json
from pathlib import Path
import re
import subprocess
import unittest

from openapi_contract import OpenAPIContract, RUN_OPERATIONS
import yaml

ROOT = Path(__file__).resolve().parents[2]


class CombinedContracts(unittest.TestCase):
    def test_both_deployment_and_run_routes_remain_documented(self):
        contract = OpenAPIContract()
        contract.assert_route_alignment()
        self.assertTrue(RUN_OPERATIONS <= set(contract.operations))
        self.assertTrue({("GET", "/v1/deployments"), ("POST", "/v1/deployments"),
                         ("GET", "/v1/deployments/{name}")} <= set(contract.operations))

    def test_console_disconnect_clears_both_feature_sets(self):
        html = (ROOT / "integrations/enterprise-console/index.html").read_text()
        ids = re.findall(r'\bid="([^"]+)"', html)
        self.assertEqual(len(ids), len(set(ids)), "duplicate console identifiers")
        # Execute the actual script with a minimal DOM. This is a control-flow
        # regression, not a replacement for the real-service browser exercise.
        harness = r"""
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const elements = new Map(JSON.parse(process.argv[1]).map(id => [id, {
  textContent: 'sensitive prior session data', value: 'prior credential',
  disabled: false, listeners: {},
  addEventListener(kind, fn) { this.listeners[kind] = fn; },
  replaceChildren(...children) { this.children = children; }
}]));
vm.runInNewContext(fs.readFileSync(process.argv[2], 'utf8'), {
  document: { getElementById(id) {
    assert.ok(elements.has(id), 'script references missing element ' + id);
    return elements.get(id);
  }}, setInterval() {}
});
elements.get('disconnect').listeners.click();
for (const id of ['run', 'deployments', 'deployment', 'evidence', 'verdict'])
  assert.equal(elements.get(id).textContent, 'Disconnected', id);
assert.equal(elements.get('credential').value, '');
assert.equal(elements.get('refresh').disabled, true);
"""
        subprocess.run(["node", "-e", harness, json.dumps(ids),
                        str(ROOT / "integrations/enterprise-console/app.js")],
                       check=True, capture_output=True, text=True, timeout=15)

    def test_same_run_retrieval_uses_built_customer_client(self):
        smoke = (ROOT / "validation/enterprise/run_typescript_smoke.ts").read_text()
        self.assertIn('from "../../sdk/typescript/dist/index.js"', smoke)
        workflow = yaml.safe_load((ROOT / ".github/workflows/same-run-validation.yml").read_text())
        commands = "\n".join(step.get("run", "") for step in
                             workflow["jobs"]["local-model-linux"]["steps"])
        self.assertLess(commands.index("npm ci --prefix sdk/typescript --ignore-scripts"),
                        commands.index("validation/enterprise/same_run_validation.py"))
        self.assertLess(commands.index("npm run build --prefix sdk/typescript"),
                        commands.index("validation/enterprise/same_run_validation.py"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
