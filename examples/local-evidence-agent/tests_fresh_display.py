"""Controlled display/CLI components; no genuine capture or model is invoked."""
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
NODE = r"""
const fs=require('node:fs'),vm=require('node:vm');
const data=JSON.parse(process.argv[2]);
class Element{
  constructor(){this.children=[];this.hidden=true;this.disabled=true;this.style={};this.textContent='';}
  set innerHTML(_value){throw Error('unsafe HTML write');}
  append(...values){this.children.push(...values);}
  replaceChildren(...values){this.children=[...values];}
  addEventListener(){}
}
const elements=new Map();
const document={getElementById(id){if(!elements.has(id))elements.set(id,new Element());return elements.get(id);},createElement(){return new Element();},querySelectorAll(){return [];}};
let calls=0;
const context={document,fetch:async path=>{if(path!=='/api/status')throw Error('unexpected API call');calls++;return{ok:true,json:async()=>data};}};
vm.createContext(context);vm.runInContext(fs.readFileSync(process.argv[1],'utf8'),context);
setTimeout(()=>console.log(JSON.stringify({calls,hidden:document.getElementById('fresh-observation').hidden,
 cards:document.getElementById('fresh-stats').children.map(c=>c.children.map(x=>x.textContent)),
 details:document.getElementById('fresh-details').textContent,admission:document.getElementById('fresh-admission').textContent,
 old_ids:document.getElementById('run').children.map(x=>x.value),button_disabled:document.getElementById('send').disabled,
 status:document.getElementById('live').textContent})),0);
"""


class FreshDisplayControls(unittest.TestCase):
    def render(self, fresh):
        if not shutil.which("node"):
            self.skipTest("Node is missing; controlled JavaScript rendering requires Node")
        script = re.search(r"<script[^>]*>(.*?)</script>", (HERE / "index.html").read_text(), re.S)[1]
        fixture = {"model": "CONTROLLED_FIXTURE_NO_INFERENCE", "fresh_observation": fresh,
                   "runs": [{"id": "old-" + str(i), "label": "Historical fixture"} for i in range(3)]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "script.js"
            path.write_text(script)
            reply = subprocess.run(["node", "-e", NODE, str(path), json.dumps(fixture)], capture_output=True, check=True, timeout=10)
        return json.loads(reply.stdout)

    def test_controlled_fresh_panel_keeps_historical_inputs_and_uses_text(self):
        fresh = {"status": "PASS", "classification": "CONTROLLED_DISPLAY_FIXTURE_NOT_A_CAPTURE",
                 "source_commit": "a" * 40, "task": {"from_ms": 1793600000000, "to_ms": 1793600001000, "exit_code": 0},
                 "capture": {"platform": "Linux", "signed_batches": 2, "kernel_events": 5, "agent_bound_events": 3, "health_records": 1, "task_coverage": "FIXTURE"},
                 "model": {"name": "<img src=x onerror=malicious()>", "completed_http_requests": 8},
                 "output": {"sha256": "b" * 64}, "extra_future_field": "preserved in details"}
        result = self.render(fresh)
        self.assertEqual(result["calls"], 1)
        self.assertFalse(result["hidden"])
        self.assertEqual(result["old_ids"], ["old-0", "old-1", "old-2"])
        self.assertIn(["Workload exit code", "0"], result["cards"])
        self.assertIn(["Task coverage", "FIXTURE"], result["cards"])
        self.assertIn(["Archive batches / total events / health", "2 / 5 / 1"], result["cards"])
        self.assertIn(["Agent-bound events (process instance)", "3"], result["cards"])
        self.assertIn(["Qwen runtime / completed requests", "<img src=x onerror=malicious()> / 8"], result["cards"])
        self.assertEqual(json.loads(result["details"]), fresh)
        self.assertIn("not admitted through /v1/observations", result["admission"])
        self.assertIn("512 KiB", result["admission"])

    def test_no_fresh_capture_panel_without_verified_result(self):
        result = self.render(None)
        self.assertTrue(result["hidden"])
        self.assertEqual(len(result["old_ids"]), 3)

    def test_failed_fresh_result_does_not_enable_questions(self):
        result = self.render({"status": "FAIL"})
        self.assertTrue(result["hidden"])
        self.assertTrue(result["button_disabled"])
        self.assertEqual(result["status"], "Service unavailable")

    def test_fresh_cli_requires_both_inputs_before_model_setup(self):
        reply = subprocess.run([sys.executable, str(HERE / "demo.py"), "--fresh-evidence", "/not-used/fixture"],
                               capture_output=True, timeout=10)
        self.assertNotEqual(reply.returncode, 0)
        self.assertIn(b"--fresh-evidence and --fresh-trust must be supplied together", reply.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
