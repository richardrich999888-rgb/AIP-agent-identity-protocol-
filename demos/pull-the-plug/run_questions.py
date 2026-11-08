#!/usr/bin/env python3
"""Ask every question to both sides and write one JSON line per answer (W1.4).

usage: run_questions.py QUESTIONS.json OUT.jsonl -- RUNTIME_CMD...
Run it inside the offline namespace (harness.py run-offline) so that bytes out
is measured where nothing can leave. Each line: the question, the local side's
meter reading, and the cloud side's.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import meter  # noqa: E402

i = sys.argv.index("--")
qfile, out = sys.argv[1], sys.argv[2]
cmd = sys.argv[i + 1:]
q = json.loads(Path(qfile).read_text())
with open(out, "w") as f:
    for item in q["questions"]:
        req = json.dumps({"id": item["id"], "principal": q["principal"], "text": item["text"]})
        local = meter.measure_local(cmd, req)
        cloud = meter.measure_cloud(item["text"])
        f.write(json.dumps({"id": item["id"], "question": item["text"], "local": local, "cloud": cloud}) + "\n")
        f.flush()
        print(f"{item['id']:18} local={local['status']:8} out={local['outer']['bytes_out_non_loopback']} "
              f"cloud={cloud.get('status')}/{cloud.get('reason', '')}")
