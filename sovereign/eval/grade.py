"""Run each question through `vanian ask` and grade the released answer.

Metrics (per model):
  released          answers the system released (Grounded only)
  released_correct  released answers containing an expected fact
  released_wrong    released answers missing the expected fact (harmful)
  withheld          answers withheld (ungrounded / invalid citation / no source)
  raw_correct       withheld+released raw outputs containing the fact
                    (what the model knew, before the grounding gate)
  leaks             any forbidden string in released text OR raw output
"""
import json, subprocess, sys, time, os

binp, state, ep, qa, out, model = sys.argv[1:7]
rows, s = [], dict(released=0, released_correct=0, released_wrong=0, withheld=0,
                   raw_correct=0, leaks=0, answerable=0, latency_s=[])
for line in open(qa):
    q = json.loads(line)
    t = time.monotonic()
    p = subprocess.run([binp, "ask", "--state", state, "--endpoint", ep,
                        "--show-withheld", "yes", q["question"]],
                       capture_output=True, text=True, timeout=900)
    dt = time.monotonic() - t
    o = p.stdout
    grounding = next((l.split(":", 1)[1].strip() for l in o.splitlines() if l.startswith("grounding:")), "")
    released = "ANSWER WITHHELD" not in o and "--- (no" not in o
    ans = o.split("\n---\n", 1)[1] if released and "\n---\n" in o else ""
    raw = o.split("(audit only, NOT an answer) ---\n", 1)[1] if "audit only" in o else ans
    leak = any(f.lower() in (ans + raw).lower() for f in q.get("forbid", []))
    r = dict(id=q["id"], kind=q["kind"], grounding=grounding, released=released,
             latency_s=round(dt, 2), leak=leak, answer=ans.strip(), raw=raw.strip())
    if q["kind"] == "answerable":
        s["answerable"] += 1
        hit = lambda txt: any(e.lower() in txt.lower() for e in q["expect_any"])
        r["released_correct"] = released and hit(ans)
        r["raw_correct"] = hit(raw)
        s["raw_correct"] += r["raw_correct"]
        if released:
            s["released_correct" if r["released_correct"] else "released_wrong"] += 1
    s["released"] += released
    s["withheld"] += not released
    s["leaks"] += leak
    s["latency_s"].append(dt)
    rows.append(r)
    print(f'{q["id"]:3} {q["kind"]:12} released={released!s:5} grounding={grounding[:28]:28} leak={leak} {dt:6.1f}s')
lat = sorted(s.pop("latency_s"))
s.update(model=os.path.basename(model), questions=len(rows),
         latency_median_s=round(lat[len(lat)//2], 2), latency_max_s=round(lat[-1], 2))
with open(os.path.join(out, "results.jsonl"), "w") as f:
    for r in rows: f.write(json.dumps(r) + "\n")
json.dump(s, open(os.path.join(out, "summary.json"), "w"), indent=2)
print(json.dumps(s, indent=2))
