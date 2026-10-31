"""S1 measurement — evidence-bound execution on the three families. Rules fixed before running.

usage: fp_evidence.py OUT_DIR

Arm A (text): the validated capability as deployed, numbers read from text.
Arm B (signed record): the same procedure with evidence = signed_record. Each
real unseen request carries a record signed by a registered instrument key,
built from the item's structured inputs (the dataset's ground-truth reading;
missing readings omitted). Hypothetical / planned probes (fp_probes rules)
carry NO record: no instrument measured them. Unsafe = a release decision
where the expected answer is not a release.
Limitation stated in the output: records are built from ground truth, so arm B
measures decision logic given correct readings, not instrument availability.
"""
import json, os, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import fp_probes as P
BIN = P.BIN
MAP = {"ir": {"kv": ("kV",), "ir_mohm": ("MΩ",), "temp_c": ("°C",), "pi": ("cue", "PI")},
       "bt": {"v": ("V",), "t": ("°C",), "sg": ("cue", "SG")},
       "tx": {"kv": ("kV",), "ir": ("MΩ",), "t": ("°C",), "dar": ("cue", "DAR")}}
TEN = {"ir": "koravi-process", "bt": "halvorn-power", "tx": "halvorn-power"}

def run(cmd): return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout

o = sys.argv[1]; os.makedirs(o, exist_ok=True)
key = os.path.join(o, "instrument.key.json")
if not os.path.exists(key): run([BIN, "keygen", "--id", "instrument:test-set-1", "--out", key])
pub = json.load(open(key))["public_hex"]; inst = os.path.join(o, "instruments.json")
json.dump({"instrument:test-set-1": pub}, open(inst, "w"))
summary = {"limitation": "records built from dataset ground-truth inputs; measures logic given correct readings"}
for fam, (d, cap, rel, _, _) in P.FAM.items():
    c = json.load(open(os.path.join(P.CL, cap))); c["evidence"] = "signed_record"
    cb = os.path.join(o, f"{fam}.signed.capability.json"); json.dump(c, open(cb, "w"), ensure_ascii=False)
    items = [r for r in P.rows(d, "test_unseen.jsonl") if r["label"] != "AMBIGUOUS"]
    recs = []
    for r in items:
        q = []
        for k, v in r["inputs"].items():
            if v is None or k not in MAP[fam]: continue
            m = MAP[fam][k]
            q.append({"cued": {"cue": m[1], "value": v}} if m[0] == "cue" else {"physical": {"reading": f"{v} {m[0]}"}})
        recs.append({"record_id": r["id"], "tenant": TEN[fam], "asset_id": r["id"], "instrument_id": "instrument:test-set-1",
                     "taken_at_ms": 1, "quantities": q or [{"cued": {"cue": "none", "value": 0}}], "signature_hex": ""})
    uf = os.path.join(o, f"{fam}.unsigned.jsonl")
    with open(uf, "w") as f: f.writelines(json.dumps(x, ensure_ascii=False) + "\n" for x in recs)
    signed = [json.loads(l) for l in run([BIN, "record-sign", "--key", key, "--in", uf]).splitlines()]
    probes = [p for p in P.probes(fam) if p["rule"] in ("hypothetical", "planned")]
    cases = [{"id": r["id"], "text": r["text"], "label": r["label"]} for r in items]
    with open(os.path.join(o, f"{fam}.A.jsonl"), "w") as f:
        f.writelines(json.dumps(x, ensure_ascii=False) + "\n" for x in cases + [{"id": p["id"], "text": p["text"], "label": "-"} for p in probes])
    with open(os.path.join(o, f"{fam}.B.jsonl"), "w") as f:
        f.writelines(json.dumps({**x, "record": s}, ensure_ascii=False) + "\n" for x, s in zip(cases, signed))
        f.writelines(json.dumps({"id": p["id"], "text": p["text"], "label": "-"}, ensure_ascii=False) + "\n" for p in probes)
    res = {}
    for arm, capf in (("A_text", os.path.join(P.CL, cap)), ("B_signed_record", cb)):
        out = run([BIN, "cap-check", "--file", capf, "--cases", os.path.join(o, f"{fam}.{arm[0]}.jsonl"), "--instruments", inst])
        got = {json.loads(l)["id"]: json.loads(l)["got"] for l in out.splitlines()}
        res[arm] = {"real_strict": f"{sum(got[r['id']] == r['label'] for r in items)}/{len(items)}",
                    "real_wrong_release": sum(1 for r in items if got[r['id']] != r['label'] and got[r['id']] in rel),
                    "probe_unsafe_release": f"{sum(1 for p in probes if got[p['id']] in rel)}/{len(probes)}",
                    "misses": [(r["id"], r["label"], got[r["id"]]) for r in items if got[r["id"]] != r["label"]]}
    summary[fam] = res
json.dump(summary, open(os.path.join(o, "summary.json"), "w"), indent=1, ensure_ascii=False); print(json.dumps(summary, indent=1, ensure_ascii=False))
