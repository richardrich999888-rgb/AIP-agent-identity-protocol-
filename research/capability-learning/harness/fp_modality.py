"""R2d — can a small model gate modality? (where a model is genuinely needed)

usage (offline): fp_modality.py OUT_DIR --model GGUF:SHA --server LLAMA [--port 8460]

Items: every non-AMBIGUOUS unseen request of the three families (an actual
completed measurement) and four non-actual framings of each, from templates
fixed before running. Zero-shot, greedy, JSON-constrained yes/no. Reports
sensitivity (non-actual caught), specificity (actual kept), CPU-s per call.
"""
import argparse, hashlib, json, os, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "compute-memory", "bench"))
import llama_proc as L  # noqa: E402

TEMPLATES = ["If we were to test it, we might expect: {t}",
             "Test planned next week, readings from the previous unit for reference: {t}",
             "Expected values after the repair is finished (not yet measured): {t}",
             "Training example only, not a real asset: {t}"]
PROMPT = ("Does the following text report a measurement that was actually carried out on real equipment "
          "and is being submitted for a decision now? Hypothetical, planned, expected, example or borrowed "
          "readings do not count.\nTEXT: \"{x}\"\nAnswer as JSON {{\"actual\": true|false}}.")


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("out"); ap.add_argument("--model", required=True)
    ap.add_argument("--server", required=True); ap.add_argument("--port", type=int, default=8460); a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    path, sha = a.model.split(":")
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while b := f.read(1 << 20): h.update(b)
    if h.hexdigest() != sha: sys.exit("hash mismatch")
    items = []
    for fam in ("ir-tasks-v1", "bt-tasks-v1", "tx-tasks-v1"):
        for l in open(os.path.join(HERE, "..", "data", fam, "test_unseen.jsonl")):
            r = json.loads(l)
            if r["label"] == "AMBIGUOUS": continue
            items.append({"id": f"{fam}:{r['id']}", "text": r["text"], "actual": True})
            for k, t in enumerate(TEMPLATES):
                items.append({"id": f"{fam}:{r['id']}:t{k}", "text": t.format(t=r["text"]), "actual": False})
    srv = L.Server(a.server, path, a.port, ("-c", "2048"), os.path.join(a.out, "llama.log"))
    load_s = srv.start(); schema = {"type": "object", "properties": {"actual": {"type": "boolean"}}, "required": ["actual"]}
    c0 = srv.stats()["cpu_s"]; t0 = time.monotonic()
    try:
        for it in items:
            resp, _ = srv.post("/v1/chat/completions", {"messages": [{"role": "user", "content": PROMPT.format(x=it["text"])}],
                       "temperature": 0, "seed": 0, "max_tokens": 12, "response_format": {"type": "json_schema", "json_schema": {"schema": schema}}})
            try: it["pred"] = json.loads(resp["choices"][0]["message"]["content"])["actual"]
            except (ValueError, KeyError): it["pred"] = None
        cpu = srv.stats()["cpu_s"] - c0; peak = srv.stats()["VmHWM"]
    finally:
        srv.stop()
    act = [i for i in items if i["actual"]]; non = [i for i in items if not i["actual"]]
    res = {"model": os.path.basename(path), "n_actual": len(act), "n_non_actual": len(non),
           "specificity_actual_kept": sum(i["pred"] is True for i in act), "sensitivity_non_actual_caught": sum(i["pred"] is False for i in non),
           "by_template": {t[:30]: sum(i["pred"] is False for i in non if i["id"].endswith(f":t{k}")) for k, t in enumerate(TEMPLATES)},
           "unparsed": sum(i["pred"] is None for i in items), "cpu_s_per_call": round(cpu / len(items), 3),
           "wall_s": round(time.monotonic() - t0, 1), "load_s": round(load_s, 2), "peak_rss_mib": round(peak, 1)}
    with open(os.path.join(a.out, "items.jsonl"), "w") as f: f.writelines(json.dumps(i) + "\n" for i in items)
    json.dump(res, open(os.path.join(a.out, "summary.json"), "w"), indent=1); print(json.dumps(res))


if __name__ == "__main__":
    main()
