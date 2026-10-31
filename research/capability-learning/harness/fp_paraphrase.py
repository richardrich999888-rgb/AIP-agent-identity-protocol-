"""R4 — does the document compiler survive rephrasing? (H2/H3 generalisation)

usage: fp_paraphrase.py OUT_DIR   (then run the pipeline on OUT_DIR/<fam>_L<k>/task.json)
       fp_paraphrase.py --score OUT_DIR

Meaning-preserving rewrites, fixed before any run, applied cumulatively:
  L1 unit symbols ("degrees Celsius"->"°C", "megohms"->"MΩ", "volts"->"V");
     "Otherwise accept."-style defaults -> "In all other cases, accept."
  L2 + synonyms already in the comparator lexicon ("below"->"less than",
     "above"->"greater than", "at least"->"not less than")
  L3 + synonyms NOT in the lexicon ("less than"->"beneath", "greater than"->
     "in excess of", "not less than"->"no lower than")
  L4 + decision sentences restructured outcome-first ("If C, O." -> "O when C.")
Scoring: semantic agreement of the produced IR with the reference IR on the
reference's deterministic boundary points (reference semantics via
atomic.evaluate_ir), whether or not the pipeline's gate passed.
"""
import json, os, re, shutil, sys
HERE = os.path.dirname(os.path.abspath(__file__))
CL = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
FAMS = {"ir": ("tasks/ir_ep114.json", "results/v02/attempt3_ir/ir.json"),
        "bt": ("tasks/bt_hubt4.json", "results/v02/attempt3_bt/ir.json"),
        "tx": ("tasks/tx_hutx2.json", "results/v02/engineer_tx/engineer.ir.json")}


def L1(t):
    t = re.sub(r"degrees Celsius", "°C", t); t = re.sub(r"\bmegohms\b", "MΩ", t); t = re.sub(r"\bvolts\b", "V", t)
    return re.sub(r"(?m)(^|\. )Otherwise,? (accept|pass)\.", lambda m: f"{m.group(1)}In all other cases, {m.group(2)}.", t)


def L2(t):
    t = L1(t)
    for a, b in ((r"\bat least\b", "not less than"), (r"\bbelow\b", "less than"), (r"\babove\b", "greater than")):
        t = re.sub(a, b, t)
    return t


def L3(t):
    t = L2(t)
    for a, b in ((r"\bnot less than\b", "no lower than"), (r"\bless than\b", "beneath"), (r"\bgreater than\b", "in excess of")):
        t = re.sub(a, b, t)
    return t


def L4(t):
    t = L3(t)
    # "If C, O." -> "O when C." for sentences whose condition has no internal comma.
    return re.sub(r"(?<=[.:] )[Ii]f ([^,.]+(?:\.\d+[^,.]*)*), ([^.]+(?:\.\d+[^.]*)*)\.",
                  lambda m: f"{m.group(2)[0].upper()}{m.group(2)[1:]} when {m.group(1)}.", t)


LEVELS = {1: L1, 2: L2, 3: L3, 4: L4}


def make(out):
    for fam, (tp, _) in FAMS.items():
        spec = json.load(open(os.path.join(CL, tp)))
        src = os.path.join(CL, spec["data"])
        head, body = open(os.path.join(src, spec["doc_file"])).read().split("\n", 1)
        for k, f in LEVELS.items():
            d = os.path.join(out, f"{fam}_L{k}")
            os.makedirs(os.path.join(d, "corpus"), exist_ok=True)
            open(os.path.join(d, spec["doc_file"]), "w").write(head + "\n" + f(body))
            shutil.copy(os.path.join(src, "demos.jsonl"), d)
            json.dump({**spec, "data": os.path.relpath(d, CL)}, open(os.path.join(d, "task.json"), "w"))


def score(out):
    import atomic as A
    res = {}
    for fam, (_, ref) in FAMS.items():
        R = json.load(open(os.path.join(CL, ref)))
        pts = [p["inputs"] for p in A.boundary_points(R)]
        for k in [0] + list(LEVELS):
            run = os.path.join(out, f"run_{fam}_L{k}")
            if not os.path.exists(os.path.join(run, "ir.json")):
                continue
            I = json.load(open(os.path.join(run, "ir.json")))
            tri = json.load(open(os.path.join(run, "triage.json")))
            try:
                agree = sum(A.evaluate_ir(I, p) == A.evaluate_ir(R, p) for p in pts)
            except Exception as e:  # incomplete IR cannot be evaluated
                agree = f"not evaluable ({type(e).__name__})"
            res[f"{fam}_L{k}"] = {"status": tri["status"], "agree_on_boundary_points": agree, "points": len(pts),
                                  "issues": len(tri["claim_issues"]) + len(tri["assembly_issues"]) + len(tri["coverage_issues"]),
                                  "demos": tri.get("demo_agreement")}
    json.dump(res, open(os.path.join(out, "score.json"), "w"), indent=1); print(json.dumps(res, indent=1))


if __name__ == "__main__":
    score(sys.argv[2]) if sys.argv[1] == "--score" else make(sys.argv[1])
