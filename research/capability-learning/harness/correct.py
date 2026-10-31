"""Phase B — engineer corrections applied to a model draft, as an explicit edit list.

usage: correct.py DRAFT.json OUT.json CORRECTIONS.json

Each correction cites the EP-114 sentence it implements. They were written
from the document text only, before any candidate was run on the validation
suite or the unseen test set. The number and size of edits is the human
effort recorded in the acquisition cost. Author note: the corrections and all
ir-tasks-v1 data have the same single author (disclosed in LEARNING_BENCHMARK).
"""
from __future__ import annotations

import json
import sys

CORRECTIONS = [
    {"id": "C1", "field": "procedure.derive[corrected_resistance]",
     "cite": "multiplying it by two raised to the power of (winding temperature minus 40) divided by 10",
     "why": "operator precedence: the exponent is ((t - 40) / 10)"},
    {"id": "C2", "field": "procedure.derive[+minimum]",
     "cite": "the minimum acceptable corrected resistance is 10 times (rated kV plus 1) megohms",
     "why": "draft used `minimum` without defining it"},
    {"id": "C3", "field": "procedure.rules[*]",
     "cite": "polarization index (PI)", "why": "draft referenced `PI`; its input is `polarization_index`"},
    {"id": "C4", "field": "procedure.numeric_guards",
     "cite": "does not apply to ... motors rated above 11 kV",
     "why": "draft made out-of-range temperature OUT_OF_SCOPE (it is INVALID per Step 1) and missed the >11 kV scope limit"},
    {"id": "C5", "field": "procedure.text_guards",
     "cite": "does not apply to transformers, cables, generators",
     "why": "terms are matched as words; the phrase 'motors rated above 11 kV' can never match and singular forms were missing"},
    {"id": "C6", "field": "procedure.rules[PI bands]",
     "cite": "acceptable but PI is below 1.5, dry out. If PI is at least 1.5 but below 2.0, accept ... retest in 30 days. Otherwise pass",
     "why": "draft mapped PI < 1.5 to RETEST_30D and 1.5 <= PI < 2.0 to PASS"},
    {"id": "C7", "field": "applicability.any_terms",
     "cite": "measured insulation resistance in megohms",
     "why": "draft required 'induction motor' or 'rated voltage'; requests say IR / megohms / megger"},
]


def apply(draft: dict) -> dict:
    c = json.loads(json.dumps(draft))
    p = c["procedure"]
    names = {i["kind"]: i["name"] for i in p["inputs"]}
    kv, ir, t = names["voltage"], names["resistance"], names["temperature"]
    pi = next(i["name"] for i in p["inputs"] if i["kind"] == "cued")
    # C1, C2
    p["derive"] = [{"name": "corrected_resistance", "expr": f"{ir} * 2 ^ (({t} - 40) / 10)"},
                   {"name": "minimum", "expr": f"10 * ({kv} + 1)"}]
    # C4
    p["numeric_guards"] = [{"when": f"{kv} > 11", "outcome": "OUT_OF_SCOPE"}]
    # C5
    p["text_guards"] = [{"any_terms": ["transformer", "transformers", "cable", "cables", "generator", "generators"],
                         "outcome": "OUT_OF_SCOPE"}]
    # C3, C6 (Step 1 validity rule kept from the draft, renamed variables)
    p["rules"] = [
        {"when": f"{t} < 10 or {t} > 75", "outcome": "INVALID_TEST"},
        {"when": "corrected_resistance < 0.5 * minimum", "outcome": "REJECT"},
        {"when": "corrected_resistance < minimum", "outcome": "DRY_OUT"},
        {"when": f"{pi} < 1.5", "outcome": "DRY_OUT"},
        {"when": f"{pi} < 2.0", "outcome": "RETEST_30D"},
    ]
    p["default_outcome"] = "PASS"
    # C7
    c["applicability"]["any_terms"] = ["insulation", "IR", "megohm", "megohms", "MΩ", "Mohm", "megger"]
    c["id"] = "koravi.ep114.ir-acceptance.learned"
    c["proposed_by"] = draft["proposed_by"]  # the proposal remains the model's; corrections are recorded separately
    return c


def main() -> None:
    draft = json.load(open(sys.argv[1]))
    out = apply(draft)
    json.dump(out, open(sys.argv[2], "w"), indent=1, ensure_ascii=False)
    json.dump({"draft": sys.argv[1], "corrections": CORRECTIONS, "n_corrections": len(CORRECTIONS)},
              open(sys.argv[3], "w"), indent=1)
    print(json.dumps({"corrections": len(CORRECTIONS), "out": sys.argv[2]}))


if __name__ == "__main__":
    main()
