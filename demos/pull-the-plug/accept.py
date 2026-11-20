#!/usr/bin/env python3
"""Acceptance for Pull the plug (W1.4), judged from answers.jsonl against
questions.json (fixed before the run). Stdlib only.

  every question: local bytes out == 0, the run was offline, the cloud side failed
  answered:       local answered, cites the named document, contains the fact
  must_not_*:     the forbidden text and document never appear in the local answer

usage: accept.py QUESTIONS.json ANSWERS.jsonl OFFLINE_CHECK.json
"""
import json
import sys
from pathlib import Path


def judge(questions: dict, answers: list[dict], offline: dict) -> dict:
    problems = []
    if not offline.get("offline"):
        problems.append(f"the run was not offline: {offline}")
    by = {a["id"]: a for a in answers}
    for q in questions["questions"]:
        a = by.get(q["id"])
        if a is None:
            problems.append(f"{q['id']}: no answer recorded")
            continue
        loc, cl, e = a["local"], a["cloud"], q["expect"]
        text = (loc.get("answer") or "")
        sources = ((loc.get("runtime") or {}).get("sources")) or []
        if loc["outer"]["bytes_out_non_loopback"] != 0:
            problems.append(f"{q['id']}: local sent {loc['outer']['bytes_out_non_loopback']} bytes out")
        if cl.get("status") != "failed":
            problems.append(f"{q['id']}: cloud side did not fail offline ({cl.get('status')})")
        if e.get("answered"):
            if loc["status"] != "answered":
                problems.append(f"{q['id']}: local did not answer ({loc['status']})")
            if e["cites"] not in sources:
                problems.append(f"{q['id']}: does not cite {e['cites']} (cites {sources})")
            if e["contains"] not in text:
                problems.append(f"{q['id']}: answer lacks {e['contains']!r}")
        if "must_not_contain" in e and e["must_not_contain"].lower() in text.lower():
            problems.append(f"{q['id']}: answer contains forbidden {e['must_not_contain']!r}")
        if "must_not_cite" in e and e["must_not_cite"] in sources:
            problems.append(f"{q['id']}: cites forbidden {e['must_not_cite']}")
    return {"pass": not problems, "problems": problems, "questions": len(questions["questions"])}


if __name__ == "__main__":
    q = json.loads(Path(sys.argv[1]).read_text())
    ans = [json.loads(l) for l in Path(sys.argv[2]).read_text().splitlines() if l.strip()]
    r = judge(q, ans, json.loads(Path(sys.argv[3]).read_text()))
    print(json.dumps(r, indent=2))
    print("ACCEPTANCE:", "PASS" if r["pass"] else "FAIL")
    sys.exit(0 if r["pass"] else 1)
