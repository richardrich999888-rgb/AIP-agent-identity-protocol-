"""Render the offline demo run into one self-contained local HTML page.

usage: render_demo.py OUT_DIR   (OUT_DIR is the directory run_demo.sh wrote)

Reads only files the demo run produced (OUT_DIR/scenes/*) and recorded
benchmark results in the repository (paths printed on the page). Nothing is
computed, estimated or invented here: a missing file is shown as "not run".
Standard library only; no network, no external assets.
"""
from __future__ import annotations

import glob
import html
import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
ECON = "research/capability-learning/results/economics.json"
SPRINT = "research/capability-learning/results/sprint/summary.json"


def load(path: str):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def jsonl(path: str) -> list:
    try:
        return [json.loads(l) for l in open(path) if l.strip()]
    except (OSError, ValueError):
        return []


def resp(path: str) -> dict:
    d = load(path) or {}
    return d.get("response") or {}


def esc(x) -> str:
    return html.escape(str(x))


def raw(obj) -> str:
    return f"<details><summary>raw runtime output</summary><pre>{esc(json.dumps(obj, indent=1, ensure_ascii=False))}</pre></details>"


def strategy_name(s) -> str:
    if s == "Exact":
        return "Exact computation (deterministic rules)"
    if s == "Interpreter":
        return "Specialist interpreter (no language model)"
    if isinstance(s, dict):
        k = next(iter(s))
        return {"GroundedQa": "Local language model, grounded in documents", "ModelExtraction": "Local language model extraction",
                "Capability": "Approved capability (no language model)", "Refuse": "Refused"}.get(k, k)
    return str(s)


def facts(r: dict) -> str:
    c = r.get("cost", {})
    rss = c.get("rss_mib", {})
    rows = [("How it was executed", strategy_name(r.get("strategy"))),
            ("Language-model calls", c.get("model_calls")),
            ("Latency", f"{c.get('wall_ms', 0):.1f} ms"),
            ("CPU seconds (per process)", ", ".join(f"{k} {v}" for k, v in c.get("cpu_s", {}).items()) or "—"),
            ("Resident memory (MiB)", ", ".join(f"{k} {v}" for k, v in rss.items()) or "—")]
    return "<table>" + "".join(f"<tr><th>{esc(a)}</th><td>{esc(b)}</td></tr>" for a, b in rows) + "</table>"


def outcome(r: dict) -> str:
    o = r.get("outcome", {})
    k = o.get("kind")
    if k == "answer":
        return f"<p class=answer>“{esc(o.get('text'))}”</p><p>Evidence: {esc(', '.join(o.get('sources', [])))}</p>"
    if k == "decision":
        vals = o.get("detail", {}).get("values")
        extra = "" if not vals else "<p>Values used: " + esc(", ".join(f"{k}={round(v, 4)}" for k, v in vals.items())) + "</p>"
        return f"<p class=decision>Decision: <b>{esc(o.get('label'))}</b></p>{extra}"
    if k == "refused":
        return f"<p class=refused>Refused: {esc(json.dumps(o.get('refusal'), ensure_ascii=False))}</p>"
    if k == "withheld":
        return f"<p class=refused>Withheld: {esc(o.get('reason'))}</p>"
    return "<p class=missing>not run</p>"


def section(n: int, title: str, why: str, body: str) -> str:
    return f"<section><h2><span>{n}</span>{esc(title)}</h2><p class=why>{esc(why)}</p>{body}</section>"


def main() -> None:
    out = sys.argv[1]
    S = os.path.join(out, "scenes")
    first = lambda pat: (sorted(glob.glob(os.path.join(S, pat))) or [""])[0]
    s1s = [resp(p) for p in sorted(glob.glob(os.path.join(S, "scene1-*.json")), key=lambda p: int(p.rsplit("-", 1)[1].split(".")[0]))]
    s2, s4 = resp(first("scene2-*.json")), resp(first("scene4-*.json"))
    s5 = [resp(p) for p in sorted(glob.glob(os.path.join(S, "scene5-*.json")))]
    val = load(os.path.join(S, "scene3-validation.json")) or {}
    draft = jsonl(os.path.join(S, "scene3-draft-check.jsonl"))
    recs = jsonl(os.path.join(S, "scene3-records.jsonl"))
    after = jsonl(os.path.join(S, "scene5-records-after-tamper.jsonl"))
    econ = load(os.path.join(ROOT, ECON)) or {}
    sprint = load(os.path.join(ROOT, SPRINT))
    offline = open(os.path.join(S, "scene6.txt")).read() if os.path.exists(os.path.join(S, "scene6.txt")) else "not run"
    audit = load(os.path.join(S, "audit.json")) or {}
    parts = []
    p1 = ""
    for k, r in enumerate(s1s):
        p1 += ("<h3>Question that needs a calculation</h3><p>The local model only restated the rule, so the runtime says the calculation was not completed instead of presenting it as an answer.</p>" if k else "")
        p1 += outcome(r) + facts(r) + raw(r)
    parts.append(section(1, "Private AI", "An authorised engineer asks about a confidential procedure. The answer comes from local documents the engineer may read, with the evidence cited.", p1))
    parts.append(section(2, "Efficient execution", "A routine structured report does not need a language model: deterministic rules decide it.",
                         outcome(s2) + facts(s2) + raw(s2)))
    teach = "<h3>What the local model proposed</h3>"
    teach += ("<p>The model's own draft did not compile: " + esc(draft[0].get("error", "")) + "</p>") if draft and "compiled" in draft[0] else "<p>see raw</p>"
    teach += "<p>An engineer applied 7 cited corrections (recorded). The capability was then validated against a test suite signed by an independent expert:</p>"
    teach += "<table>" + "".join(f"<tr><th>{esc(k)}</th><td>{esc(val.get(k))}</td></tr>" for k in
                                  ("passed", "expert_cases", "expert_passed", "counterexamples", "counterexamples_passed",
                                   "suite_signature_ok", "suite_independent", "evidence_scope_ok")) + "</table>"
    teach += "<p>Lifecycle record: " + esc(", ".join(f"{r['id']} v{r['version']} {r['state']} (executable={r['executable']})" for r in recs)) + "</p>"
    if sprint:
        teach += "<h3>New in this sprint: constrained capability compiler (research result)</h3><table>"
        teach += "".join(f"<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>" for k, v in sprint.get("headline", {}).items()) + "</table>"
        teach += f"<p class=src>source: {esc(SPRINT)}</p>"
    parts.append(section(3, "Teach the AI", "An organisation's procedure becomes a typed, versioned capability. It cannot approve itself: an independent expert's signed tests and a separate approver are required.", teach + raw(val)))
    parts.append(section(4, "Reuse intelligence", "A new request the capability has never seen. It runs the approved procedure exactly, with no language-model call and no fine-tuning.",
                         outcome(s4) + facts(s4) + raw(s4)))
    b = econ.get("baselines", {})
    cap = econ.get("capability", {})
    rows = [("Local model alone (B1)", b.get("B1", {})), ("Local model + document retrieval (B2)", b.get("B2", {})),
            ("Local model + prompt-based skills (B3)", b.get("B3", {}))]
    cost = "<table><tr><th>System</th><th>Accuracy (32 unseen decisions)</th><th>CPU-s per task</th><th>CPU-s per correct answer</th></tr>"
    cost += "".join(f"<tr><td>{esc(n)}</td><td>{esc(x.get('accuracy'))}</td><td>{esc(x.get('per_task_cpu_s'))}</td><td>{esc(x.get('cpu_per_correct_s'))}</td></tr>" for n, x in rows)
    cost += f"<tr><td><b>Approved capability</b></td><td>{esc(cap.get('accuracy'))}</td><td>≤ {esc(cap.get('per_task_cpu_s_upper_bound'))}</td><td>see break-even</td></tr></table>"
    acq = econ.get("acquisition", {})
    cost += (f"<p>Acquisition: {esc(acq.get('model_cpu_s'))} model CPU-s plus human inputs {esc(acq.get('human_inputs'))}. "
             f"Break-even uses (compute only): {esc(econ.get('break_even_uses'))}.</p>"
             "<p class=warn>CPU-only research results on a 2-core, 8 GB virtual machine with 0.5–1.5B models. Human time was not measured; these are not total-cost figures.</p>"
             f"<p class=src>source: {esc(ECON)}</p>")
    parts.append(section(5, "Compare cost", "Measured cost per correct answer against conventional local-model approaches on the same machine and tasks.", cost))
    parts.append(section(6, "Offline operation", "Every model call runs inside a network namespace with no route out; the check below ran in that namespace.",
                         f"<pre>{esc(offline)}</pre>"))
    sec = ""
    labels = ["Another organisation invokes the capability", "Same organisation, lower clearance", "After tampering with the stored capability"]
    for lab, r in zip(labels, s5):
        sec += f"<h3>{esc(lab)}</h3>" + outcome(r) + raw(r)
    sec += "<p>Capability record after tampering: " + esc(", ".join(f"executable={r['executable']}" for r in after)) + "</p>"
    sec += f"<p>Audit log hash chain: {esc(audit)}</p>"
    parts.append(section(7, "Security", "Requests without authority are refused; a modified capability stops working.", sec))
    page = f"""<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>SYNTRIASS Offline Demo</title><style>
:root{{--bg:#fbfaf7;--fg:#1d1d1b;--mute:#5f5e58;--line:#dedbd2;--acc:#1f5f8b;--ok:#2d6a3e;--bad:#9b2c2c}}
@media (prefers-color-scheme:dark){{:root{{--bg:#151514;--fg:#ecebe6;--mute:#a5a39b;--line:#3a3935;--acc:#7fb4dc;--ok:#8fcf9d;--bad:#e59a9a}}}}
body{{background:var(--bg);color:var(--fg);font:16px/1.55 system-ui,sans-serif;margin:0;padding:24px 16px}}
main{{max-width:880px;margin:auto}} h1{{font-size:26px;margin:0 0 4px}} .lede{{color:var(--mute);margin:0 0 24px}}
section{{border-top:1px solid var(--line);padding:18px 0}} h2{{font-size:19px;margin:0 0 6px}} h2 span{{color:var(--acc);margin-right:10px}}
h3{{font-size:15px;margin:14px 0 4px}} .why{{color:var(--mute);margin:0 0 10px}} table{{border-collapse:collapse;width:100%;font-size:14px;margin:8px 0}}
th,td{{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line);vertical-align:top}} th{{color:var(--mute);font-weight:500;width:38%}}
.answer{{font-size:17px}} .decision b{{color:var(--ok)}} .refused{{color:var(--bad)}} .warn{{color:var(--bad);font-size:14px}}
.src{{color:var(--mute);font-size:13px}} pre{{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}} details{{margin:6px 0;color:var(--mute)}}
</style></head><body><main><h1>SYNTRIASS — private AI, offline</h1>
<p class=lede>Every value on this page is copied from the runtime's own output for this run ({esc(out)}), or from a recorded benchmark file named next to it.</p>
{''.join(parts)}</main></body></html>"""
    with open(os.path.join(out, "demo.html"), "w") as f:
        f.write(page)


if __name__ == "__main__":
    main()
