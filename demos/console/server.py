#!/usr/bin/env python3
"""SYNTRIASS demo console — one page that runs the real demos live.

  sudo SYNTRIASS_BUNDLE=/path/to/bundle python3 demos/console/server.py [PORT]   → http://127.0.0.1:8770/

Everything shown comes from a live run started from the page or, for the
benchmark, from recorded result files that are labelled RECORDED with their
date. Nothing is mocked.

  GET  /                     the page (self-contained; no CDN, font or remote script)
  GET  /assets/<name>        brand assets (fixed list)
  GET  /api/status           readiness of every mode, hardware, commits
  POST /api/run   {mode}     start one demo through demos/launch.py (one at a time)
  GET  /api/job/<id>         its live console text, then its parsed result
  POST /api/ask   {question, model}
                             one question to the local runtime inside a network
                             namespace with no route out, and to the cloud app
  GET  /api/benchmark        the recorded benchmark and its fresh rerun (files)
  GET  /api/report/<id>      the Quantum X-ray one-page report of a finished job

Local only: binds 127.0.0.1, refuses other Host headers, caps bodies at 16 KiB.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEMOS = HERE.parent
REPO = DEMOS.parent
sys.path.insert(0, str(DEMOS))
sys.path.insert(0, str(DEMOS / "common"))
import harness  # noqa: E402
import launch  # noqa: E402

RESULTS = DEMOS / "results" / "console"
ASSETS = {"syntriass-mark.png": "image/png", "syntriass-wordmark.png": "image/png",
          "syntriass-logo.jpg": "image/jpeg", "favicon.png": "image/png"}
CONSOLE_MODES = ("pull-the-plug", "security", "quantum", "pq")
MODELS = {"qwen2.5-1.5b-q4": "Qwen2.5-1.5B (Q4)", "granite-3.3-2b-q4": "IBM Granite 3.3-2B (Q4)"}
MAX_BODY = 16 * 1024
JOBS: dict[str, dict] = {}
LOCK = threading.Lock()  # one demo or question at a time: they share CPU, models and container names


def _busy() -> bool:
    return any(j["state"] == "running" for j in JOBS.values())


# ── demo runs ──────────────────────────────────────────────────────────────

def _summarise(mode: str, out: Path, rc: int) -> dict:
    """Read the run's own files; return only what they say."""
    s: dict = {"passed": rc == 0, "exit_code": rc}
    inner = out / "run"
    try:
        if mode == "pull-the-plug":
            rows = [json.loads(l) for l in (inner / "answers.jsonl").read_text().splitlines() if l.strip()]
            s["answers"] = [{"id": r["id"], "question": r["question"], "status": r["local"]["status"],
                             "answer": r["local"].get("answer"),
                             "sources": (r["local"].get("runtime") or {}).get("sources"),
                             "wall_ms": r["local"]["outer"]["wall_ms"],
                             "bytes_out": r["local"]["outer"]["bytes_out_non_loopback"],
                             "cloud": f"{r['cloud'].get('status')} ({r['cloud'].get('reason', '')})"} for r in rows]
        elif mode == "security":
            s["screen"] = (inner / "screen.txt").read_text()
            if (inner / "control-screen.txt").exists():
                s["control"] = (inner / "control-screen.txt").read_text()
        elif mode == "pq":
            s["phases"] = [json.loads(l) for l in (inner / "phases.jsonl").read_text().splitlines() if l.strip()]
            acc = json.loads((inner / "acceptance.txt").read_text().rsplit("ACCEPTANCE", 1)[0])
            s["overhead"] = acc.get("overhead_reported_not_judged")
        elif mode == "quantum":
            acc = json.loads((inner / "acceptance.txt").read_text().rsplit("ACCEPTANCE", 1)[0])
            s["found"] = acc.get("found_by_planted_item")
            s["invented"] = acc.get("invented")
            s["timings"] = (inner / "timings.txt").read_text()
            s["report"] = (inner / "report.html").exists()
    except (OSError, ValueError, KeyError) as e:
        s["parse_note"] = f"result files incomplete: {e}"
    res = sorted(out.glob("launch-*.json"))
    if res:
        r = json.loads(res[-1].read_text())
        s["result_file"] = str(res[-1].relative_to(REPO))
        s["wall_s"] = r["measurements"]["wall_s"]
        s["provenance"] = r["provenance"]
    return s


def _run_job(jid: str, mode: str) -> None:
    job = JOBS[jid]
    out = Path(job["out"])
    with LOCK:
        p = subprocess.run([sys.executable, str(DEMOS / "launch.py"), "run", mode, "--out", str(out)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=os.environ.copy())
        job["summary"] = _summarise(mode, out, p.returncode)
        job["state"] = "passed" if p.returncode == 0 else ("not_ready" if p.returncode == 3 else "failed")
        job["finished"] = time.time()


def start(mode: str) -> dict:
    if mode not in CONSOLE_MODES:
        return {"error": f"unknown mode {mode!r}"}
    if _busy():
        return {"error": "a demo is already running; wait for it to finish"}
    why = launch.mode_spec(mode)["ready"]()
    if why:
        return {"error": f"NOT READY: {why}"}
    jid = uuid.uuid4().hex[:12]
    out = RESULTS / f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{mode}-{jid}"
    out.mkdir(parents=True, exist_ok=True)
    JOBS[jid] = {"id": jid, "mode": mode, "state": "running", "out": str(out), "started": time.time()}
    threading.Thread(target=_run_job, args=(jid, mode), daemon=True).start()
    return {"id": jid}


def job_view(jid: str) -> dict:
    j = JOBS.get(jid)
    if not j:
        return {"error": "no such job"}
    con = Path(j["out"]) / "console.txt"
    text = con.read_text(errors="replace") if con.exists() else ""
    return {**{k: j[k] for k in ("id", "mode", "state", "started")},
            "elapsed_s": round((j.get("finished") or time.time()) - j["started"], 1),
            "console": text[-60000:], "summary": j.get("summary")}


# ── ask one question ───────────────────────────────────────────────────────

def ask(question: str, model: str) -> dict:
    if model not in MODELS:
        return {"error": "unknown model"}
    question = question.strip()
    if not question or len(question) > 500:
        return {"error": "ask a question of 1 to 500 characters"}
    if _busy() or LOCK.locked():
        return {"error": "a demo is running; ask again when it has finished"}
    why = launch._models()
    if why:
        return {"error": f"NOT READY: {why}"}
    with LOCK:
        work = Path(tempfile.mkdtemp(prefix="ask-", dir=RESULTS))
        cfg = _config(model)
        q = {"principal": {"tenant": "plant-alpha", "clearance": "internal"},
             "questions": [{"id": "ask", "text": question, "expect": {}}]}
        (work / "q.json").write_text(json.dumps(q))
        env = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
        env.setdefault("CLOUD_API_URL", "https://cloud.example.invalid/v1/chat/completions")
        cmd = [sys.executable, str(DEMOS / "common/harness.py"), "run-offline", "--", "bash", "-c",
               f"python3 '{DEMOS}/common/harness.py' offline-check > '{work}/offline.json';"
               f"python3 '{DEMOS}/pull-the-plug/run_questions.py' '{work}/q.json' '{work}/a.jsonl' -- "
               f"'{REPO}/target/release/syntriass' serve --eval --config '{cfg}'"]
        subprocess.run(cmd, env=env, capture_output=True, timeout=600)
        try:
            row = json.loads((work / "a.jsonl").read_text().splitlines()[0])
            offline = json.loads((work / "offline.json").read_text())
        except (OSError, IndexError, ValueError) as e:
            return {"error": f"the run produced no answer ({e})"}
        loc, cl = row["local"], row["cloud"]
        rt = loc.get("runtime") or {}
        return {"label": "LIVE", "model": MODELS[model], "offline": offline["offline"],
                "local": {"status": loc["status"], "answer": loc.get("answer"), "sources": rt.get("sources"),
                          "strategy": rt.get("strategy"), "model_calls": rt.get("model_calls"),
                          "wall_ms": loc["outer"]["wall_ms"], "cpu_s": rt.get("cpu_s_total"),
                          "bytes_out": loc["outer"]["bytes_out_non_loopback"]},
                "cloud": {"status": cl.get("status"), "reason": cl.get("reason")},
                "corpus": "synthetic plant procedures (sovereign/eval/corpus), tenant plant-alpha, clearance internal"}


_CFG: dict[str, str] = {}


def _config(model: str) -> str:
    """One runtime config per model, built once with the harness's mkconfig."""
    if model in _CFG:
        return _CFG[model]
    st = RESULTS / f"state-{model}"
    if st.exists():
        shutil.rmtree(st)
    subprocess.run([sys.executable, str(REPO / "research/intelligence-runtime/harness/mkconfig.py"), str(st), "balanced"],
                   check=True, capture_output=True)
    cfg = st / "config.json"
    if model != "qwen2.5-1.5b-q4":
        import hashlib
        extra = {m["logical_name"]: m for m in json.loads((DEMOS / "models/extra-models.json").read_text())["models"]}
        path = Path(os.environ["SYNTRIASS_BUNDLE"]) / "models" / extra[model]["file"]
        h = hashlib.sha256(path.read_bytes()).hexdigest()
        if h != extra[model]["sha256"]:
            raise RuntimeError(f"{path} is not the pinned file")
        c = json.loads(cfg.read_text())
        c["q4"] = {"path": str(path), "sha256": h}
        cfg.write_text(json.dumps(c, indent=1))
    _CFG[model] = str(cfg)
    return _CFG[model]


# ── recorded benchmark ─────────────────────────────────────────────────────

def benchmark() -> dict:
    sys.path.insert(0, str(DEMOS / "benchmark"))
    import compare  # noqa: E402
    rec = compare.load(REPO / "research/capability-learning/results")
    fresh_dirs = sorted((DEMOS / "benchmark/evidence").glob("*"))
    fresh = compare.load(fresh_dirs[-1]) if fresh_dirs else None
    names = {"B1": "Local model alone", "B2": "+ conventional RAG", "B3": "+ prompt skill library",
             "B4": "Runtime, no taught capability", "candidate": "Runtime + taught capability"}
    rows = []
    for n, label in names.items():
        a = rec[n]
        ca, da = compare.row(a)
        r = {"system": label, "recorded": {"correct": ca, "decision": da, "cpu": round(a["cpu"], 2)}}
        if fresh:
            b = fresh[n]
            cb, db = compare.row(b)
            same = sum(x["got"] == y["got"] for x, y in zip(sorted(a["items"], key=lambda i: i["id"]),
                                                             sorted(b["items"], key=lambda i: i["id"])))
            r["fresh"] = {"correct": cb, "decision": db, "cpu": round(b["cpu"], 2), "same_labels": same}
        rows.append(r)
    return {"label": "RECORDED", "recorded_source": "research/capability-learning/results (recorded run)",
            "fresh_source": str(fresh_dirs[-1].relative_to(REPO)) if fresh_dirs else None,
            "rows": rows, "n": 40,
            "notes": ["One author wrote the procedure, the data and the system.",
                      "No model weights were changed: the capability is taught, validated and approved.",
                      "CPU-s per task is over all 40 items; the 8 false-activation probes go to the model."]}


# ── HTTP ───────────────────────────────────────────────────────────────────

READY: dict = {"modes": {}, "checked": None}


def _readiness_loop() -> None:
    """Readiness re-hashes the models (~3 GB), so it is computed here every
    20 s, never per request; the page shows when it was last checked."""
    while True:
        if not _busy():
            READY["modes"] = {r["mode"]: r for r in launch.check() if r["mode"] in CONSOLE_MODES}
            READY["checked"] = time.strftime("%H:%M:%S")
        time.sleep(20)


def status() -> dict:
    return {"modes": READY["modes"], "checked": READY["checked"],
            "busy": _busy(), "hardware": harness.hardware_report()["label"],
            "provenance": [harness.provenance(REPO)] + ([harness.provenance(launch.overlay())] if launch.overlay().exists() else []),
            "models": MODELS}


class Handler(BaseHTTPRequestHandler):
    server_version = "syntriass-console"

    def log_message(self, fmt, *args):  # quiet
        pass

    def _origin_ok(self) -> bool:
        host = self.headers.get("Host", "")
        return host in (f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}")

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; img-src 'self'; style-src 'self' 'unsafe-inline'; "
                         "script-src 'self' 'unsafe-inline'; frame-src 'self'; connect-src 'self'")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj: dict, code: int = 200) -> None:
        self._send(code, json.dumps(obj).encode(), "application/json")

    def do_GET(self):
        if not self._origin_ok():
            return self._send(403, b"forbidden", "text/plain")
        p = self.path.split("?", 1)[0]
        if p == "/":
            return self._send(200, (HERE / "index.html").read_bytes(), "text/html; charset=utf-8")
        if p.startswith("/assets/") and p[8:] in ASSETS:
            return self._send(200, (HERE / "assets" / p[8:]).read_bytes(), ASSETS[p[8:]])
        if p == "/api/status":
            return self._json(status())
        if p == "/api/benchmark":
            return self._json(benchmark())
        m = re.fullmatch(r"/api/job/([0-9a-f]{12})", p)
        if m:
            return self._json(job_view(m.group(1)))
        m = re.fullmatch(r"/api/report/([0-9a-f]{12})", p)
        if m and m.group(1) in JOBS and JOBS[m.group(1)]["mode"] == "quantum":
            f = Path(JOBS[m.group(1)]["out"]) / "run" / "report.html"
            if f.exists():
                return self._send(200, f.read_bytes(), "text/html; charset=utf-8")
        return self._send(404, b"not found", "text/plain")

    def do_POST(self):
        if not self._origin_ok():
            return self._send(403, b"forbidden", "text/plain")
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            return self._json({"error": "body too large"}, 413)
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self._json({"error": "bad JSON"}, 400)
        if self.path == "/api/run":
            return self._json(start(str(body.get("mode", ""))))
        if self.path == "/api/ask":
            return self._json(ask(str(body.get("question", "")), str(body.get("model", "qwen2.5-1.5b-q4"))))
        return self._send(404, b"not found", "text/plain")


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8770
    RESULTS.mkdir(parents=True, exist_ok=True)
    threading.Thread(target=_readiness_loop, daemon=True).start()
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"SYNTRIASS demo console: http://127.0.0.1:{srv.server_port}/  (local only)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
