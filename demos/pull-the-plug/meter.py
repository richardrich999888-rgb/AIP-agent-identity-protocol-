#!/usr/bin/env python3
"""Live meter for the Pull-the-plug demo (W1.2). Stdlib only.

Every figure on the meter is measured during the answer it describes, and
every figure says where it came from:

* ``runtime`` — what the AIRON runtime reported about its own request
  (`syntriass serve --eval` → {"response": Response} → Response.strategy /
  Response.cost: model calls,
  tokens, per-component CPU-seconds, wall ms). Shown as *runtime-reported*.
* ``outer`` — measured around the call by this meter, independently of the
  runtime: wall ms, CPU-seconds of the child process (``wait4`` rusage), and
  bytes out = change in this network namespace's **non-loopback** transmit
  counter. In the offline demo namespace only the demo runs there; on a
  connected host the counter is namespace-wide and is labelled as such.
* ``inr`` — estimated ₹ per answer, computed only from operator-set rates
  (``METER_INR_PER_CPU_HOUR`` for the local side, ``METER_INR_PER_1K_TOKENS``
  for the cloud side). With no rate set the meter shows no rupee figure, and
  the formula and rate are always in the result.

Nothing is filled in when a measurement is missing: a field the runtime did
not report is ``null`` and labelled "not reported".
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "common"))
import harness  # noqa: E402


def _tx_non_loopback() -> int:
    return harness.offline_status()["tx_bytes_non_loopback"]


def _rate(env: dict, name: str) -> float | None:
    v = env.get(name, "").strip()
    if not v:
        return None
    r = float(v)
    if r < 0:
        raise ValueError(f"{name} must not be negative")
    return r


def inr_local(cpu_s: float | None, env: dict) -> dict:
    rate = _rate(env, "METER_INR_PER_CPU_HOUR")
    if rate is None or cpu_s is None:
        return {"inr": None, "note": "rate not set — no rupee figure shown" if rate is None
                else "CPU time not measured — no rupee figure shown"}
    return {"inr": round(cpu_s / 3600 * rate, 6), "formula": "cpu_s / 3600 × METER_INR_PER_CPU_HOUR",
            "rate": rate, "cpu_s": cpu_s}


def inr_cloud(tokens: int | None, env: dict) -> dict:
    rate = _rate(env, "METER_INR_PER_1K_TOKENS")
    if rate is None or tokens is None:
        return {"inr": None, "note": "rate not set — no rupee figure shown" if rate is None
                else "endpoint reported no token usage — no rupee figure shown"}
    return {"inr": round(tokens / 1000 * rate, 6), "formula": "tokens / 1000 × METER_INR_PER_1K_TOKENS",
            "rate": rate, "tokens": tokens}


def _runtime_view(resp: dict) -> dict:
    """The runtime's own report, read field by field; absent → null."""
    cost = resp.get("cost") or {}
    cpu = cost.get("cpu_s")
    outcome = resp.get("outcome") or {}
    return {
        "source": "runtime-reported",
        "strategy": resp.get("strategy"),
        "outcome_kind": outcome.get("kind"),
        "sources": outcome.get("sources"),
        "model_calls": cost.get("model_calls"),
        "prompt_tokens": cost.get("prompt_tokens"),
        "completion_tokens": cost.get("completion_tokens"),
        "escalations": cost.get("escalations"),
        "wall_ms": cost.get("wall_ms"),
        "cpu_s_by_component": cpu,
        "cpu_s_total": round(sum(cpu.values()), 3) if isinstance(cpu, dict) else None,
    }


def measure_local(cmd: list[str], request_line: str, env: dict | None = None, timeout_s: float = 600) -> dict:
    """Run one runtime request (`cmd` reads one JSON request line on stdin and
    prints one JSON Response) and meter it."""
    import resource
    env = dict(os.environ if env is None else env)
    ru0 = resource.getrusage(resource.RUSAGE_CHILDREN)
    tx0, t0 = _tx_non_loopback(), time.monotonic()
    try:
        p = subprocess.run(cmd, input=(request_line.rstrip("\n") + "\n").encode(), capture_output=True,
                           env=env, timeout=timeout_s)
        out, code = p.stdout.decode(errors="replace"), p.returncode
    except subprocess.TimeoutExpired as e:
        out, code = (e.stdout or b"").decode(errors="replace"), None
    wall_ms = round((time.monotonic() - t0) * 1000, 1)
    tx = _tx_non_loopback() - tx0
    ru1 = resource.getrusage(resource.RUSAGE_CHILDREN)
    # This process starts no other children, so the delta is this request's.
    cpu = round((ru1.ru_utime - ru0.ru_utime) + (ru1.ru_stime - ru0.ru_stime), 3)
    outer = {"source": "measured by meter", "wall_ms": wall_ms, "cpu_s_child": cpu,
             "bytes_out_non_loopback": tx,
             "bytes_out_scope": "this network namespace (non-loopback interfaces)"}
    lines = [l for l in out.splitlines() if l.strip()]
    try:
        reply = json.loads(lines[-1])
        if not isinstance(reply, dict):
            raise ValueError("not an object")
    except (IndexError, ValueError):
        return {"side": "airon-native", "status": "failed", "reason": "no_runtime_response",
                "exit_code": code, "outer": outer, "inr": inr_local(outer["cpu_s_child"], env)}
    # `serve --eval` replies {"id", "response": Response} or {"error": "..."};
    # `ask` prints a bare Response. Accept both; never read the envelope as
    # the response.
    if "error" in reply and "response" not in reply:
        return {"side": "airon-native", "status": "failed", "reason": "runtime_error",
                "runtime_error": reply["error"], "exit_code": code, "outer": outer,
                "inr": inr_local(outer["cpu_s_child"], env)}
    resp = reply["response"] if isinstance(reply.get("response"), dict) else reply
    rt = _runtime_view(resp)
    status = "answered" if rt["outcome_kind"] in ("answer", "decision") else (rt["outcome_kind"] or "unknown")
    answer = (resp.get("outcome") or {}).get("text") or (resp.get("outcome") or {}).get("label")
    return {"side": "airon-native", "status": status, "answer": answer, "runtime": rt, "outer": outer,
            "inr": inr_local(outer["cpu_s_child"], env), "exit_code": code}


def measure_cloud(question: str, env: dict | None = None) -> dict:
    """Meter one cloud-API question (W1.1 app)."""
    import cloud_app  # local module, stdlib only
    env = dict(os.environ if env is None else env)
    tx0 = _tx_non_loopback()
    r = cloud_app.ask(question, env)
    r["outer"] = {"source": "measured by meter", "wall_ms": r.get("ms"),
                  "bytes_out_non_loopback": _tx_non_loopback() - tx0,
                  "bytes_out_scope": "this network namespace (non-loopback interfaces)"}
    r["inr"] = inr_cloud(r.get("tokens"), env)
    return r


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "local":
        line = sys.stdin.readline()
        print(json.dumps(measure_local(sys.argv[2:], line)))
    elif len(sys.argv) == 3 and sys.argv[1] == "cloud":
        print(json.dumps(measure_cloud(sys.argv[2])))
    else:
        print(__doc__ + "\nusage: meter.py local CMD... < request.json | meter.py cloud QUESTION", file=sys.stderr)
        sys.exit(2)
