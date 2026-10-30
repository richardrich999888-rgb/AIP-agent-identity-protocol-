"""Local LLM decision methods over llama-server (loopback only).

readout   — Hypothesis A. One prefill + one constrained token. The decision
            distribution is read from the model's logits over the four digit
            tokens: no text is generated beyond the single label token.
json_gen  — The generative baseline as typically deployed: the model writes a
            JSON object {"priority": "1".."4", "rationale": "..."} under a
            schema. No probability is available, so confidence is 1.

Both receive the same SOP text (knowledge in context, not in weights —
Hypothesis C) and the same report.
"""
from __future__ import annotations

import json
import time
import urllib.request

import numpy as np

from datasets.maintenance_priority import SOP_TEXT

SYSTEM = SOP_TEXT + "\nRead the operator report. If it contains several readings, the most urgent one decides."
LABELS = ("1", "2", "3", "4")
# Logprob assigned to a label token absent from top_logprobs (< any observed).
FLOOR = -30.0
JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "priority": {"type": "string", "enum": list(LABELS)},
        "rationale": {"type": "string", "maxLength": 200},
    },
    "required": ["priority", "rationale"],
    "additionalProperties": False,
}


def _post(endpoint: str, body: dict, timeout: float = 600) -> dict:
    req = urllib.request.Request(f"http://{endpoint}/v1/chat/completions", data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def _messages(text: str, instruction: str) -> list:
    return [{"role": "system", "content": SYSTEM}, {"role": "user", "content": f"Report: {text}\n{instruction}"}]


def readout(endpoint: str, text: str, cache_prompt: bool = True) -> tuple:
    """Return (logits[4], latency_s, completion_tokens)."""
    body = {
        "messages": _messages(text, "Priority digit:"),
        "max_tokens": 1,
        "temperature": 0,
        "seed": 42,
        "logprobs": True,
        "top_logprobs": 20,
        "grammar": "root ::= [1-4]",
        "cache_prompt": cache_prompt,
    }
    t = time.perf_counter()
    o = _post(endpoint, body)
    dt = time.perf_counter() - t
    top = o["choices"][0]["logprobs"]["content"][0]["top_logprobs"]
    lp = {x["token"].strip(): x["logprob"] for x in top}
    return np.array([lp.get(k, FLOOR) for k in LABELS]), dt, o.get("usage", {}).get("completion_tokens")


def json_gen(endpoint: str, text: str) -> tuple:
    """Return (label or None, latency_s, completion_tokens, raw)."""
    body = {
        "messages": _messages(text, 'Reply with JSON {"priority": "1"-"4", "rationale": short reason}.'),
        "max_tokens": 160,
        "temperature": 0,
        "seed": 42,
        "response_format": {"type": "json_schema", "json_schema": {"name": "decision", "schema": JSON_SCHEMA}},
    }
    t = time.perf_counter()
    o = _post(endpoint, body)
    dt = time.perf_counter() - t
    raw = o["choices"][0]["message"]["content"]
    try:
        label = int(json.loads(raw)["priority"])
    except (ValueError, KeyError, TypeError):
        label = None
    return label, dt, o.get("usage", {}).get("completion_tokens"), raw
