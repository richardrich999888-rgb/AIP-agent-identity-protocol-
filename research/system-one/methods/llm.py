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

from datasets.maintenance_priority import METRICS, SOP_TEXT

SYSTEM = SOP_TEXT + "\nRead the operator report. If it contains several readings, the most urgent one decides."
LABELS = ("1", "2", "3", "4")
# Logprob assigned to a label token absent from top_logprobs (< any observed).
FLOOR = -30.0
# Two property orders. Grammar order is generation order (llama.cpp emits
# properties as listed). "decision_first" commits to a label before any
# reasoning tokens; "reason_first" lets the rationale precede the label — the
# strongest generative configuration available without a reasoning model.
def _schema(order: tuple) -> dict:
    props = {
        "priority": {"type": "string", "enum": list(LABELS)},
        "rationale": {"type": "string", "maxLength": 300},
    }
    return {
        "type": "object",
        "properties": {k: props[k] for k in order},
        "required": list(order),
        "additionalProperties": False,
    }


JSON_SCHEMAS = {
    "decision_first": _schema(("priority", "rationale")),
    "reason_first": _schema(("rationale", "priority")),
}


def _post(endpoint: str, body: dict, timeout: float = 600) -> dict:
    req = urllib.request.Request(f"http://{endpoint}/v1/chat/completions", data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def _messages(text: str, instruction: str) -> list:
    return [{"role": "system", "content": SYSTEM}, {"role": "user", "content": f"Report: {text}\n{instruction}"}]


# Readout instruction versions. v1 ("Priority digit:") left ~95 % of the
# next-token mass on words ("The", "Priority"), so the grammar-forced digit was
# read from the distribution's tail (iteration-1 finding). v2 asks for the
# digit alone; `label_mass` below records how much mass the four labels carry.
READOUT_INSTRUCTION = {
    "v1": "Priority digit:",
    "v2": "Reply with exactly one character: the priority digit 1, 2, 3 or 4. No words.",
}


# INSTRUMENT WARNING (iteration 1): with the pinned llama.cpp build
# (llama-cpp-python 0.3.16 vendor), `top_logprobs` across sequential requests
# disagreed with the token the server emitted on 11–12 of 16 probe items, with
# or without grammar or prompt caching (emitted tokens were 15/16 correct, the
# logprob argmax 4/16). Decisions are therefore scored on the EMITTED token;
# logprob-derived probabilities are kept only as a flagged diagnostic.


def readout(endpoint: str, text: str, cache_prompt: bool = True, version: str = "v2") -> tuple:
    """Return (logits[4], latency_s, completion_tokens, label_mass, emitted_token).

    label_mass = sum of the four label tokens' probabilities in the model's
    unconstrained next-token distribution. Low mass means the readout is
    sampling a distribution the model did not intend to answer from."""
    body = {
        "messages": _messages(text, READOUT_INSTRUCTION[version]),
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
    logits = np.array([lp.get(k, FLOOR) for k in LABELS])
    emitted = o["choices"][0]["message"]["content"].strip()
    return logits, dt, o.get("usage", {}).get("completion_tokens"), float(np.exp(logits).sum()), emitted


def json_gen(endpoint: str, text: str, order: str = "decision_first") -> tuple:
    """Return (label or None, latency_s, completion_tokens, raw)."""
    instr = {
        "decision_first": 'Reply with JSON {"priority": "1"-"4", "rationale": short reason}.',
        "reason_first": 'Reply with JSON {"rationale": compare the reading with the SOP threshold step by step, "priority": "1"-"4"}.',
    }[order]
    body = {
        "messages": _messages(text, instr),
        "max_tokens": 200,
        "temperature": 0,
        "seed": 42,
        "response_format": {"type": "json_schema", "json_schema": {"name": "decision", "schema": JSON_SCHEMAS[order]}},
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


# ─── Candidate 4: the model interprets; exact code evaluates the policy ───
#
# The model is asked only "which SOP quantity does this report refer to?" —
# never to compare numbers. The value is parsed deterministically and the SOP
# rule table is applied exactly.

METRIC_LETTERS = "ABCDEFGH"
METRIC_MENU = "\n".join(f"{METRIC_LETTERS[i]} = {m.equipment} {m.name} ({m.unit})" for i, m in enumerate(METRICS))
EXTRACT_SYSTEM = (
    "You map maintenance reports to the plant quantity they describe.\n"
    "Quantities:\n" + METRIC_MENU + "\nThe report may use different words, abbreviations or equipment spellings."
)


def metric_readout(endpoint: str, text: str) -> tuple:
    """Single-token choice over the 8 quantities. Return (probs[8], latency_s, label_mass)."""
    body = {
        "messages": [
            {"role": "system", "content": EXTRACT_SYSTEM},
            {"role": "user", "content": f"Report: {text}\nReply with exactly one letter A-H for the quantity reported. No words."},
        ],
        "max_tokens": 1,
        "temperature": 0,
        "seed": 42,
        "logprobs": True,
        "top_logprobs": 20,
        "grammar": "root ::= [A-H]",
        "cache_prompt": True,
    }
    t = time.perf_counter()
    o = _post(endpoint, body)
    dt = time.perf_counter() - t
    top = o["choices"][0]["logprobs"]["content"][0]["top_logprobs"]
    lp = {x["token"].strip(): x["logprob"] for x in top}
    logits = np.array([lp.get(k, FLOOR) for k in METRIC_LETTERS])
    mass = float(np.exp(logits).sum())
    p = np.exp(logits - logits.max())
    emitted = o["choices"][0]["message"]["content"].strip()
    return p / p.sum(), dt, mass, emitted


EXTRACT_SCHEMA = {
    "type": "object",
    "properties": {
        "readings": {
            "type": "array",
            "minItems": 1,
            "maxItems": 3,
            "items": {
                "type": "object",
                "properties": {"quantity": {"type": "string", "enum": list(METRIC_LETTERS)}, "value": {"type": "number"}},
                "required": ["quantity", "value"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["readings"],
    "additionalProperties": False,
}


def extract_json(endpoint: str, text: str) -> tuple:
    """Constrained extraction of every (quantity, value). Return (readings | None, latency_s, tokens, raw)."""
    body = {
        "messages": [
            {"role": "system", "content": EXTRACT_SYSTEM},
            {"role": "user", "content": f"Report: {text}\nList every reading as JSON {{\"readings\": [{{\"quantity\": letter, \"value\": number}}]}}. Copy numbers exactly."},
        ],
        "max_tokens": 120,
        "temperature": 0,
        "seed": 42,
        "response_format": {"type": "json_schema", "json_schema": {"name": "extraction", "schema": EXTRACT_SCHEMA}},
    }
    t = time.perf_counter()
    o = _post(endpoint, body)
    dt = time.perf_counter() - t
    raw = o["choices"][0]["message"]["content"]
    try:
        rd = [(METRICS[METRIC_LETTERS.index(r["quantity"])], float(r["value"])) for r in json.loads(raw)["readings"]]
    except (ValueError, KeyError, TypeError, IndexError):
        rd = None
    return rd, dt, o.get("usage", {}).get("completion_tokens"), raw


# ─── Iteration 2: extraction with explicit abstention ───
# v1 (EXTRACT_SCHEMA, minItems 1) could not say "nothing covered here", so it
# was forced to invent a reading for out-of-policy equipment. v2 allows an
# empty list and states when to use it; values are requested in the listed
# unit. Same model, same menu; only abstention and unit instructions differ.
EXTRACT_SCHEMA_V2 = {
    "type": "object",
    "properties": {
        "readings": {
            "type": "array",
            "minItems": 0,
            "maxItems": 3,
            "items": {
                "type": "object",
                "properties": {"quantity": {"type": "string", "enum": list(METRIC_LETTERS)}, "value": {"type": "number"}},
                "required": ["quantity", "value"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["readings"],
    "additionalProperties": False,
}
EXTRACT_V2_INSTRUCTION = (
    "List every reading of a listed quantity as JSON {\"readings\": [{\"quantity\": letter, \"value\": number}]}. "
    "The equipment must be exactly the listed equipment (P-9 is not P-7). Convert the value to the unit shown in the list. "
    "If the equipment is not listed, there is no numeric value, or you cannot tell which quantity is meant, return {\"readings\": []}."
)


def extract_json_v2(endpoint: str, text: str) -> tuple:
    """Return (readings list (possibly empty) | None on parse failure, latency_s, tokens, raw)."""
    body = {
        "messages": [
            {"role": "system", "content": EXTRACT_SYSTEM},
            {"role": "user", "content": f"Report: {text}\n{EXTRACT_V2_INSTRUCTION}"},
        ],
        "max_tokens": 120,
        "temperature": 0,
        "seed": 42,
        "cache_prompt": True,
        "response_format": {"type": "json_schema", "json_schema": {"name": "extraction", "schema": EXTRACT_SCHEMA_V2}},
    }
    t = time.perf_counter()
    o = _post(endpoint, body)
    dt = time.perf_counter() - t
    raw = o["choices"][0]["message"]["content"]
    try:
        rd = [(METRICS[METRIC_LETTERS.index(r["quantity"])].key, float(r["value"])) for r in json.loads(raw)["readings"]]
    except (ValueError, KeyError, TypeError, IndexError):
        rd = None
    return rd, dt, o.get("usage", {}).get("completion_tokens"), raw
