"""Explicit example-label review for a bounded taught capability.

An unsigned mapping declaration is not expert authentication or approval. It
only connects an immutable session's binary examples to explicitly named native
outcomes. Missing/ambiguous/out-of-scope-native refusals never count as answers.
No labels are inferred from names or from the example's free-text reason.
"""
from __future__ import annotations

SCHEMA = "syntriass.teach-example-map/v1"
NATIVE_REFUSALS = frozenset(("NOT_APPLICABLE", "AMBIGUOUS", "EVIDENCE_REQUIRED"))
BINDINGS = frozenset(("session_id", "capability_hash", "source_sha256", "task_sha256",
                      "answers_sha256", "suite_sha256"))


class MappingRefused(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise MappingRefused(message)


def validate(mapping, expected, session, capability, answer_author):
    require(isinstance(mapping, dict) and set(mapping) == {"schema", "bindings", "review", "outcomes"},
            "example mapping has unexpected or missing fields")
    require(mapping["schema"] == SCHEMA, "unsupported example mapping version")
    require(isinstance(expected, dict) and set(expected) == BINDINGS, "invalid internal mapping bindings")
    require(mapping["bindings"] == expected, "example mapping bindings are stale or mismatched")
    review = mapping["review"]
    require(isinstance(review, dict) and set(review) == {"who", "when_ms", "why"}, "invalid example review declaration")
    require(review["who"] in (session["expert_id"], answer_author), "example reviewer is not a session/answer author")
    require(type(review["when_ms"]) is int and 0 < review["when_ms"] <= (1 << 64) - 1,
            "example review timestamp must be positive integer milliseconds")
    why = review["why"]
    require(isinstance(why, str) and bool(why.strip()) and len(why) <= 1000
            and not any(ord(c) < 32 or ord(c) == 127 for c in why), "example review needs a bounded plain-text reason")
    outcomes = mapping["outcomes"]
    require(isinstance(outcomes, dict) and bool(outcomes), "example outcome mapping is empty")
    require(set(outcomes) <= set(capability["outcomes"]), "example mapping names an undeclared outcome")
    require(all(v in ("allowed", "not_allowed", "withheld") for v in outcomes.values()), "invalid mapped example label")
    # The missing-input outcome is defined by this capability, not guessed by
    # matching a frozen label string. A refusal cannot satisfy a negative case.
    refusals = NATIVE_REFUSALS | {capability["procedure"]["missing_input_outcome"]}
    require(all(outcomes.get(label, "withheld") == "withheld" for label in refusals),
            "a missing-input or native refusal outcome cannot be mapped to an answer")
    examples = session["examples"]
    require(2 <= len(examples) <= 5 and len({e["id"] for e in examples}) == len(examples),
            "session examples must have 2–5 distinct identities")
    require({e["label"] for e in examples} == {"allowed", "not_allowed"},
            "session examples need both allowed and not_allowed labels")
    return refusals


def evaluate(mapping, expected, session, capability, answer_author, observed):
    refusals = validate(mapping, expected, session, capability, answer_author)
    examples = session["examples"]
    require(len(observed) == len(examples), "native example replay omitted or duplicated results")
    cases = []
    for example, actual in zip(examples, observed):
        require(isinstance(actual, dict) and actual.get("id") == example["id"] and actual.get("expected") == example["label"],
                "native example replay changed identity, order or expected label")
        raw = actual.get("got")
        require(isinstance(raw, str), "native example replay omitted the outcome")
        if raw in refusals or raw.startswith("FAILED:"):
            mapped, reason = "withheld", "The runtime did not provide a decision for this example."
        else:
            require(raw in capability["outcomes"], "native example replay returned an undeclared outcome")
            mapped = mapping["outcomes"].get(raw, "withheld")
            reason = "No answer label was explicitly reviewed for this outcome." if mapped == "withheld" else None
        cases.append({"id": example["id"], "input": example["text"], "expected": example["label"],
                      "expert_reason": example["reason"], "native_outcome": raw, "mapped_label": mapped,
                      "passed": mapped != "withheld" and mapped == example["label"], "withheld_reason": reason})
    passed = sum(c["passed"] for c in cases)
    return {"status": "PASSED" if passed == len(cases) else "FAILED", "passed": passed,
            "total": len(cases), "withheld": sum(c["mapped_label"] == "withheld" for c in cases),
            "cases": cases, "review_declaration": mapping["review"], "bindings": expected,
            "expert_identity_verified": False, "independent_suite_cases_added": 0,
            "limitation": "Unsigned declared review; examples remain separate from the independently signed suite."}
