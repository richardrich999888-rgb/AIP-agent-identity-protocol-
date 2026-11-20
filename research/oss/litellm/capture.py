"""Turn one LiteLLM callback payload into a usage record. Pure: no LiteLLM import.

LiteLLM 1.110.2's `standard_logging_object` reports `0` in three cases where
nothing was measured. Item 1.3 measured each of them:

- a model with no declared price: `response_cost` is 0.0, and only
  `response_cost_failure_debug_info` says the price was unknown;
- a provider response with no `usage`: the tokens are 0/0/0 and the cost is
  0.0, with status "success";
- a failed call: the tokens are 0 and the cost is 0.0.

This module maps each of them to `None` with a stated reason, never to 0.
Whether the provider reported usage is read from the raw provider response
(`original_response`), not from LiteLLM's normalised object.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass

LABEL = "TEST DATA"
ATTRIBUTION_KEYS = ("agent_id", "workflow", "owner")

COST_ESTIMATED = "estimated at declared test price"
COST_PRICE_UNKNOWN = "no telemetry: price unknown"
COST_NO_USAGE = "no telemetry: provider reported no usage"
COST_FAILED = "no telemetry: call failed"


@dataclass(frozen=True)
class UsageRecord:
    """One model call. A None value means "not measured", never zero."""

    label: str
    call_id: str | None
    status: str  # "success" | "failure"
    model: str | None
    provider: str | None
    agent_id: str | None
    workflow: str | None
    owner: str | None
    attribution_missing: tuple[str, ...]
    prompt_tokens: int | None
    completion_tokens: int | None
    total_tokens: int | None
    cost_usd: float | None
    cost_basis: str

    def to_json(self) -> str:
        """Canonical one-line JSON (sorted keys)."""
        return json.dumps(asdict(self), sort_keys=True)


def provider_reported_usage(original_response: object) -> bool:
    """True only if the raw provider response is a JSON object with `usage`.

    Unparseable or absent input counts as "not reported" (fail closed).
    """
    if isinstance(original_response, str):
        try:
            original_response = json.loads(original_response)
        except json.JSONDecodeError:
            return False
    return isinstance(original_response, dict) and isinstance(original_response.get("usage"), dict)


def _nonneg_int(v: object) -> int | None:
    # bool is an int subclass; a True token count is not a count.
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None


def _attribution(kwargs: dict) -> tuple[dict[str, str | None], tuple[str, ...]]:
    params = kwargs.get("litellm_params")
    md = params.get("metadata") if isinstance(params, dict) else None
    md = md if isinstance(md, dict) else {}
    got = {k: (md[k] if isinstance(md.get(k), str) and md[k] else None) for k in ATTRIBUTION_KEYS}
    return got, tuple(k for k in ATTRIBUTION_KEYS if got[k] is None)


def to_record(kwargs: dict, succeeded: bool) -> UsageRecord:
    """Map a LiteLLM callback `kwargs` to a UsageRecord, per the module rules."""
    slo = kwargs.get("standard_logging_object")
    slo = slo if isinstance(slo, dict) else {}
    who, missing = _attribution(kwargs)
    tokens: tuple[int | None, int | None, int | None] = (None, None, None)
    cost: float | None = None
    if not succeeded:
        basis = COST_FAILED
    elif not provider_reported_usage(kwargs.get("original_response")):
        basis = COST_NO_USAGE
    else:
        tokens = (
            _nonneg_int(slo.get("prompt_tokens")),
            _nonneg_int(slo.get("completion_tokens")),
            _nonneg_int(slo.get("total_tokens")),
        )
        raw_cost = slo.get("response_cost")
        if slo.get("response_cost_failure_debug_info") is not None:
            basis = COST_PRICE_UNKNOWN
        elif isinstance(raw_cost, (int, float)) and not isinstance(raw_cost, bool) and raw_cost >= 0:
            cost, basis = float(raw_cost), COST_ESTIMATED
        else:
            basis = COST_PRICE_UNKNOWN
    call_id = slo.get("id") if isinstance(slo.get("id"), str) else kwargs.get("litellm_call_id")
    return UsageRecord(
        label=LABEL,
        call_id=call_id if isinstance(call_id, str) else None,
        status="success" if succeeded else "failure",
        model=slo.get("model") if isinstance(slo.get("model"), str) else None,
        provider=slo.get("custom_llm_provider") if isinstance(slo.get("custom_llm_provider"), str) else None,
        agent_id=who["agent_id"],
        workflow=who["workflow"],
        owner=who["owner"],
        attribution_missing=missing,
        prompt_tokens=tokens[0],
        completion_tokens=tokens[1],
        total_tokens=tokens[2],
        cost_usd=cost,
        cost_basis=basis,
    )
