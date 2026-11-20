"""Map an LLM UsageRecord to an event-store event (item 4.1a). Pure.

The event is the record's fields, unchanged, plus:

- `kind` = "llm.usage";
- `subject` = "agent:<agent_id>", only when the agent is known; unattributed
  usage stays queryable by kind and is never filed under a made-up agent;
- `observed_at_ms`, when the call's end time is known;
- `price_source` = "declared test price", because every price in this lab is
  a TEST price, labelled "estimated" (4.1).

None stays None. Missing telemetry is never written as 0.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import asdict

from llm_capture import UsageRecord

USAGE_KIND = "llm.usage"
PRICE_SOURCE = "declared test price"
MS_PER_S = 1000


def to_ms(t: object) -> int | None:
    """Epoch ms from a timezone-aware datetime or epoch seconds; None if unusable.

    A naive datetime is refused (None) rather than guessed in local time.
    """
    if isinstance(t, dt.datetime):
        if t.tzinfo is None:
            return None
        ms = round(t.timestamp() * MS_PER_S)
    elif isinstance(t, (int, float)) and not isinstance(t, bool):
        ms = round(t * MS_PER_S)
    else:
        return None
    return ms if ms >= 0 else None


def usage_event(rec: UsageRecord, observed_at_ms: int | None) -> dict:
    """The event-store event for one usage record."""
    ev = {"kind": USAGE_KIND, "price_source": PRICE_SOURCE, **asdict(rec)}
    ev["attribution_missing"] = list(rec.attribution_missing)
    if rec.agent_id:
        ev["subject"] = f"agent:{rec.agent_id}"
    if observed_at_ms is not None:
        ev["observed_at_ms"] = observed_at_ms
    return ev
