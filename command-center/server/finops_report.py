"""FinOps aggregation over `llm.usage` events (item 4.2a). Pure: no IO, no clock.

The console reads this; it computes nothing itself. Rules:

- Sums cover **measured** values only. Each group also counts the calls
  whose tokens, and separately whose cost, were not measured (None in the
  event, see llm_capture).
- `status` per group:
  - `NO_TELEMETRY`: no call in the group has measured tokens. `tokens` and
    `cost_usd` are None, never 0 (adversarial #12);
  - `PARTIAL`: some calls are unmeasured, so the sums are **lower bounds**;
  - `COMPLETE`: every call is measured.
- Budgets are declared per owner, in TEST USD. `used_fraction` is computed
  from measured cost only, and `used_is_lower_bound` is set whenever any of
  the owner's calls lack a cost. With no measured cost at all,
  `used_fraction` is None.
- Unattributed usage (no agent id, workflow or owner) is grouped under
  `None` and is never merged into a named group.
- Trend: the same aggregation per fixed time bucket of `observed_at_ms`.
  Events without a time are counted in `untimed`, not dropped.

Parent→child roll-up needs lineage from P0-059 and is not here (4.2b).
"""

from __future__ import annotations

from dataclasses import dataclass, field

USAGE_KIND = "llm.usage"
GROUP_KEYS = ("agent_id", "workflow", "owner")


@dataclass
class Group:
    calls: int = 0
    failed_calls: int = 0
    calls_with_tokens: int = 0
    calls_with_cost: int = 0
    tokens: int = 0
    cost_usd: float = 0.0

    def view(self) -> dict:
        """Serialisable view with the None-not-0 rules applied."""
        no_tokens = self.calls - self.calls_with_tokens
        no_cost = self.calls - self.calls_with_cost
        if self.calls_with_tokens == 0:
            status = "NO_TELEMETRY"
        elif no_tokens or no_cost:
            status = "PARTIAL"
        else:
            status = "COMPLETE"
        return {
            "calls": self.calls,
            "failed_calls": self.failed_calls,
            "tokens": self.tokens if self.calls_with_tokens else None,
            "cost_usd_estimated": self.cost_usd if self.calls_with_cost else None,
            "calls_without_token_telemetry": no_tokens,
            "calls_without_cost": no_cost,
            "status": status,
            "sums_are_lower_bounds": status == "PARTIAL",
        }


def _is_count(v: object) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def _add(g: Group, e: dict) -> None:
    g.calls += 1
    g.failed_calls += e.get("status") == "failure"
    t = e.get("total_tokens")
    if _is_count(t):
        g.calls_with_tokens += 1
        g.tokens += t
    c = e.get("cost_usd")
    if isinstance(c, (int, float)) and not isinstance(c, bool) and c >= 0:
        g.calls_with_cost += 1
        g.cost_usd += float(c)


def usage_events(events: list[dict]) -> list[dict]:
    """Only well-formed llm.usage events labelled TEST DATA (this lab has no real usage)."""
    return [e for e in events if isinstance(e, dict) and e.get("kind") == USAGE_KIND]


def by_key(events: list[dict], key: str) -> dict[str | None, dict]:
    """Aggregate per value of `key` (agent_id, workflow or owner); None = unattributed."""
    if key not in GROUP_KEYS:
        raise ValueError(f"unknown group key {key!r}")
    groups: dict[str | None, Group] = {}
    for e in usage_events(events):
        k = e.get(key) if isinstance(e.get(key), str) and e.get(key) else None
        _add(groups.setdefault(k, Group()), e)
    return {k: g.view() for k, g in groups.items()}


def budgets(events: list[dict], declared_usd: dict[str, float]) -> dict[str, dict]:
    """Per declared owner budget: measured spend, fraction used, lower-bound flag."""
    per_owner = by_key(events, "owner")
    out = {}
    for owner, budget in sorted(declared_usd.items()):
        if not isinstance(budget, (int, float)) or isinstance(budget, bool) or budget <= 0:
            raise ValueError(f"budget for {owner!r} must be a positive number")
        g = per_owner.get(owner)
        spent = g["cost_usd_estimated"] if g else None
        out[owner] = {
            "budget_usd_test": float(budget),
            "spent_usd_estimated": spent,
            "used_fraction": (spent / budget) if spent is not None else None,
            "used_is_lower_bound": bool(g and g["calls_without_cost"]),
            "calls": g["calls"] if g else 0,
        }
    return out


def trend(events: list[dict], bucket_ms: int) -> dict:
    """Totals per time bucket (bucket start ms → group view), plus untimed calls."""
    if not _is_count(bucket_ms) or bucket_ms == 0:
        raise ValueError("bucket_ms must be a positive integer")
    buckets: dict[int, Group] = {}
    untimed = Group()
    for e in usage_events(events):
        t = e.get("observed_at_ms")
        if _is_count(t):
            _add(buckets.setdefault(t - t % bucket_ms, Group()), e)
        else:
            _add(untimed, e)
    return {"buckets": {k: buckets[k].view() for k in sorted(buckets)},
            "untimed": untimed.view() if untimed.calls else None}
