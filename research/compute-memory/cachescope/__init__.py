"""Scoped KV/prefix-cache reuse policy (hypothesis B3).

Core logic only: no IO, no clocks, no network. The adapter that applies the
decisions to llama-server lives in bench/llama_adapter.py.

Rule (fail closed): cached state produced under one CacheScope may be reused
only by a request carrying an *identical* CacheScope. Any difference in model,
tokenizer, policy, source snapshot, authorization scope or security domain is
a miss, and the slot is erased before it serves the new scope. Erasure is what
removes the timing side channel: a request can never observe whether another
scope's prefix is resident, because another scope's prefix is never resident
in the slot that serves it.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

_SEP = b"\x1f"  # unit separator: fields cannot contain it (validated below)


@dataclass(frozen=True)
class CacheScope:
    """Every dependency that makes cached attention state valid and permitted."""
    model_sha256: str
    tokenizer_sha256: str
    policy_version: str
    source_snapshot: str      # e.g. corpus Merkle root / snapshot id
    principal_scope: str      # canonical authorization scope, not a user name
    security_domain: str

    def __post_init__(self) -> None:
        for name, v in self.__dict__.items():
            if not isinstance(v, str) or not v:
                raise ValueError(f"{name} must be a non-empty string")
            if "\x1f" in v or len(v) > 512:
                raise ValueError(f"{name} contains a separator or is too long")

    def key(self) -> str:
        """Deterministic 256-bit key; field order is part of the contract."""
        parts = (self.model_sha256, self.tokenizer_sha256, self.policy_version,
                 self.source_snapshot, self.principal_scope, self.security_domain)
        return hashlib.sha256(_SEP.join(p.encode() for p in parts)).hexdigest()


@dataclass(frozen=True)
class Decision:
    """What the adapter must do before sending the request."""
    slot: int
    erase_first: bool
    reuse_allowed: bool


@dataclass
class SlotTable:
    """Which scope key last wrote each slot (None = empty/erased)."""
    n_slots: int
    owner: list = field(default_factory=list)
    last_use: list = field(default_factory=list)
    tick: int = 0

    def __post_init__(self) -> None:
        if self.n_slots <= 0:
            raise ValueError("n_slots must be positive")
        self.owner = [None] * self.n_slots
        self.last_use = [0] * self.n_slots


def decide(table: SlotTable, scope: CacheScope) -> Decision:
    """Pick a slot for `scope` and update the table.

    1. A slot already owned by this exact scope → reuse (no erase).
    2. Else an empty slot → use it (no erase needed, nothing resident).
    3. Else the least-recently-used slot → erase first, then use.
    Deterministic: ties break on the lowest slot index.
    """
    k = scope.key()
    table.tick += 1
    if k in table.owner:
        s = table.owner.index(k)
        d = Decision(s, erase_first=False, reuse_allowed=True)
    elif None in table.owner:
        s = table.owner.index(None)
        d = Decision(s, erase_first=False, reuse_allowed=False)
    else:
        s = min(range(table.n_slots), key=lambda i: (table.last_use[i], i))
        d = Decision(s, erase_first=True, reuse_allowed=False)
    table.owner[s] = k
    table.last_use[s] = table.tick
    return d


def invalidate(table: SlotTable, predicate) -> list[int]:
    """Mark slots whose owner key satisfies predicate as needing erase.

    Returns the slots the adapter must erase now (e.g. on policy or snapshot
    change, call with the set of keys that are no longer valid).
    """
    out = []
    for i, k in enumerate(table.owner):
        if k is not None and predicate(k):
            table.owner[i] = None
            out.append(i)
    return out
