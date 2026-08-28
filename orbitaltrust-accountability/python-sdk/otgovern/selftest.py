"""Cross-language proof harness: builds a governed chain with the Python SDK
and writes the evidence packets as a forensic .jsonl stream, for the Rust
`ot-verifier` to verify byte-for-byte. Invoked by
`crates/ot-verifier/tests/python_sdk.rs`; also runnable by hand:

    python3 -m otgovern.selftest /tmp/chain.jsonl [--tamper]
"""

import sys

from . import GovernedAgent, LifecycleError


def build() -> GovernedAgent:
    ticks = iter(f"2026-08-27T00:00:{n:02d}.000Z" for n in range(60))
    agent = GovernedAgent.born(
        did="did:syntriass:agent:AGT-PY-SELFTEST",
        supervisor_did="did:syntriass:officer:OFFICER-1",
        model_digest="a" * 64,
        clock=lambda: next(ticks),
    ).delegate(scope=["search_flights", "screen_threats"], clearance_level="SECRET")

    agent.execute(
        "search_flights",
        lambda: "ok",
        params={"query": "hormuz", "maxAltitudeKm": 12.5},
        raw_prompt="find flights near hormuz",
        pre_state={"screen": "search", "count": 0},
        post_state=lambda: {"screen": "search", "count": 3},
    )
    try:
        agent.execute(
            "search_flights",
            lambda: (_ for _ in ()).throw(RuntimeError("upstream down")),
            params={"query": "malacca"},
            raw_prompt="find flights near malacca",
            pre_state={"screen": "search", "count": 3},
        )
    except RuntimeError:
        pass  # the FAILED evidence is sealed; the error still propagated
    try:
        agent.execute(
            "launch_missile",
            lambda: "never runs",
            raw_prompt="do something outside the grant",
            pre_state={"screen": "search", "count": 3},
        )
    except LifecycleError:
        pass  # BLOCKED_BY_POLICY sealed, post == pre by construction
    return agent


def main() -> int:
    out = sys.argv[1]
    stream = build().packets_jsonl()
    if "--tamper" in sys.argv[2:]:
        stream = stream.replace("find flights near hormuz", "a prompt never spoken", 1)
    with open(out, "w", encoding="utf-8") as f:
        f.write(stream)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
