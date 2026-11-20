"""Item 1.3 acceptance: LiteLLM SDK usage and cost capture, no Postgres, offline.

    unshare -n VENV/bin/python acceptance.py OUT.jsonl --isolated

`--isolated` (run inside `unshare -n`) brings up loopback only and asserts
that an outside name does not resolve, so the run cannot have depended on
the network. The mock model runs in-process on 127.0.0.1. Exit 0 only if
every check passes. Every record is TEST DATA; prices are declared test prices.
"""

from __future__ import annotations

import fcntl
import math
import os
import socket
import struct
import sys
import threading
import time
from pathlib import Path

# Declared TEST prices (USD per token). Not any provider's real price.
TEST_PRICE_IN = 1e-6
TEST_PRICE_OUT = 2e-6
EVENT_WAIT_S = 10.0
POLL_S = 0.05
SIOCGIFFLAGS, SIOCSIFFLAGS, IFF_UP = 0x8913, 0x8914, 0x1
OUTSIDE_NAME = "pypi.org"


def loopback_up() -> None:
    """Set IFF_UP on `lo` in a fresh network namespace (no `ip` binary here)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifr = struct.pack("16sH14s", b"lo", 0, b"\0" * 14)
    flags = struct.unpack("16sH14s", fcntl.ioctl(s, SIOCGIFFLAGS, ifr))[1]
    fcntl.ioctl(s, SIOCSIFFLAGS, struct.pack("16sH14s", b"lo", flags | IFF_UP, b"\0" * 14))


def outside_resolves() -> bool:
    try:
        socket.getaddrinfo(OUTSIDE_NAME, 443)
        return True
    except OSError:
        return False


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3) or (len(argv) == 3 and argv[2] != "--isolated"):
        print(__doc__, file=sys.stderr)
        return 2
    checks: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, detail: object = "") -> None:
        checks.append((name, bool(ok), str(detail)))

    if len(argv) == 3:
        loopback_up()
        check("isolated: outside name does not resolve", not outside_resolves(), OUTSIDE_NAME)
    check("LITELLM_LOCAL_MODEL_COST_MAP=True", os.environ.get("LITELLM_LOCAL_MODEL_COST_MAP") == "True")

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "command-center" / "server"))
    import mock_openai

    srv = mock_openai.serve(0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}/v1"

    import litellm
    from llm_capture import COST_ESTIMATED, COST_FAILED, COST_NO_USAGE, COST_PRICE_UNKNOWN
    from capture_logger import UsageCapture
    import json

    out = Path(argv[1])
    out.write_text("")
    cap = UsageCapture(out)
    litellm.callbacks = [cap]
    litellm.register_model({"openai/mock-1": {
        "input_cost_per_token": TEST_PRICE_IN, "output_cost_per_token": TEST_PRICE_OUT,
        "litellm_provider": "openai", "mode": "chat"}})

    msgs = [{"role": "user", "content": "hello there agent"}]
    md = {"agent_id": "recon-reporter", "workflow": "wf-1", "owner": "alice"}
    scenarios = [
        ("priced", "mock-1", md),
        ("unpriced", "mock-2", md),
        ("no-usage", "mock-no-usage", md),
        ("provider-error", "mock-error", md),
        ("missing-owner", "mock-1", {"agent_id": "orchestrator", "workflow": "wf-1"}),
    ]
    for i, (_, model, meta) in enumerate(scenarios):
        try:
            litellm.completion(model="openai/" + model, api_base=base, api_key="sk-test-not-a-secret",
                               messages=msgs, metadata=meta, num_retries=0)
        except Exception:  # the provider-error scenario is expected to raise
            pass
        deadline = time.monotonic() + EVENT_WAIT_S
        while cap.written < i + 1 and time.monotonic() < deadline:
            time.sleep(POLL_S)
    check("one record per call", cap.written == len(scenarios), f"{cap.written}/{len(scenarios)}")
    recs = [json.loads(line) for line in out.read_text().splitlines()]
    by = dict(zip([s[0] for s in scenarios], recs)) if len(recs) == len(scenarios) else {}

    if by:
        p = by["priced"]
        want = 3 * TEST_PRICE_IN + 5 * TEST_PRICE_OUT
        check("priced: tokens 3/5/8 from provider", (p["prompt_tokens"], p["completion_tokens"], p["total_tokens"]) == (3, 5, 8), p)
        check("priced: cost = 3*in + 5*out at test price", p["cost_usd"] is not None and math.isclose(p["cost_usd"], want, rel_tol=1e-9), (p["cost_usd"], want))
        check("priced: basis estimated", p["cost_basis"] == COST_ESTIMATED, p["cost_basis"])
        check("priced: attribution complete", (p["agent_id"], p["workflow"], p["owner"], p["attribution_missing"]) == ("recon-reporter", "wf-1", "alice", []), p)
        check("priced: model/provider", (p["model"], p["provider"]) == ("mock-1", "openai"), p)
        u = by["unpriced"]
        check("unpriced: cost None, not 0", u["cost_usd"] is None and u["cost_basis"] == COST_PRICE_UNKNOWN, u)
        check("unpriced: tokens still recorded", u["total_tokens"] == 8, u)
        n = by["no-usage"]
        check("no-usage: tokens and cost None, not 0", (n["total_tokens"], n["cost_usd"], n["cost_basis"]) == (None, None, COST_NO_USAGE), n)
        e = by["provider-error"]
        check("provider-error: failure recorded, None not 0", (e["status"], e["total_tokens"], e["cost_usd"], e["cost_basis"]) == ("failure", None, None, COST_FAILED), e)
        m = by["missing-owner"]
        check("missing-owner: recorded with attribution_missing", m["attribution_missing"] == ["owner"] and m["total_tokens"] == 8, m)
        check("every record labelled TEST DATA", all(r["label"] == "TEST DATA" for r in recs))
    check("no Postgres configured", not os.environ.get("DATABASE_URL"))
    ent = sorted(x for x in sys.modules if "enterprise" in x)
    check("no enterprise module loaded", not ent, ent)
    srv.shutdown()

    for name, ok, detail in checks:
        print(f"{'ok  ' if ok else 'FAIL'} {name}" + ("" if ok else f" :: {detail}"))
    failed = sum(not ok for _, ok, _ in checks)
    print(f"checks: {len(checks) - failed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
