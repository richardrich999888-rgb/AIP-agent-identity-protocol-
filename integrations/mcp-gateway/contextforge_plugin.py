"""IBM ContextForge adapter for the AIP tool boundary (Phase 2).

This is the thin production adapter. It does NOT reimplement the cryptography:
for each tools/call, it canonicalises the arguments and shells out to the
`aip-mcp-gateway` binary (this repo's `aip-mcp-gateway` crate), which computes
the commitment and signs the ToolReceipt with the gateway's own key. Keeping
the signing in one place — the crate that owns the ToolReceipt format — is why
the reference gateway and this adapter cannot drift.

Wire it into ContextForge's plugin pipeline as a pre-forward hook on
tools/call. The binary reads AIP_GATEWAY_KEY / AIP_GATEWAY_ID /
AIP_GATEWAY_KEY_VERSION / AIP_GATEWAY_RECEIPTS from the environment, exactly as
in integrations/mcp-gateway/README.md.

Status: adapter written; not exercised against a live ContextForge in this
environment (ContextForge is not installed here). The receipt-signing it calls
IS exercised — see the reference gateway's tests and smoke run.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any


def countersign_tool_call(
    gateway_binary: str,
    method: str,
    tool_name: str,
    arguments: dict[str, Any],
    agent_id: str,
    decision_id_hex: str,
    env: dict[str, str],
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Feed one tools/call to the aip-mcp-gateway binary and return its result.

    Raises RuntimeError if the gateway refuses (e.g. header/body mismatch) —
    fail closed, never forward unrecorded.
    """
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "headers": headers
        or {"Mcp-Method": method, "Mcp-Name": tool_name},
        "authorization": {"agent_id": agent_id, "decision_id": decision_id_hex},
        "params": {"name": tool_name, "arguments": arguments},
    }
    proc = subprocess.run(
        [gateway_binary],
        input=json.dumps(request) + "\n",
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    line = proc.stdout.strip().splitlines()[0]
    resp = json.loads(line)
    if "error" in resp:
        raise RuntimeError(f"gateway refused: {resp['error']}")
    return resp["result"]
