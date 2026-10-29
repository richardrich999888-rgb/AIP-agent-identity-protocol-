"""ContextForge's reference-stdio helper; retained for existing callers.

This function uses the original echo demonstration gateway. It does not
dispatch a ContextForge tool or establish a downstream business result.
The registered real-gateway plugin is ``vanian_contextforge.py``; it uses
the additive Rust ``aip-tool-receipt`` interface and actual pre/post hooks.
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
