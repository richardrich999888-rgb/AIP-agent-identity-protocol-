"""Real MCP 2.3.0 upstream used only by the loopback integration harness."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sqlite3
from pathlib import Path

from mcp.server.mcpserver import MCPServer

server = MCPServer("vanian-receipt-test-upstream")


def record(tool: str, loan_id: int, amount: int) -> None:
    descriptor = os.open(os.environ["VANIAN_TEST_UPSTREAM_EVENTS"], os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        os.write(descriptor, (json.dumps({"tool": tool, "loan_id": loan_id, "amount": amount}) + "\n").encode())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@server.tool()
async def loan_read(loan_id: int, amount: int = 0) -> dict:
    """Read synthetic non-production loan metadata; performs no banking write."""
    record("loan_read", loan_id, amount)
    with sqlite3.connect("file:" + os.environ["VANIAN_TEST_BANK_DB"] + "?mode=ro", uri=True) as connection:
        row = connection.execute("SELECT document_status FROM loan_documents WHERE loan_id=?", (loan_id,)).fetchone()
    if row is None:
        raise ValueError("synthetic loan fixture does not exist")
    return {"loan_id": loan_id, "amount_seen": amount, "document_status": row[0], "recommendation": "review-only"}


@server.tool()
async def loan_fail(loan_id: int, amount: int = 0) -> dict:
    """Return an actual tool error to exercise failed gateway dispositions."""
    record("loan_fail", loan_id, amount)
    raise ValueError("controlled non-production upstream failure")


@server.tool()
async def loan_slow(loan_id: int, amount: int = 0) -> dict:
    """Delay beyond the configured gateway timeout."""
    record("loan_slow", loan_id, amount)
    await asyncio.sleep(5)
    return {"loan_id": loan_id, "recommendation": "late"}


@server.tool()
async def loan_pause(loan_id: int, amount: int = 0) -> dict:
    """Pause at a test barrier so the harness can simulate a post-dispatch signing outage."""
    record("loan_pause", loan_id, amount)
    release = Path(os.environ["VANIAN_TEST_RELEASE_FILE"])
    for _ in range(100):
        if release.exists():
            return {"loan_id": loan_id, "recommendation": "review-only"}
        await asyncio.sleep(0.02)
    raise TimeoutError("test barrier not released")


@server.tool()
async def loan_unapproved(loan_id: int, amount: int = 0) -> dict:
    """Existing upstream tool deliberately excluded from the plugin allowlist."""
    record("loan_unapproved", loan_id, amount)
    return {"loan_id": loan_id}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    server.run(transport="streamable-http", host="127.0.0.1", port=args.port, streamable_http_path="/mcp")
