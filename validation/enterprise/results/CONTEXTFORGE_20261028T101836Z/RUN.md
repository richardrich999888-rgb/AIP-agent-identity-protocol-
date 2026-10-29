# Actual ContextForge and LangGraph validation

Run: 2026-10-28 10:18:36–10:18:47 UTC (15:48:36–15:48:47 IST).
Host: macOS/Darwin arm64, Python 3.12.12. Result: **28 checks passed**.
Two checks exercise actual plugin configuration/filesystem rejection; the
remaining checks exercise the running gateway, real tool server, comparator,
offline verification and optional genuine LangGraph workload.

The repository implementation was based on `3a029aec83fa2aa57ea8bb0a2c28968f3be037a4`.
The exact changed source and binaries used by this run are identified in
`source-manifest.json`; all 13 entries were checked against the workspace after
the run with no mismatches. The final review commit is separate from the base.

Upstream IBM ContextForge revision:
`ff6a566a4b5c098093db90bbb4d5df483e108026`.
CPEX 0.1.4, official MCP SDK/types 2.3.0, uv 0.13.6.
The upstream `uv.lock` SHA-256 is
`76ef83096d34d7a95aca91407cbf085c3da1e0c937616d86da393b9549117f0c`.

## Executed command

After installing the exact upstream runtime lock and building the additive
Rust signer and authorization-fixture example:

```bash
/private/tmp/aip-contextforge.a79qGb/source/.venv/bin/python integrations/mcp-gateway/validate_contextforge.py \
  --contextforge-source /private/tmp/aip-contextforge.a79qGb/source \
  --signer-binary target/debug/aip-tool-receipt \
  --agent-script examples/bank-ai-execution-assurance/loan_agent.py \
  --agent-python .local/bank-agent-venv/bin/python \
  --output /private/tmp/aip-contextforge.a79qGb/results-12
```

Fresh-environment setup commands are in
`integrations/mcp-gateway/README.md`. The LangGraph environment and local-model
requirements are in `examples/bank-ai-execution-assurance/`.

## What the evidence establishes

Actual ContextForge dispatched to an actual MCP server reading a synthetic
SQLite database in read-only mode. The official MCP client used protocol
`2026-07-28`. The test server recorded 17 actual upstream invocations: 15
produced final signed receipts and two deliberately left receipt uncertainty.
The independent signer persisted 28 receipts in total, including 13 gateway
refusals. All exported receipts verified offline with the public anchor alone.

The real Rust comparator returned `Agrees` for a preissued test authorization
and `Diverges/ReceiptDoesNotMatchAuthorization` for changed parameters, with no
agent claim supplied. The authorization fixture's process binding is explicitly
test data, not independently observed runtime evidence.

The genuine LangGraph workload called a real local model, chose a read tool,
performed that call through ContextForge and received an independently signed
gateway receipt. Its decision identifier was only a join label; this agent run
does not prove signed authorization or independent kernel execution. Its final
report explicitly states `NOT_RUN` for independent execution evaluation.

Negative checks cover missing identity, authenticated-principal mismatch,
unsupported tools, malformed JSON-RPC, both header disagreements, unauthenticated
access, Origin refusal, replay, concurrent duplicates, restart, upstream failure,
timeout, wrong signing key and sink outage. Signing failure after dispatch
returned `CANNOT_PROVE`; simultaneous journal failure did not mask uncertainty.
The deliberately induced final journal states include one `receipt_error` and
one `pending`; neither was converted to a success receipt.

Pinned ContextForge strips successful top-level response metadata on `/mcp`.
The official-client check independently confirmed its signed receipt in the
gateway sink. `/rpc` returns the receipt metadata directly. This upstream
compatibility limitation is not hidden by the adapter.

## Earlier failures and limits

`failures/langgraph-invalid-json.log` preserves the earlier real model failure:
the unstructured/truncated JSON response failed parsing before a tool call.
The agent subsequently used bounded schema-constrained output; the final run
passed. No fallback fabricated an agent tool choice or recommendation.

No Linux kernel observation, two-host key-separation deployment, complete
observation/authorization/receipt reconciliation, banking outcome, benchmark,
regulatory approval or independent security assessment was exercised here.
Operational gateway/upstream logs, private keys, JWTs, environment values and
SQLite databases were excluded from this exported public artifact set.
