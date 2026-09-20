# Phase 2 — MCP tool boundary → ToolReceipt (runbook, NOT executed here)

**Status: not executed. Gated on `PRIOR_ART_NOTES.md` (rule: prior-art review
before any filing).** Needs an IBM ContextForge deployment (network).

## Gateway

**IBM ContextForge** (`github.com/IBM/mcp-context-forge`, Apache-2.0) —
strongest candidate: it already runs a plugin pipeline over tool calls with
OpenTelemetry tracing. Fallback: **Lasso MCP Gateway** (already validates
args). Pin the exact version at setup and record it in
`THIRD_PARTY_LICENSES.md`.

## The plugin

A plugin that, for each `tools/call`, computes the canonical-argument
commitment and signs a **`ToolReceipt`** with the **gateway's own Ed25519
key — never the agent's**; the collector refuses a receipt anchored under the
agent key (the independence check `aip-airi` already enforces). Match the real
`ToolReceipt` symbol and `compare_tool_boundary` in `aip-airi` exactly — do
not invent a shape.

Commit over the request **body**. The 2026-07-28 MCP spec adds `Mcp-Method` /
`Mcp-Name` headers for routing and rejects a request whose headers and body
disagree; route on the header if useful, but the body is the source of truth
and is what the receipt commits over.

## Exit gate

A deliberately mis-parameterised tool call is caught against the gateway
receipt, and the finding does **not** rest on the agent's own account of what
it asked for.
