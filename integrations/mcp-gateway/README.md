# Phase 2 — MCP tool boundary → ToolReceipt (BUILT + tested; ContextForge adapter written)

**Status: the gateway is built and tested; the ContextForge adapter is
written but not exercised against a live ContextForge here.** The prior-art
review (`PRIOR_ART_NOTES.md`) is done. The receipt-signing core is the
`aip-mcp-gateway` crate, so the exit gate is met in first-party code and the
ContextForge plugin is a thin adapter over it.

## What is built and tested

- **`aip-standalone/aip-mcp-gateway`** — a real MCP gateway. `issue_receipt`
  signs a `ToolReceipt` over the **canonical** body arguments with the
  gateway's own key; `check_header_body` enforces the 2026-07-28 spec's
  header/body agreement before signing; the binary speaks JSON-RPC over stdio
  and appends signed receipts to a sink.
- **Exit gate proven** (`tests/tool_boundary.rs`, 5 tests + 6 canonical): a
  mis-parameterised call `Diverges` via `compare_tool_boundary` **with no
  agent claim supplied**, so the finding rests on the gateway receipt versus
  the decision, not the agent's account. A receipt signed under the agent's
  key is refused (`GatewayKeyIsAgentKey`). Argument key order does not
  manufacture a divergence.
- **Live smoke run**: `aip-mcp-gateway` fed real JSON-RPC over stdio emits a
  `Forwarded` receipt for an honest call and a `Refused` receipt + JSON-RPC
  error for a header/body mismatch.

## The ContextForge adapter

`contextforge_plugin.py` is the production adapter: a pre-forward hook on
tools/call that shells to the `aip-mcp-gateway` binary rather than
reimplementing the signing, so the two cannot drift. It is written and
unit-shaped; running it inside a live ContextForge is the remaining
integration step, and needs a ContextForge deployment.

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
