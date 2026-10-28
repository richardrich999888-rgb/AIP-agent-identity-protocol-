# ContextForge tool receipts

The registered adapter is `vanian_contextforge.VanianToolReceiptPlugin`, using
the actual `cpex.framework.Plugin` pre/post hooks in IBM ContextForge at
`ff6a566a4b5c098093db90bbb4d5df483e108026`. `contextforge.lock.json` pins the
gateway source, dependency-lock hash, CPEX 0.1.4 and MCP SDK/types 2.3.0.

Real validation on 2026-10-28 passed 28 checks, including the official MCP client
and genuine LangGraph/local-model tool use. Public artifacts and precise scope:
`validation/enterprise/results/CONTEXTFORGE_20261028T101836Z/RUN.md`.

The adapter delegates canonicalization, signing and verification to the existing
Rust cryptographic core through the additive `aip-tool-receipt` binary. The
original `aip-mcp-gateway` stdio echo demonstration and ToolReceipt v1 format
remain unchanged. `contextforge_plugin.countersign_tool_call` is retained only
for existing reference-demo callers; it is not the registered real integration.

## Reproduce the real integration

Requirements: Python 3.12, Rust 1.91.1 or later, Git, network access for pinned
dependencies, and permission to bind loopback ports. Docker is not required.
From this repository root:

```bash
CONTEXTFORGE_RUN=$(mktemp -d)
python3.12 -m venv "$CONTEXTFORGE_RUN/bootstrap"
"$CONTEXTFORGE_RUN/bootstrap/bin/python" -m pip install --index-url https://pypi.org/simple uv==0.13.6
git init "$CONTEXTFORGE_RUN/source"
git -C "$CONTEXTFORGE_RUN/source" remote add origin https://github.com/IBM/mcp-context-forge.git
git -C "$CONTEXTFORGE_RUN/source" fetch --depth 1 origin ff6a566a4b5c098093db90bbb4d5df483e108026
git -C "$CONTEXTFORGE_RUN/source" checkout --detach FETCH_HEAD
"$CONTEXTFORGE_RUN/bootstrap/bin/uv" sync --project "$CONTEXTFORGE_RUN/source" --locked --no-dev --no-install-project --python python3.12
cargo test -p aip-mcp-gateway --locked
cargo build -p aip-mcp-gateway --bin aip-tool-receipt --example contextforge_fixture --locked
"$CONTEXTFORGE_RUN/source/.venv/bin/python" integrations/mcp-gateway/validate_contextforge.py \
  --contextforge-source "$CONTEXTFORGE_RUN/source" \
  --signer-binary target/debug/aip-tool-receipt \
  --output "$CONTEXTFORGE_RUN/results"
```

The harness starts the real pinned ContextForge process, registers a real MCP
upstream, reads a synthetic SQLite fixture through a read-only connection, and
exercises both HTTP JSON-RPC `/rpc` and the official MCP 2.3.0 client against
`/mcp` with protocol `2026-07-28`. It creates fresh test-only signing/authentication
keys; private keys and tokens stay in a temporary directory removed at exit.
It does not modify an existing ContextForge deployment or connect to a bank.

Tests cover real forwarding, invalid/missing identity, authenticated principal
binding, both header disagreements, unsupported tools, malformed JSON-RPC,
unauthenticated access, Origin refusal, duplicate/replay attempts, simultaneous
duplicate calls, concurrent distinct calls, gateway restart, upstream error,
timeout, key mismatch, sink failure, and a signing outage after actual dispatch.
The last case returns `CANNOT_PROVE` and does not produce a successful receipt.
Every exported receipt is verified by Rust with the public anchor alone.

For parameter comparison, the Rust `contextforge_fixture` example signs a test
authorization before invocation. Its execution binding is explicitly fixture
data, not observed runtime evidence. Captured real gateway receipts are then
passed to the actual `aip_airi::compare_tool_boundary`: the honest parameters
`Agrees`; altered parameters `Diverges` without an agent claim. This is a tool
boundary test, not proof of a completed banking operation or kernel execution.

To include the genuine LangGraph/local-model example after preparing its
separate locked environment, append:

```bash
  --agent-script examples/bank-ai-execution-assurance/loan_agent.py \
  --agent-python .local/bank-agent-venv/bin/python
```

That optional run also needs the specified local Ollama model. The agent gets a
gateway credential and join identifiers; it never receives signing-key paths,
collector credentials or authority keys. Its identifiers do not establish signed
authorization. Independent Linux observation remains a separate prerequisite.

## Install in an institution-managed gateway

See `docs/enterprise/MCP_GATEWAY_INTEGRATION.md` and
`contextforge.example.yaml`. Apply the plugin only to explicitly approved tools
and authenticated principals. The gateway controls its own signing key, outside
the monitored workload's administration. Set `ENABLE_HEADER_PASSTHROUGH=true`
and explicitly allow the receipt headers so the real hook can receive them.
The plugin consumes these headers before upstream dispatch.

The final pre-invoke hook must be this adapter; no later hook may change tool
name/arguments. Automatic tool retries, response-cache short circuits, direct
proxy paths and other plugins are outside this validated configuration. Disable
them for receipted tools until independently tested. The current validation uses
one ContextForge worker and a persistent local SQLite reservation journal.

The journal enforces one request per agent/decision and one use of an
agent/request identifier. It does not provide exactly-once downstream business
transactions. A crash between dispatch and post-hook leaves `pending`; a signing
outage leaves `receipt_error` when the journal is writable, otherwise `pending`.
Both require operational review. Never relabel a
pending invocation as successful or automatically retry an uncertain effect.

## Receipt semantics and compatibility

`Forwarded` means the gateway dispatched and received a non-error tool response;
`Failed` means an error/timeout was reported; `Refused` means this gateway refused
the request. None establishes an authoritative bank transaction outcome.
`compare_tool_boundary::Agrees` compares parameters, regardless of disposition;
it is not a verified-execution verdict.

Missing/malformed decision IDs cannot be represented honestly in ToolReceipt
v1, so the adapter refuses them without inventing a zero decision or issuing a
receipt. The decision ID is a join reference; the plugin does not validate an AIP
authorization chain. Reconciliation verifies the independent signed expectation.

Pinned ContextForge strips successful top-level result `_meta` on its `/mcp`
transport. The signed receipt remains durably available in the gateway JSONL
sink for reconciliation; `/rpc` also returns it in `_meta.vanian`. A client must
not infer receipt absence/presence solely from successful `/mcp` metadata.

Canonical argument bytes keep the existing sorted-key/no-whitespace encoding.
Numbers retain Rust serde_json rendering. Cross-language authorization systems
must use the existing canonicalizer or an agreed integer-only argument profile;
this change does not silently migrate signed commitments to another encoding.

## Evidence artifacts

`report.json`, `source-manifest.json`, `trust-anchor.json`, `receipts.jsonl`, the
signed test authorizations and comparator outputs form the public verification
set. `source-manifest.json` hashes the exact tested source and built binaries.
Operational logs are diagnostic and contain only synthetic test traffic in this
harness; do not treat them as independently signed observation evidence.
Archive only an explicit public-artifact allowlist, never the temporary private
key, tokens, environment, gateway database or replay journal.
