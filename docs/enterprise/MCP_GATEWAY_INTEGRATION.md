# MCP gateway integration

## Implemented boundary

`integrations/mcp-gateway/vanian_contextforge.py` is a registered native plugin
for IBM ContextForge revision
`ff6a566a4b5c098093db90bbb4d5df483e108026`. It uses the actual
`cpex.framework.Plugin` API (`tool_pre_invoke`, `tool_post_invoke`), CPEX 0.1.4
and MCP SDK/types 2.3.0. The source revision and full upstream dependency-lock
hash are enforced by the real integration harness.

The gateway attests to its received, parsed tool parameters and handling. The
existing Rust `aip_mcp_gateway::issue_receipt`, `aip_airi::GatewaySigner`,
`verify_tool_receipt` and `compare_tool_boundary` own the cryptography. The
adapter introduces no Python receipt-signing implementation and changes no
ToolReceipt v1 encoding, signature domain or existing stdio-demo contract.

The probe and collector do not depend on this plugin. The gateway key belongs
to the institution's gateway trust boundary, separate from agent, probe,
collector and decision-authority keys.

## Configuration and installation

Build the signer on the gateway's supported operating system:

```bash
cargo build --release --locked -p aip-mcp-gateway --bin aip-tool-receipt
```

Install that executable and the Python adapter on the pinned ContextForge host.
Adapt `integrations/mcp-gateway/contextforge.example.yaml` with absolute paths,
approved tool invocation names and a gateway-authenticated principal-to-agent
mapping. Run this adapter as the final pre-invoke hook. Do not enable later
argument/name transformations, automatic retries, direct proxy bypasses or
response-cache short circuits for receipted tools.

Set these through administrator-controlled service configuration. Values below
are placeholders, never provisioned credentials:

```text
PLUGINS_ENABLED=true
PLUGINS_CONFIG_FILE=/etc/vanian/contextforge-plugins.yaml
ENABLE_HEADER_PASSTHROUGH=true
PASSTHROUGH_HEADERS_SOURCE=env
DEFAULT_PASSTHROUGH_HEADERS=["X-AIP-Agent-Id","X-AIP-Decision-Id","X-AIP-Request-Id","Mcp-Method","Mcp-Name"]
AUTH_REQUIRED=true
MCP_REQUIRE_AUTH=true
MCP_ALLOWED_ORIGINS=["https://approved-bank-client.example"]
AIP_GATEWAY_KEY_FILE=/run/secrets/vanian-gateway-seed.hex
AIP_GATEWAY_PUBLIC_KEY=<independently-provisioned-32-byte-public-key-hex>
AIP_GATEWAY_ID=gateway.bank.internal
AIP_GATEWAY_KEY_VERSION=1
AIP_GATEWAY_RECEIPTS=/var/lib/vanian-gateway/receipts.jsonl
```

The seed is a 32-byte Ed25519 private seed encoded as hex in a regular,
owner-readable file (mode 0600 or stricter). Provision the corresponding public
anchor independently to verifiers. The signer checks the private key against
that anchor before dispatch. The sink must be a regular owner-only file; its
parent and the SQLite replay-journal parent must be gateway-administrator
controlled. This implementation uses a raw seed file and does not claim gateway
HSM/KMS custody.

Authentication, institutional TLS ingress, RBAC, tenant boundaries and approved
egress remain institution-administered controls. The local test uses loopback,
temporary JWT credentials and a narrow Origin allowlist; it does not prove a
bank's production identity, TLS, isolation or availability configuration.

## Calling a supported tool

Use the actual ContextForge namespaced invocation name (for example,
`receipt-test-loan-read`). Attach:

```text
Authorization: Bearer <gateway-credential>
X-AIP-Agent-Id: <agent assigned to the authenticated principal>
X-AIP-Decision-Id: <32 hex characters identifying an independent decision>
X-AIP-Request-Id: <unique bounded invocation identifier>
```

`X-AIP-Request-Id` becomes this adapter's ToolReceipt `tool_call_id` correlation
label. It is caller-supplied, not independently proven model identity. The agent
ID is checked against the authenticated principal mapping; these checks do not
establish kernel process attribution or signed AIP authorization.

The adapter requires a well-formed decision reference to avoid fabricating a
decision in the existing receipt format. Missing authorization evidence remains
unknown; refusal under this configured receipt policy is not a finding that the
underlying business operation was unauthorized.

## Execution and failure behavior

Before dispatch, the plugin validates headers, tool scope, IDs, input limits,
signing-key anchor and sink readiness. It durably reserves a single use of the
agent/decision and agent/request references. It consumes receipt-control headers
so the gateway's MCP client can construct upstream protocol headers for the
resolved original tool name.

The actual post-invoke hook chooses `Forwarded` or `Failed` from the gateway
result and asks Rust to sign/fsync the JSONL receipt. Deliberate refusals with
valid receipt fields receive `Refused` receipts. Malformed IDs or unavailable
signing material cause explicit refusal without an invented receipt.

A crash before the post hook leaves `pending`. Signing failure after actual
dispatch returns `CANNOT_PROVE`, records `receipt_error` when the journal is
writable (otherwise retains `pending`), and warns against
automatic retry because an effect may have occurred. Journal capacity is bounded;
exhaustion refuses new receipted calls explicitly. Operators must review/archive
the journal under institutional retention policy before replacing it: deleting
replay history re-enables old identifiers.

The live validation uses one gateway worker, SQLite reservations and a locked
local sink. Multi-host distributed idempotency, journal-corruption recovery,
general plugin combinations and a crash-injection campaign remain unvalidated.
The journal does not establish exactly-once downstream business transactions.

The independent observer remains advisory and separate. No containment,
process killing, firewall modification or banking write capability is added.

## Reconciliation and offline verification

The sink contains existing `aip_airi::SignedToolReceipt` JSON records. Transfer
them through an authorized evidence-export process with public trust anchors.
The additive offline executable supports:

```text
aip-tool-receipt verify    # stdin: one SignedToolReceipt JSON object
aip-tool-receipt compare   # stdin: {signed_receipt, expectation}
```

Both use verifier-provisioned `AIP_GATEWAY_ID`, `AIP_GATEWAY_KEY_VERSION` and
`AIP_GATEWAY_PUBLIC_KEY`. `compare` additionally uses
`AIP_DECISION_POINT_ID` and `AIP_DECISION_POINT_PUBLIC_KEY`. Neither requires
a private key, sink or online service. `compare` returns the actual Rust
`ToolBoundary`; no LLM judges evidence.

`Agrees` means the trusted decision's and gateway's parameters agree. Read
disposition separately; this is not proof of runtime execution, observation
coverage or a completed bank transaction. The existing canonicalization and
ToolReceipt domain remain unchanged. Integer-only argument profiles avoid
cross-language numeric-rendering drift.

Pinned ContextForge strips successful top-level result metadata on `/mcp` while
converting the result to its list/tuple representation. Receipts remain in the
durable sink, tested through the official MCP client. `/rpc` also returns
`_meta.vanian.signed_receipt`. Production customers should retrieve receipts
through authorized evidence service/export paths, not infer coverage from
successful MCP result metadata.

## Reproduction and acceptance evidence

The 2026-10-28 run under
`validation/enterprise/results/CONTEXTFORGE_20261028T101836Z/` passed 28 checks,
including the official MCP client and genuine local-model LangGraph workload.
It exported 28 verifiable gateway receipts and recorded 17 upstream invocations.
This count includes two configuration-negative checks; it is not a count of
full Linux observation demonstrations. `RUN.md` records scope and earlier
model failure precisely.

Run the commands in `integrations/mcp-gateway/README.md`. They install the exact
upstream lock, build the Rust signer/fixture, start actual ContextForge and a
real MCP server, and run positive/negative checks. The synthetic loan server
uses SQLite opened in `mode=ro`; no bank-record write tool is exposed. The
optional genuine LangGraph/local-model run gets only its gateway credential.

The harness exports signed receipts, public anchors, preissued signed test
authorizations, real Rust comparator outputs, a structured report and source
hash manifest. The test authority's binding is labeled fixture-only, not Linux
observation. Its expectation is signed before the tool request; mismatch
comparison supplies no agent claim.

This establishes gateway interoperability and receipt behavior. The separate-host
Linux observer/collector join, institutional pilot, authoritative banking
outcomes, production HSM support, regulatory approval and independent security
assessment remain separate acceptance work.
