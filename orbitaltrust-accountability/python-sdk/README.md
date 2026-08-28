# otgovern — the SENTINEL governance SDK for Python agents

Seal your agent's NEXORA lifecycle anchors and AIP evidence packets from
Python, **byte-identical to the Rust core** (proven in
`crates/ot-verifier/tests/python_sdk.rs`, which verifies chains this SDK
builds with the offline Rust verifier), and stream them to a governance hub
whose ML-DSA-signed receipts confirm the server verified the same bytes.

No dependencies outside the standard library.

## Install

```sh
pip install sdks/python          # from the repo root
```

## Govern an agent

```python
from otgovern import GovernedAgent, HubClient, governed

agent = GovernedAgent.born(
    did="did:syntriass:agent:AGT-PY-001",
    supervisor_did="did:syntriass:officer:OFFICER-1",
    model_digest="0" * 64,
).delegate(scope=["search_flights"], clearance_level="SECRET")

# Optional: stream every record to a hub (ot-api). Each receipt's tail must
# equal the locally sealed tail — a live cross-language check per record.
agent.attach(HubClient(
    "http://localhost:8080",
    token="fleet-token-1",                 # OT_GOVERNANCE_TOKENS on the hub
    signer_identity="<pinned 64-hex id>",  # GET /governance/signer, out of band
))

@governed(agent, "search_flights", state_fn=lambda: {"screen": "search"})
def search_flights(query: str):
    ...
```

Every call — success, exception, or out-of-scope refusal — seals evidence:
a `SUCCESS`/`FAILED`/`BLOCKED_BY_POLICY` packet with pre/post state hashes,
acknowledged by an `ACTION_EXECUTION_SEAL` anchor. Out-of-scope calls raise
`LifecycleError` *after* sealing the refusal; nothing executes after
`agent.revoke()`. The Rust core enforces this lifecycle at compile time;
Python enforces it at runtime with the same law.

## Govern an MCP server

Wrap the tool handlers you register — the MCP surface becomes governed
without touching the protocol:

```python
@governed(agent, "lookup_orders", state_fn=current_session_state)
def lookup_orders(customer_id: str): ...

server.register_tool("lookup_orders", lookup_orders)
```

## Audit offline

```sh
python3 - <<'PY'
from myagent import agent
open("chain.jsonl", "w").write(agent.packets_jsonl())
PY
cargo run -p ot-verifier -- --dossier chain.jsonl --verbose
cargo run -p ot-verifier -- --attestation receipt.json --signer <pinned-id>
```

## Tests

```sh
python3 -m unittest discover sdks/python/tests   # SDK behavior
cargo test -p ot-verifier --test python_sdk      # cross-language byte proof
```
