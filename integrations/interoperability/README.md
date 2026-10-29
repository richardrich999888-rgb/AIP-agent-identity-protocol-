# VANIAN interoperability references

This optional Python package connects existing VANIAN evidence boundaries to external SDKs. It never loads into the privileged observer. Status: PARTIALLY_VERIFIED; the institutional same-run acceptance gate remains open.

## Install and test (Linux reference environment)

From the repository root, with Python 3.12 and uv 0.13.4:

```sh
uv sync --project integrations/interoperability --frozen --extra adk --extra test
uv run --project integrations/interoperability --frozen --extra adk --extra test pytest integrations/interoperability/tests -q
cargo test --locked -p aip-airi --example interop_verify
cargo build --locked -p aip-mcp-gateway --bin aip-tool-receipt --example contextforge_fixture
```

`uv.lock` pins the adapter/ADK test dependency graph. `runtime-packages.json` records the actual separate model/native-governance environment; it is an inventory, not an assertion that every recorded package is required. `upstreams.lock.json` distinguishes inspected main commits from executed releases, model bytes and native crate checksums.

For model execution, use a **separate** venv from the existing Python SDK parity tests, whose model metadata depends on installed frameworks. Install `transformers==4.57.1` and the CPU build `torch==2.9.0+cpu` from the official PyTorch CPU index. Download `Qwen/Qwen2.5-0.5B-Instruct` at revision `7ae557604adf67be50417f59c2c2f167def9a775` and verify the file hashes in the upstream lock. No remote model code is enabled.

The tested native Microsoft SDK is built from `microsoft/agent-governance-toolkit` commit `4eca1f5b44d30ebe5e9745ac36ca394f887e617b`, directory `policy-engine/sdk/python`. Install it with the current Rust toolchain and pip build isolation. Its resulting package is 0.4.0b0, backed by agent-control-spec 0.4.0-alpha.4. Set `ACS_OPA_PATH` (not `OPA`) to the pinned OPA executable.

## Live policy and identity tests

Download the OPA/SPIRE release assets and verify exact SHA-256 values from the upstream lock before executing them. The workflow provides the full commands.

```sh
python integrations/interoperability/examples/opa_live.py --opa /absolute/path/opa --output /tmp/opa-new-run
python integrations/interoperability/examples/spire_jwt_live.py --spire-directory /absolute/path/spire-1.15.3 --output /tmp/spire-new-run
```

SPIRE requires Unix sockets and process visibility. The local managed environment blocked it; the test must fail rather than use a synthetic substitute. The CLI workload identity is not an ADK agent binding. These labs destroy ephemeral private keys and leave public references only.

## Genuine two-agent workload

Set the environment for the model venv, using fresh output directories:

```sh
export VANIAN_LOCAL_MODEL_DIR=/absolute/path/model
export VANIAN_INTEROP_RESULTS=/tmp/adk-new-run
python integrations/interoperability/examples/adk_a2a_live.py
```

For native Microsoft governance also set `VANIAN_MICROSOFT_MANIFEST` to the absolute path of `examples/microsoft/manifest.yaml` and `ACS_OPA_PATH` to the pinned binary.

The full same-run **application/gateway** test reuses the existing harness. Prepare ContextForge at `ff6a566a4b5c098093db90bbb4d5df483e108026` with its own `uv sync --locked --no-dev --no-install-project`. Run its Python interpreter:

```sh
/absolute/contextforge/.venv/bin/python integrations/mcp-gateway/validate_contextforge.py \
  --contextforge-source /absolute/contextforge \
  --signer-binary target/debug/aip-tool-receipt \
  --fixture-binary target/debug/examples/contextforge_fixture \
  --agent-script integrations/interoperability/examples/adk_a2a_live.py \
  --agent-python /absolute/model-venv/bin/python \
  --agent-kind adk-a2a --agent-model-directory /absolute/model \
  --agent-governance-manifest integrations/interoperability/examples/microsoft/manifest.yaml \
  --agent-opa-binary /absolute/opa --output /tmp/combined-new-run
```

Omit the last two governance flags for the ADK-only variant. The harness forwards only its scoped gateway credential and explicit model/governance configuration, never collector/decision-point signer keys. Its separate comparator cases use clearly labeled signed fixture authorizations, not independently authorized model operations.

## Offline verification

```sh
python validation/interoperability/verify_gateway_archive.py \
  --archive validation/interoperability/results/20261028/combined/receipts.jsonl \
  --anchor /independently/established/trust-anchor.json \
  --verifier target/debug/aip-tool-receipt
cargo run --locked -p aip-airi --example interop_verify -- \
  /assessor/anchors.json /untrusted/native-bundle.json
```

The bundled lab public anchor can reproduce receipt verification. Establish its authority independently before relying on it. The Rust example accepts ExpectedExecution, optional SignedToolReceipt, optional attested batches/health and an optional native authority bundle; see its explicit JSON structs. Add `authority: {root_token: <ScopedToken>, delegation_chain: [<DelegationToken>, ...]}` to the untrusted bundle. Independently supply `authority_roots` and `authority_delegators` maps of issuer ID to 32-byte public-key arrays in assessor anchors. No keys are accepted from the untrusted bundle. The verifier authenticates the referenced chain and effective action scope at issuance; missing authority stays unassessed. Revocation, resource/spend policy, institutional custody and actual execution are not established by this chain check. Existing archived fixture-only runs are not retroactively upgraded.

Before running an observation lab on an authorized isolated host:

```sh
python validation/interoperability/host_preflight.py --output /tmp/host-prerequisites.json --require-ready
```

This checks local process visibility, Linux capabilities, BTF, tracepoint access and Unix socket availability. A nonzero exit identifies a blocked prerequisite; even a successful check establishes no sensor coverage or independent key custody. The script neither installs nor starts an observer. The managed workspace's report is retained under `validation/interoperability/results/20261028-authority/`.

See [architecture](../../docs/interoperability/ARCHITECTURE.md), [validation](../../docs/interoperability/VALIDATION_REPORT.md), and [production gaps](../../docs/interoperability/PRODUCTION_GAPS.md). This is not an advertised production support matrix.

## Microsoft input to gateway receipt comparison

The native SDK is optional. Build the previously pinned Microsoft source with `maturin==1.8.7` and `maturin build --locked --release`, then install its wheel and `PyYAML==6.0.3` in a separate environment. The new CI job contains exact commands. No upstream SDK is copied into VANIAN or the observer.

The combined harness now emits `governance-comparison-context.json` containing the lab tenant, expected agent references, policy version and tool aliases. Review or independently provision these inputs before institutional use. The gateway public anchor also remains an assessor decision; an untrusted record cannot choose its own key or tenant.

```sh
cargo build --locked -p aip-mcp-gateway --bin aip-tool-receipt
python validation/interoperability/verify_microsoft_archive.py \
  --result /tmp/combined-new-run/adk-a2a/result.json \
  --receipts /tmp/combined-new-run/receipts.jsonl \
  --context /assessor/governance-comparison-context.json \
  --anchor /assessor/trust-anchor.json \
  --verifier target/debug/aip-tool-receipt \
  --output /tmp/new-microsoft-comparison.json
python -m pytest validation/interoperability/test_microsoft_receipt.py -q
```

The tests default to the new committed `20261028-receipt-join/combined` archive. To exercise a fresh archive, set `VANIAN_MICROSOFT_ARCHIVE` to that combined output directory. They require the real pinned SDK and native binary; missing prerequisites do not become passing mocks.

For general native request correlation, `aip-tool-receipt compare-request` reads `{signed_receipt, request}` from stdin, where request contains `method`, `tool_name`, `arguments`, `agent_id`, a 16-byte hex `decision_id`, and `tool_call_id`. Supply the same public `AIP_GATEWAY_ID`, `AIP_GATEWAY_KEY_VERSION` and `AIP_GATEWAY_PUBLIC_KEY` variables as `verify`. It never reads a signer key or receipt sink. `Matches` means only that those request fields match a signature-verified receipt. It does not authenticate caller-supplied identity or decision references, grant authority, infer a tenant, or prove downstream execution.

The ACS profile supports untransformed pre-tool allow/deny with integer JSON arguments only. The bridge preserves Refused/Failed dispositions and reports unsupported transforms, approvals and other profiles as insufficient. Reported policy input may match an authentic gateway receipt even if the policy record itself was fabricated: policy-source authenticity therefore stays unestablished. No comparison gates the banking workload or controls an observer.
