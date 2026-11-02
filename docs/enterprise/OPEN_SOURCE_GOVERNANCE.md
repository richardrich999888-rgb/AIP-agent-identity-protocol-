# Open-source governance and observability integration

Implementation status: **local component controls pass; the governance-enabled
Linux genuine workload is pending.** This record does not replace the separate
collector-custody, installation, security-scan or production acceptance gates.

VANIAN connects an existing policy engine and observability standard to its
existing execution-assurance path. The current profile evaluates a synthetic,
read-only loan-document request; it does not approve or change bank records.

| Layer | Existing component and pinned addition | Responsibility | Evidence meaning |
| --- | --- | --- | --- |
| Policy | Open Policy Agent 1.22.0, exact release binary and Rego hashes | Check the controller-measured peer and exact configured read scope before AIP signing | OPA output and its audit hashes are supporting application records |
| Authorization | Existing independent Rust authority and ContextForge gateway | Issue the original signed ExpectedExecution; verify the real tool parameters and sign the gateway receipt | Existing authorization and receipt verification rules remain mandatory |
| Observation | Existing Sniffer Dog probe, authenticated collector and reconciler | Capture supported Linux activity, retain coverage, verify and reconcile the available records | Signed kernel evidence and coverage remain distinct from application traces |
| Operations | OpenTelemetry SDK 1.45.2 and Collector Contrib 0.164.0 | Export actual controller phase timestamps, opaque run/decision IDs and evidence-file digests through OTLP/HTTP | Explicitly controller application telemetry, exported after workload cleanup |
| Review | Existing API, SDKs, restricted MCP server, console and offline verifier | Retrieve the same execution evidence and supported verdict | Traces never grant authorization or turn unsupported evidence into proof |

The policy gate uses the peer PID/UID/GID measured by the existing Linux
`SO_PEERCRED` boundary. The agent may propose only a tool and arguments. It
cannot supply the trusted peer, authority identity, allowlist or signing keys.
A denied, undefined, malformed, unavailable or timed-out policy evaluation
cannot reach the signer. An OPA approval still needs the unchanged Rust
signer's approval. The demo policy permits the configured read of synthetic
loan 1 with amount 0; other records, extra arguments and injected identities
are denied. The OPA audit-to-AIP decision link is controller correlation, not
an additional cryptographic signature over the policy version.

The telemetry SDK has its own hash-pinned environment, separate from the agent,
gateway and evidence clients. Export accepts a fixed phase/attribute schema.
Collector output is retained privately, stopped, and checked in full before
any byte-preserving public copy. Unknown fields, duplicate JSON keys, extra
spans or tails, wrong trace/parent/nonce/timestamps and privacy canaries refuse
publication. Raw Collector logs remain private. The local profile binds its
receiver to loopback and uses no model or production credentials. Remote OTLP
receivers, customer backends and production TLS/identity deployment remain
unvalidated.

## Reproduce the component checks

Use Python 3.12 on a supported Linux x86-64 or macOS arm64 host:

```sh
python3.12 integrations/governance/prepare.py --root /tmp/aip-governance-assets
export AIP_GOVERNANCE_TEST_ROOT=/tmp/aip-governance-assets
export AIP_OPA_BINARY="$(python3.12 -c 'import json,pathlib; p=pathlib.Path("/tmp/aip-governance-assets"); print(p/json.loads((p/"assets-manifest.json").read_text())["opa_engine"])')"
python3.12 integrations/governance/check_components.py
```

Bootstrap downloads only pinned public artifacts before workload keys exist.
Runtime verification and policy evaluation do not install or repair assets.
The component gate fails if an actual-engine test is skipped. Component
fixtures and local loopback spans are not genuine agent or kernel evidence.

## Run the genuine joined validation

Dispatch the existing `same-run-validation.yml` workflow on the reviewed
integration revision with `governance_stack=true`. It installs the actual
frameworks, checks that missing assets refuse execution before authorization,
then runs the genuine LangGraph workload, actual observer interruption and
fresh recovery. Each profile uses its own signed evidence and trace output.

The public workflow artifact includes the original run bundle, authorization,
receipts, signed archives and checkpoints plus `public/governance/` policy
correlation, validated controller records and final verified Collector spans.
Private keys and unvalidated Collector output are excluded. Original failed
agent attempts remain in the separate November 1 validation package.

## Pitch wording and limits

After the enabled genuine validation passes, the supported description is:

> VANIAN connects open-source policy and observability tools to signed AI-agent
> execution evidence. Open Policy Agent checks the permitted action before AIP
> authorization; Sniffer Dog independently records supported Linux activity;
> the existing verifier reconciles the available evidence; and OpenTelemetry
> carries operational trace references into a standard Collector.

This is a reproducible engineering integration under a trusted shared host
administrator. It is not regulatory approval, independently administered
collector custody, logical sub-agent attribution, authoritative business-outcome
proof, validation of every agent framework or a completed customer deployment.
Historical `CannotProve`, missing-coverage and failed-business results retain
their original meanings. Security scans and remaining infrastructure gates
must be shown alongside the successful tests.

Primary upstream references: [OPA integration API](https://www.openpolicyagent.org/docs/integration),
[OPA 1.22.0 release](https://github.com/open-policy-agent/opa/releases/tag/v1.22.0),
[OpenTelemetry Collector configuration](https://opentelemetry.io/docs/collector/configuration/),
[Collector 0.164.0 release](https://github.com/open-telemetry/opentelemetry-collector-releases/releases/tag/v0.164.0).
Exact hashes are in the two integration lock files; version labels alone are
not asset verification or independent custody.
