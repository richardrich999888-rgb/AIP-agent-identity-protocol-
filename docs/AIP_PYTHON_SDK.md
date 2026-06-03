# AIP Python SDK Integration Plan

The `python/airon-aip-sdk` package is the open-source adoption layer for AIP.
It is intentionally thin: it uses the production `aip-service` HTTP contract
and keeps framework integrations optional.

## Core SDK

| Capability | Module | Purpose |
| --- | --- | --- |
| HTTP client | `airon_aip.AipClient` | Calls issue, verify, delegate, verify-chain, revoke, public-key, and health endpoints |
| Persistent identity | `airon_aip.PersistentAgentIdentity` | Loads or issues a stable local identity alias and refreshes expired tokens |
| Agent Passport | `airon_aip.AgentPassport` | Issues portable signed passport documents and verifies them through AIP |
| Local store | `airon_aip.IdentityStore` | JSON-backed identity persistence under `~/.airon/aip/identities.json` by default |
| Artifact manifest | `airon_aip.artifact_manifest` | Binds an AIP identity to a file or digest without embedding private key material |

## Optional Integrations

| Ecosystem | Module | Integration Surface |
| --- | --- | --- |
| LangChain | `airon_aip.integrations.langchain` | Runnable config metadata/tags and callback event capture |
| PyTorch | `airon_aip.integrations.torch` | Attach public AIP metadata and optional identity hash buffer to `nn.Module` |
| NumPy | `airon_aip.integrations.numpy` | Wrap arrays and compute content fingerprints |
| pandas | `airon_aip.integrations.pandas` | Stamp DataFrame `.attrs["airon_aip"]` with identity and dataset fingerprint |

## Validation

```bash
make aip-sdk-test
make aip-ci-local
```

The SDK unit tests avoid optional dependencies so CI can validate the package in
a minimal Python environment. Framework-specific users can install extras:

```bash
pip install -e 'python/airon-aip-sdk[langchain,numpy,pandas,torch]'
```

## Agent Passport UX

```python
from airon_aip import AIPConfig, AgentPassport

config = AIPConfig.from_env()
passport_service = AgentPassport(config)

passport = passport_service.issue(
    friendly_name="InvoiceBot",
    capabilities=["invoice.read", "ledger.post"],
    metadata={"runtime": "langchain-v0.2"},
)
passport.save("agent.passport.json")

result = passport_service.verify(passport)
assert result.is_valid
```

The same document can be verified offline with:

```bash
cargo run --manifest-path aip-standalone/Cargo.toml \
  --package airon-verify --bin airon-passport -- verify agent.passport.json
```

## Claim Boundary

The SDK persists and propagates AIP identity metadata. The AIP service remains
the authority for token issuance, signature verification, delegation, and
revocation. Framework adapters do not store raw bearer tokens in model artifacts
unless a caller explicitly does so outside the SDK.

AgentPassport Phase 1 uses the active AIP Ed25519 issuer key for portable
passport signatures and reserves the `pqc_signature` field for the ML-DSA-65
hybrid keyring upgrade.
