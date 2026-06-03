# AIP Python SDK Integration Plan

The `python/airon-aip-sdk` package is the open-source adoption layer for AIP.
It is intentionally thin: it uses the production `aip-service` HTTP contract
and keeps framework integrations optional.

## Core SDK

| Capability | Module | Purpose |
| --- | --- | --- |
| HTTP client | `airon_aip.AipClient` | Calls issue, verify, delegate, verify-chain, revoke, public-key, and health endpoints |
| Persistent identity | `airon_aip.PersistentAgentIdentity` | Loads or issues a stable local identity alias and refreshes expired tokens |
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

## Claim Boundary

The SDK persists and propagates AIP identity metadata. The AIP service remains
the authority for token issuance, signature verification, delegation, and
revocation. Framework adapters do not store raw bearer tokens in model artifacts
unless a caller explicitly does so outside the SDK.
