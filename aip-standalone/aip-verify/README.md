# aip-verify

Standalone, offline verifier for AIP **EvidencePackets** — the auditor's
self-service tool. Verification is a pure function of the packet plus the trust
roots you supply; it makes **no network calls** and does not depend on the AIP
service.

## Install

```bash
# From this repository (today):
cargo install --path aip-standalone/aip-verify

# Goal (once published): cargo install aip-verify
```

This installs the `aip-verify` binary onto your `PATH`.

## Audit-export bundles

`aip-verify` also verifies a full **audit-export bundle** (`.zip` from
`GET /v1/evidence/{id}/export`) entirely offline:

```bash
aip-verify bundle.zip            # integrity + signature (PASS/WARNING/FAIL)
aip-verify bundle.zip --report   # every check
aip-verify bundle.zip --json     # machine-readable
aip-verify bundle.zip --trust <authority-id>=<pubkey-hex>   # full authority verification
```

Zero-config (`aip-verify bundle.zip`) checks bundle structure, per-file
hashes, the manifest signature, and packet integrity; without `--trust` keys
the authority chain is reported as WARNING (not FAIL). See
`docs/AUDIT_EXPORT_SPEC.md`.

## Usage

```bash
# Integrity check with zero configuration:
# confirms the packet is internally authentic (canonical hash + agent
# signature) and flags tampering — even before you trust any issuer keys.
aip-verify evidence.json

# Full per-rule report (human readable):
aip-verify evidence.json --report

# Machine-readable VerificationReport:
aip-verify evidence.json --json

# Full authority verification: supply the trusted public keys (hex) of the
# principal and each delegation issuer, optionally counterparties + revocations.
aip-verify evidence.json \
  --trust aip1PRINCIPAL...=<pubkey_hex> \
  --trust aip1ISSUER...=<pubkey_hex> \
  --counterparty ledger.bank.example=<pubkey_hex> \
  --revoked <jti_hex> \
  --receipt-data receipt.bin
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Packet parsed and verification returned **valid** |
| 2 | Packet parsed but verification returned **invalid** (see failed rules) |
| 1 | Could not read/parse the packet, or bad arguments |

## What "no trust keys" tells you

Run with no `--trust` keys and the authority rules (root token, delegation
chain, scope) cannot pass — but the **integrity** rules still run. If
`tampered: false` and `trust_floor: AgentSigned`, the packet is internally
authentic and unmodified; supply trust keys to confirm the authority chain.
If `tampered: true`, someone altered the packet after it was sealed.
