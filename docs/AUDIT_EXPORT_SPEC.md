# AIP Audit-Export Bundle — Specification

**Status:** v1 (`aip-bundle-1`) · reference implementation: `aip-protocol::bundle`

An **audit-export bundle** is a portable ZIP an enterprise hands to an
auditor, regulator, internal-audit/risk team, or counterparty so they can
**verify an AI agent's action and its authority entirely offline** — without
calling AIP servers.

## 1. Bundle structure

`GET /v1/evidence/{id}/export` returns `application/zip` containing:

| File | Purpose |
|---|---|
| `evidence.json` | The signed EvidencePacket (the cryptographic record). |
| `verification_report.json` | Machine-readable `VerificationReport` computed at export. |
| `verification_report.md` | Plain-language report for auditors/compliance/regulators. |
| `authority_graph.json` | Human→Authority→Agent→Decision→Action→Receipt graph (nodes + edges). |
| `authority_graph.dot` | Graphviz DOT of the same graph (render with `dot`). |
| `manifest.json` | Bundle metadata + per-file SHA-256 (see §2). |
| `bundle_signature.sig` | Hex Ed25519 signature over `manifest.json` bytes. |

## 2. Manifest

```jsonc
{
  "schema_version": "aip-bundle-1",
  "bundle_id":   "<hex>",
  "tenant_id":   "<tenant>",
  "packet_id":   "<hex packet id>",
  "exported_at": 1781769600000,            // Unix ms
  "packet_hash": "<hex SHA-256 of the packet canonical bytes>",
  "bundle_hash": "<hex SHA-256 over the sorted (name,sha256) file list>",
  "signer_algorithm": "Ed25519",
  "signer_public_key": "<hex 32-byte service public key>",
  "files": [ { "name": "evidence.json", "sha256": "<hex>" }, ... ]
}
```

- `bundle_hash = SHA-256( Σ sorted "name:sha256\n" )` over the **content**
  files (everything except `manifest.json` and `bundle_signature.sig`).
- `bundle_signature.sig` is `hex(Ed25519_sign(service_seed, manifest.json bytes))`.
  The signing public key is embedded in the manifest; a verifier confirms the
  signature offline and surfaces its SHA-256 fingerprint for out-of-band
  comparison against the known AIP service key.

## 3. Verification process

`aip-verify bundle.zip` (or `aip_protocol::verify_zip`) runs these checks,
each reported as **PASS / WARNING / FAIL**:

| Check | What it proves |
|---|---|
| `BUNDLE_STRUCTURE` | All seven files are present. |
| `MANIFEST_PARSE` | `manifest.json` parses and is `aip-bundle-1`. |
| `FILE_HASHES` | Every file's SHA-256 matches the manifest (per-file tamper detection). |
| `BUNDLE_HASH` | `bundle_hash` matches the file set (manifest tamper detection). |
| `BUNDLE_SIGNATURE` | The signature verifies over `manifest.json` with the embedded key. |
| `EVIDENCE_INTEGRITY` | The packet is self-consistent and its hash matches the manifest. |
| `PACKET_VERIFICATION` | Full `verify_packet` against any supplied trust keys. |

**Overall result:** `FAIL` if any check fails; else `WARNING` if any warns;
else `PASS`.

**Trust keys.** With **no** `--trust` keys, integrity + signature still verify
(`PASS`), but the authority chain cannot be confirmed → `PACKET_VERIFICATION`
is `WARNING` and the overall result is `WARNING`. Supplying the authorizing
party's and intermediaries' public keys (out of band) yields a full `PASS` at
the `AUTHORITY_BOUND`/`COUNTERPARTY_SIGNED` floor.

## 4. Offline verification workflow (auditor)

```bash
# 1. Receive bundle.zip. Integrity + signature, zero configuration:
aip-verify bundle.zip                 # → PASS/WARNING/FAIL, exit 0 unless FAIL

# 2. Full report of every check:
aip-verify bundle.zip --report

# 3. Confirm the authority chain with keys obtained out of band:
aip-verify bundle.zip \
  --trust <authority-id>=<pubkey-hex> \
  --trust <intermediary-id>=<pubkey-hex>

# 4. Machine-readable result for pipelines:
aip-verify bundle.zip --json

# 5. Render the authority graph:
unzip -p bundle.zip authority_graph.dot | dot -Tpng -o authority.png
```

Exit codes: `0` PASS/WARNING · `2` FAIL · `1` unreadable/bad arguments.

## 5. Threat model

| Threat | Mitigation |
|---|---|
| Edit a content file (e.g. the amount in `evidence.json`) | `FILE_HASHES` mismatch; and the packet's own agent signature fails `EVIDENCE_INTEGRITY`/`PACKET_VERIFICATION`. |
| Edit the manifest (e.g. swap a file hash or tenant) | `BUNDLE_SIGNATURE` fails (manifest bytes no longer match the signature). |
| Replace the signature | `BUNDLE_SIGNATURE` fails (no valid signature from the embedded key). |
| Re-sign with an attacker key | Signature verifies against the embedded key, but the **signer fingerprint** won't match the known AIP service key — compared out of band by the auditor. (The packet's own agent/authority signatures are independent and still bind the evidence.) |
| Remove a file | `BUNDLE_STRUCTURE` fails. |
| Forge authority | The delegation chain inside the packet is per-hop Ed25519-signed; `PACKET_VERIFICATION` with trusted keys fails for any forged hop. |
| Replay an old (since-revoked) record | Supply the revocation list (`--revoked`); `PACKET_VERIFICATION` fails on revoked tokens. |

**Trust model:** verification is a pure function of the bundle plus the
verifier's own trusted keys/revocations. No AIP server is contacted. The
service signature attests *who exported* the bundle and that the manifest is
intact; the packet's own signatures attest *what happened and under whose
authority*. The two are independent — a compromised exporter cannot fabricate
a valid authority chain.

## 6. Key custody note

The bundled `verification_report.*` reflects the **integrity level** the
exporting service can attest without external trust keys (the service holds
the agents'/principals' public keys out of band, not necessarily at export
time). Full authority verification is performed by the recipient with
`aip-verify --trust …`. This keeps the exporter honest: the bundle never
*claims* an authority verification it cannot itself prove.
