# 01 — Evaluation Package

## 1. Product overview

AIP (Accountability Infrastructure for Autonomous AI) answers one question
for every consequential action an AI agent takes:

> **Who did it, who authorized it, within what limits — and can you prove the
> record was not altered, without trusting us?**

It does this by emitting an **EvidencePacket**: a self-contained,
cryptographically signed, tamper-evident record that binds

- the acting agent's identity (and a provenance commitment to its model/build),
- the **chain of delegated authority** from a human principal down to the agent,
- the decision (inputs + rationale, bound by hash),
- the individually-signed action(s) performed,
- an external receipt the counterparty can **countersign**,

into one object that anyone can verify **offline** against trusted public keys.
Change one byte and verification fails on a named cryptographic rule.

## 2. Architecture

```
   Human Principal ──issues──▶ Scoped Root Token
        (signs)                     │ delegates (scope can only narrow)
                                     ▼
                              Delegation Chain ──▶ Acting Agent
                                                      │ decides + acts (signs)
                                                      ▼
   ┌──────────────────────────  EvidencePacket  ──────────────────────────┐
   │ agent identity · root authority · delegation chain · decision ·        │
   │ signed actions · trace/receipt bindings · trust floor · packet sig     │
   └────────────────────────────────────────────────────────────────────────┘
        │ generate (aip-service, authenticated, tenant-scoped)
        ▼
   Evidence Vault (append-only)  ──derives──▶  Authority Graph (per tenant)
        │ verify (pure function of packet + trusted keys; offline-capable)
        ▼
   VerificationReport  →  auditor / regulator / counterparty
```

**Implementation:** Rust. Strategic core = `aip-core` (delegation lattice,
scope attenuation, revocation) + `aip-protocol` (EvidencePacket, 14-rule
verification engine, accountability graph). Deployable surface = `aip-service`
(authenticated, tenant-isolated HTTP API over that core).

## 3. EvidencePacket example (abridged for readability)

Full, exact bytes are reproducible via
`cargo run -p aip-protocol --example loan_approval`. Byte arrays
(`[u8; N]`) serialize as number arrays; elided as `…` here.

```jsonc
{
  "magic": "AEP1", "version": 1,
  "packet_id": "9943642cf27540a09822eb9fbc9c6eeb",
  "created_at": 1781605813921,
  "agent": {
    "aip_id": "aip14PkYiP72rmqY2nCf1BWzkRaxBZQdJPAcySkb6nLGcn",
    "public_key": { "algorithm": "Ed25519", "key_bytes": "…32 bytes…" },
    "provenance": { "model_commitment":"…", "environment_commitment":"…", "toolchain_commitment":"…" }
  },
  "root_authority": {
    "principal_id": "aip17V6PKzBzpMw9JH4pLQJGsPPgd2bKWCYogSa47JBwMU",
    "display_role": "Branch Manager",
    "root_token": { "jti":"94d5f7d4…", "scope": {"allowed":["Read","Write","Execute","Delegate"],"denied":["Admin"]}, "issuer_sig": "…" }
  },
  "delegation_chain": [
    { "depth":1, "issuer_id":"…loan-agent…", "grantee_id":"…sub-agent…",
      "scope": {"allowed":["Write"],"denied":["Admin","Delete"]}, "issuer_sig":"…" }
  ],
  "decision": {
    "decision_id":"b217b7343fc441ec801c2cd21bc7d64c",
    "action_kind":{"Standard":"Write"},
    "summary":"Approve term loan LN-2026-5512 for INR 5,00,00,000 …",
    "input_hash":"…", "rationale_hash":"…", "decided_at":1781605813921
  },
  "actions": [
    { "action_id":"…", "description":"POST /v1/core-banking/loans/approve …",
      "payload_hash":"…", "performed_at":1781605813930, "agent_sig":"…" }
  ],
  "receipt_binding": {
    "receipt_system":"core-banking.examplebank.in", "receipt_id":"LEDGER-LN-2026-5512",
    "receipt_hash":"…", "counterparty_id":"core-banking.examplebank.in", "counterparty_sig":"…"
  },
  "claimed_trust_floor":"COUNTERPARTY_SIGNED",
  "packet_hash":"…", "agent_sig":"…"
}
```

## 4. Verification example (real output)

`POST /v1/evidence/verify` (or the library `verify_packet`) returns a
`VerificationReport`. Abridged real output from the loan example:

```json
{
  "valid": true,
  "trust_floor": "COUNTERPARTY_SIGNED",
  "claimed_trust_floor": "COUNTERPARTY_SIGNED",
  "tampered": false,
  "authority_chain_verified": true,
  "delegation_chain_verified": true,
  "scope_verified": true,
  "receipt_verified": true,
  "revocation_clear": true,
  "checks": [ /* 14 named rules, each pass/fail with a human-readable reason */ ]
}
```

The 14 rules: `STRUCTURE, AGENT_ID_BINDING, CANONICAL_HASH, AGENT_SIGNATURE,
ROOT_TOKEN_SIGNATURE, DELEGATION_CHAIN, AUTHORITY_CHAIN, SCOPE_AUTHORITY,
REVOCATION, TEMPORAL_VALIDITY, ACTION_ATTESTATIONS, TRACE_BINDING,
RECEIPT_BINDING, TRUST_FLOOR`. Full text in `03_LOAN_DEMO.md`.

## 5. Authority graph example (real output)

`GET /v1/authority/{id}` reconstructs and validates the chain. The graph
exports to Graphviz DOT (rendered in `03_LOAN_DEMO.md`):

```
Branch Manager ─Issues→ Root Token ─Delegates→ Sub-Agent delegation ─ActsUnder→
   Agent ─Decides→ Decision ─Performs→ Action ─Produces→ Ledger Receipt
```

## 6. Threat model & security model (summary)

Tenancy is a **storage envelope**; the signed EvidencePacket is unchanged and
independently verifiable. Tenant is taken from the API key, never the request.

| Threat | Mitigation (in code) |
|---|---|
| Evidence forgery / silent edit | Canonical hash + Ed25519 agent signature; `CANONICAL_HASH`/`AGENT_SIGNATURE` fail on any change — even if the attacker recomputes the hash |
| Authority overreach (confused deputy) | Per-hop signed delegation + lattice scope attenuation; `SCOPE_AUTHORITY` rejects actions outside the most-attenuated scope |
| Cross-tenant access | `vault.get(tenant,id)` returns `None` on mismatch (no existence leak); authority graph is per-tenant |
| Evidence deletion | Append-only vault; no delete path |
| Authority-graph poisoning | Graph is a *derived* index over signed packets; queries re-verify; full trust needs keys |
| Replay | Generation requires a valid key; verification is idempotent; revoked JTIs checked |
| Insider abuse | Roles (only admin revokes); admin actions logged with key id; secrets stored only as SHA-256 hashes |

**Security model:** Ed25519 (RFC 8032) + SHA-256; bearer API keys
(hashes-at-rest) bound to tenant + role; fail-closed (no keys → 401); offline
verification (no call-home in the trust path). Full detail:
`/aip-service/MIGRATION_NOTES.md`, `/AIP_SPEC.md`.

## 7. Pilot deployment guide

Minimal, single-node pilot (no new infrastructure beyond a host + TLS proxy):

1. **Build:** `cargo build --release` in `aip-service`.
2. **Keys:** create `keys.json` — for each integrating system/operator a
   `{key_id, tenant_id, role, secret_sha256}`. Mint a secret out of band;
   store `printf %s "$SECRET" | sha256sum`. **No plaintext secret is stored.**
3. **Run** behind the deployment's **TLS-terminating ingress/proxy** (the
   service speaks HTTP behind it):
   ```bash
   AIP_API_KEYS_PATH=/etc/aip/keys.json \
   AIP_VAULT_PATH=/var/lib/aip/evidence.jsonl \
   AIP_KEY_PATH=/var/lib/aip/signing.key \
   ./airon-aip
   ```
4. **Integrate:** the agent/workflow calls `POST /v1/evidence/generate` with
   its decision + pre-signed authority tokens; the auditor calls
   `POST /v1/evidence/verify` and `GET /v1/authority/{id}`.
5. **Verify offline:** auditors can verify any exported packet with the
   library/verifier and the trusted public keys — no connection to AIP needed.

**Pilot prerequisites the deploying org provides:** TLS proxy, host + backup
of the vault file, the trusted public keys of principals/intermediaries.
**Known pilot limits** (see `04_PILOT_READINESS.md`): single-node file
storage, static keys (rotate by file edit + restart), no built-in rate limit.
