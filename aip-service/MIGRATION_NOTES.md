# aip-service — Migration Notes (v0.2 → accountability layer)

This change makes the deployable service a **thin layer over the strategic
core** (`aip-core` + `aip-protocol`), closing the #1 architectural defect:
the service previously shared no code with the crates that hold the value.

## TASK 1 — Dependency audit

**Before**
```
aip-service  → (nothing internal; parallel JWT impl: jsonwebtoken, own
                delegation.rs / revocation.rs / capability.rs)
aip-core     → aip-crypto, aip-types        (unused by the service)
aip-protocol → aip-core, aip-crypto, aip-types (unused by the service)
```

**After (this change)**
```
aip-service  → aip-core, aip-protocol, aip-crypto, aip-types   (path deps)
aip-core     → aip-crypto, aip-types
aip-protocol → aip-core, aip-crypto, aip-types
```

Added in `aip-service/Cargo.toml`:
```toml
aip-types    = { path = "../aip-standalone/aip-types" }
aip-crypto   = { path = "../aip-standalone/aip-crypto" }
aip-core     = { path = "../aip-standalone/aip-core" }
aip-protocol = { path = "../aip-standalone/aip-protocol" }
```

### Modules still requiring migration (tracked, NOT done in this increment)
The legacy JWT endpoints (`/v1/identity/*`) and their parallel implementations
remain in place to avoid breaking existing callers. They should be migrated
onto the core in follow-up increments:

| Legacy module | Migrate onto | Status |
|---|---|---|
| `capability.rs` (service-local scope) | `aip-core::capability` | TODO (P1) |
| `delegation.rs` (service-local chain) | `aip-core::delegation` | TODO (P1) |
| `revocation.rs` (service-local) | `aip-core::revocation` | TODO (P1) |
| `tokens.rs` (jsonwebtoken JWT) | issue scoped tokens via `aip-core` | TODO (P2) |

This increment is **additive**: nothing was removed, so the migration carries
zero breakage risk. Consolidation is a separate, sequenced step.

## TASK 3 — Evidence Service v1 APIs (implemented)

New routes (added in `main.rs`, handlers in `evidence.rs`):

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/evidence/generate` | Build + sign + store + index an EvidencePacket |
| POST | `/v1/evidence/verify` | Verify a packet against caller-supplied trust keys |
| GET | `/v1/evidence/{id}` | Fetch a stored packet by hex packet id |
| GET | `/v1/authority/{id}` | Authority-graph query (action / principal / agent) |

Request/response **Rust structs** live in `evidence.rs`
(`GenerateRequest`, `GenerateResponse`, `VerifyRequest`, `AuthorityResponse`)
and reuse `aip-protocol`'s `EvidencePacket` and `VerificationReport` verbatim
as wire types (both already `Serialize`/`Deserialize`).

**Storage requirement:** one writable file, `AIP_VAULT_PATH`
(default `/var/lib/aip/evidence.jsonl`).

### Key-custody migration note (important)
`/v1/evidence/generate` accepts the **agent seed** in the request and signs
server-side. This is correct for the **single-tenant / managed reference
deployment** and SDK-backed testing. The authority tokens
(`root_token`, `delegation_chain`) are supplied **pre-signed**, so the schema
is already forward-compatible with the production model where:
- agents sign packets **client-side** via an SDK, and
- the service is used for **verify + ingest** only (no agent keys on the wire).

Do **not** expose `/generate` with request-supplied seeds on a multi-tenant
or untrusted network. Follow-up (P1): an `/v1/evidence/ingest` endpoint that
accepts an already-sealed packet (no key) for the production path.

## TASK 4 — Authority Graph (implemented as a derived index)

`authority.rs` builds a **derived, rebuildable** index over the vault
(`AuthorityGraph::build(&vault)`); it is not a system of record. It reuses
existing primitives only (`EvidencePacket`, `AccountabilityGraph`, the
packet's own integrity self-check).

Answers the required questions:
1. *Who authorized this action?* → `who_authorized(action_id)` → `AuthorityPath`
2. *Which human delegated?* → `AuthorityPath.principal_id` / `principal_role`
3. *Which agent executed?* → `AuthorityPath.agent_id`
4. *What scope existed?* → `AuthorityPath.effective_scope_allowed` (leaf scope)
5. *What evidence proves it?* → `packet_id` + `integrity_ok` self-check; full
   trust via `/v1/evidence/verify` with keys.

**Migration note:** the index is in-memory, rebuilt from the vault on each
`/v1/authority` query (fine for v1 volumes). When packet counts grow, swap to
an incrementally maintained index or embedded KV behind the same methods —
the query API does not change.

## TASK 5 — Evidence Vault v1 (implemented)

`vault.rs`: append-only JSONL at `AIP_VAULT_PATH`, in-memory
`packet_id → EvidencePacket` index loaded at startup, idempotent `store`,
`get`, `all`. No blockchain, no distributed systems — a single file, exactly
as the brief required. Rebuildable; the authority graph derives from it.

**Retrieval / verification / audit export:**
- retrieval: `GET /v1/evidence/{id}` and `Vault::all()`.
- verification: re-run `/v1/evidence/verify` on any retrieved packet.
- audit export: packets are stored as canonical JSON and re-verify
  identically; a signed export-bundle endpoint is the next increment (P1).

## Compatibility & rollout

- **Backward compatible:** all existing `/v1/identity/*` and `/.well-known/*`
  endpoints are unchanged.
- **New env var:** `AIP_VAULT_PATH` (optional; sensible default).
- **No DB, no new infra** to deploy — one extra file path.
- **Tests:** `cargo test` in `aip-service` → 31 pass (vault store/reload,
  authority resolution + tamper self-check, generate→verify roundtrip,
  tamper detection). Workspace crates unchanged except an additive
  `EvidencePacket::to_json_compact` in `aip-protocol`.

## Verification performed

```
cargo build           # clean
cargo test            # 31 passed, 0 failed
./target/debug/airon-aip   # boots; /health ok; vault wired (evidence_packets=0);
                           # GET /v1/evidence/{unknown} → 404; /v1/authority/{unknown} → 200 empty
```

## P1(c) — Authentication & tenant isolation (pilot gate)

Closes the "all endpoints effectively public" risk. **API keys** (bearer,
stored only as SHA-256 hashes), each bound to a `tenant_id` and a `Role`
(`machine` | `admin`). Tenant is taken from the key, never the request body.
Fail closed: no keys configured ⇒ authenticated routes return 401.

- New module `auth.rs`: `ApiKeyStore` (loads `AIP_API_KEYS_PATH`),
  `Principal`/`AdminPrincipal` axum extractors.
- `vault.rs`: records wrapped in `VaultRecord { tenant_id, stored_at, packet }`;
  `store(tenant,..)`, `get(tenant,..)` (cross-tenant ⇒ `None`), `all_for_tenant`.
  Backward compatible: pre-tenancy bare-packet lines load as tenant `legacy`.
- `authority.rs`: `build_for_tenant`; `who_authorized(vault, tenant, action)`.
- Evidence/authority handlers take `Principal` and scope to its tenant;
  `verify` requires auth but is stateless. Legacy `issue`/`delegate` now
  authenticated; `revoke` requires `AdminPrincipal` (and logs the admin key).

**Route classification**

| Route | Class | Checks |
|---|---|---|
| `GET /health`, `/.well-known/*`, `/v1/identity/public-key` | Public | none |
| `POST /v1/evidence/generate` | Machine | auth; store under key's tenant |
| `POST /v1/evidence/verify` | Machine | auth; stateless (no tenant) |
| `GET /v1/evidence/{id}` | Machine | auth; tenant-checked read |
| `GET /v1/authority/{id}` | Machine | auth; tenant-scoped graph |
| `POST /v1/identity/issue` | Machine | auth; token carries the key's tenant (`tid`) |
| `POST /v1/identity/verify` | Public read | stateless; revocation looked up in the token's own tenant |
| `GET /v1/identity/revocation-status/{jti}` | Machine | auth; answered for the caller's tenant only |
| `POST /v1/identity/revoke` | Admin | auth + `admin` role; recorded under the admin's tenant; `cascade` refused |
| ~~`POST /v1/identity/delegate`~~, ~~`/verify-chain`~~ | removed | unsigned delegation model deleted; use `aip-core` signed chains inside evidence packets |

**New env var:** `AIP_API_KEYS_PATH` → JSON `{ "keys": [{key_id, tenant_id,
role, secret_sha256}] }`. Mint a secret out of band; store
`printf %s "$SECRET" | sha256sum`. No plaintext secret is ever persisted.

**Verified over HTTP:** public 200; no/bad key 401; machine key authenticates;
`revoke` 403 for machine, passes for admin; `issue` 401 anonymous. Cross-tenant
`get`/authority denial unit-tested. `cargo test` → 37 pass.

**Known limitations (post-pilot, documented not hidden):** keys are static
(no rotation endpoint yet — rotate by editing the file + restart); no rate
limiting; TLS terminates at the deployment's ingress/proxy (the service
speaks plain HTTP behind it); legacy JWT delegation/revocation logs remain
global, not tenant-partitioned (the evidence layer is the tenant-scoped
pilot surface).

### Not yet proven at the HTTP layer (honest)
A full `generate → verify → get → authority` roundtrip is proven by unit
tests against real crypto (`evidence::tests`, `vault::tests`,
`authority::tests`). An HTTP-level integration test that mints pre-signed
authority tokens and drives the four endpoints over the socket is a
recommended follow-up (P2) — the handlers are thin adapters over the
unit-tested pure functions, so the residual risk is low but non-zero.
