---
name: aip-service-hardening
description: Security review rules for the aip-service HTTP layer (axum) — endpoints, API-key auth, roles, tenant isolation, JWT issuance, signing-key handling, the EvidenceStore backends (JSONL and PostgreSQL), and deployment. Use whenever adding or changing a route, an extractor, a store method, a SQL statement, key loading, the delegation or revocation endpoints, or anything under aip-service/src or deploy/.
---

# aip-service hardening

`aip-service` is a thin, correct layer over `aip-protocol` for **evidence**, and a
parallel, materially weaker implementation for **identity and delegation**. Know
which half you are touching.

## The rule that matters most: do not extend the second authority engine

The evidence path correctly shares the audited core:

| Concern | Function actually used | Shared with `aip-standalone`? |
|---|---|---|
| Identity derivation | `aip_crypto::derive_aip_id` (`src/evidence.rs:228`) | **yes** |
| Evidence verification | `aip_protocol::verify_packet` (`src/evidence.rs:329,421`) | **yes** |
| Bundle build/verify | `aip_protocol::build_zip` / `verify_zip` | **yes** |

The identity path does not:

| Concern | Service implementation | Problem |
|---|---|---|
| Delegation tokens | `src/delegation.rs:22-40` | **no signature field at all** |
| Log integrity | `src/delegation.rs:58-62` | unkeyed SHA3-256 over a `format!` string that **omits `scope` and `expires_at`** |
| Attenuation | `src/handlers.rs:219-225` | `req.scope` written verbatim; `CapabilityScope::is_subset_of` has no caller outside its own test |
| Expiry | `src/handlers.rs:284-335` | `verify_chain` never reads `expires_at` |
| Depth | `src/delegation.rs:18` | `MAX_DEPTH` off-by-one vs `aip-core` (`>` vs `>=`) |
| Revocation | `src/revocation.rs:57` | UUID strings; disjoint from the `[u8;16]` JTI namespace used by `verify_packet` |

**Consequences already present:** any `machine`-role key can mint an
admin-scoped delegation from a submitter-scoped parent; anyone who can write
`AIP_DELEGATION_LOG_PATH` can escalate a token's scope without disturbing
`entry_hash`; expired service delegations verify forever.

**Rules:**

- Do not add features to `src/delegation.rs` or `src/capability.rs`. The correct
  direction is deletion — route through `aip_core::delegation::verify_delegation_chain`
  and `aip_core::capability`.
- Never let `/v1/identity/verify-chain`'s `effective_scope` be used for an access
  control decision. It is backed by an unsigned, mutable JSONL file and the
  endpoint is unauthenticated.
- If you must touch it: enforce `is_subset_of(req.scope, parent_scope)` at
  issuance, check `expires_at`, and sign the entry.

## Endpoint checklist

Router: `src/lib.rs:63-89`. **8 of 15 routes are unauthenticated** — `/health`,
`/v1/identity/verify`, `/v1/identity/public-key`, `/v1/identity/verify-chain`,
`/v1/identity/revocation-status/:jti`, and both `/.well-known/*`.

For every new or modified route, state explicitly:

1. **Auth** — does the handler take `Principal` (any role) or `AdminPrincipal`?
   Adding a route with neither makes it public. `AdminPrincipal`
   (`src/auth.rs:201-220`) is the only authorization guard in the codebase and
   is used on exactly one route.
2. **Tenant** — the tenant comes from the key, never the request body
   (`src/auth.rs:154`). Any store call must pass `principal.tenant_id`.
3. **Existence leak** — a wrong-tenant read returns **404, identical to
   not-found** (`src/evidence.rs:391-394`). Preserve that. Do not return a
   distinguishable 403.
4. **Cost** — unauthenticated routes are unthrottled and there is no rate
   limiting anywhere. Do not add an unauthenticated route that performs
   signature verification or unbounded work.

## Tenant isolation

Enforced at the storage layer, not by middleware:

```rust
// src/store.rs:204-211  (JSONL)
inner.by_id.get(id).filter(|r| r.tenant_id == tenant_id)

// src/store/pg.rs:196-204  (PostgreSQL)
"SELECT evidence_json FROM evidence_packets WHERE id=$1 AND tenant_id=$2"
```

- **Every** new `EvidenceStore` query must filter on `tenant_id`. There is **no
  Row-Level Security** in `deploy/sql/schema.sql` — `tenant_id` is a plain
  `TEXT NOT NULL` column and isolation is application-only. One forgotten
  `WHERE` clause is a full cross-tenant disclosure with no defence in depth.
- The identity layer has **no tenant dimension at all** — `DelegationToken` and
  `RevocationEntry` have no `tenant_id` field. Do not add identity features that
  assume tenancy exists there.
- `StoreError::TenantConflict`'s message confirms a packet id exists in another
  tenant and is returned to the client — a real existence oracle that
  contradicts the 404 posture. Do not add more of these.

## Error handling

Good pattern to copy — `src/handlers.rs:89-94` logs the real error and returns a
generic message. Bad pattern to stop repeating: `src/evidence.rs:346-353`,
`:383-390`, `:409-417`, `:466-472` all return `e.to_string()` on a `StoreError`,
which wraps raw `tokio_postgres` / `std::io` text and can leak table names,
column names and filesystem paths (`format!("open vault: {e}")`, `src/store.rs:197`).

**Rule:** log the detail, return a generic message and a stable error code.

## Keys and JWT

- `src/keys.rs:144-151` — a corrupt or unreadable key file causes a **silent
  regeneration** of the service identity, invalidating every issued JWT *and*
  every previously exported bundle manifest (the same seed signs both,
  `src/main.rs:118`). If persistence then fails it continues with an ephemeral
  key (`:161-165`). **Change this to a hard failure before adding any key feature.**
- `src/keys.rs:179-192` — `chmod 0600` is applied *after* `fs::write`, leaving a
  TOCTOU window at the umask default. Use `OpenOptions::new().mode(0o600).create_new(true)`.
  Loading performs no permission check.
- No rotation exists; `/.well-known/jwks.json` publishes exactly one key with no
  `kid` set. Any rotation design needs an overlap window before it can ship.
- JWT validation is correct and should stay that way: `Algorithm::EdDSA` pinned,
  `leeway = 0` (`src/tokens.rs:98-100`). Do not relax leeway or enable
  additional algorithms.
- **Revocation is not consulted inside `tokens::verify`** — it is an opt-in call
  at 4 separate sites (`src/handlers.rs:125-128,192,260,309`). Any new caller of
  `tokens::verify` must check `revocation::is_revoked` explicitly, or the check
  should be moved inside `verify`.
- The revocation set is an in-memory `HashSet` (`src/revocation.rs:57`), so a
  revoke on one replica is invisible to another. Do not document the service as
  horizontally scalable until this is externalised.

## Storage

- **JSONL (`src/store.rs:174-202`) has no `fsync` and no cross-process locking.**
  An acknowledged write can vanish on power loss; two processes sharing
  `AIP_VAULT_PATH` can append duplicate ids, and reload is last-write-wins
  (`:142`), which can silently re-tenant a packet and bypass `TenantConflict`.
  Prefer the PostgreSQL backend for anything durable.
- `integrity_status` (`src/store.rs:57-65`) is called only on the Postgres path
  (`src/store/pg.rs:147`) and only at write time. The JSONL path never validates
  on write or read.
- The `tenant_id` envelope is **not** covered by the packet signature — anyone
  with file write access can move a packet between tenants and every
  cryptographic check still passes.
- SQL is currently **fully parameterised with no `format!`-built statements**
  (`src/store/pg.rs`). Keep it that way — never interpolate into SQL.
- `deploy/sql/schema.sql` duplicates `src/store/pg.rs:18-49` by hand with no
  migration tooling and no version table. `CREATE TABLE IF NOT EXISTS` will not
  apply an added column to an existing database. Changing the schema requires a
  migration plan, not just an edit.
- Postgres connects with `NoTls` (`src/store/pg.rs:13,65`).

## Deployment

Absent and worth stating in any production discussion: TLS in-process, rate
limiting, request timeouts, graceful shutdown, `/metrics`, body-size policy
beyond axum's implicit 2 MiB default. `src/lib.rs:63-89` has no `.layer(` call
at all. The Docker image does run as non-root uid 10001 (`deploy/docker/Dockerfile`).

## Test expectations

The strongest existing test is `src/evidence.rs:501` — a real HTTP `oneshot`
proving cross-tenant export returns 404. Match that standard.

Currently **missing**, so add them if you are nearby:

- HTTP-level 401 for missing/malformed `Authorization` (only the store-level
  `src/auth.rs:243` exists).
- HTTP-level 403 for a `machine` key hitting `/v1/identity/revoke` — the single
  authorization guard has zero coverage.
- A revoked JTI rejected through `/v1/identity/verify`.
- Attenuation, expiry and depth enforcement on `/v1/identity/delegate`.
- Tampered delegation/revocation log line rejected on load.

Run before finishing:

```bash
cd aip-service
cargo fmt --all --check
cargo clippy --all-targets --features postgres -- -D warnings
cargo test                                   # 38 passed
cargo test --features postgres               # 41 passed, 1 ignored
```

Note: the Postgres tests **silently no-op** without `AIP_TEST_DATABASE_URL`
(`src/store/pg.rs:251-253`) — they report `ok` while exercising nothing. To
actually test the backend:

```bash
AIP_TEST_DATABASE_URL=postgresql://aip:aip@127.0.0.1:5432/aip cargo test --features postgres
```
