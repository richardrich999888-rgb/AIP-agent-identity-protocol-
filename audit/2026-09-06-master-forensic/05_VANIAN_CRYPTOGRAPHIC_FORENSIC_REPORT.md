# Cryptographic Forensic Report

## 1. Primitive inventory

**CODE-PROVEN.** No primitive is implemented in-tree; every one is a call
into a vetted crate.

| Purpose | Primitive | Crate | Where |
|---|---|---|---|
| Signatures | Ed25519 | `ed25519-dalek 2.1` | `aip-crypto` |
| Hashing | SHA-256 | `sha2 0.10` | `aip-crypto`, all payloads |
| Hashing (service) | SHA3-256 | `sha3` | `aip-service` |
| Identifier encoding | Base58 | `bs58` | AIP-ID derivation |
| KEM (valladder/aipv4 only) | Kyber-768 | `pqcrypto-kyber 0.8.1` | `aegis-quantum-userspace` |
| ECDH (valladder/aipv4 only) | X25519 | `x25519-dalek 2.0.1` | `aegis-quantum-userspace` |

No hand-rolled arithmetic, no custom curve code, no bespoke hash. This is
the right call and it removes an entire class of risk.

## 2. Canonical encoding

The single most consequential cryptographic change across the six branches.

### 2.1 The defect on main (and four other branches)

`main/aip-standalone/aip-core/src/capability.rs:208-231` builds the signing
payload by raw concatenation:

```rust
buf.extend_from_slice(jti);
buf.extend_from_slice(issuer_id.as_bytes());
buf.extend_from_slice(agent_id.as_bytes());
…
buf.push(0xFF);                       // "separator"
…
buf.extend_from_slice(&issued_at.to_le_bytes());
```

Three distinct failures:

1. **Not injective.** `issuer_id = "ab", agent_id = "c"` and
   `issuer_id = "a", agent_id = "bc"` produce identical bytes. A signature
   over one is a valid signature over the other.
2. **Not domain-separated.** Nothing distinguishes a `ScopedToken` preimage
   from a `DelegationToken` preimage. A signature made in one context can be
   presented in another.
3. **`expires_at` is not covered at all.** The field the verifier
   subsequently enforces is absent from the bytes the issuer signed.

The custom-action encoder compounds (1): `ScopeAction::Custom(s)` is encoded
as `0x01 ‖ s ‖ 0x00`, so a custom action containing an interior NUL is
ambiguous with two adjacent actions, and the `0xFF` allowed/denied separator
is a byte a custom action can also contain.

### 2.2 The fix on prod

`prod/aip-standalone/aip-core/src/capability.rs:221-238`:

```rust
put_domain(&mut buf, SCOPED_TOKEN_DOMAIN);   // "AIP/ScopedToken/v1"
buf.extend_from_slice(jti);                  // fixed 16 bytes
put_str(&mut buf, issuer_id);                // u32-LE length prefix
put_str(&mut buf, agent_id);
encode_scope(&mut buf, scope);
put_u64(&mut buf, issued_at);
put_opt_u64(&mut buf, &expires_at);          // explicit presence byte
```

All three failures are closed. `put_opt_u64` gives `None` and `Some(0)`
distinct preimages, which is the difference between "unbounded authority"
and "already expired" — the two most consequential values the field can
take.

### 2.3 Codec location

**CODE-PROVEN.** `aip-types/src/canonical.rs` (195 lines) exists **only on
prod**. On main the prefix-free codec lives in `aip-protocol/src/
canonical.rs`, where `aip-core` — the crate that mints tokens — cannot reach
it. Promoting the codec to `aip-types` is what made the fix possible, and it
is the correct dependency direction: the encoding is a property of the type
system, not of the protocol layer.

`valladder` and `aipv4` have no `aip-types/src/canonical.rs` and carry the
main-era encoder verbatim.

## 3. Signature coverage audit

| Object | Field | Signed on main | Signed on prod |
|---|---|:--:|:--:|
| `ScopedToken` | `jti`, `issuer_id`, `agent_id`, `scope`, `issued_at` | ✓ | ✓ |
| `ScopedToken` | **`expires_at`** | **✗** | **✓** |
| `DelegationToken` | `jti`, `parent_jti`, `issuer_id`, `grantee_id`, `scope`, `depth`, `issued_at` | ✓ | ✓ |
| `DelegationToken` | **`expires_at`** | **✗** | **✓** |
| `AttestedBatch` | version, observer_id, key_version, sequence, prev_head, batch bytes | n/a | ✓ |
| `Warrant` | full preimage under `SYNTRIASS/GHOST/WARRANT/v1` | n/a | ✓ |
| Bundle manifest | manifest bytes | ✓ | ✓ |
| Bundle manifest | **the signer's identity** | **✗** | **✗** |

The last row is finding I-9. `verify_bundle_signature`
(`bundle.rs:437`, identical on both branches) decodes the public key from
`manifest.signer_public_key` — a field inside the manifest being verified —
and checks the signature against it. The check is therefore
self-referential: it establishes that whoever produced the bundle held the
private half of a key they also chose to name, which is no constraint at
all. Nothing binds that key to a trusted issuer.

## 4. Key management

**CODE-PROVEN, unchanged on every branch.**

- `aip-core/src/store.rs:138` — `IdentityStore::save` serializes the store
  (which contains private keys) with `serde_json::to_string_pretty` and
  writes it via `std::fs::write`. There is no `set_permissions`, no umask
  handling, and no attempt at atomic replace. The file lands with the
  process umask, typically `0644`.
- `aip-service/src/keys.rs:130` — `load_or_generate` mints a fresh keypair
  when the configured key file is absent **or when it exists and fails to
  load**. The second case is the serious one: `:144-151` catches the load
  error, emits `tracing::warn!("Failed to load key file — generating new
  keypair")`, and falls through to `Self::generate()` at `:154`. A transient
  read error, a permissions change, or a partially-written file therefore
  produces a running service under a **new identity** rather than a startup
  failure — and every previously issued token signed by the old key becomes
  unverifiable while the service reports itself healthy. This is fail-open at
  the identity layer.
- `aip-service/src/evidence.rs:125,130` — private seeds are accepted as hex
  strings in HTTP request bodies, and so pass through any request logging,
  proxy, or trace collector in the path.

**Positive.** `aip-observe::attest` (`prod`) is the counter-example and
shows the authors know how to do this: the signing key is held by
`CollectorSigner` off-host, `probe` has no key field and no signing method,
`ObservationBatch` has no signature field, and the module doc states the
resulting property and its limits explicitly. `key_version` is carried in
the signed preimage so verifiers anchor `(observer_id, key_version)` pairs —
rotation is designed in rather than retrofitted.

## 5. Randomness

**CODE-PROVEN.** `random_jti` (`aip-core/src/capability.rs:205-213`) draws
from the OS CSPRNG. `test_nonce_uniqueness_csprng` and
`test_sha256_uniqueness_10k_inputs` pass. No `rand::thread_rng` seeding from
time, no LCG, no reuse of a nonce across signatures was found on any branch.

One nondeterminism defect, in test code only:
`aegis-quantum-userspace` `test_kyber768_performance_under_5ms` asserts a
wall-clock bound inside a unit test (P3). The main workspace handles this
correctly by contrast — `test_signing_throughput` and
`test_verification_throughput` are `#[ignore]`d with the message
"wall-clock throughput gate — meaningful only under `cargo test --release`".

## 6. Post-quantum posture

**valladder / aipv4 only.** See Report 03, I-20 for the full finding. In
cryptographic terms:

- The **combiner is correct**: `hybrid_session_hash` domain-separates under
  `AIRON-AEGIS-HYBRID-v1` and length-prefixes both the X25519 and Kyber
  secrets before hashing. Hybrid construction of this shape is the right
  pattern.
- The **protocol does not exist**: both peers are simulated in-process,
  so the combiner is never exercised across a trust boundary.
- The **label is wrong**: output is reported as `"Kyber-768 (ML-KEM)"`.
  `pqcrypto-kyber` implements round-3 Kyber; FIPS 203 ML-KEM differs from it.
  Conflating the two in a field named `algorithm` will mislead any downstream
  compliance claim.
- The **dependency is unpinned**: `pqcrypto-kyber = "0.8"` is a caret range
  on a cryptographic primitive.

**No branch of AIP proper (main, prod) contains any post-quantum code.** Any
statement that the protocol is quantum-resistant is unsupported by main or
prod, and supported on valladder/aipv4 only by a loopback benchmark.

## 7. Cryptographic verdict by branch

| Branch | Verdict |
|---|---|
| **prod** | The only branch whose token and delegation signing payloads are sound. Domain-separated, prefix-free, expiry-covering, with adversarial tests that genuinely exercise the properties. Remaining defects (I-3, I-7, I-9) are in *verification logic*, not in encoding. |
| **main** | Signing payloads are non-injective, non-domain-separated, and omit the expiry the verifier enforces. |
| **audit / importot** | Identical to main. |
| **valladder / aipv4** | Identical to main, plus a post-quantum component that measures latency rather than establishing a shared secret with anyone. |
