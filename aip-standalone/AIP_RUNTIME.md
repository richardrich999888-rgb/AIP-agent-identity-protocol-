# AIP Runtime — Agent Identity Protocol

## Overview

AIP provides end-to-end verifiable agent identity: Ed25519 key generation, provenance-bound AIP-IDs, lifecycle state machine, liveness challenge-response, nonce-based replay protection, and BFT reputation aggregation.

## Quick Start

```bash
cd aip/
cargo build --workspace

# Create an identity
./target/debug/aip-cli create-identity --model "my-model" --env "production"

# List stored identities
./target/debug/aip-cli list

# Sign a payload
./target/debug/aip-cli sign --payload "Hello, AIP!"

# Issue a liveness challenge
./target/debug/aip-cli challenge --target-id <AIP-ID>

# Run 5-agent simulation
./target/debug/aip-cli simulate --agents 5
```

## Identity Lifecycle

```
create_identity() → Pending
       │
activate_identity() → Active ←── reactivate_identity()
       │                              ↑
suspend_identity() → Suspended ───────┘
       │
revoke_identity() → Revoked (TERMINAL)
```

- **Pending**: Created but not yet activated. Self-signature is valid.
- **Active**: Fully operational. Can sign, be challenged, participate in reputation.
- **Suspended**: Temporarily disabled. Can be reactivated.
- **Revoked**: Permanently disabled. Cannot be reactivated.

## AIP-ID Format

```
aip1<fingerprint_b58><checksum_b58>
```

- `fingerprint` = SHA-256(public_key || provenance_triple)[0:26], Base58-encoded
- `checksum` = SHA-256(SHA-256("aip1" || fingerprint_b58))[0:4], Base58-encoded
- Same key with different provenance → different AIP-ID (model/environment binding)

## Signing & Verification

Every signature includes:
- **Algorithm**: Ed25519
- **Signer ID**: AIP-ID
- **Timestamp**: Unix ms (validated within 5-minute window)
- **Nonce**: 16 random bytes (prevents replay)
- **Payload hash**: SHA-256 of signed data
- **Signature bytes**: Ed25519 over SHA-256(algorithm || signer_id || timestamp || nonce || payload_hash)

## Liveness Protocol

```
Verifier                 Agent
   │                       │
   ├─ LivenessChallenge ──►│  (random 32-byte nonce, 30s deadline)
   │                       │
   │◄─ LivenessResponse ──┤  (signed nonce + proof)
   │                       │
   ├─ verify_liveness() ──►│  (check sig, deadline, proof)
```

Prevents: replay (nonce uniqueness), stale responses (deadline), impersonation (Ed25519 sig).

## Replay Protection

`NonceTracker` validates every signature:
1. **Freshness**: Timestamp within configurable window (default 5 min)
2. **Uniqueness**: (signer_id, nonce) pair never reused
3. **Eviction**: Old nonces automatically purged

## Runtime Binding

`bind_identity_to_runtime()` computes SHA-256 of: agent_id + hostname + PID + executable path hash + timestamp + optional container ID.

## Storage

`IdentityStore` provides HashMap-backed storage with JSON file persistence:

```rust
let mut store = IdentityStore::with_file("store.json")?;
store.put_identity(aid, keypair);
store.save()?;
```

## Tests

```bash
# Run all 82 tests
cargo test --workspace

# Run only simulation tests
cargo test --package aip-core simulation

# Run integration tests
cargo test --package aip-test
```

## Architecture

```
aip/
├── crates/
│   ├── aip-types/     # Pure data types (475 lines)
│   ├── aip-crypto/    # Ed25519, SHA-256, Merkle, AIP-ID (270 lines)
│   ├── aip-core/      # Domain logic + new modules
│   │   ├── lib.rs     # Identity, lifecycle, capabilities, reputation, liveness
│   │   ├── nonce.rs   # NonceTracker (anti-replay)
│   │   ├── runtime.rs # Runtime binding
│   │   ├── store.rs   # File-backed identity store
│   │   └── simulation.rs # Multi-node verification
│   ├── aip-test/      # Integration tests (13 tests)
│   └── aip-cli/       # CLI binary
```
