# AIP Distribution Milestone 3: Permissioned P2P Design

**Status:** assessment and staged design; no networking implementation included.
**Repository:** `validation/snifferdog-complete-enterprise-validation`
**Assessment date:** 2026-11-12

## Executive recommendation

Proceed toward a dedicated `aip-distribution` libp2p network adapter, conditional
on explicit approval of libp2p Noise's `ring` crypto resolver and the Rust 1.88
MSRV. Start implementation with dependency/provider approval, then implement
the AIP peer-binding and authorization layer before allowing application
requests. Begin deployment with statically provisioned peer addresses and
trusted identities. Do not use public bootstrap nodes, public DHT, relays,
UPnP, or automatic NAT traversal.

This assessment is read-only. It creates no networking code and changes no
Cargo manifest or lockfile. Repository APIs below are facts from the current
source. New structures, policies, and limits are recommendations unless marked
otherwise.

## 1. Existing APIs and architecture boundaries

### Transfer and package APIs

- [`TransferManifest`, `TransferChunk`, and `ResumeState`](../../aip-standalone/aip-distribution/src/lib.rs#L91) are the existing strict-serde transfer types. `parse_manifest()` has an 8 KiB ceiling ([`lib.rs`](../../aip-standalone/aip-distribution/src/lib.rs#L110)); `verify_manifest()` authenticates the publisher-signed manifest against a caller-supplied publisher ID/key ([`lib.rs`](../../aip-standalone/aip-distribution/src/lib.rs#L326)); `verify_chunk()` checks chunk length, index, transfer-bound Merkle proof, and root ([`lib.rs`](../../aip-standalone/aip-distribution/src/lib.rs#L371)). Keep the v1 transfer ID, signature preimage, chunk sizing, and Merkle domains unchanged.
- [`DiskTransferReceiver`](../../aip-standalone/aip-distribution/src/disk.rs#L51) exposes `create`, `resume`, `accept`, `completed_chunks`, and `finalize` ([`disk.rs`](../../aip-standalone/aip-distribution/src/disk.rs#L60)). It is Unix-only; the crate's non-Unix public stub fails closed ([`lib.rs`](../../aip-standalone/aip-distribution/src/lib.rs#L22)). Networking should send proof-checked chunks into `accept` in order, or use bounded staging and then submit them sequentially. It must not write directly to the receiver's files or bypass its journal.
- [`PortablePackageExport`](../../aip-standalone/aip-package/src/lib.rs#L519) is the existing signed package export. [`verify_package_contents()`](../../aip-standalone/aip-package/src/lib.rs#L699) checks the detached publisher signature, expected external AIBOM digest, embedded manifest and full ZIP inventory, bounds, and file hashes before returning `VerifiedPackage`. It remains the final package-authenticity check. The AIBOM-aware [`aip-package-cli`](../../aip-package-cli/src/main.rs) can verify an AIBOM manifest and detached seal against its own external anchor; do not move that dependency into `aip-distribution` or `aip-package` (ADR-017).

### Identity, custody, capabilities, and delegation

- [`AgentIdentityDocument`](../../aip-standalone/aip-types/src/lib.rs#L143) contains AIP ID, primary key, status, sequence, optional expiry, lineage, and self-signature. [`IdentityStatus`](../../aip-standalone/aip-types/src/lib.rs#L96) includes Pending, Active, Suspended, and Revoked.
- `aip_core::identity_signing_payload()` is public ([`aip-core/src/lib.rs`](../../aip-standalone/aip-core/src/lib.rs#L190)); it returns the current self-signature payload. `validate_aid()` and variants are public ([`lib.rs`](../../aip-standalone/aip-core/src/lib.rs#L401)). **Limit:** `validate_aid()` verifies AID structure, derived ID, status not Revoked, and self-signature; it does not establish an external trust path, reject Suspended/Pending, enforce `expires_at`, provide a trusted current status feed, or verify a parent unless the parent-specific API is used. The current self-signing encoder's listed fields at lines 194–211 omit `expires_at` and some other document fields, so it must not be repurposed as a digest of the complete serialized AID document.
- [`Custodian`](../../aip-standalone/aip-crypto/src/custody.rs#L152) exposes `public_key()` and `sign(signer_id, payload)` and has no private-key accessor. It is a usable signing boundary for a new binding statement, but no peer-binding signing/verifying API exists today. `InMemoryCustodian` is explicitly development-only; production should use an approved wrapped-file, PKCS#11, or other production custodian.
- `CapabilityScope`, `ScopedToken`, and `DelegationToken` are defined in [`aip-types`](../../aip-standalone/aip-types/src/lib.rs#L277). `scope_permits()` and scope attenuation are in [`capability.rs`](../../aip-standalone/aip-core/src/capability.rs#L79); `verify_scoped_token()` checks token signature and payload binding ([`capability.rs`](../../aip-standalone/aip-core/src/capability.rs#L204)); `is_token_expired()` is a separate check ([line 224](../../aip-standalone/aip-core/src/capability.rs#L224)). `verify_delegation_chain()` verifies root and hop signatures, holder linkage, depth, attenuation, and expiry attenuation ([`delegation.rs`](../../aip-standalone/aip-core/src/delegation.rs#L189)). These are primitives, not a complete network admission policy: callers must provide trusted issuer keys, current time, and current revocation information.
- [`RevocationLog`](../../aip-standalone/aip-core/src/revocation.rs#L40) and `check_token_valid()` / `check_delegation_valid()` ([`revocation.rs`](../../aip-standalone/aip-core/src/revocation.rs#L223)) concern capability/delegation JTIs and cascading token revocation. They are not an AIP identity-status publication protocol. Offline deployments need a signed, versioned status snapshot or an explicitly bounded freshness policy before identity revocation can be enforced.
- [`aip-authorize`](../../aip-standalone/aip-authorize/src/lib.rs) is a DecisionPoint implementation for authorization expectations; it does not currently expose a general inbound package-network authorization/admission API. Do not interpret a successful TCP/Noise handshake or a signed `ExpectedExecution` as a generic package receive/serve grant.
- [`aip-transport`](../../aip-standalone/aip-transport/src/wire.rs#L18) is a blocking TCP protocol for observation batches. Its `Message`, handshake, frame and acknowledgement types ([`wire.rs`](../../aip-standalone/aip-transport/src/wire.rs#L62)) are unrelated to package distribution and must not be reused as the P2P wire contract. Its deliberate Snow configuration is in [`aip-transport/Cargo.toml`](../../aip-standalone/aip-transport/Cargo.toml).

### Workspace and resolved dependency facts

Root [`Cargo.toml`](../../Cargo.toml#L156) sets edition 2021 and has no
`rust-version`. The lockfile currently contains Tokio 1.53.3, `snow` 0.10.0,
`ed25519-dalek` 2.2.0, and `ring` 0.17.14, but **does not contain libp2p**.
Therefore no repository-resolved libp2p dependency tree, feature union, target
build, or provider behavior can be asserted without adding the dependency (not
allowed in this assessment). `ring` is already present for other dependency
paths; its presence does not approve it for the libp2p transport boundary.

Review of the published 0.57.1 package manifests finds notable parallel
dependency lines: `libp2p-identity` 0.3 uses `ed25519-dalek` 3, SHA-2 0.11,
and rand 0.10, while this workspace currently uses `ed25519-dalek` 2.2,
SHA-2 0.10, and rand 0.8. `libp2p-noise` 0.47 also uses x25519-dalek 3 and
rand 0.10. Cargo can resolve these semver-major versions alongside the
workspace versions, but APIs and key wrapper types are distinct. Keep AIP
signing keys and libp2p transport keys separate; explicitly and safely bind
their public representations in the signed statement. Budget for larger
builds, duplicate crypto implementations, and an exact feature-tree review.

## 2. libp2p version, feature set, and crypto decision

At the assessment date, crates.io/docs.rs reports libp2p **0.57.1** as the
latest published stable release; the upstream default branch advertises 0.58.0
but is not the version shown as published on crates.io. Pin `=0.57.1` for a
reproducible first integration, subject to rechecking immediately before
implementation. The 0.57 release sets MSRV to Rust 1.88.0. The workspace has
no declared MSRV or CI decision, so adopting it requires owners to approve and
test Rust 1.88 rather than silently raising the floor.

Recommended restricted feature selection for the initial direct-TCP
implementation:

```toml
libp2p = { version = "=0.57.1", default-features = false, features = [
  "tokio", "tcp", "noise", "yamux", "ed25519", "macros",
  "identify", "request-response", "cbor", "memory-connection-limits",
] }
```

Use direct `tokio` and `futures` dependencies in the new adapter rather than
relying on transitive crates. Add `mdns` only for a separately enabled,
controlled-LAN profile; add `kad` only for a later institution-operated
permissioned overlay. The feature names above are present in 0.57.1. Do not
enable `full`, `autonat`, `dcutr`, `relay`, `upnp`, `quic`, `gossipsub`, or
public-facing discovery in the first implementation. `identify` is protocol
metadata exchange, not identity authorization. CBOR support is a codec, not a
message-size defense; put hard byte ceilings in a bounded codec before
deserialization.

### Noise/Ring concern — approval blocker

The existing transport pins Snow 0.10.0 with `default-features = false` and
explicit RustCrypto/default resolver primitives, intentionally avoiding
Snow's `ring/std` path. The published libp2p 0.57.1 facade uses
`libp2p-noise` 0.47.x. Its Noise implementation depends on Snow and selects
Snow's `ring-resolver` on non-Wasm builds. Snow documents that feature as
enabling the Ring resolver; Cargo feature unification enables features for the
same resolved Snow package across dependents. This does not change the
existing `aip-transport` source configuration, but the new P2P transport would
have a Ring-backed provider in the same application dependency graph. A Cargo
lock/tree after adoption must confirm exact target resolution.

**Do not adopt libp2p Noise until the security owner approves this provider.**
If policy forbids Ring, stop at Milestone A and evaluate a reviewed, supported
libp2p transport/provider design with equivalent authentication and
interoperability. Do not flip Snow features, rely on resolver feature
unification to imply a selected runtime resolver, patch vendor code, or add
unreviewed crypto features as a workaround. An upstream `ring-resolver`
feature is not evidence that the repository's required provider policy is
satisfied. Also assess target-native builds, FIPS obligations, and libp2p
Noise's maturity/API compatibility before approval.

## 3. Peer identity binding

Keep five identities/decisions distinct:

1. **PeerId:** libp2p identifier derived from the libp2p public key encoding.
2. **Transport-authenticated key:** the key proven by Noise for this
   connection; it authenticates the channel peer.
3. **AIP agent identity:** the organization-authorized AIP identity and its
   status/lineage.
4. **Package publisher:** the signer authenticated by the package export and
   external publisher trust anchor.
5. **Installation authority:** the local policy that permits an approved
   package to be installed; neither PeerId nor a valid publisher signature
   grants it.

Recommend a new versioned `PeerBindingStatement`, signed by the AIP identity
that controls the peer key or by an explicitly trusted AIP identity issuer.
Its domain-separated canonical payload should include:

- AIP identity ID and a digest of a complete, canonical AID representation;
- the libp2p public-key protobuf bytes and the derived PeerId bytes;
- signer/issuer AIP ID and algorithm/key identifier;
- `not_before`, `not_after`, monotonically increasing binding sequence, and a
  status/revocation epoch or signed status reference;
- binding schema version and intended network/protocol audience.

The verifier must recompute PeerId from the supplied public key and require
both the signed AIP ID and peer key to match the Noise-authenticated remote
peer. It must validate the AID, establish its trust/lineage path to an
independently provisioned organization/issuer anchor, require `Active`, enforce
expiry and a policy-pinned minimum sequence, verify the statement signature,
and consult sufficiently fresh signed status/revocation state. A binding
issued for one protocol/audience must not be replayable in another.

Current APIs can supply pieces: `validate_aid[_with_parent...]`,
`Custodian::sign`, `aip_crypto::verify_ed25519`, and domain-separated byte
encoders in `aip_types::canonical`. There is **no existing PeerId derivation
binding, PeerBindingStatement, complete canonical AID digest API, trusted
identity registry/status snapshot API, or binding sequence/revocation
contract**. A dedicated implementation/API is needed; do not hash JSON emitted
by an unconstrained serializer as identity evidence or mistake self-signature
for external trust.

Key rotation should issue a higher-sequence binding under an already trusted
active AIP identity or an authorized issuer, with overlap/grace explicitly
controlled by local trust policy. Revoke the old PeerId in signed status data.
Never accept an older binding after a newer sequence has been observed. Offline
verifiers cannot know about later revocation; define maximum trust snapshot age
and fail closed beyond it.

## 4. Fail-closed admission and operation authorization

Recommended order for a new connection and every application operation:

1. Enforce transport connection/pending limits; complete Noise authentication.
   Extract authenticated PeerId/key only from the connection, not request data.
2. Obtain a binding statement and AID via a bounded authenticated exchange or
   provisioned cache. Validate key-to-PeerId equality, binding signature,
   audience, validity interval, sequence, AID self-signature/lineage, external
   identity trust, active status, and fresh signed revocation/status state.
3. Resolve capability issuer keys from independently trusted AIP anchors.
   Verify `ScopedToken`, enforce current time/expiry, check JTI revocation,
   verify any delegation chain and its effective attenuated scope, and reject
   stale/unknown revocation state. Do not rely on `verify_scoped_token()` alone
   for time/revocation policy.
4. Authorize the requested operation and exact package/transfer resource
   against local policy and the existing capability model. Peer admission is
   only eligibility to proceed; it does not grant a package operation.
5. Before serving, require a valid publisher-signed transfer manifest and a
   local publisher/namespace distribution policy. Before receiving, require
   an explicit receive grant and pass externally provisioned publisher and
   AIBOM trust material to the existing offline verifier path.
6. Recheck authorization on each manifest/chunk/status/cancel operation and
   at transfer resume. On disconnect or revocation, stop serving/accepting
   and retain only safely journaled partial chunks.

Existing `CapabilityScope` has standard Read/Write/Delete/Admin/Execute/Delegate
actions and `Custom(String)`; package-specific semantics are not presently
defined. A policy owner must select action/resource naming (for example,
`aip.package.receive` / `aip.package.serve`) and define how the package name,
publisher ID, and release sequence are bound to the scope/constraints. Do not
silently map every package operation to broad `Read` or `Write`. The existing
`CapabilityGrant` and `aip-authorize` flow should be examined before choosing
whether the future adapter uses grants, scoped tokens, or both; a generic
network policy adapter is absent today.

## 5. Dedicated network protocol

Use a dedicated versioned request-response protocol such as
`/aip/distribution/1.0.0`; do not reuse the observation transport's batch
protocol. Bind every request to a connection PeerId, authenticated AIP binding,
capability decision, protocol version, transfer ID, and request nonce/id.
Require request-response correlation IDs and a bounded replay cache per peer;
requests must be idempotent where possible. Chunks are verified by the
existing transfer Merkle verifier before storage; whole export and publisher
signature are verified by existing finalization APIs.

| Message | Essential fields and behavior |
|---|---|
| `ManifestRequest` | random request ID, package selector or transfer ID; authorized discovery only |
| `ManifestResponse` | request ID, exact bounded signed `TransferManifest`; verify against external publisher anchor before accepting |
| `ChunkRequest` | request ID, transfer ID, bounded set/range of indexes, receiver's verified resume bitmap/high-water mark |
| `ChunkResponse` | request ID, transfer ID, index, bytes, Merkle proof; reject mismatch, duplicate, unexpected, or unrequested response |
| `TransferStatus` | transfer ID, verified indexes/high-water mark, sender/receiver state; treat as untrusted hint, not evidence |
| `ResumeNegotiation` | transfer ID and manifest digest; receiver revalidates local journal via `DiskTransferReceiver::resume()`; sender never dictates trusted progress |
| `Cancel` | request ID and transfer ID; idempotent, cannot delete arbitrary paths or another peer's partial data |
| `Reject/Error` | bounded stable code and correlation ID; no secret/path/key details and no trust decision based on message text |

Start with one outstanding chunk request per transfer until bounded
backpressure and resource behavior are demonstrated; later allow a small
window and stage out-of-order replies in a bounded queue before ordered
`accept()`. Never trust peer-reported chunk completion. No network payload may
specify a filesystem path, extraction destination, trust anchor, package key,
or arbitrary transfer metadata outside the signed manifest.

## 6. Discovery and deployment model

**Initial recommendation: static provisioning.** Distribute a signed or
administratively protected peer inventory containing expected PeerId, AIP ID,
binding sequence/status reference, approved address/port, and trust-policy
version. This has the smallest exposed surface and is suitable for
institutional and air-gapped networks. Provision the same trust anchors/status
snapshots independently of the package transfer channel.

- **mDNS:** optional later for controlled LANs only. It is unauthenticated
  discovery and leaks presence/metadata; every discovered address remains
  untrusted until binding and authorization checks complete.
- **Permissioned Kademlia:** only later for multi-subnet fleets, with
  institution-operated bootstrap nodes, authenticated/authorized providers,
  signed records, namespace scoping, bounded record TTLs, and independent
  routing-table limits. DHT membership does not prove publisher trust or
  complete discovery and is vulnerable to eclipse/Sybil behavior if admission
  policy is weak.
- Do not enable public bootstrap, public DHT, relay, hole punching, UPnP, or
  automatic NAT traversal for the initial institutional/air-gapped profile.
  Use manually configured reachable addresses across network segments.

## 7. Resource policy (proposed starting ceilings)

These are initial engineering limits, not measured production capacity; tune
with load tests before deployment.

| Resource | Initial bound |
|---|---:|
| Signed manifest JSON | Existing 8 KiB limit |
| Transfer | Existing 400 MiB limit |
| Chunk | Existing 256 KiB fixed size |
| CBOR control frame | 16 KiB maximum before decode |
| Chunk response frame | 300 KiB maximum including proof and envelope |
| Pending + established connections | 64 total, 8 inbound pending; 4 connections per peer |
| In-flight requests | 4 per peer, 16 globally; begin sequential per transfer |
| Concurrent partial transfers | 4 per peer, 16 globally, plus operator disk quota |
| Request timeout | 10 s control, 30 s chunk; at most 3 retries with capped exponential backoff |
| Rate limits | bounded request and byte token buckets per peer and globally |

Reject excessive lengths before deserializing or allocating. Apply connection
limits, request queues, idle timeouts, CPU budgets for proof verification,
global and per-peer byte quotas, partial-storage quotas, and cancellation on
authorization loss. No retry on invalid signatures, malformed data, denied
capability, or invalid proof. The disk receiver's existing per-transfer bounds
do not replace network-wide concurrency and disk quota policy.

## 8. Threat model and residuals

| Threat | Mitigation | Residual limitation |
|---|---|---|
| Peer impersonation / MITM | Noise-authenticated PeerId; verify signed PeerBindingStatement and exact key-to-PeerId derivation | Compromise of binding issuer or peer key permits identity misuse until revocation is distributed |
| Stolen peer key | Short binding lifetime, monotonic sequence, signed revocation snapshots, explicit peer revocation | Offline peers may have stale status; enforce max snapshot age and fail closed |
| Invalid/suspended/revoked AIP identity | Validate AID and require Active plus external trust, lineage, expiry, and current status | `validate_aid` alone does not provide current status or external trust |
| Unauthorized request/serve | Per-operation capability and resource policy checks; separate receive and serve grants | Current repo lacks a complete network admission adapter and package-specific semantics |
| Compromised/unauthorized publisher | External publisher trust anchor and unchanged `aip-package` verifier; distinct publisher authorization policy | Authorized publisher may still sign malicious content; signature is not a safety guarantee |
| Malicious/tampered chunks | Existing transfer-bound Merkle proof checked before persistence and complete export digest/signature at finalization | A malicious peer can waste bounded bandwidth/CPU and cause denial of service |
| Replay | Request IDs/nonces, connection-bound peer, bounded replay cache, idempotency, transfer ID + manifest digest, capability expiry/revocation | Replay cache state loss across restart needs epoch/nonce policy; signed package exports themselves may be intentionally reusable |
| Malformed CBOR / parser bomb | Pre-decode message limits, strict schema/version, bounded vectors/proofs, reject unknown fields | Codec implementation and serde behavior still require fuzzing and adversarial tests |
| Resource exhaustion | Connection/request/transfer/byte quotas, timeouts, backpressure, bounded retry and disk quotas | Distributed attackers can consume aggregate allowed quota; operational monitoring/rate coordination needed |
| Eclipse / Sybil | Static approved peers first; authenticated AIP bindings; independent admission anchors; later permissioned bootstrap | Multi-operator collusion and compromised provisioning can isolate a node |
| Stale offline anchors | Signed, versioned trust/status snapshots with validity and maximum age; explicit fail-closed stale behavior | An air-gapped verifier cannot learn newly issued revocations until update delivery |
| Concurrent transfer race | Existing per-directory writer lock; network transfer ownership and per-peer transfer quota; revalidate on resume | Cross-host concurrent writes to unsupported/shared filesystems are outside local flock guarantees |
| Network interruption | Persistent `DiskTransferReceiver` journal; verify all stored chunks on resume; bind resume to same signed manifest/root | Resume progress is local state, not a remote peer attestation; transfer may restart if manifest changes |
| Auto-execution / false safety claims | Return only verified package data; explicit separate installer/policy stage; never execute downloaded payload | Correct verification does not establish business safety or authorize installation/execution |

## 9. Staged implementation and acceptance criteria

Do not combine these milestones.

### A. Dependency and cryptographic-provider approval

Approve or reject Rust 1.88, libp2p `=0.57.1`, restricted feature list, Ring
provider implications, platform targets, and exact resolved `cargo tree -e
features` output. Demonstrate existing `aip-transport` tests and config remain
unchanged. If Ring is not approved, stop and resolve with upstream-supported
provider architecture before adding networking dependencies.

### B. Peer identity and signed binding

Specify canonical statement bytes/domain and full AID digest; define issuer
trust anchors, sequence, expiry, revocation/status freshness, rotation and
audience rules. Add deterministic vectors and tests for key/PeerId mismatch,
wrong signer, altered AID digest, stale sequence, expiry, revoked/suspended
identity, and malformed encoding. No socket admission yet.

### C. Admission and capability authorization

Build a policy adapter over existing token, delegation, scope, revocation, and
identity APIs. Define package-specific action/resource semantics first. Test
unauthorized issuer, wrong holder, attenuated/overbroad delegation, expiry,
revoked JTIs, stale identity status, receive-vs-serve distinctions, and
authorization recheck on resume. Fail closed when trusted keys/status are
missing.

### D. One-peer loopback transport

Implement a local-only TCP/Noise/Yamux Swarm with bounded connection limits.
Assert authenticated PeerId and independently validate binding/admission
before application behaviour accepts requests. No discovery or package bytes.

### E. Authenticated manifest exchange

Add versioned request-response control protocol with bounded CBOR framing,
strict schema, request IDs, replay handling, timeouts, cancellation, and per
operation authorization. Verify publisher manifest signature against an
external anchor. Test malformed, oversized, replayed, unauthorized and
substituted responses.

### F. Chunk exchange

Request chunk indexes only for a verified manifest; validate transfer ID,
index, length, proof, requested window, and proof root before invoking the
existing disk receiver. Test malicious peers, wrong proof/index, duplicates,
cross-transfer replies, and that invalid data never reaches storage.

### G. Resume/reconnect

Reconnect only after repeating peer binding and operation authorization.
Resume by locally revalidating the persisted manifest and every journaled
chunk; negotiate missing indexes as an optimization only. Test changed trust
anchor, revoked binding, manifest substitution, restart, stale/replayed status,
and concurrent writers.

### H. Adversarial/resource testing

Fuzz frame and CBOR parsers; test quotas, slow peers, oversized and partial
frames, queue saturation, rate limiting, interrupted transfers, malicious
discovery advertisements, eclipse simulations, and denial-of-service recovery.
Run package/AIBOM/transfer focused suites plus the workspace regression set
required by project policy; document the exact tested platforms and MSRV.

## 10. Blockers, unresolved decisions, and recommendation

**Blocking before code:**

1. Security owner decision on Snow/Ring as the libp2p Noise provider. Existing
   deliberate RustCrypto policy cannot be considered preserved merely because
   the existing transport still compiles.
2. Project/CI decision to set and support Rust 1.88 (or choose another
   libp2p release with a formally accepted MSRV).
3. Identity authority decision: who issues PeerBindingStatements, how a
   verifier gets the AIP trust root, and how fresh suspension/revocation data
   is provisioned offline.
4. Capability policy decision defining exact package receive/serve actions,
   resource binding, delegation issuers, and whether token or grant semantics
   govern each operation.
5. Operational quota and trust-snapshot freshness policy for target
   institutional deployments.

**Recommendation:** use native libp2p as the target substrate after these
decisions, with static peers and direct TCP as the first deployment profile.
It better fits AIP's need to authenticate an AIP-bound peer and evaluate a
capability per operation than traditional private BitTorrent. BitTorrent's
tracker membership and piece exchange do not replace AIP identity binding,
revocation, publisher trust, or package-specific authorization. Native
libp2p keeps those checks adjacent to the existing Rust transfer receiver and
package verifier. It does not itself provide those checks; the proposed
binding/admission adapter is required.

### External upstream references checked

- [libp2p 0.57.1 release page](https://github.com/libp2p/rust-libp2p/releases) and [0.57.1 feature list](https://docs.rs/crate/libp2p/0.57.1/features).
- [libp2p 0.57.1 manifest](https://docs.rs/crate/libp2p/0.57.1/source/Cargo.toml.orig), [change log/MSRV](https://docs.rs/crate/libp2p/0.57.1/source/CHANGELOG.md), and [request-response API](https://docs.rs/libp2p/0.57.1/libp2p/request_response/).
- [libp2p-noise 0.47.0 manifest](https://docs.rs/crate/libp2p-noise/0.47.0/source/Cargo.toml) selects Snow's `ring-resolver` for non-Wasm targets; the [libp2p-identity 0.3.0 manifest](https://docs.rs/crate/libp2p-identity/0.3.0/source/Cargo.toml) shows its current key/dependency line.
- [Snow 0.10 feature list](https://docs.rs/crate/snow/0.10.0/features) and [provider documentation](https://docs.rs/snow/0.10.0/snow/).
