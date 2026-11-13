# AIP Permissioned Package Distribution: Technology Assessment

**Status:** assessment and design proposal; no distribution implementation is included.
**Repository branch inspected:** `validation/snifferdog-complete-enterprise-validation`
**Assessment date:** 2026-11-12

## Executive recommendation

Adopt Rust libp2p as the network substrate for a future `aip-distribution`
crate, with an AIP-specific, versioned request-response protocol for signed
transfer manifests and content-addressed chunks. Keep transfer authorization,
publisher signature verification, package installation policy, and content
integrity as independent decisions. Use libp2p's peer identity only to
authenticate the channel; require an AIP-signed binding and an AIP capability
before a peer may request or serve a package.

Use exact crate version `libp2p = 0.57.1`, `default-features = false`, and only
the features listed below. This is conditional on the project accepting its
Rust 1.88 MSRV and the `ring` resolver that the current libp2p Noise crate
selects on non-Wasm targets. This repository currently declares edition 2021
and does **not** declare a workspace `rust-version`; the distribution work
must first establish the supported compiler in CI. If Rust 1.88 is not
acceptable, pin and test an older libp2p line rather than silently accepting
an MSRV increase.

Prefer native libp2p chunks over traditional private BitTorrent for this AIP
deployment. AIP needs authenticated AIP-agent admission, per-operation
capability checks, institutional discovery, and audit-friendly fail-closed
behavior. Libp2p gives the Rust implementation an authenticated peer and
modular discovery/request-response substrate where those policies can be
implemented at the application boundary. BitTorrent provides mature piece
scheduling, but private-torrent admission is tracker-centric and is not a
substitute for AIP identity or capability authorization. It remains a valid
later alternative if an institution already operates a hardened private
tracker and accepts a separate BitTorrent-to-AIP admission bridge.

## 1. Repository and compatibility findings

### Workspace/runtime

- Root [`Cargo.toml`](../../Cargo.toml#L156) sets `edition = "2021"`. No
  workspace `rust-version` is declared. The existing crates share a workspace
  lockfile and many already use Tokio transitively, but
  [`aip-transport`](../../aip-standalone/aip-transport/Cargo.toml) itself is a
  blocking TCP implementation, not a Tokio/libp2p runtime.
- Current stable Rust libp2p release verified for this assessment is
  `0.57.1` (published 2026-10-15). Its release changelog raises MSRV to
  Rust 1.88.0. Edition 2021 in this repository is not in itself an obstacle;
  the compiler floor is. Pin `=0.57.1` and record the MSRV decision in the
  workspace before adopting it. [Crate release and dependencies](https://docs.rs/crate/libp2p/latest),
  [0.57.0 changelog/MSRV](https://docs.rs/crate/libp2p/latest/source/CHANGELOG.md)
- libp2p is async and its Tokio integration is feature gated. Add Tokio and
  Futures as direct dependencies of the new crate rather than relying on
  transitive workspace dependencies. Do not convert or repurpose the existing
  observation transport's blocking server loop.

### Current AIP security interfaces

- [`aip-package`](../../aip-standalone/aip-package/src/lib.rs#L540) has a
  portable export API that retains the existing v1/v2 package formats and
  detached signature. `verify_package_contents()` (line 699) checks the
  package against an externally supplied publisher key and AIBOM digest,
  validates the embedded manifest and full ZIP inventory, applies archive and
  extraction limits, and returns `VerifiedPackage` contents only on success.
  This API is the final verifier; distribution must not duplicate its checks.
- [`aip-crypto::custody::Custodian`](../../aip-standalone/aip-crypto/src/custody.rs#L152)
  supports private-key custody without a private-key accessor, including
  wrapped-file and PKCS#11 backends. New distribution metadata signatures
  should call the custodian and use AIP domain-separated canonical bytes.
- [`aip-core::validate_aid`](../../aip-standalone/aip-core/src/lib.rs#L402)
  validates an AIP identity document, its ID/key/provenance binding,
  self-signature, and lineage structure; its current status check rejects
  `Revoked`. Distribution policy must separately reject `Suspended`, enforce
  identity expiry/sequence rules, and consume current revocation state. The
  scoped-token APIs are
  [`issue_scoped_token`](../../aip-standalone/aip-core/src/capability.rs#L136)
  and [`verify_scoped_token`](../../aip-standalone/aip-core/src/capability.rs#L204);
  delegation-chain verification is in
  [`verify_delegation_chain`](../../aip-standalone/aip-core/src/delegation.rs#L189).
  These are suitable building blocks for package-specific request/serve
  scopes, but distribution still needs a policy adapter that supplies issuer
  trust anchors, current time, revocation state, and the precise action.
- [`aip-spiffe`](../../aip-standalone/aip-spiffe/src/lib.rs#L177) compares a
  SPIFFE workload assertion with AIP runtime identity evidence. It is useful
  for an optional local workload policy, but it does not authenticate remote
  libp2p peers or replace AIP capability checks.
- [`aip-transport`](../../aip-standalone/aip-transport/src/wire.rs#L18)
  defines a 4 MiB observation frame and a wire protocol specifically for
  opaque observation batches. Its handshake and Noise wrapper
  ([`confidential.rs`](../../aip-standalone/aip-transport/src/confidential.rs#L58))
  are not package distribution APIs. Reuse neither its batch message types nor
  its observation protocol semantics.

## 2. Recommended libp2p version and Cargo features

Use the umbrella crate, with defaults disabled and an exact release pin:

```toml
libp2p = { version = "=0.57.1", default-features = false, features = [
  "tokio",
  "tcp",
  "noise",
  "yamux",
  "ed25519",
  "macros",
  "identify",
  "request-response",
  "cbor",
  "mdns",
  "kad",
  "memory-connection-limits",
] }
```

Feature purpose:

| Feature | Use |
|---|---|
| `tokio` | Tokio executor integration for Swarm and async I/O. |
| `tcp` | Direct institutional TCP connectivity. |
| `noise` | Authenticated encrypted transport and the libp2p peer key exchange. |
| `yamux` | Multiplex concurrent protocol streams over a connection. |
| `ed25519` | Explicit Ed25519 libp2p peer keys. |
| `macros` | `NetworkBehaviour` derive for composing narrowly scoped behaviours. |
| `identify` | Exchange peer protocol/address metadata. Treat all advertised application metadata as untrusted. |
| `request-response` | Versioned package-manifest and chunk request-response protocols. |
| `cbor` | Bounded CBOR codec support for small control messages; chunk frames still need explicit size checks. A custom codec is also reasonable. |
| `mdns` | Optional local-subnet discovery for controlled LAN deployments. Discovery does not confer authorization. |
| `kad` | Optional private Kademlia provider/index discovery for multi-subnet institutional overlays. Bootstrap peers must be provisioned privately. |
| `memory-connection-limits` | Memory-scoped connection limits in addition to the general connection-limits behaviour. |

Do not enable `full`, `autonat`, `dcutr`, `relay`, `upnp`, public-facing DNS,
or QUIC in the first milestone. These increase surface area and may encourage
external rendezvous/NAT behavior that the isolated deployment does not need.
Add DNS only if institutional addresses require it. Use static addresses or
an institution-operated directory for cross-subnet peers; use mDNS only on
approved LAN segments.

The 0.57.1 feature list and optional protocol feature mappings are documented
in [libp2p's feature page](https://docs.rs/crate/libp2p/latest/features).
Connection limits support pending inbound/outbound and established total,
directional, and per-peer ceilings; add application-level request and byte
budgets too ([connection-limits API](https://docs.rs/libp2p-connection-limits/0.7.0/libp2p_connection_limits/)).
The libp2p Rust file-sharing example combines Kademlia and request-response,
but is a generic example rather than an AIP authorization design
([official examples overview](https://github.com/libp2p/rust-libp2p/blob/master/examples/README.md)).

### Crypto and dependency risks

- The workspace uses `ed25519-dalek 2.2.0`, SHA-2 0.10, `chacha20poly1305
  0.10.1`, `curve25519-dalek 4.1.3`, and `snow 0.10.0`. `aip-transport`
  deliberately configures Snow with its RustCrypto resolver/features and
  documents why it avoids `ring`.
- `libp2p-noise 0.47.0` also uses Snow 0.10, but its non-Wasm dependency
  explicitly enables `ring-resolver`. This will feature-unify the shared
  Snow package and add `ring` to the libp2p Noise path; `ring 0.17.14` is
  already present in the current workspace lockfile, but that does not make
  it an approved provider for the new security boundary. This is a provider
  and review-policy decision, not an expected symbol/link conflict. Review
  FIPS requirements, native build support, feature unification, and target
  builds before approval. [libp2p-noise 0.47 manifest](https://docs.rs/crate/libp2p-noise/latest/source/Cargo.toml.orig)
- libp2p-noise says it supports `IK`, `IX`, and `XX`, and that only `XX` is
  guaranteed interoperable across libp2p implementations. It also labels the
  crate experimental with possible major API/wire changes. Pinning and
  testing is therefore important; do not assume every pattern is cross-stack
  interoperable. [libp2p-noise documentation](https://docs.rs/libp2p-noise/0.47.0/libp2p_noise/)
- The release family also brings `rand 0.10`, `x25519-dalek 3`, `bytes 1.12`,
  and current libp2p core/protocol crates. The project has `rand 0.8` and
  existing Snow/X25519 components. Cargo can resolve multiple semver-major
  versions, but this adds compile time and distinct RNG/key types; avoid
  passing raw RNG/key objects across those API versions.
- Run a dependency-tree and target matrix before implementation is approved.
  In particular verify Linux, Windows, the deployed institutional targets,
  offline `--locked` builds, and the chosen MSRV. The assessment did not add
  or resolve libp2p dependencies because source/Cargo changes were explicitly
  out of scope.

## 3. AIP and libp2p identity binding

A libp2p `PeerId` is derived from the libp2p identity public key. An AIP ID is
not the same identifier: AIP derives it from the primary key **and provenance**.
Do not treat an advertised AIP ID in Identify metadata as proof of identity,
and do not accept a Noise-authenticated PeerId as permission to distribute.

Recommended binding:

1. Each distribution daemon has a dedicated libp2p Ed25519 transport key.
2. The corresponding `PeerId` is included in an AIP-signed
   `PeerBindingStatement` containing the AIP ID, identity-document digest,
   peer public key/PeerId, validity interval, and binding sequence.
3. The receiver validates the AIP identity document with `validate_aid()`,
   validates the binding signature against its AIP identity/trust policy,
   checks status/expiry/sequence using distribution policy (beyond the
   current `validate_aid()` checks), and maps the authenticated connection's
   `PeerId` to that AIP ID.
4. The peer then presents a current capability (or a verified delegated
   capability) scoped to the requested operation and package. The peer
   binding authenticates the peer; capability policy authorizes actions.

This binding lets an AIP `Custodian` sign the link between AIP identity and
transport key without exporting an AIP private key into libp2p. It avoids
relying on Ed25519-to-X25519 key conversion or sharing a private key across
identity and transport contexts. If future libp2p key-provider APIs can use
the existing custodian directly, reconsider the dedicated key; today the
binding record is the compatible custody boundary. SPIFFE/SPIRE may provide
an extra workload-placement fact at an institution, but it must not become a
second publisher trust root or a substitute for the AIP binding/capability.

## 4. Minimal `aip-distribution` crate architecture

Add one crate depending one-way on `aip-package`, `aip-core`, `aip-crypto`,
`aip-types`, and the selected libp2p features. The package crate must not
depend on distribution. Suggested modules:

```text
aip-distribution/
  admission.rs       PeerId ↔ AIP binding, AID validation, capability/delegation/revocation checks
  manifest.rs        Signed transfer manifest, canonical signing preimage, strict parser
  protocol.rs        Versioned bounded request/response control and chunk messages
  merkle.rs          Chunk leaf/node hashing, proofs, index/length validation
  scheduler.rs       Rarest-first/peer selection, bounded parallel requests, retries
  storage.rs         Partial file, bitmap/journal, atomic finalize, disk quotas
  swarm.rs           libp2p transport/behaviour composition and policy event loop
  verifier.rs        Reassemble exact portable export and invoke aip-package verifier
```

Keep protocol types and pure validation separate from the Swarm event loop.
Use a bounded custom CBOR codec (or a deterministic fixed binary codec) for
control messages. Never deserialize an unbounded peer-provided length into a
large allocation. Keep discovery as a replaceable adapter so air-gapped
provisioned peers do not require public infrastructure.

## 5. Peer admission and authorization flow

1. **Reachability only:** discover a candidate address from configured
   addresses, mDNS, or the private directory/Kademlia. Discovery claims are
   untrusted hints.
2. **Channel peer authentication:** dial with TCP + Noise + Yamux. libp2p
   authenticates the remote libp2p key and yields its PeerId. Require the
   selected compatible Noise handshake (XX for interop); reject negotiation
   errors, timeouts, and unsupported protocol versions.
3. **AIP binding:** send a fresh challenge and verify the AIP-signed binding
   record for that PeerId. Refuse absent, expired, revoked, malformed, or
   mismatched records. Do not grant access based on Identify fields.
4. **Operation authorization:** verify the AIP capability/delegation chain
   against configured issuer keys and revocation data. Define separate
   package actions such as `aip.package.discover`, `aip.package.fetch`, and
   `aip.package.serve`; bind package ID and optional classification in
   constraints. Check authorization at each request/serve operation, not
   only once at connection establishment.
5. **Transfer-manifest validation:** accept a transfer only when its AIP
   detached signature verifies against independently provisioned publisher
   anchors and its package identity/version are permitted by local policy.
   The transfer descriptor is not itself the package signature.
6. **Revocation/timeouts:** close outstanding streams and cancel requests on
   identity/capability expiry or revocation. Fail closed on policy-service or
   trust-anchor lookup failure. An unavailable peer is not treated as an
   authorized peer or as evidence of package authenticity.

Peer identity and package publisher identity stay separate. The peer that
serves bytes may not be the package publisher; it has no authority to change
the package's signed publisher, release policy, or AIBOM digest.

## 6. Package and chunk wire protocol

Use a new protocol ID, for example `/aip/package-distribution/1.0.0`,
negotiated through request-response. It is unrelated to the observation-batch
transport protocol.

### Signed transfer manifest

The publisher (or release authority explicitly trusted for distribution)
creates a separate `TransferManifest` using the existing `Custodian` and an
AIP domain-separated signing preimage. Keep the existing signed package
format unchanged. The transfer manifest fields should include:

- protocol and transfer-manifest schema versions;
- package name, package version, publisher ID, and package format version;
- exact portable-export byte length and SHA-256 digest;
- embedded package archive SHA-256 (for cross-checking with the export);
- fixed chunk size, chunk count, and a SHA-256 Merkle root over those exact
  export bytes;
- validity/not-before/not-after and optional release sequence;
- AIP signature over every preceding field, including the Merkle root.

The separately trusted publisher/release anchor authenticates this manifest.
The receiver still runs the existing `aip-package` verifier afterward; the
manifest signature is only the content-addressed transfer commitment.

Use a fixed 256 KiB chunk size initially. The current package archive cap is
256 MiB; the JSON export has bounded envelope overhead. At this chunk size a
maximum-size object is around 1,400 chunks and a Merkle proof is bounded to a
small number of sibling hashes. Define hashes as
`leaf = SHA256(domain_leaf || transfer_id || index_u64be || length_u32be || chunk)`
and `node = SHA256(domain_node || left || right)`. Define odd-node padding
explicitly (duplicate-last or fixed empty hash) and include that rule in the
manifest version. Bind the index and exact expected length, including the
short final chunk, so proofs cannot be moved between positions or transfers.

### Messages

| Message | Essential fields | Behavior |
|---|---|---|
| `ManifestRequest` | request ID, package name/version or package ID, nonce | Requires `discover`/`fetch` scope. Bounded response or explicit not-found/denied. |
| `ManifestResponse` | request ID, signed `TransferManifest` | Verify publisher/release signature and policy before scheduling any chunks. |
| `ChunkRequest` | request ID, transfer ID, chunk index, expected length, requester sequence | Requires `fetch` at request side and `serve` at responder side. Index/length must match manifest. |
| `ChunkResponse` | request ID, transfer ID, index, bytes, Merkle proof | Verify correlation, response size, index, expected chunk length, and proof before writing. |
| `TransferError` | request ID, bounded code, retryable flag | No unbounded peer text; denial/invalid content is not silently retried as success. |
| `Cancel` | request ID / transfer ID | Cancels queued work and releases reserved quota. |

Use random request IDs and per-peer sequence numbers to reject stale or
cross-request responses. Exact duplicate valid chunk responses may be treated
as idempotent after checking they match the existing verified chunk digest;
they must not advance a second transfer or overwrite verified bytes.

### Scheduling and resource bounds

Request different chunks concurrently from multiple authorized peers using
independent request-response streams. Start with a small fixed concurrency
ceiling (for example, four requests per peer and sixteen per transfer),
timeouts, maximum queued work, bounded retries, and a disk quota. A rarest-first
policy is optional optimization; integrity and admission checks are not.
Configure libp2p pending/established connection limits, per-peer connection
limits, memory limits, and the application-level stream/chunk limits. Reject
unknown or oversized manifests before reserving disk/memory. Enforce both
maximum simultaneous peers and total bytes in flight.

## 7. Reassembly and the existing package verifier

1. Stream each proof-verified chunk to a preallocated or sparse temporary file
   at `index * chunk_size`; persist a bounded verified-chunk bitmap and transfer
   ID if resume is supported.
2. Do not mark bytes complete until the chunk proof, exact length, and index
   validate. On restart, revalidate persisted chunk data or re-fetch it; do not
   trust the bitmap alone.
3. Require every expected chunk. Hash the complete exact portable-export file
   and compare with the signed transfer manifest's whole-export digest.
4. Parse the strict portable export and cross-check its archive digest,
   publisher, name/version, and package format against transfer metadata.
5. Pass the reconstructed export to the existing `aip-package` API/CLI with
   publisher trust anchors and either a separately trusted expected AIBOM
   digest or the independently sealed AIBOM artifact path.
6. Only after `verify_package_contents()` succeeds may the caller hand the
   private `VerifiedPackage` value to an explicit installation workflow.
   `aip-distribution` never executes payloads or installs automatically.

Incomplete downloads remain partial state and produce no `VerifiedPackage`.
Invalid chunk proof, package-export digest, package signature, archive
inventory, or AIBOM binding fails closed. Keep the temporary file outside any
installer watched directory and atomically move/copy verified data only after
the final checks.

## 8. Threat model and failure behavior

| Threat | Required control/failure |
|---|---|
| Unauthorized or spoofed peer | Noise PeerId is mapped through a signed AIP binding, then current request/serve capability is required. Deny and close. |
| Authorized peer serves tampered chunk | Verify chunk Merkle proof and index/length before disk write. Reject response, mark peer suspect, retry another authorized peer. |
| Peer replays a prior chunk/response | Bind request ID, transfer ID, index, session/request sequence; accept only for outstanding request; idempotently compare already verified bytes. |
| Peer lies about release/publisher | Transfer-manifest signature and external publisher anchor, then independent package signature verification. Peer metadata alone is ignored. |
| Missing chunks, slow peers, churn | Timeout/retry within caps; report incomplete; never publish/extract as verified. |
| Malicious sizes, proofs, message floods | Strict schema, checked arithmetic, pre-allocation length caps, connection/stream limits, quotas, rate limits, bounded concurrency. |
| Peer eclipse or false discovery | Discovery is not trust. Use multiple privately provisioned sources and signed AIP metadata; monitor source diversity. |
| Compromised or malicious authorized publisher | Cryptography cannot prove package safety. A valid publisher signature establishes origin/integrity only; separate review/assessment and install policy remain necessary. |
| Revoked identity or release during download | Recheck policy per request and before finalization; cancel and quarantine/remove partial state on revocation. |
| Offline time/revocation uncertainty | Define maximum capability/manifest validity and require periodically provisioned revocation snapshots. Fail closed when policy freshness requirements cannot be met. |

## 9. Native libp2p versus private BitTorrent

Traditional BitTorrent has proven piece scheduling, peer exchange patterns,
and content integrity. BEP 3 v1 uses SHA-1 piece hashes; BEP 52 v2 uses
SHA-256 Merkle trees and proofs. A deployment choosing it must require v2
integrity (or retain an AIP SHA-256 whole-object commitment) and still validate
the AIP package signature separately. [BEP 3](https://github.com/BitTorrent/bittorrent.org/blob/master/beps/bep_0003.rst),
[BEP 52](https://github.com/BitTorrent/bittorrent.org/blob/master/beps/bep_0052.rst)

Private BitTorrent is not a peer permission system equivalent to AIP. BEP 27
requires private torrents to use only the private tracker and peers it
returns; its own rationale notes that a peer whose address becomes known can
connect to another peer and then participates as an equal peer. A private
tracker therefore supplies swarm membership, not per-package `fetch`/`serve`
capability checks or cryptographic AIP identity binding. Tracker availability,
tracker authentication, client configuration drift, DHT/PEX/LSD suppression,
and a separate AIP authorization gateway become deployment risks.
[BEP 27: Private Torrents](https://github.com/BitTorrent/bittorrent.org/blob/master/beps/bep_0027.rst)

Native libp2p means AIP owns and tests the chunk protocol, content-manifest
signature, scheduling, storage resume, and abuse controls. That is real
engineering cost. It is preferable here because it avoids introducing a
parallel tracker/member database and custom BitTorrent admission bridge, fits
the Rust workspace, supports static institutional peer provisioning and
optional LAN discovery, and lets AIP enforce capability policy at each
request. A private BitTorrent deployment is worth reconsidering if the
institution already has an operational private tracker and accepts that
additional trust and control plane.

Neither choice requires public bootstrap infrastructure. libp2p Kademlia
requires a known peer/address to bootstrap, which can be supplied through
configuration or a signed institutional directory; mDNS can discover peers
on the local subnet. Use multiple internal bootstrap peers for availability,
not globally operated public nodes. [Kademlia bootstrap API](https://docs.rs/libp2p-kad/0.49.0/libp2p_kad/struct.Behaviour.html),
[mDNS behavior](https://docs.rs/libp2p-mdns/0.49.0/libp2p_mdns/struct.Behaviour.html)

## 10. Security validation plan

Before production distribution, cover pure logic, loopback multi-peer tests,
and offline package verification:

- unauthorized PeerId, absent/forged/expired/revoked AIP binding;
- valid peer binding but wrong AIP ID, revoked AID, wrong grantee, insufficient
  scope, expired token, invalid delegation, and revoke-during-transfer;
- transfer-manifest signature tampering, wrong publisher anchor, expired or
  revoked release, package ID/export digest mismatch;
- altered, truncated, duplicated, out-of-order, cross-transfer, wrong-index,
  wrong-length, malformed-proof, and replayed chunks;
- incomplete transfer and restart/resume with corrupted partial state;
- malicious peer returns inconsistent chunks or colludes with another peer;
- unsupported protocol/version, malformed CBOR, integer overflow, huge
  advertised object, excessive concurrency, slowloris, request flood, and
  exhausted disk/memory quotas;
- complete export passed to `aip-package` and rejected when signature,
  archive, manifest, inventory, publisher anchor, or AIBOM binding is wrong;
- payload remains non-executed; no extraction/install side effect occurs
  before the existing verifier returns verified contents;
- offline two-peer isolated network with only provisioned static peers, plus
  optional same-subnet mDNS; no public bootstrap/DHT/relay dependency.

For adversarial peer behavior, assert both the local transfer outcome and
that no partial/untrusted file appears in the verified-output location.

## 11. Dependencies and implementation risks

1. MSRV is currently unspecified at workspace level; libp2p 0.57.1 sets a
   concrete 1.88 floor. Confirm every supported build/deployment toolchain.
2. libp2p Noise enables Ring's resolver despite AIP transport's deliberate
   RustCrypto-only Snow setup. Approve that provider change or block the
   selected dependency. Do not quietly infer compatibility because both use
   the same Snow version.
3. libp2p-noise currently documents experimental/API-wire stability concerns
   and only XX cross-implementation guarantees. Pin, interoperability-test,
   and define protocol upgrade windows.
4. Peer identity binding requires a signed AIP transport-key statement and
   a capability validation service/cache. A self-reported ID or PeerId
   mapping table without signatures would create an unrelated trust system.
5. Revocation snapshots and trusted institutional peer discovery must have
   an offline provisioning and freshness process. No public infrastructure
   is required, but there must be an operational method for publishing trust
   updates into isolated networks.
6. Distribution of the portable package JSON duplicates archive bytes in
   base64 and in the transfer file's storage cost. A later binary framing
   format may be more efficient, but should wrap or reconstruct the same
   existing package export and must not change the signed package format.
7. Chunk Merkle tree construction, odd leaf treatment, and byte-range bounds
   are new protocol semantics requiring independent vectors and fuzzing.
8. Discovery and DHT provider records are attacker-controlled hints and can
   enable eclipse/denial-of-service attacks even when data is signed.

## 12. Exact first implementation milestone

**Milestone 1: offline transfer-manifest and chunk-verification core, with no
network socket or libp2p dependency.** Add `aip-distribution` pure modules to:

1. take an existing portable `aip-package` export byte sequence;
2. create and verify an AIP-signed transfer manifest committing exact export
   length, SHA-256, chunk size/count, package metadata, and Merkle root;
3. split and verify chunks/proofs using a frozen deterministic vector set;
4. reassemble only complete verified exports and invoke the existing package
   verifier with external package/AIBOM trust inputs; and
5. demonstrate rejection of tampered, reordered, duplicate, missing, and
   oversized chunks while proving the package verifier remains authoritative.

Exit criteria: tests establish byte-for-byte reproducibility of manifest and
Merkle vectors, invalid chunks never reach the final file, and a valid
reassembled v1 and v2 package is independently verified by `aip-package`.
After that passes, milestone 2 adds one libp2p loopback peer and the
PeerId-to-AIP binding/admission flow. This sequencing isolates hashing and
trust decisions from asynchronous networking failures before the dependency
and MSRV change lands.

## Recommendation

Proceed with libp2p as the target architecture, subject to a Rust 1.88 and
Ring-provider decision. Keep the first code milestone networkless. Use
private static peer provisioning or an institution-managed signed directory,
with mDNS only on approved LANs and private Kademlia only where multi-subnet
discovery is needed. Do not add public bootstrap, public DHT, relays, or
automatic NAT traversal to the isolated deployment.

This is preferable to traditional private BitTorrent because AIP needs
cryptographic agent-to-peer binding and per-action permission checks, while
private BitTorrent relies on tracker membership and explicitly does not
prevent a known peer address from connecting outside the tracker's peer list.
The extra chunk scheduler and integrity protocol are justified by keeping
distribution authorization in the existing AIP trust model and retaining the
existing package verifier as the independent final authority.
