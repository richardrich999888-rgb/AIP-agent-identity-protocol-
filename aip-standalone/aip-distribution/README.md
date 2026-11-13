# AIP Distribution offline core and permission policy foundation

This crate operates on the exact bytes of an existing `aip-package`
`PortablePackageExport`. It has no network, peer discovery, extraction,
installation, or execution behavior. `TransferReceiver` is the in-memory
compatibility API; `DiskTransferReceiver` stores chunks on disk and supports
restart/resume. It returns `VerifiedPackage` only after persisted chunks,
the complete export digest, and the existing package verifier succeed.

The opt-in Cargo feature `p2p` enables the PeerId/AIP binding and package
authorization APIs with Ed25519 identity support, but does not enable a
transport. Live TCP/Noise/Yamux request-response is separately gated behind
`live-noise`; this compiles/activates libp2p's Ring-backed Noise provider and
has not received security-owner approval. The feature also has no public DHT,
relay, QUIC, UPnP, NAT traversal, or public bootstrap.

`network_protocol` defines bounded CBOR envelopes for
`/aip/distribution/1.0.0`, strict application validation, timeouts,
connection/memory limits, per-peer/global request and transfer accounting,
and a fixed replay window that fails closed when full. `authorize_inbound_request()`
is the reusable admission function: it validates the envelope, verifies the
transport-authenticated PeerId against caller-resolved AIP binding/status and
external anchors, checks the requester's exact Receive/Resume capability,
and checks the local Serve/ServeResume capability before dispatch. A Noise-authenticated
PeerId alone is not application authorization. The crate still does not provide
a production server loop that resolves trust inventory, starts/stops peers, or
automatically routes every decoded request through admission; applications
must call this function before any operation or response side effect.

On Unix, `PersistentReplayGuard` provides a single-writer durable replay
journal. After successful admission, call `RequestAdmission::begin_durable()`
before dispatch. Request IDs are retained for 24 hours, capped at 131,072
overall and 4,096 per peer; a full journal fails closed and does not evict
unexpired IDs. It uses an atomic synced replacement, a local exclusive lock,
and a domain-separated digest to detect accidental corruption. The digest is
not authentication and restoring an older valid journal remains possible;
the journal therefore has no rollback resistance without a separately trusted
checkpoint. Journal corruption and concurrent writers fail closed.

The local two-peer data-path test is explicitly opt-in:
`cargo test -p aip-distribution --features live-noise --test live_network`.
It uses loopback TCP, validates both AIP bindings and exact Receive/Serve
grants, transfers a two-chunk signed export, exercises the shared inbound
admission function for each request, writes replay IDs durably only after
admission, disconnects and resumes from the disk receiver after revalidation,
finalizes via the package verifier, checks a separate Install grant, and stages
the verified files with `aip-install`. Persistent replay across a process
restart is covered by a journal unit test; the live network test itself does
not restart the server process.
The test's AIBOM digest is externally supplied fixture data; the independent
AIBOM seal check is exercised by the higher-level offline evidence API tests.
The live feature and loopback test are not approval of Ring or a production
deployment profile.

## Peer binding and authorization foundation

`peer_binding` is available only with `p2p`. A signed `PeerBindingStatement`
binds an AIP ID and digest of every AID document field to the protobuf
Ed25519 public key and derived PeerId. Binding issuers and the subject IDs
they may issue for are externally provisioned. A separately signed status
snapshot must be fresh and active; the trust anchor has a minimum accepted
epoch. Operators must persist and advance that epoch floor through trusted
policy updates. The module still does not define a live identity directory,
key rotation workflow, or network admission exchange. `validate_aid()` proves
the AID's self-signature; trust in the identity is established here only
through the external binding-issuer subject grant and trusted status signer.

`authorization` maps each operation to an exact custom scope action containing
a domain-separated 192-bit digest over operation, package ID, publisher ID,
release digest, and recipient AIP ID. The action is checked through the
existing signed `ScopedToken`, delegation-chain, scope attenuation, and
revocation APIs. `Serve`, `Receive`, receiver-side `Resume`, server-side
`ServeResume`, and `Install` are distinct;
broad Read/Write does not grant them. The caller must supply trusted issuer
keys and a `VerifiedRevocationSnapshot`; the authorization API rejects stale
snapshot data. The underlying `aip-core::RevocationLog` remains an
append-only local log and does not authenticate its synchronization source.
Installation authorization is only a decision result and does not install,
extract, or execute package contents.

The `p2p` feature is optional because libp2p 0.57.1 Noise uses Snow's Ring
resolver and has an MSRV of Rust 1.88. The repository has no declared MSRV,
and security-owner approval for this additional crypto-provider path and
deployment MSRV has not been recorded. The existing `aip-transport`
implementation and resolver configuration are unchanged. This crate must not
be treated as production network transport until those approvals and the
bounded protocol/admission layers exist.

## Signed revocation and identity-status snapshots

`revocation_snapshot::RevocationSnapshot` is a bounded signed current-state
snapshot for capability JTI revocations. Version 1 signs a canonical,
domain-separated encoding of issuer ID, monotonically increasing epoch,
issue and expiry times, audience, and a strictly JTI-sorted list of revocation
records. Unknown JSON fields, duplicate or unordered JTIs, unsupported
versions, invalid time windows, oversized snapshots, and invalid signatures
are rejected. Its snapshot digest includes the full signature envelope.

The independent verifier provisions `RevocationAuthorityAnchor` out of band:
issuer identity, 32-byte public key, minimum epoch, audience, maximum age, and
maximum lifetime. No organization root is inferred. `verify_revocation_snapshot`
requires that anchor and can compare against a trusted `SnapshotCheckpoint`.
Lower epochs and a different digest at a pinned epoch fail closed. A
successful verification returns the next checkpoint. Operators must persist
that checkpoint with rollback-resistant trusted policy state; a plain file
that can be restored with an old backup does not provide rollback protection.
An unchanged exact snapshot at its already-pinned epoch is accepted
idempotently. Issuer governance, key rotation, checkpoint storage, and maximum
offline freshness remain explicit deployment decisions.

Peer identity status uses the separate signed `PeerStatusSnapshot`, with its
own issuer anchor and audience. Its digest covers the canonical payload and
signature. `verify_peer_status_snapshot` returns a `PeerStatusCheckpoint`,
which can be provisioned through `PeerStatusAuthorityAnchor::with_checkpoint`
to reject same-epoch conflicts and rollback. Binding verification requires
the AIP sequence, peer-binding sequence, and full binding digest to match the
active status entry.

## Composed offline package verification

With `aip-package-cli`'s `offline-evidence` feature,
`aip_package_cli::offline_verify::verify_offline_package_evidence()` composes
the existing AIBOM seal verifier, package verifier, peer-binding verifier,
package capability/delegation verifier, and signed revocation snapshot
verifier. All trust anchors are separate arguments; this API performs no I/O
or network access. It returns `INPUTS_VERIFIED` with
`execution_status=NOT_EVALUATED`; it does not claim installation, execution,
or downstream effects. Optional transfer evidence is checked against the
exact supplied export bytes, publisher-signed transfer manifest, every chunk
proof, index, and position. Missing transfer evidence is reported as absent
and does not invalidate other verified inputs.

For composed verification, provision a digest-pinned `PeerStatusCheckpoint`
inside the peer-status anchor and a separate `SnapshotCheckpoint` for the
revocation authority. The API requires the revocation checkpoint; it rejects
uncheckpointed peer status. Bootstrap verification of a first snapshot is a
separate provisioning step: verify its signature against the authority anchor,
then transfer the returned digest checkpoint through a trusted channel before
using it for independent bundle verification.

The existing `aip-package verify` CLI independently verifies package and
AIBOM authenticity. The composed peer-binding, capability, and revocation
checks are currently exposed as a Rust API; a portable CLI bundle schema and
command are still needed. Do not combine package CLI `VERIFIED` output with
evidence CLI output into an execution claim.

## Frozen v1 contract

* The transfer-manifest signer is the **package publisher**, identified by
  `publisher_id`. Verifiers provide that publisher ID and public key from an
  external trust anchor. The transfer signature does not replace the package
  signature or establish AIBOM authenticity.
* `transfer_id` is lowercase hex SHA-256 of
  `"AIP-DISTRIBUTION-TRANSFER-ID-v1\\0" || export_len_u64be ||
  SHA256(exact_export_bytes) || chunk_size_u32be`. It excludes the Merkle
  root and all signatures. The manifest signature binds the ID, root,
  metadata, exact byte digest and lengths.
* The signature preimage is `manifest_signing_bytes()`: the raw
  `AIP-DISTRIBUTION-MANIFEST-SIGN-v1\\0` domain followed by fixed-order
  fields. Integers are big endian. Each UTF-8 string is prefixed by its
  unsigned u32 big-endian byte length. Digests are raw 32-byte values.
  The signature is the repository's AIP Ed25519 signature envelope made by
  `Custodian`; its payload hash is SHA-256 of those preimage bytes.
* Chunk size is exactly 262144 bytes. Indexes start at zero. Count is
  checked `ceil(export_len / chunk_size)`. Every non-final chunk is exactly
  chunk size; final length is the exact remainder, or one full chunk when
  evenly divisible. Zero-length transfers are invalid.
* A leaf is `SHA256("AIP-DISTRIBUTION-LEAF-v1\\0" || transfer_id_raw32 ||
  index_u64be || chunk_len_u32be || chunk_bytes)`. A parent is
  `SHA256("AIP-DISTRIBUTION-NODE-v1\\0" || left32 || right32)`. At each
  level, an unpaired final node is duplicated as its own right sibling.
  Proofs are bottom-up; side is inferred from index parity, and an odd
  unpaired node's supplied sibling must equal the current hash.
* Reassembly accepts only the next index. A network scheduler may stage
  verified out-of-order pieces separately, but must submit them in order to
  this API. Duplicate, reordered, missing, malformed, oversized, or
  cross-transfer chunks fail closed.

`verify_complete()` requires the publisher key for the existing package
verifier and the expected canonical AIBOM digest. The higher-level
integration must first parse and validate the AIBOM, verify its detached seal
against an external trust map, derive the canonical digest, and pass that
digest here. The API boundary deliberately does not claim that an arbitrary
caller-supplied digest proves AIBOM authenticity. The existing package
verifier checks that the package binds to the supplied digest and then
authenticates the publisher, manifest, archive inventory, and file contents.
The returned contents are verified data, not permission to execute them.

The AIBOM-aware `aip-package` command is built from the higher-level
`aip-package-cli` workspace crate. Its command name and subcommands are
unchanged; Cargo invocation uses `cargo run -p aip-package-cli --bin
aip-package -- ...`.

## Deterministic vector

`vectors/transfer-v1.json` fixes the canonical preimage and AIP envelope
signature for a small one-chunk example. `vectors/merkle-v1-odd3.json` fixes
three leaf hashes and the nonempty proof for the odd final leaf. The
signature fixture includes only its public key and signature; production APIs
accept a `Custodian` and never export private keys. Unit tests pin these
bytes and proof values.

## Durable partial-transfer storage

On Unix, construct `DiskTransferReceiver` with a caller-selected directory
outside installation and execution locations:

```rust,ignore
let mut receiver = DiskTransferReceiver::create(
    partial_directory,
    signed_manifest,
    trusted_publisher_id,
    trusted_publisher_key,
)?;
receiver.accept(verified_chunk)?;
// After restart, resume() revalidates all metadata and stored chunks.
let mut receiver = DiskTransferReceiver::resume(
    partial_directory,
    trusted_publisher_id,
    trusted_publisher_key,
)?;
let verified = receiver.finalize(
    trusted_publisher_id,
    trusted_publisher_key,
    independently_verified_aibom_digest,
)?;
```

The directory is created exclusively with mode `0700`; `manifest.json`,
`chunks.bin`, `journal.json`, and `writer.lock` are mode `0600`. Names are
fixed by the implementation. Directory traversal uses pinned directory file
descriptors and `openat`/`mkdirat` with `O_NOFOLLOW`; files are created with
`O_EXCL`, and a nonblocking `flock` permits one writer per transfer. Parent
path components are checked and opened without following symlinks. Non-Unix
platforms currently fail closed because equivalent no-follow operations are
not implemented there.

`chunks.bin` is pre-sized to the signed export length. Chunks are accepted in
index order. Proof and length validation happen before writing; bytes are
synced before an atomic journal replacement records the index and proof. The
journal is bounded to 4 MiB and is never treated as integrity evidence.
Resume re-verifies the manifest with the external anchor and re-reads every
journaled chunk, checking its exact length and Merkle proof. A stale
`journal.tmp` from a crash before rename is discarded; the installed journal
remains authoritative. Data written before its journal entry is ignored and
overwritten on retry. Corrupt journals, truncated stores, invalid chunks,
symlinks, non-regular files, and unexpected entries fail closed.

Limits are 400 MiB per transfer, 256 KiB per chunk, at most 32 proof levels,
8 KiB for an encoded manifest, and 4 MiB for the journal. There is no global
quota or cap on the number of separate caller-created transfer directories;
deployments should use a quota-managed partial-transfer filesystem and limit
active transfers at the caller.

The existing `aip-package` verifier consumes in-memory package structures.
The disk receiver therefore reads the assembled export into a bounded buffer
at finalization and invokes that unchanged verifier. Chunk reception and
resume do not retain the whole transfer in RAM, but finalization memory still
includes the portable export and the verifier's decoded archive and verified
payload. The transfer is bounded to 400 MiB, the compressed archive to 256 MiB,
and total uncompressed package files to 512 MiB. Peak memory can be substantial
because these buffers can overlap, but the current path does not allocate an
unbounded export. A streaming package verifier would require changing the
existing package API while preserving the detached signature, inventory, and
ZIP-entry checks; that change was not made.

Filesystem safety assumes the caller selects a protected parent directory
and the host correctly implements Unix `openat`, `O_NOFOLLOW`, `flock`, atomic
rename, and `fsync`. An attacker controlling the host or able to modify the
partial data and all local metadata can cause denial of service or rollback;
the journal is not a trust anchor. Publisher signatures, Merkle proofs, the
complete export digest, externally validated AIBOM digest, and the package
verifier remain the authenticity checks.

## Offline authorization evidence and revocation

The optional `aip-package-cli` library feature `offline-evidence` composes the
existing package verifier with AIBOM detached-seal verification, AIP peer
binding, capability/delegation authorization, signed revocation status, and
optional transfer chunk evidence. Enable it with
`cargo test -p aip-package-cli --features offline-evidence`; callers use
`aip_package_cli::offline_verify::verify_offline_package_evidence`. This is a
Rust API, not a bundle-reading command-line workflow. The caller must parse
the evidence and supply each trust anchor independently.

The API returns `INPUTS_VERIFIED` only after all supplied artifacts pass
verification and the requested package operation is authorized. Its report
sets `execution_status` to `NOT_EVALUATED`: verification does not establish
installation, execution, or external business effects. Missing required
anchors/checkpoints, invalid signatures, expired evidence, revoked identities
or tokens, and bad transfer proofs fail closed. Optional transfer evidence is
validated against the exact portable export bytes; omitting it means the
package and its other evidence are still verified, but transfer provenance is
not asserted.

Distribution revocation snapshots use version 1 JSON with strict unknown-field
rejection and a 4 MiB bound. The signed payload is a canonical, fixed-order
binary encoding under `AIP/DISTRIBUTION/REVOCATION_SNAPSHOT/v1`; the digest
uses the separate `AIP/DISTRIBUTION/REVOCATION_SNAPSHOT_DIGEST/v1` domain and
covers the signed payload and complete signature envelope. The payload binds
issuer ID, monotonically increasing epoch, issue/expiry times, audience, and a
strictly sorted unique JTI list with revocation time and reason. Verification
requires an externally provisioned issuer/key anchor, expected audience,
maximum age/lifetime, and an externally retained epoch/digest checkpoint.
Lower epochs, expired/stale snapshots, and a different digest at a pinned
epoch are rejected. The first accepted checkpoint is only a bootstrap value;
it must be persisted using rollback-resistant trusted policy storage. A
checkpoint shipped alongside the snapshot is not independent trust.

Project owners still need to approve issuer governance, how initial anchors
and checkpoints are provisioned, the rollback-resistant checkpoint store, and
deployment freshness/max-age values. The format does not choose an
organization root or make an unauthenticated synchronization source trusted.
Peer-status snapshots have the same external-anchor and checkpoint
requirements. AIP binding and operation checks are reusable APIs; the live
swarm does not automatically receive trust material or run an application
handler. A production host must invoke those APIs for every request, resume,
and installation transition. Replay and quotas currently use bounded
in-memory state and reset only as documented by the peer lifecycle API;
durable across-process request replay prevention is not implemented.
