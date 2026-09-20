# Phase 1 — probe daemon, collector daemon, authenticated transport

> **Status: implemented.** `aip-transport`, `aip-collector`, `aip-probe` are
> built with unit + integration tests and pass `clippy -D warnings`. The
> end-to-end proof is `aip-collector/tests/e2e.rs`. Remaining follow-ups are in
> `BFSI_PILOT_PLAN.md` §7.

Design record for the three components, written before the code. Scope is
deliberately the **smallest security-correct** system that turns the
demonstrator into a two-host pilot: it adds no evidence class, no new
cryptographic primitive, and no wire change to the signed
`AttestedBatch`/`SensorHealth` formats.

## Components and crates

| Crate | Kind | Holds a key? | Job |
|---|---|---|---|
| `aip-transport` | lib | — | Framed, authenticated probe↔collector channel over blocking TCP. No knowledge of evidence semantics; carries opaque batch/health bytes. |
| `aip-collector` | bin | **evidence signing key** (wrapped, off-host) | Accepts authenticated batches, signs them via `CollectorRuntime`, persists, serves signed health. The trust anchor. |
| `aip-probe` | bin | **transport-auth key only** | Drives `aip-observe` sensors, builds `ObservationBatch`, ships it. Holds **no** evidence key and has no signing method for evidence. |

No async runtime. Blocking `std::net` with a thread per connection — a probe→
collector link is one connection per host, so blocking IO is adequate and adds
zero dependencies. Dependencies are limited to what the workspace already pins:
`ed25519-dalek`, `sha2`, `serde`, `serde_json`, plus `aip-crypto`/`aip-observe`.

## The two keys — do not conflate them

This is the invariant a reviewer will check first, so it is stated first.

- **Evidence signing key** — lives only on the collector host, wrapped at rest
  (`CollectorKey::production` / `WrappedFileCustodian`). Signs `AttestedBatch`
  and `SensorHealth`. This is the trust root; the whole architecture exists so
  that only an off-host holder of this key can vouch for an observation.
- **Transport-auth key** — an Ed25519 keypair the probe holds to authenticate
  the *channel*. It signs transport frames, never evidence. Possessing it lets a
  host connect and submit observations; it does **not** let the host forge an
  attestation, choose a chain position, or label a report as a mechanism the
  collector did not register for. Those are all decided by the collector under
  the evidence key.

Consequence, made explicit so it is never overclaimed: **the transport-auth key
is not a second evidence root.** A compromised probe (holding its transport key)
can submit false observations — exactly what the reconciler's `CANNOT_PROVE`
default, the `EvidenceCeiling`, and the collector's probe registry already
bound. The transport authenticates *who may submit*, not *what is true*.

## Trust model for the transport

Threat: the probe host is attacker-reachable; the network between probe and
collector is untrusted; the collector is the trust anchor.

What the transport must do (defense-in-depth, not the evidence root):

1. **Authenticate the probe to the collector** — only a probe whose transport
   public key is in the collector's allow-list may submit. Stops an anonymous
   attacker flooding the collector or injecting observations under a probe id.
2. **Bind each session to a fresh challenge** — anti-replay across sessions.
3. **Order and integrity within a session** — strictly increasing frame
   sequence + a signature over each frame, so frames cannot be reordered,
   duplicated, or altered on the wire.

What the transport explicitly does **not** do:

- ~~It does not provide confidentiality.~~ **Superseded by R9.** The
  authenticated channel now runs inside a `Noise_NK_25519_ChaChaPoly_SHA256`
  session (`aip_transport::confidential`), with the probe pinning the
  collector's static public key. The challenge, the probe's identity and
  transport key, and every batch frame are inside the session; a capture of
  the link shows none of them (`aip-transport/tests/confidential.rs`, with a
  plaintext control). The daemons use it unconditionally. The channel's
  integrity still does not depend on this layer: the Ed25519 frame
  signatures hold even if the outer session were somehow stripped.
- It does not make the host kernel trustworthy (N1). A root attacker on the
  probe host still lies to the probe; the transport faithfully delivers that
  lie, which the reconciler handles as it always has.

## Wire protocol (v1)

Length-prefixed frames: `u32` big-endian length, then that many bytes of a
`serde_json` message. A frame length above `MAX_FRAME_BYTES` (a fixed cap) is
refused before allocation — untrusted input is bounded first.

Handshake, then a stream of batch frames:

```text
  collector → probe   Challenge { protocol_version, nonce: [u8;32] }
  probe → collector   Auth {
                        probe_id, transport_pubkey: [u8;32],
                        signature over  DOMAIN_AUTH ‖ protocol_version ‖ nonce
                      }
  collector           verify signature; verify transport_pubkey ∈ allow-list
                      for probe_id; else close (no partial state)
  collector → probe   AuthResult { accepted: bool, reason? }

  loop:
  probe → collector   BatchFrame {
                        seq: u64,                 // strictly increasing from 1
                        batch: ObservationBatch,  // serde
                        signature over  DOMAIN_FRAME ‖ nonce ‖ seq ‖ sha256(batch_json)
                      }
  collector           verify seq == last_seq + 1; verify signature under the
                      session's authenticated transport_pubkey; else close.
                      attest(batch) → AttestedBatch (signed under the EVIDENCE key)
  collector → probe   BatchAck { seq, attested_sequence, head: [u8;32] }
```

Domain-separated preimages (`DOMAIN_AUTH`, `DOMAIN_FRAME`) so an auth signature
can never be replayed as a frame signature or vice versa. The batch signature is
over `sha256(batch_json)`, so the collector re-hashes the exact bytes it parsed
before it trusts the frame — it never verifies a hash supplied beside the data.

The collector always re-derives the batch's **canonical** bytes itself for the
evidence signature (`signer.attest`), so the transport encoding (JSON) is
irrelevant to evidence integrity; a malformed or dishonest transport encoding
can at worst cause a parse failure or a false observation, never a forged
attestation.

## Failure semantics (fail closed)

- Unknown or unauthenticated probe key → connection closed, nothing stored.
- Bad frame signature, out-of-order seq, or oversize frame → connection closed;
  the collector keeps its chain position (the probe reconnects and continues).
- Collector continuity refused at start (amnesia/rollback/fork under strict
  policy) → the collector does **not** serve; it exits after writing the signed
  continuity report. A collector that cannot prove its own continuity does not
  sign.
- Transport/network error → the probe buffers and retries; an unshipped batch is
  a coverage gap the collector reports as such, never a fabricated observation.

## Custody composition (prerequisite change to `aip-observe`)

`CollectorRuntime::start` takes a raw private key; `WrappedFileCustodian` never
exposes one. To run the collector under wrapped, off-host custody without
duplicating continuity logic, `aip-observe` gains a custody-aware path that
reuses the existing logic verbatim:

- `CollectorSigner::resume_with_custodian(snapshot, observer_id, custodian, archive)`
  — the body of `resume`, taking a `Box<dyn Custodian>` instead of raw bytes;
  `resume` is rewritten to build an `InMemoryCustodian` and delegate, so there
  is one continuity implementation.
- `CollectorRuntime::start_with_custodian(store, observer_id, key_version, custodian, policy)`
  — mirrors `start`, signing the continuity report through the custodian.
- `CollectorKey::into_custodian(self) -> Box<dyn Custodian>` — hands the
  wrapped custodian to the runtime after the production-policy check.

No signed field, canonical encoder, verification rule, or protocol version
changes; the signatures produced are identical, only the key holder differs.
`aip-protocol-change-guard` reviewed: none of its triggers fire.

## Mechanism-integrity across the split (closed)

In the single-host demonstrator the tracepoint-gate detector
(`ProcessTracer::mechanism_integrity` and its two siblings) and the signer
shared a process, so a blinded observer signed
`ObserverState::IntegrityUnknown` directly. In the two-host split the detector
runs on the **probe** and the signer on the **collector**, and the original
Phase-1 wire carried only an opaque batch — so the collector could not sign
`IntegrityUnknown` from a probe-side gate. That gap is closed:

- **The finding travels inside the batch.** `ObservationBatch` (protocol
  version 11) carries `mechanism_integrity: Vec<MechanismIntegrityReport>`,
  one `(mechanism, finding)` per perf-tracepoint sensor the probe has open.
  It is inside the transport frame signature (a network attacker cannot strip
  it) **and** inside the attested bytes (it cannot be edited or dropped after
  signing). `aip-probe` re-checks every open tracer every cycle
  (`sensors.rs`); the single-host demonstrator now declares its findings into
  the same probe field rather than into the signer, so the two paths are one.
- **The collector absorbs it fail-closed.** `CollectorSigner` notes every
  non-capable report (a found gate or a refused query) as reported, and a
  `Verified` report only for a mechanism the same batch declares active — a
  probe cannot clear a slot for a sensor it stopped running.
- **The daemon refuses silence.** `aip-collector`'s sink treats a batch that
  declares a gate-able sensor active and carries no finding for it as an
  `Unverifiable` report: an older or edited probe cannot keep the state
  `Active` by omitting the check. Gate-independent sources (the connector,
  fanotify, AF_PACKET) owe no report.

Trust bound: the report is a probe self-report, so a root probe host lies
about itself exactly as it lies about every other batch field (N1). It can
only *lower* the signed state. The safety layer described before — a
non-occurrence claim requires a **gate-independent** kernel-pushed mechanism
in the signed coverage (`covered_by_kernel_pushed_source`) — is unchanged and
still does not rest on this signal.

Tests: `aip-collector/src/sink.rs` (gate → `IntegrityUnknown`; omitted →
`IntegrityUnknown`; verified-for-every-open-sensor → not `IntegrityUnknown`;
no tracepoint sensors → no report owed; stale `Verified` cannot clear a
gate). The live attack against the two-daemon pair on institution hardware
remains a Phase-4 item.

## The netlink process-event connector in the probe (added)

`aip-probe` drives the netlink process-event connector (`AIP_PROBE_SENSORS=
...,connector`, `CAP_NET_ADMIN` in the initial network namespace, granted by
the systemd unit). It is the pilot's only **gate-independent** kernel-pushed
source and the only one whose coverage licenses a process-lifecycle
non-occurrence statement (`SourceMechanism::covers_process_lifecycle`);
without it the pilot observer could never reach `PHANTOM_CLAIM`, only
`CANNOT_PROVE`. `ENOBUFS` on the receive queue is recorded as a counted loss
(a floor of one) and degrades the epoch like any other loss.

**fanotify and AF_PACKET are driven as of R8**, which makes the connector no
longer the *only* gate-independent source — it remains the only one that
licenses a **process-lifecycle** non-occurrence statement, which is the
property `PHANTOM_CLAIM` rests on.

- `fanotify` (`CAP_SYS_ADMIN`) marks the mount holding
  `AIP_PROBE_FANOTIFY_PATH` for `FAN_CLOSE_WRITE`: one event per completed
  write-and-close, carrying a pidfd the kernel created from the event's own
  process reference, so the acting instance is bound by the kernel rather
  than by a pid number. The probe reads nothing through the descriptor. The
  path is required — `FAN_MARK_MOUNT` makes the choice of mount the choice
  of how much of the host is watched, and there is no safe default.
- `afpacket` (`CAP_NET_RAW`) binds a device tap and records TCP/IP
  **headers only**: addresses, ports, flags, sequence numbers and the
  payload *length*. No payload byte is copied, hashed or kept (I23). The
  device layer knows no task, so a wire segment is never bound to an
  instance — it proves bytes crossed a device, not who sent them.

Neither owes an integrity report and neither is asked for one: neither
reaches the probe through a perf tracepoint, so neither is exposed to the
eBPF submission gate those reports exist to detect. A requested sensor that
cannot be opened is a startup error, never a silent downgrade. Live tests
drive both against the real kernel (`aip-probe/tests/live_sensors.rs`),
including that no file content and no wire payload reaches a batch.

## What Phase 1 does not include (named, not hidden)

- ~~TLS/mTLS as an in-process layer~~ — confidentiality is in-process since R9 (Noise NK); TLS at the *service* ingress remains a proxy concern (plan B1, R9b).
- HSM/KMS custodian (plan B4; the `Custodian` trait is the seam).
- ~~Persistence of the attested batches themselves~~ — **done.** This was
  listed here as future work, and it was the item that made the phase's own
  exit gate unreachable: the collector attested a batch, returned its
  sequence in the acknowledgement and dropped it, so *"the verifier accepts
  it offline"* had nothing on disk to accept. `RuntimeSink` now appends every
  `AttestedBatch` to `attested.archive.jsonl` in the state directory
  (`AIP_COLLECTOR_ATTESTED_ARCHIVE_PATH` overrides the path), the collector
  publishes its evidence **public** key as `observer.pub` so an auditor can
  be given the anchor without anyone unwrapping the private half, and
  `aip-observe-verify` reads the two archives offline. An archive write
  failure is returned to the probe rather than logged: a probe must learn
  that its batch was not durably kept.
- Decision-point coverage statements (Phase 2).

## Test plan

- `aip-transport` unit: frame codec round-trip; oversize frame refused;
  handshake happy path; tampered auth signature rejected; wrong transport key
  rejected; replayed frame (same seq) rejected; reordered frame rejected.
- `aip-observe` unit: `resume_with_custodian` produces the same head/sequence as
  `resume` with the equivalent in-memory key; `start_with_custodian` round-trips
  a restart.
- Integration (loopback, in-process): probe client ships a real
  `ObservationBatch` to a collector server on `127.0.0.1:0`; the collector emits
  an `AttestedBatch` that `verify_attested_batch` accepts; adversarial —
  wrong transport key, replayed frame, tampered frame each rejected and no
  attestation produced.
- Exit gate (`aip-collector/tests/e2e.rs`): a batch shipped over the
  transport is attested, written to the archive, read back **from the file**
  and accepted under anchors the verifier supplies; a mutated line is
  refused.
- Offline verifier (`aip-observe-verify/tests/verify.rs`, ledger rows
  EA-01..EA-10): built against a real attested chain, not fixtures. Wrong
  key, edited observation, a record deleted from the middle, reordering,
  duplication, a corrupt line, an empty archive, a health head that
  disagrees with the batch at the same chain position — each refused; a
  clean chain and a mid-chain window each accepted, the latter reported as
  a window rather than as a chain complete from its origin.
- Live (`validation/pilot_e2e/run.sh`, Phase D): the verifier runs as a
  separate process against the archives the live collector just wrote, with
  only the published `observer.pub`, and must refuse the same archive with
  one record deleted.
