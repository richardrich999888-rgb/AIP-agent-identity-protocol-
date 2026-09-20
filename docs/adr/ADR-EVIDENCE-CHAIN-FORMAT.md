# ADR — Two evidence-chain formats in one repository

**Status: ACCEPTED (2026-09-20) — Option A, bounded coexistence, with the
observation-side adapter that makes it worth having.**

Raised by the merge of `orbitaltrust-accountability/` and the wiring of two
of its four Rust crates into the workspace (2026-09-20). The import itself
said the question was "a decision for the maintainers, not something this
import should make silently". This closes it.

See `docs/adr/ADR-KEY-CUSTODY.md` for the ADR conventions on this branch.

---

## Context

This repository contains two hash-chained evidence constructions. Both are
sound. They are not byte-compatible, and a packet sealed by one will not
verify under the other.

| | `aip-core` (`aip-standalone/`) | `ot-accountability-core` (imported) |
|---|---|---|
| Chain link | raw 32-byte digests, `previous_hash: [u8; 32]` | `SHA-256(previous ‖ canonical JSON)`, hex |
| Canonical form | length-prefixed binary, domain-separated | canonical JSON |
| Verifier | `aip-verify`, `nexora-verify`, `aip-observe-verify` | `ot-verifier` (**cannot build here** — needs `ot-pqc`, not imported) |
| In the workspace | yes, throughout | `ot-accountability-core` and `ot-sentinel` only |

The overlap is not limited to the chain. Evidence packets, identity and
delegation, and the verification CLI all exist twice, in different shapes.

## The forcing function

Before the wiring, the second construction was inert: files on disk that
nothing compiled. It is now a workspace member with 56 passing tests and a
dependent (`ot-sentinel`, 82 tests). That is a strict improvement in
capability and a strict increase in the cost of leaving this open, because:

1. A new caller can now `use ot_accountability_core::…` and seal something
   that none of this repository's three verifiers will accept.
2. `ot-sentinel` — the reason the wiring was worth doing — reconciles
   observed effects against *sealed packets*, and the packets it understands
   are the imported format's. Feeding it `aip-core` evidence is not a
   configuration change.
3. The technical brief tells a regulator that each of three evidence
   families has an offline verifier and that verification is a pure function
   of the artefact and the institution's keys. A fourth format with a
   verifier that does not build would make that sentence need a footnote.

## Options that were on the table

**A. Keep both, bounded.** Declare `ot-accountability-core` internal to the
sentinel's reconciliation path and forbid it as an evidence format for
anything that leaves the host. Cheapest; needs a guard test that fails if
any crate outside `orbitaltrust-accountability/` depends on it, or the
boundary is prose and will erode.

**B. Port the sentinel onto `aip-core`'s chain.** Keeps one evidence format
everywhere. The sentinel's value is the reconciliation primitive — set
difference keyed on the canonical parameter digest — not the chain under it,
so this is plausible. Cost: it rewrites imported code, breaking the SHA-256
manifest wholesale and forking from upstream, so future imports stop being
drop-in.

**C. Port `aip-core` onto the imported chain.** Rejected on sight, recorded
so nobody re-proposes it. `aip-core`'s construction is what every shipped
verifier, the NEXORA log, the attested-batch chain and the sealed adversarial
evidence already use. Changing it invalidates all of that and every
demonstration in `docs/security/ADVERSARIAL_RESULTS.md`.

**D. A translation layer.** A packet sealed in one format re-sealed in the
other. Rejected: re-sealing across formats means one authority vouching for
another's bytes, and the re-sealer becomes a party the verifier must trust.
That is the opposite of what this system is for.

## Decision

**Option A**, with an addition the original framing missed.

### Why A and not B

B rewrites 6,181 lines and 82 passing tests, forks permanently from upstream,
and buys nothing any external deliverable uses: the RBI submission documents
deliberately do not mention `ot-accountability-core` and do not need to. That
is a large regression risk against no gain. A is cheap, is already true, and
is already enforced by a test rather than by prose.

### Why A alone was not enough

As the open version of this document noted, `ot-sentinel` reconciles against
sealed packets **in the imported format**. Under a bare option A the sentinel
could therefore never consume AIP evidence, and closing the ADR that way would
leave a 6,181-line crate in the workspace that AIP cannot use for anything.
Tidy, and useless.

The way through is on the other axis. **The format conflict is entirely on the
evidence side** — sealed packets and the chain under them. The sentinel's
*observation* side carries no chain at all: it is a list of things a sensor
saw, read by `JsonlEffectLog` from a plain JSONL file.

That side is also where the sentinel is weakest. Its effect sensor was
designed to tail logs written by the components being watched — a tool
server's own access log is the tool server's account of itself — and
`sensors.rs` records that the `EffectConformanceDetector` "had nothing feeding
it" at all. AIP observes process spawns and connections **from the kernel**,
binds them to instances through pidfd, and has an off-host collector sign the
result. It is the sensor that crate's own source comments ask for.

So: **`aip-standalone/aip-sentinel-feed`** renders verified AIP evidence as an
effect log the sentinel tails. No packet crosses formats. Nothing is re-sealed.
No authority vouches for another's bytes — the objection that sank option D
does not arise, because no evidence is translated: an observation is not a
packet, and the feed asserts only what a sensor saw.

**The coupling is a file, not a link.** `aip-sentinel-feed` does not depend on
`ot-sentinel` or on `ot-accountability-core`. One process writes JSONL; the
other tails JSONL.

### What was built to close this

* `aip-standalone/aip-sentinel-feed` — verify-first adapter, 34 tests.
  Verifies the archive under the observer's anchor before rendering anything;
  the binary exits 1 and writes nothing if that fails. Every event that cannot
  be rendered honestly is dropped **and counted**, including the unbound events
  derivation never sees.
* `orbitaltrust-accountability/rust/aip-feed-conformance` — a **test-only**
  crate, 4 tests, and the only place the two worlds link. It proves the real
  Phase-1 feed parses through `ot-sentinel`'s own tailer with zero malformed
  lines, and that kernel-observed effects drive its detectors — with a
  soundness control proving the detector is not simply always red.

  It sits **inside** `orbitaltrust-accountability/`, which is the bounded
  region this ADR draws, so the rule below holds literally and in substance:
  the link exists in one test binary, seals nothing, and ships nothing.

### What this is not

Not independent corroboration. `ot-sentinel` was written by the same people
as AIP. Corroboration means an observer someone else built — `aip-corroborate`
(bpftrace, auditd) and `aip-spiffe` (SPIRE). This completes an architecture;
it does not validate one, and no external document may present it as though
it did.

## The rule, now permanent

- No crate under `aip-standalone/` or `aip-service/` may depend on
  `ot-accountability-core`, directly or transitively, including under
  `[dev-dependencies]`.
- `ot-accountability-core`'s format must not be described to an external
  party as one of this system's evidence formats. It is internal to the
  sentinel's reconciliation path.
- A crate that must link both worlds lives under
  `orbitaltrust-accountability/`, is test-only, and seals nothing.
  `aip-feed-conformance` is the only such crate today.
- **The exclusion is a test, not prose.**
  `aip-standalone/aip-test/tests/evidence_chain_boundary.rs` scans every
  `Cargo.toml` outside `orbitaltrust-accountability/` and fails if any
  declares `ot-accountability-core`. A second test pins that the crate still
  exists, so the guard cannot start forbidding something absent and pass
  forever. Both were verified against a deliberate violation: adding the
  dependency to `aip-test` fails the guard, removing it passes.

## What reopening this would take

Evidence that the bounded region is leaking — a crate outside it needing the
imported chain for a reason the feed cannot serve — or a decision to ship
`ot-verifier`, which would require importing `ot-pqc` and would make the
second format externally visible. Neither is true today. Option B remains the
fallback and its cost estimate above stands.
