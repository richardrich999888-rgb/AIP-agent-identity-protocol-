# ADR — Two evidence-chain formats in one repository

**Status: OPEN — no decision made.** This document exists to stop the
decision being made by accident.

Raised by the merge of `orbitaltrust-accountability/` and the wiring of two
of its four Rust crates into the workspace (2026-09-20). The import itself
said the question was "a decision for the maintainers, not something this
import should make silently". It still is. What has changed is that the
second format is now **compiled** rather than dormant, so a caller can reach
it by mistake.

See `docs/adr/ADR-KEY-CUSTODY.md` for the ADR conventions on this branch.

---

## Context

This repository now contains two hash-chained evidence constructions. Both
are sound. They are not byte-compatible, and a packet sealed by one will not
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

## Options

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
other. Rejected for now: re-sealing across formats means one authority
vouching for another's bytes, and the re-sealer becomes a party the verifier
must trust. That is the opposite of what this system is for.

## What is NOT decided by this document

The choice between A and B. Both are defensible and the decision needs an
owner, not a default.

## Interim rule, in force until this ADR is closed

- No crate under `aip-standalone/` or `aip-service/` may depend on
  `ot-accountability-core`. Nothing does today, which is what makes this a
  rule rather than a migration.
- `ot-accountability-core`'s format must not be described to an external
  party as one of this system's evidence formats. The RBI submission
  documents deliberately do not mention it; two incompatible evidence chains
  is not something to put in front of a regulator while it is
  mid-resolution.
- **The exclusion is a test, not prose.**
  `aip-standalone/aip-test/tests/evidence_chain_boundary.rs` scans every
  `Cargo.toml` outside `orbitaltrust-accountability/` and fails if any
  declares `ot-accountability-core`, including under `[dev-dependencies]`,
  which is the cheapest way to reintroduce it. A second test pins that the
  crate still exists, so the guard cannot start forbidding something absent
  and pass forever. Both were verified against a deliberate violation: adding
  the dependency to `aip-test` fails the guard, removing it passes.
- To close this ADR under option A, that test becomes permanent and its
  message changes. To close it under option B, both tests go. Either way the
  decision is made in this file first and the test follows it — not the other
  way round.
