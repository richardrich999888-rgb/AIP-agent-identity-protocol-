# ADR — Private-key custody backend

**Status: ACCEPTED** · Phase A of the production-blocker closure.

This is the only ADR on *this* branch. ADR-001, ADR-002 and ADR-003 do
exist, on `claude/autonomous-accountability-skills-16-30`
(`docs/architecture/ADR-00{1,2,3}-*.md`); they are simply not on the branch
this decision was made on. This document does not number itself into that
sequence and does not claim any relationship to it.

The one that bears on this decision is **ADR-002 — Hardware-Rooted
Attestation, status PROPOSED / NOT IMPLEMENTED**. Nothing here changes
that, and nothing here implements hardware attestation. `Backend::Tpm`,
`Backend::Hsm` and `Backend::Kms` are deliberately absent for the reason
given below, which is the same reason ADR-002 is a STOP rather than an
implementation.

See `docs/architecture/FINAL_AUDIT_RECONCILIATION.md` for how findings are
tracked in this repository.

---

## Context

Private key material was persisted as plaintext JSON by
`aip-core::store::IdentityStore`, in a file created mode 644, and
`aip-observe` offered no custody path at all for the collector's signing
key — the key that anchors every attested observation. A deployer's only
worked example was `ghost-demo-collector`, which writes a hex private key
with default permissions from a crate whose description says
`NOT_PRODUCTION_CAPABILITY`.

Ten key classes were inventoried. The crates that own the security-critical
signing keys — collector, decision point, warrant authority, NEXORA signer,
containment authority — all take `&[u8]` and persist nothing, so the
exposure was concentrated in `IdentityStore` and the demo binary, and the
gap was the absence of any supported alternative.

## The distinction this decision must not blur

> **Key custody is not attestation.**

A hardware-protected, non-exportable signing key establishes *who signed*.
It establishes nothing whatever about whether what was signed is true. The
three ideas stay separate throughout:

```
hardware-backed key   ≠   hardware-attested execution   ≠   physical-effect proof
```

No claim anywhere in this repository derives observation truthfulness from
key protection, and this decision introduces none.

## Options considered

| | Linux | edge / UAS / UGV | offline & air-gapped | provisioning | backup / recovery | rotation | host replacement | containers | dev usability | sovereign / defence |
|---|---|---|---|---|---|---|---|---|---|---|
| **A** OS credential store (keyring / Secret Service) | desktop only | ✗ no session bus | ✓ | daemon needed | opaque | via daemon | manual re-enrol | ✗ commonly absent | awkward headless | ✗ dependency on desktop stack |
| **B** Passphrase-wrapped file | ✓ everywhere | ✓ | ✓ | copy file + supply passphrase | copy the file | rewrap | copy or re-enrol | ✓ | ✓ | ✓ no external dependency |
| **C** TPM-sealed | ✓ where present | partial — many boards lack a TPM | ✓ | per-host enrolment | **not portable by design** | per-host | **full re-enrol** | needs device passthrough | ✗ | ✓ where hardware exists |
| **D** HSM | ✓ | ✗ | ✓ within an enclave | heavy | vendor | vendor | vendor | ✗ | ✗ | ✓ datacentre only |
| **E** External KMS | ✓ | ✗ | **✗ requires network** | account + IAM | provider | provider | provider | ✓ | ✓ | ✗ violates disconnected operation |
| **F** Hybrid: a custodian trait with pluggable backends | — | — | — | — | — | — | — | — | — | — |

## Decision

**F, with B as the only production backend implemented now.**

A `Custodian` trait in `aip-crypto::custody` is the single abstraction.
Two backends exist today and each names itself:

- `Backend::DevelopmentInMemory` — key material in process memory, never
  written anywhere. Tests and development. `is_production()` is false.
- `Backend::WrappedFile` — Argon2id (memory-hard) derives a key-encryption
  key from a passphrase; XChaCha20-Poly1305 wraps the signing key; the file
  is written mode 0600 via an atomic temp-and-rename. `is_production()` is
  true.

`Backend::Tpm`, `Backend::Hsm` and `Backend::Kms` are deliberately *not*
enumerated. Adding a variant that nothing implements would be a capability
claim, and this repository has spent considerable effort on not making
those. They arrive with their implementations.

**Why B and not C.** TPM sealing is stronger against an attacker with the
disk but not the host, and weaker against everything else the deployment
targets need: it is not portable, so backup and host replacement become
re-enrolment; many edge boards have no TPM; and container access requires
device passthrough. It is a good *second* backend behind this trait and a
poor only one.

**Why not E.** An external KMS requires the network. Disconnected and
air-gapped operation is a stated deployment property of this system, so a
custody mechanism that fails without connectivity would make the rest of
the design untrue.

## The API shape that matters

The trait signs; it does not surrender.

```rust
pub trait Custodian {
    fn public_key(&self) -> &[u8];
    fn sign(&self, signer_id: &str, payload: &[u8]) -> Result<Signature, CustodyError>;
    fn backend(&self) -> Backend;
}
```

There is no `private_key()`. A production custodian never returns key
material to a caller, and `WrappedFileCustodian` has no method that could.
The signing key is decrypted into a `Zeroizing` buffer for the life of the
custodian and wiped on drop.

Custody backends must not create alternate security semantics: every
backend produces the same `Signature` through the same `sign_ed25519`
envelope, so verification is unchanged and unaware of which backend signed.

## Ownership

`aip-observe` owns the collector key's custody. `aip-crypto` owns the
*mechanism*; `aip-observe` owns the *policy* for its own key, and no other
crate may. Observer trust is independent of the observed subject, and
moving that ownership into a platform, reconciliation or proof layer would
end that independence quietly.

## What this decision does not settle

- **Passphrase custody.** The wrapped file moves the problem from "protect
  a key" to "protect a passphrase", which is a smaller problem but not no
  problem. Where the passphrase comes from — an operator, a systemd
  credential, a sealed blob — is a deployment decision, and this repository
  does not make it.
- **An attacker with the running process.** Anyone who can read the
  process's memory has the decrypted key, on any software backend. That is
  what C and D exist to address, and they are not implemented.
- **Revocation.** Custody does not revoke. Revocation in this system is
  withdrawal of a trust anchor by the verifier, which already exists and is
  tested; adding a second revocation model inside custody would be a second
  security model.
