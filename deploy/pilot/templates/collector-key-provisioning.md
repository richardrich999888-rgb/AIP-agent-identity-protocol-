# Collector key provisioning (do this on the collector host only)

This is the one security-critical procedure in the pilot that is fully buildable
with the code in this repository today. It generates the collector's Ed25519
signing key, **wrapped at rest** (argon2id KDF + XChaCha20-Poly1305, via
`aip-crypto`'s `WrappedFileCustodian`), on the collector host.

The key **must** be generated on the collector host and **must never** be copied
to an observed (agent) host. The probe holds no key by construction; moving one
to it destroys the pilot's off-host-attestation guarantee (plan P3).

## Public API used (real, in-tree)

```rust
use aip_observe::{CollectorKey, CollectorSigner};

// First run creates the wrapped key file; every later start opens it.
// A development (in-memory) backend is refused under the production policy —
// there is no silent downgrade.
let key = CollectorKey::production(
    "/var/lib/aip-collector/collector.key.wrapped", // 0600, collector host only
    passphrase,                                      // from a secret store, not a literal
)?;

// The collector signs with the custodian; the private key is never returned.
let signer = CollectorSigner::with_custodian(
    observer_id,   // e.g. "aip-collector.bank.example"
    key_version,   // bump on rotation
    /* the custodian held by `key` */,
)?;
```

Rotation is `CollectorKey::rotate(path, passphrase)`; signatures made by the old
key stay verifiable for anyone holding its public key, because verification
never consults custody.

## Passphrase handling

- Source the passphrase from the bank's secret manager (systemd
  `LoadCredential=`, Vault, or an HSM-fronted secret) — never a file literal,
  never a process argument, never an environment variable committed anywhere.
- The wrapped key file is `0600`, owned by the collector service user, on the
  collector host's local disk. Back it up encrypted per the bank's DR plan
  (plan B3).

## What this does and does not give you

- **Gives:** a signing key that survives the process, is wrapped at rest, is
  refused if mistakenly configured with a development backend, and lives on a
  host the observed workload cannot reach.
- **Does not give:** an HSM/KMS-backed key. Production hardening (plan B4) moves
  this to a KMS/HSM custodian implementing the same `Custodian` trait. The
  wrapped-file custodian is the pilot-grade step, not the production endpoint.

## Verification after provisioning

- Confirm the key file is `0600` and owned by the service user.
- Confirm the public key you distribute to verifiers matches the one the
  collector signs with (export it once at provisioning; `aip-verify` and the
  reconciler are handed public keys out of band — never keys shipped inside an
  artifact).
- Confirm no key material exists on any agent host (`find / -name '*collector*key*'`
  on each probe host should return nothing).
