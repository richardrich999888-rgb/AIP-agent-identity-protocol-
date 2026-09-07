# Private Key Custody — Inventory and Decision

**Status** ANALYSIS + DECISION. Produced before any code change.
**Branch** `claude/codebase-production-readiness-wm6idp` @ `197ea5a`
**Scope** Private key custody only.

---

## 0. Two corrections to the stated blocker

Both were established by reading the code, and both change what the fix must
be. Recording them before proposing anything.

### 0.1 The collector signing key is **not** stored as plaintext JSON

The brief states the plaintext-JSON blocker "includes the collector signing
key, which is the cryptographic anchor for attested observations."

It does not. `CollectorSigner` (`aip-observe/src/attest.rs:357`) has:

- **no `Serialize` / `Deserialize` derive** (`grep` for one returns 0 hits),
- **no persistence path anywhere in the workspace**,
- a **private** `private_key: Vec<u8>` field with no accessor.

Every call site constructs it from bytes the caller supplies. The observer key
is therefore never written to disk *by this codebase*.

That is not reassuring, and the real problem is arguably worse than the one
described: **the observer key has no custody story at all.** Whoever deploys a
collector obtains key bytes from somewhere unspecified and passes them in.
There is no generation path, no storage contract, no rotation procedure and no
guidance. "Not persisted insecurely" is not the same as "custodied."

### 0.2 What *is* stored as plaintext JSON

`aip_core::store::IdentityStore` persists `StoredIdentity { aid, keypair }`,
and `KeyPair` carries `pub private_key: Vec<u8>` with `Serialize`.

`IdentityStore::save` (`store.rs:138`) writes with `std::fs::write` and
**no permission control whatsoever** — no mode, no `O_EXCL`, no chmod. The file
lands at whatever the process umask allows, commonly `0644`, containing
**agent private keys as pretty-printed JSON**.

Written by `aip-cli` (`main.rs:129-130`) on every identity creation.

This is worse than a missing encryption layer: even the file-permission
mitigation that costs nothing is absent.

---

## 1. Key inventory

| # | Key | Owner | Generation | Storage | Use | Exportable? | Rotation | Revocation | Backup | Recovery | Level |
|---|---|---|---|---|---|---|---|---|---|---|---|
| K1 | Agent identity keypair | `aip-types::KeyPair`, persisted by `aip-core::store` | `create_identity` | **plaintext JSON, umask perms** | packet + action signing | **YES** — `pub private_key`, `Serialize` | none | none | file copy | file copy | **BROKEN** |
| K2 | Collector / observer signing key | `aip-observe::CollectorSigner` | **caller-supplied; no path** | **none — never persisted** | attested batches, sensor health | No — private field, no accessor | `(observer_id, key_version)` anchors exist | anchor removal | undefined | undefined | **UNDEFINED CUSTODY** |
| K3 | Service signing key | `aip-service::keys::KeyPair` | `load_or_generate` | base64 seed file, `fs::write` **then** chmod 0600 | JWT issuance, bundle manifests | via `private_pem`, `signing_seed()` | none | none | file copy | file copy | **WEAK** |
| K4 | Decision point key | `aip-authorize::DecisionPoint` | caller-supplied | none | signs `ExpectedExecution` | No — private field | via anchors | anchor removal | undefined | undefined | UNDEFINED CUSTODY |
| K5 | Warrant authority key | `aip-warrant::WarrantAuthority` | caller-supplied | none | signs warrants | No — private field | via anchors | anchor removal | undefined | undefined | UNDEFINED CUSTODY |
| K6 | Containment authority key | `aip-containment::ContainmentAuthority` | caller-supplied | none | signs containment records | No — private field | via anchors | anchor removal | undefined | undefined | UNDEFINED CUSTODY |
| K7 | NEXORA signer key | `aip-nexora` | caller-supplied | none | signs proofs / commitments | No — private field | via anchors | anchor removal | undefined | undefined | UNDEFINED CUSTODY |
| K8 | Test / development keys | `aip-test`, `aip-real-tests`, demos | `generate_ed25519_keypair` | in-memory | fixtures | yes | n/a | n/a | n/a | n/a | acceptable **if** it cannot be a production path |

### The shape of the finding

**Six of the seven production key types (K2, K4–K7) already implement the
correct pattern**: a private field, constructed once, used only through a
`sign()` method, with no accessor. That is a custodian, six times over, with
no common interface and no storage contract.

Only **K1 and K3 have a storage path at all**, and both are defective:

- **K1** is exportable by type (`pub private_key` + `Serialize`) and written
  with no permissions.
- **K3** has the write-then-chmod race and regenerates a *new identity* on any
  load failure, silently rotating the service's identity.

So the fix is not "encrypt a JSON file." It is: give the six correct
implementations one named interface, give the two defective ones a real
storage contract, and make production refuse the development path.

---

## 2. Custody options evaluated

| | **A** OS keyring | **B** passphrase-wrapped file | **C** TPM non-exportable | **D** HSM | **E** external KMS | **F** hybrid: one interface, pluggable backends |
|---|---|---|---|---|---|---|
| Linux edge | daemon dependency (`gnome-keyring`, DBus) — often absent headless | **yes** | varies by SoC | rare | needs network | **yes** |
| UAS / UGV / robotics | usually unavailable | **yes** | some SoCs | no | **no** (link-constrained) | **yes** |
| Offline | yes | **yes** | yes | yes | **no** | **yes** |
| Provisioning complexity | medium | **low** | high | high | medium | **low now, high later by choice** |
| Non-exportability | no | **no** | **yes** | **yes** | **yes** | per backend |
| Backup / recovery | awkward | **straightforward** | **hard by design** | hard | provider-managed | per backend |
| Rotation | manual | **file + version** | attested | attested | provider | **uniform** |
| Fleet replacement | per-host | **file provisioning** | per-device | per-site | central | **per backend** |
| Containers | poor (no session bus) | **good** | needs passthrough | no | good | **good** |
| Testing | poor | good | very poor | very poor | poor | **explicit dev backend** |
| Dev usability | poor | good | poor | poor | medium | **good** |
| Air-gapped / sovereign | yes | **yes** | yes | yes | **no** | **yes** |

**Selected: F — one signing interface with pluggable custody backends**, and
**B (OS-protected, mode-enforced file)** as the only production backend
implemented now.

### Why

- **A is not viable at the edge.** A headless UAS or industrial node usually
  has no session keyring daemon, and a custody mechanism that is unavailable
  on the primary target is not a custody mechanism.
- **C, D, E each need a new trust anchor or a network.** C and D are ADR-002
  territory and must not be smuggled in here. E breaks the offline requirement
  that the space and disconnected profiles depend on.
- **B is the smallest production-credible step**: `O_EXCL` creation at mode
  0600, a permission check on load, and fail-closed behaviour. It works
  headless, offline, air-gapped and in containers, and it is testable.
- **F is what stops this becoming a redesign later.** The observer protocol
  never sees a key — it sees a signature. Adding a TPM backend later is a new
  implementation behind the same interface, not a protocol change.

### What B does and does not protect

**Protects:** another local user reading the key file; a key written
world-readable by umask; a key silently replaced on a corrupt read; a caller
casually serialising a key.

**Does not protect:** root on the host; a process with the same uid; memory
disclosure; an attacker with physical possession of the disk. Mode 0600 is a
file permission, not a hardware boundary, and this document does not call it
one.

---

## 3. Trust separation (stated because it is easy to lose)

```
key custody          ≠  hardware attestation
hardware-backed key  ≠  hardware-attested execution
                     ≠  physical-effect proof
```

A better-protected observer key makes it harder to *forge* an observation. It
says nothing about whether the observation is *true* — a root-compromised host
still lies to its own probe, which is why observed content is capped at
`Attested`. **ADR-002 remains PROPOSED and nothing here changes it.**

---

## 4. Provisioning lifecycle

```
INITIALIZATION → GENERATION → REGISTRATION → OPERATION → ROTATION → REVOCATION → REPLACEMENT
```

| Event | Behaviour |
|---|---|
| First boot | No key present → generate, write `O_EXCL` mode 0600, register the public key with the verifier |
| Reboot | Load; permission-check; **fail closed** on any defect |
| Process restart | Same as reboot — no state carried in memory |
| Host replacement | New key, new `key_version`; old version stays anchored so history verifies |
| Key loss | Fail closed. A new key is a new version, never a silent substitution |
| Key compromise | Verifier removes that `(id, version)` anchor; batches signed under it stop verifying from that point by policy |
| Observer replacement | New `(observer_id, key_version)` pair; the existing anchor model already supports it |

## 5. Rotation and revocation

The existing `ObserverTrustAnchors` model — `(observer_id, key_version) → key`
— already distinguishes **old** (anchored, superseded), **new** (anchored,
current), **revoked** (removed) and **unknown** (never anchored). Reusing it
rather than inventing a second scheme is deliberate: two rotation schemes in
one system is two schemes to get wrong.

**Historical proofs signed under a valid old key remain verifiable** while its
anchor is retained. Revocation is anchor removal, and whether a past signature
is still *acceptable* is verifier policy, not a property of the record.

---

## 6. Decision

1. Introduce `aip-custody`: one signing interface with **no key accessor**, so
   non-exportability is a property of the interface rather than a convention.
2. Backends: `DevCustodian` (in-memory, explicitly non-production) and
   `FileCustodian` (`O_EXCL`, mode 0600, permission-checked, fail-closed).
   `HardwareBacked` is a **reserved, unconstructible** class so its absence is
   visible rather than silently missing.
3. `CustodyPolicy::Production` **refuses** the development backend and refuses
   plaintext key persistence. No silent fallback.
4. Repair K1: `IdentityStore` refuses to persist private key material under a
   production policy, and writes mode 0600 under a development policy.
5. Repair K3: `load_or_create` replaces `load_or_generate` — create only when
   absent, `O_EXCL` at mode 0600, fail closed otherwise.
6. K2 and K4–K7 keep their existing private fields and gain the named
   interface; **no key moves crate**. Observer key custody stays in
   `aip-observe`.

> **Revised during implementation.** Item 1 was written as a single
> `SigningCustodian` trait. Building item 6 showed that giving the six domain
> authorities a general `sign(&[u8])` would hand each of them a raw-signing
> oracle: a caller could obtain the warrant authority's signature over bytes
> that are a valid containment-record preimage, and the containment verifier
> would accept it. Cross-protocol signature confusion, introduced by the
> abstraction meant to tighten key handling. The trait was therefore split —
> see §7.

### Out of scope, reported not fixed

- `aip-standalone` and `aip-service` are separate Cargo roots on this branch,
  so no single command builds both. Unrelated to key custody.

---

## 7. As built

### 7.1 The trait split

```
KeyCustody                       SigningCustodian: KeyCustody
  key_id()                         sign(&[u8]) -> [u8; 64]
  key_version()
  public_key()
  custody_class()
```

`KeyCustody` is what a key holder needs to be **inventoried and
policy-checked**. `SigningCustodian` adds general signing.

| Type | Crate | Implements | Why |
|---|---|---|---|
| `DevCustodian` | aip-custody | both | general signing is its purpose |
| `FileCustodian` | aip-custody | both | general signing is its purpose |
| `ServiceKey` | aip-service | both | signs audit-export manifests |
| `DecisionPoint` | aip-authorize | `KeyCustody` only | signs one preimage, through its own operation |
| `WarrantAuthority` | aip-warrant | `KeyCustody` only | ditto |
| `ContainmentAuthority` | aip-containment | `KeyCustody` only | ditto |
| `NexoraSigner` | aip-nexora | `KeyCustody` only | ditto |
| `ProofAssembler` | aip-nexora | `KeyCustody` only | ditto |
| `CollectorSigner` | aip-observe | `KeyCustody` only | ditto — and this is the observer key |

A narrow, domain-separated signing surface is **stronger** than a general one.
The split keeps it that way. `aip-observe/tests/key_custody.rs` asserts
structurally that `CollectorSigner` never gains `SigningCustodian`, and that no
crate outside `aip-observe` implements its custody.

`admits()` is a free function, generic over `KeyCustody + ?Sized`, rather than a
trait method: a trait method could be overridden by an implementation to report
a class it does not have, which is precisely what the policy exists to catch.

### 7.2 What the selected backend does and does not establish

`CustodyClass::OsProtectedFile` is a **plaintext key in a file the kernel
protects by permission**. Stated precisely, because the words matter:

**Protects against** — another local user reading the key; another local user
replacing it via a writable directory; a permissive `umask` at creation; an
accidental overwrite of an existing identity; a truncated or corrupt file being
mistaken for an absent one.

**Does not protect against** — `root`; any process with the same uid; memory
disclosure of this process; possession of the disk, a snapshot or a backup; an
offline attacker with the file.

It is **not** hardware-secured, **not** tamper-proof, and **not**
non-exportable at the storage layer. Non-exportability here is a property of
the *interface*: no code path in this workspace returns key material to a
caller. That is a narrower and more honest claim than a hardware backend would
earn, and it is the only one made.

Key material is **not zeroized on drop**. Memory disclosure is outside what this
class claims, and a reallocated `Vec<u8>` cannot be reliably wiped; claiming
otherwise would be the kind of thing this crate exists to stop.

### 7.3 The on-disk key format

Fixed binary layout, written and parsed by hand — no `serde`, and no custodian
type derives `Serialize`:

```
offset  size  field
0       8     magic "AIPKEY" + format version u16 LE
8       4     key_version u32 LE
12      2     key_id length u16 LE
14      n     key_id (UTF-8)
14+n    32    private key
46+n    32    public key
```

Total length is exactly `78 + n`; anything else is refused. On load, the stored
private key signs a fixed domain-separated probe and the stored public key must
verify it — a mismatched pair would otherwise produce signatures that fail far
away, at the relying party, as an unexplained rejection.

"Never *casually* serialized" is the invariant. This encoding is a deliberate,
reviewed act at one call site; a `derive` is what follows a struct into every
JSON response somebody writes later.

---

## 8. Migration requirements

Nothing here invalidates a historical proof package. The signature envelope, the
bundle bytes, `verify_zip`, `verify_attested_batch` and every trust anchor are
untouched. **Key storage changed; key identity did not.**

Two artefacts on disk need an operator decision.

### 8.1 An existing identity store containing plaintext key pairs

`IdentityStore::with_file` now **refuses** such a file with
`StoreError::PlaintextKeysPresent`. It does not open it. The alternative —
loading it and dropping the keys on the next `save()` — would rewrite the file
without them, destroying every private key it holds, irreversibly and silently.

Either:

- **Production path.** Move each key into its own `FileCustodian` file
  (`aip-cli` now does this automatically for identities it creates: the store
  path plus `.keys/<aip-id>.key`, in a directory at mode 0700), and rewrite the
  store with public data only.
- **Development path.** Open it with
  `IdentityStore::with_file_and_plaintext_keys(path, CustodyPolicy::Development)`,
  accepting that the keys are unprotected. Test fixtures that round-trip a
  private key through a file are converted to this and named as fixtures.

### 8.2 An existing service seed file

The format is unchanged — base64 of the 32-byte seed — so no migration of
content is needed. Two operational changes:

- The file's **mode must be 0600** and its directory must not be writable by
  group or other (a sticky directory such as `/tmp` is accepted). A file at
  0644 now stops the service from starting rather than being loaded. Remedy:
  `chmod 600 <path>`.
- A **corrupt or unreadable** seed file now stops the service instead of
  silently minting a new identity. Remedy: restore from backup, or move the
  file aside to have a new identity created deliberately — and re-register the
  new public key with every relying party, which is exactly the work the old
  behaviour hid.

### 8.3 `build_zip` callers

`aip_protocol::build_zip` takes `&dyn SigningCustodian` in place of
`(&[u8; 32], &[u8; 32])`. Bundle bytes are unchanged and bundles produced before
and after verify identically. In-tree callers are migrated.
