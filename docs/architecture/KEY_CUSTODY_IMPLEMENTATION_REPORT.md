# Private Key Custody — Implementation Report

**Branch** `claude/codebase-production-readiness-wm6idp`
**Base checkpoint** `197ea5a`
**Decision** [`docs/adr/ADR-KEY-CUSTODY.md`](../adr/ADR-KEY-CUSTODY.md) — **ACCEPTED**
**Inventory and options** [`KEY_CUSTODY_INVENTORY.md`](KEY_CUSTODY_INVENTORY.md)

---

## 0. A note on how this branch was worked

Two agents worked this blocker independently and both pushed to this branch.
Two complete key-custody implementations existed for a time. They have been
reconciled: `aip_crypto::custody` (Phase A) is the surviving architecture, and
the second implementation was dissolved with its distinct contributions ported
onto it. The brief forbids multiple implementations of the same semantics, and
there is now one.

What was kept from each, and why, is §5 and §6. Nothing was discarded to avoid
the work of merging it.

## 1. Status

**Complete for the scope defined: private key custody.** A custody boundary
exists, all three broken storage paths are repaired, the mandated tests and ten
mutations pass, and three consecutive full-suite runs are identical.

**Not production-ready, and not claimed to be.** The production backend
encrypts the key at rest under a passphrase; where that passphrase comes from
is a deployment decision this repository does not make, and anyone who can read
the running process's memory has the decrypted key regardless. Five of the
eight key types are inventoried and policy-checkable but still receive raw key
bytes from their operator at construction — named custody, not yet secure
provisioning. See §18.

## 2. Root cause

The stated blocker was inaccurate in one respect and understated in two others.

**The collector signing key was not stored as plaintext JSON.**
`CollectorSigner` has no `Serialize` derive, no persistence path and no
accessor. The real problem was the opposite: *no custody story at all*. It took
raw key bytes from whoever constructed it, and the only worked example of
persisting one was a demo binary writing hex at mode 644.

**What was plaintext JSON is the agent identity key.** `aip_core::store`
serialized `StoredIdentity { aid, keypair }` — private key included — through
`serde_json` and `std::fs::write`, with no mode and no policy.

**Two further defects of the same class, in code the original brief did not
name:**

- `aip-service` had no custody at all. `KeyPair::load_or_generate` generated a
  **new** key on *any* load error, silently rotating the service identity and
  invalidating every JWT and audit bundle ever signed, while reporting success.
  On a failed write it continued with an ephemeral key. It also exposed
  `signing_seed()`, and `AppState` held the raw 32-byte private key in the
  state shared with every HTTP handler in the process.
- Both the store's `save` and the wrapped custodian's `write` created the file
  and `chmod`-ed it **afterwards**. `fs::write` creates at `0o666 & !umask`, so
  key material was world-readable for the interval between the two syscalls.
  The custody module's own comment claimed the opposite of what its code did.

The root cause underneath all of it: **six of seven production signer types had
independently implemented the correct pattern — a private field, a `sign()`
method, no accessor — and none of them was named.** An unnamed convention
followed six times is one the seventh implementer breaks. Two already had.

## 3. Key inventory

| # | Key | Crate | Before | After |
|---|---|---|---|---|
| K1 | Agent identity keypair | aip-core | **BROKEN** — plaintext JSON, `fs::write`, no mode, no policy | `Persistence` named at construction; a production store refuses to write key material; the field is private with no accessor and no serialization derive; file created owner-only by the open call |
| K2 | Collector / observer signing key | aip-observe | UNDEFINED CUSTODY | `CollectorKey` in `aip-observe`, backed by a custodian; a production collector refuses a development backend |
| K3 | Service Ed25519 seed | aip-service | **WEAK** — `load_or_generate`, write-then-chmod, `signing_seed()` accessor, raw seed in `AppState` | `ServiceKey::load_or_create`, wrapped or classified plaintext, permission-checked, no accessor, `Arc<dyn RawSigner>` in state |
| K4 | Decision point key | aip-authorize | UNDEFINED CUSTODY | Takes `&[u8]`, persists nothing; a supported custodian exists to hold it |
| K5 | Warrant authority key | aip-warrant | UNDEFINED CUSTODY | as K4 |
| K6 | Containment authority key | aip-containment | UNDEFINED CUSTODY | as K4 |
| K7 | NEXORA signer + proof assembler | aip-nexora | UNDEFINED CUSTODY | as K4 |
| K8 | Test / demo keys | (tests, ghost-demo) | ad hoc, hex at mode 644 | `InMemoryCustodian`, `Backend::DevelopmentInMemory`, `is_production() == false` |

## 4. Custody options evaluated

Six options against twelve dimensions. Both independent evaluations reached
**F with B**, from opposite starting positions; the matrices are in the ADR and
in `KEY_CUSTODY_INVENTORY.md` §2.

| Option | Verdict |
|---|---|
| **A** OS keyring / platform credential store | Rejected — no session bus on a headless edge collector; commonly absent in containers |
| **B** Passphrase-wrapped file | **Implemented** as the production backend |
| **C** TPM-sealed | Deferred — ADR-002 territory; not portable, so backup and host replacement become re-enrolment, and many edge boards have no TPM. A good *second* backend, a poor only one |
| **D** HSM | Deferred — unavailable at the edge |
| **E** External KMS | Rejected — requires the network; disconnected and air-gapped operation is a stated property of this system |
| **F** Hybrid: one custodian trait, pluggable backends | **Selected** |

The one substantive disagreement between the two evaluations was B. It was
rejected in `KEY_CUSTODY_INVENTORY.md` §2 on the grounds that an unattended
collector must hold the passphrase somewhere the same process can read, making
the wrapped file plus the stored passphrase exactly as strong as the unwrapped
file. The ADR accepts that argument and scopes it honestly — where the
passphrase comes from is a deployment decision it does not make — and B wins
anyway on the case a permission bit cannot touch: **an attacker holding the
volume, a snapshot or a backup.** Encryption at rest is strictly stronger
there. The reasoning stands; the conclusion changed.

## 5. Selected architecture

```
Custodian                          RawSigner
  public_key()                       public_key()
  sign(signer_id, payload)           sign_raw(&[u8]) -> [u8; 64]
  backend()
     ├── InMemoryCustodian       Backend::DevelopmentInMemory
     └── WrappedFileCustodian    Backend::WrappedFile
         Argon2id → KEK, XChaCha20-Poly1305 wraps the key,
         header bound as AEAD associated data, mode 0600
```

- **No `private_key()`.** A caller cannot leak what it cannot obtain. The
  decrypted key lives in a `Zeroizing` buffer for the life of the custodian.
- **One set of semantics.** Every backend produces the same `Signature` through
  the same `sign_ed25519` envelope, so a verifier cannot tell which backend
  signed and does not need to.
- **`Backend::Tpm`, `Hsm`, `Kms` are deliberately absent.** A variant nothing
  implements is a capability claim. They arrive with their implementations.
- **`Backend::PlaintextFile`** was added for the service's legacy seed file:
  `is_production()` is false, so a policy check can refuse it. It names
  something the repository actually does rather than something it might.

The invariant is structural:

```
private key → no accessor on either trait
            → no serialization derive on any type that holds one
            → used through a controlled signing operation
            → signature returned
            → verification remains independent (public key only)
```

## 6. Why it was selected

**F over a single backend** because the problem was never one file. Eight key
types, four deployment classes and three already-broken paths need a
*boundary*, and a boundary lets C or D arrive later as a backend rather than a
rewrite. That is precisely what the brief asked for: "the design must support
stronger hardware-backed custody later without requiring a redesign of the
observer protocol."

**B as the production backend** because it is the strongest thing that is
actually true today on the target deployment — headless edge, no session bus,
no TPM guarantee, offline-capable — and it protects against the disk, the
snapshot and the backup, which is the threat a permission bit cannot reach.

**`RawSigner` separate from `Custodian`.** An audit-export manifest is signed
as a detached 64-byte signature so it can be checked offline with nothing but
the public key and the bytes, which the `Signature` envelope does not provide.
Widening `Custodian` with `sign_raw` would have handed a raw-signing oracle to
every implementor — including `CollectorKey`, whose holder could then obtain
the observer key's signature over arbitrary bytes, including bytes that are a
valid preimage for another protocol in this workspace. Cross-protocol signature
confusion, introduced by the abstraction meant to tighten key handling. So the
two capabilities are separate traits and a type opts in to the wider one.
**`CollectorKey` deliberately does not.**

## 7. Production / development distinction

| | Development | Production |
|---|---|---|
| Store | `Persistence::DevelopmentPlaintext` — writes private keys, still owner-only | `Persistence::ProductionNoSecrets` — an identity carrying a key makes `save` **fail**, named with a count, rather than being silently stripped |
| Collector | `CollectorKeyPolicy::Development` | `CollectorKeyPolicy::Production` — a development backend is refused, not downgraded |
| Service | `AIP_CUSTODY_POLICY=development` | default — refuses to start unless the backend's `is_production()` is true |
| Backends admitted in production | all implemented | `WrappedFile` only |

Named at construction, never inferred. The service reads its environment once,
at the process edge, and the decision travels as a value.

Refusal is refusal: a collector signing with an in-memory key is not a slightly
weaker production collector, it is a development one, and calling it production
is the mistake. There is no downgrade path anywhere.

## 8. Observer-key treatment

- The key **stays in `aip-observe`**. `aip-crypto` supplies the mechanism;
  `aip-observe` owns the policy for this key, and no other crate does.
  Structurally asserted by a test that walks every `.rs` file in the workspace.
- **Nothing moved** into AIRI, reconciliation, a platform layer or packaging.
- **Verifier trust is untouched.** `ObserverTrustAnchors` still decides what is
  trusted, keyed by `(observer_id, key_version)`. No custody code adds, removes
  or consults an anchor. Custody is a property of the signer; it is not
  evidence, and no evidence-strength decision anywhere reads which backend
  signed.
- A protected key raises the cost of forging the *signature* and says nothing
  about the truthfulness of the observation. A collector whose key is in an HSM
  and whose probe is lying produces impeccably signed lies.

## 9. Provisioning lifecycle

```
INITIALIZATION → GENERATION → REGISTRATION → OPERATION → ROTATION → REVOCATION → REPLACEMENT
```

| Event | Behaviour | Enforced by |
|---|---|---|
| First boot | No key → generate in place, wrapped, mode 0600 by the open call | `WrappedFileCustodian::create`, `ServiceKey::load_or_create` |
| Reboot / process restart | Load, permission-check, **fail closed** on any defect | `check_secret_file` |
| Key absent | The **only** condition under which generation happens | tests `a_1_11`, `wrapped_first_boot…` |
| Corrupt, unreadable, wrong passphrase, bad mode | Error. **Never** regenerated | `corrupt_or_unopenable_wrapped_key_is_fatal_and_never_regenerated` |
| Host replacement | New key, new observer id; inherits no coverage, chain restarts at sequence 1 | `a_9_a_replacement_observer_is_a_new_identity` |
| Key loss | Fail closed. A new key is a new version, never a substitution | `create` refuses to overwrite |
| Key compromise | Verifier removes the `(id, version)` anchor | `a_8_revoked_key_fails_as_untrusted_not_as_bad_crypto` |
| Backup / recovery | **Operator's**, over the wrapped file, which is portable by design — unlike a TPM-sealed key. This code refuses to paper over a lost key by minting a new one | documented |

## 10. Rotation and revocation lifecycle

The existing `ObserverTrustAnchors` model is reused rather than a second scheme
invented — two rotation schemes in one system is two schemes to get wrong.

| State | Representation | Verifier outcome |
|---|---|---|
| old | anchored, superseded | verifies — **history stays verifiable** |
| new | anchored, current | verifies |
| revoked | anchor removed | `UntrustedObserverKey` |
| unknown | never anchored | `UntrustedObserverKey` |

Revocation is a **trust** failure, kept distinct from a cryptographic one, so
an operator can tell forgery from revocation. Re-anchoring the same key
restores verification with no change to the batch — proof that revocation is a
policy decision and not damage to the record. Rotation changes the key and
never the identity, and a malformed key is refused before anything is assigned.
**No historical proof package is invalidated by any change in this work.**

## 11. Files changed

Across the reconciled result: the new `aip_crypto::custody` module and
`aip_observe::custody`, the store, the service, the bundle builder, and their
tests.

| Area | Files |
|---|---|
| Custody mechanism | `aip-crypto/src/custody.rs` — `Custodian`, `Backend`, `InMemoryCustodian`, `WrappedFileCustodian`, plus `RawSigner`, `Backend::PlaintextFile`, `check_secret_file`, `create_owner_only`, `write_owner_only_file`, `wrapped_file_seed` |
| Observer key policy | `aip-observe/src/custody.rs`, `aip-observe/tests/custody.rs` |
| K1 | `aip-core/src/store.rs`, `src/lib.rs`, `src/simulation.rs`, `tests/custody.rs` |
| K3 | `aip-service/src/{keys,lib,main,evidence,test_support,tokens,wellknown}.rs`, `aip-service/tests/key_custody.rs` |
| Bundle signing | `aip-protocol/src/bundle.rs`, `tests/common/mod.rs`, `tests/bundle.rs`, `tests/signer_anchored.rs` |
| Envelope dedupe | `aip-crypto/src/lib.rs` (`signature_signed_bytes`) |
| Callers | `aip-cli/src/main.rs`, `aip-test/src/lib.rs`, `aip-real-tests/src/e2e.rs` |
| Docs | `docs/adr/ADR-KEY-CUSTODY.md`, `KEY_CUSTODY_INVENTORY.md`, this report |

## 12. Tests

The mandated list, and where each is discharged:

| # | Requirement | Test |
|---|---|---|
| 1 | plaintext persistence rejected in production | `a1_a_production_store_must_refuse_to_write_a_private_key_in_the_clear`, `production_roundtrip_yields_a_verifiable_but_unsignable_identity` |
| 2 | private key not returned through normal API | `a_4_5_no_caller_can_obtain_the_private_key_through_the_custodian`, `stored_identity_keypair_is_private_and_unserializable`, `structural_no_private_key_accessor_remains`, `debug_redacts_the_seed_and_the_private_pem` |
| 3 | signing works through the abstraction | `signing_through_the_interface_verifies_normally`, `key_material_crosses_the_boundary_in_one_place_each` |
| 4 | verification still works | `signing_through_the_interface_verifies_normally`; every pre-existing bundle, packet and observer suite, unchanged |
| 5 | wrong identity cannot use signer | `a_5_14_wrong_identity_and_wrong_key_are_both_rejected` |
| 6 | unauthorized caller cannot export key | `a_4_5_no_caller_can_obtain_the_private_key_through_the_custodian`, `structural_no_private_key_accessor_remains`, `stored_identity_keypair_is_private_and_unserializable` |
| 7 | key rotation | `a_7_rotation_keeps_history_verifiable`, `a_7_guard_rotation_refuses_a_bad_key_and_leaves_the_old_one` |
| 8 | revoked key | `a_8_revoked_key_fails_as_untrusted_not_as_bad_crypto`, `a_8_unknown_key_version_is_refused` |
| 9 | replacement key | `a_9_a_replacement_observer_is_a_new_identity` |
| 10 | reboot / reload lifecycle | `a_1_11_first_initialization_and_restart_keep_the_same_key`, `wrapped_first_boot_creates_and_restart_reloads_the_same_key`, `plaintext_first_boot_creates_and_restart_reloads_the_same_key` |
| 11 | missing key | `create` refuses to overwrite; the absent case is the only generation path, asserted in `structural_generation_is_guarded_by_absence_only` |
| 12 | corrupt key storage | `corrupt_plaintext_key_is_fatal_and_never_regenerated` (4 shapes), `corrupt_or_unopenable_wrapped_key_is_fatal_and_never_regenerated` (wrong passphrase, flipped ciphertext byte, truncated) |
| 13 | wrong key type | `a_10_guard_a_custodian_with_a_malformed_public_key_is_refused`, `a_7_guard_…` (4 malformed shapes) |
| 14 | wrong key identity | `a_5_14_wrong_identity_and_wrong_key_are_both_rejected` |
| 15 | observer-key ownership in aip-observe | `a_14_observer_key_custody_stays_in_aip_observe` (walks every `.rs` file in the workspace) |
| 16 | dev backend clearly non-production | `a_15_a_development_backend_is_not_mistakable_for_production`, `ephemeral_key_is_development_backend`, `plaintext_backend_is_not_production_and_wrapped_is` |
| 17 | no silent fallback to plaintext JSON | `a_6_a_production_store_never_falls_back`, `a_6_a_production_collector_never_falls_back` |
| 18 | secure-custody failure fails closed | `permissive_key_file_fails_closed`, `group_writable_directory_fails_closed`, `symlink_fails_closed` |

Source-scanning guards strip comments before matching, so a guard cannot fire
on the prose describing the thing it forbids.

## 13. Mutation results

Every mutation was applied to the real source, the suite run, and the source
reverted. **All ten caught.**

| # | Mutation | Failing tests | Result |
|---|---|---|---|
| M1 | remove the plaintext-storage rejection in `save` | 3 | CAUGHT |
| M2 | permit an insecure fallback — `DevelopmentInMemory.is_production()` returns true | 4 | CAUGHT |
| M3 | allow private-key export — add `private_key()` to `WrappedFileCustodian` | 1 | CAUGHT |
| M3b | allow private-key export — make `StoredIdentity::keypair` public again | 1 | CAUGHT |
| M4 | bypass the custody abstraction — the store signs with the raw key | 1 (structural) | CAUGHT |
| M5 | skip the identity check — the observer verifier ignores `signer_id` | 1 | CAUGHT |
| M6 | accept a revoked key — `revoke()` becomes a no-op | 2 | CAUGHT |
| M7 | bypass rotation validation — `rotate_key` accepts a malformed key | 1 | CAUGHT **after a test was added** — see below |
| M8 | silent fallback to plaintext JSON — `save` stops refusing | 3 | CAUGHT |
| M9 | restore the `load_or_generate` shape in the service | 2 | CAUGHT |
| M10 | drop the file-permission check on load | 1 | CAUGHT |

**Coverage gap found and closed (M7).** Dropping the length check in
`CollectorSigner::rotate_key` failed **nothing** in the suite. The collector
would half-apply a malformed rotation — `key_version` bumped, key material set
to something that cannot sign — and produce unverifiable batches from then on,
silently, on the most sensitive key in the repository.
`a_7_guard_rotation_refuses_a_bad_key_and_leaves_the_old_one` now catches it
across four malformed shapes.

**Documented structural limitation (M4).** Bypassing the store's custodian and
signing with the raw key produces a **byte-identical signature**, so no
behavioural test can detect it. The property is structural and is guarded
structurally: `key_material_crosses_the_boundary_in_one_place_each` requires
`InMemoryCustodian::new` in `sign` and counts the one place key material is
written. It matters because the bypass reintroduces the exact shape this work
removed — key material named, borrowed and passed as an argument at a call site
— which is how the field became public and how it reached `fs::write`.

## 14. Three consecutive full-suite results

`aip-standalone` and `aip-service` are **separate Cargo roots on this branch**,
so each run is two commands. No single command builds both; reported in §18.

| Run | `aip-standalone` | `aip-service` |
|---|---|---|
| 1 | 97 suites, **975 passed, 0 failed, 4 ignored** | 4 suites, **53 passed, 0 failed, 0 ignored** |
| 2 | 97 suites, **975 passed, 0 failed, 4 ignored** | 4 suites, **53 passed, 0 failed, 0 ignored** |
| 3 | 97 suites, **975 passed, 0 failed, 4 ignored** | 4 suites, **53 passed, 0 failed, 0 ignored** |

Identical across all three, no `FAILED` and no panic in any run. Combined:
**1028 passed, 0 failed, 4 ignored.**

The validated checkpoint `197ea5a` was 925 / 0 / 4 and 39 / 0 / 0 — **964
passed**. The delta of **+64** is new custody tests from both efforts plus the
Phase B signer-anchoring suite. No pre-existing test was removed, skipped, or
weakened.

Standalone observer and verifier suites, run separately: `aip-observe`
`custody` 11 passed, and every other observer suite green; `aip-protocol`
`bundle` 6 passed / 1 ignored, `signer_anchored` 9 passed, `evidence_packet`
43 passed; `aip-verify` builds and its suites pass.

## 15. fmt result

`cargo fmt --all -- --check` — **clean (exit 0)** in `aip-standalone` and in
`aip-service`.

## 16. clippy result

`cargo clippy --workspace --all-targets --all-features -- -D warnings` —
**clean (exit 0)** in `aip-standalone` and in `aip-service` (the latter
including the `postgres` feature).

## 17. Security classification

### CODE-PROVEN — enforced by the type system or by construction

- No method on `Custodian` or `RawSigner` returns key material.
- `StoredIdentity::keypair`, `ServiceKey::seed` and `ServiceKey::private_pem`
  are private with no accessor.
- `StoredIdentity` carries no serialization derive; the on-disk shape is a
  separate type built at one place.
- `CollectorKey` does not implement `RawSigner`, so no holder of one can obtain
  a signature over arbitrary bytes.
- `Backend::Tpm`, `Hsm` and `Kms` do not exist, so nothing can report them.
- `AppState` holds `Arc<dyn RawSigner>`; there is no raw key in shared HTTP
  state.
- The decrypted key is held in `Zeroizing` and wiped on drop.
- Key files are created with the mode applied by the open call, not by a
  following `chmod`.

### TEST-PROVEN — demonstrated by an executing assertion

- All 18 mandated behaviours (§12).
- Ten mutations each fail at least one test (§13).
- Fail-closed on: absent, corrupt (7 shapes across both backends), wrong
  passphrase, flipped ciphertext byte, permissive mode, group-writable
  directory, symlink, malformed key length (4 shapes).
- Rotation keeps history verifiable; revocation is a trust failure distinct
  from a cryptographic one; a replacement observer inherits no coverage.
- A production store refuses to write key material rather than stripping it,
  and a production collector refuses a development backend.
- Observer key custody is implemented in `aip-observe` and nowhere else.

### DOCUMENTED — asserted in writing, not enforced by code

- The provisioning lifecycle table (§9) as an operational contract.
- Backup and recovery are the operator's responsibility, over a wrapped file
  that is portable by design.
- Where the passphrase comes from — an operator, a systemd credential, a sealed
  blob — is a deployment decision this repository does not make.
- What the selected backend protects and what it does not (§18).

### INFERRED — follows from platform semantics, not verified here

- That `root` and same-uid processes can read a 0600 file. POSIX semantics.
  **The test environment runs as `root`**, so cross-user denial is asserted on
  the *mode bits* rather than on an actual `EACCES`.
- That `rename(2)` is atomic within a filesystem, which the atomic replace
  relies on. POSIX guarantee.
- That Argon2id with library defaults is a sufficient work factor for the
  passphrases operators will choose. Not parameterised, not benchmarked here.
- That Ed25519 signing is deterministic (RFC 8032 §5.1.6).

### UNKNOWN

- Behaviour on non-Unix. Permission enforcement degrades to a no-op there and
  `Backend` is what tells a caller what it is relying on; no non-Unix target
  was built or run.
- Behaviour on a filesystem without POSIX permission semantics (FAT, some NFS
  and overlay configurations). A filesystem that reports 0600 while enforcing
  nothing would defeat the check silently.
- Whether operators have secure backup for key files, and whether a 0600 file
  survives their container image rebuild or orchestration.
- Whether the PostgreSQL-backed evidence store interacts with any of this — it
  compiles but has never been exercised against a database.

## 18. Remaining risks

1. **The passphrase problem is moved, not solved.** An unattended edge
   collector must hold its passphrase somewhere the same process can read. Where
   that is remains a deployment decision, and until it is answered for a given
   deployment, the wrapped file plus a co-located passphrase is no stronger than
   the unwrapped file against an attacker who has both.
2. **An attacker with the running process has the key**, on any software
   backend. That is what C and D exist to address and they are not implemented.
3. **K2 and K4–K7 are inventoried, not securely provisioned.** The collector,
   decision point, warrant, containment and NEXORA keys still arrive as `&[u8]`
   from their operator. A supported custodian now exists for them to use;
   nothing yet requires them to.
4. **`jsonwebtoken` requires the private key as a PKCS#8 PEM string.** The
   export path is confined to one named free function (`wrapped_file_seed`) and
   one module, and handed out only as an opaque `EncodingKey` — but the material
   is materialised in process memory and the path is not removable without
   replacing the JWT library.
5. **The service's plaintext backend still exists.** It is classified
   `PlaintextFile`, `is_production()` is false, and a production deployment
   refuses to start on it — but a deployment that sets
   `AIP_CUSTODY_POLICY=development` gets it, and that variable is a single
   string away from being set wrongly in production.
6. **Root-run tests.** Permission enforcement is asserted on mode bits. A test
   under a non-root uid confirming an actual `EACCES` would be stronger and does
   not exist.
7. **Two Cargo roots.** No single command validates the whole repository on this
   branch. Unrelated to key custody; reported, not fixed.
8. **Argon2 parameters are the library defaults**, unparameterised and
   unbenchmarked on the target edge hardware. A cost too low weakens the
   wrapping; a cost too high delays every collector restart.

## 19. Git commits

On `claude/codebase-production-readiness-wm6idp`. The reconciliation and the
work ported onto it:

| Commit | Subject |
|---|---|
| `b89a833` | Merge: adopt `aip-crypto::custody` as the surviving custody architecture |
| `88f8c39` | feat(service,crypto): close K3 — the service key had no custody at all |
| `14f3044` | feat(core,crypto): close the store's remaining key-export paths |
| `e05aa2d` | test(observe): rotation, revocation and replacement for the collector key |
| (this) | docs(custody): implementation report |

The Phase A and Phase B commits that this reconciles with (`9409c7b`,
`9adad9d`, `7c5c01a`, `cdac72e`, `61c7b1e`) were authored separately and are
preserved unmodified.

## 20. Explicit confirmation

- **main untouched** — `main` and `origin/main` are both `872dbf3`, unchanged.
  No commit in this work is on `main`.
- **ADR-002 remains PROPOSED** — the ADR-00x files live on
  `claude/autonomous-accountability-skills-16-30`; this branch adds, modifies
  and deletes **no ADR-00x file**. `Backend::Tpm`, `Hsm` and `Kms` do not
  exist, so nothing here implements or claims hardware attestation. The one
  correction made was to `docs/adr/ADR-KEY-CUSTODY.md`, which stated those ADRs
  "do not exist here, on any branch" — they do, on that branch, and ADR-002's
  status is recorded there as PROPOSED / NOT IMPLEMENTED.
- **Observer keys remain in `aip-observe`** — no key moved crate; enforced by a
  test that walks every `.rs` file in the workspace.
- **No plaintext production fallback** — a production store refuses to write key
  material, a production collector refuses a development backend, and the
  service refuses to start on a backend whose `is_production()` is false.
  Verified by mutations M1, M2, M8 and M9.
- **No Skill 11 started.**
- **No Skill 21 started.**
- **No reconciliation redesign** — `aip-reconcile` is not in the diff.
- **No EvidenceStrength weakening** — `EvidenceStrength` is not in the diff.
- **No promotion performed** — no branch merged to main, no status upgraded, no
  production-readiness claim made.
