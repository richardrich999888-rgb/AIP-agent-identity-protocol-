# Private Key Custody — Implementation Report

**Branch** `claude/codebase-production-readiness-wm6idp`
**Base checkpoint** `197ea5a`
**Design document** `docs/architecture/KEY_CUSTODY_INVENTORY.md`

---

## 1. Status

**Complete for the scope defined: private key custody.** A custody boundary
exists, the two broken storage paths are repaired, all 18 mandated tests and 14
mutations pass, and three consecutive full-suite runs are identical.

**Not production-ready, and not claimed to be.** The selected backend stores a
plaintext key in a permission-protected file. It is not hardware-secured, not
tamper-proof, and not non-exportable at the storage layer. Five of the eight key
types are now *inventoried and policy-checkable* but still receive raw key bytes
from their operator at construction — named custody, not yet secure
provisioning. See §18.

## 2. Root cause

The stated blocker was inaccurate in one respect and understated in another.

**The collector signing key is not stored as plaintext JSON.** `CollectorSigner`
has no `Serialize` derive, no persistence path, and no accessor. The real
problem with it was the opposite: *no custody story at all* — it takes raw key
bytes from whoever constructs it and nothing in the system says where they came
from.

**What is plaintext JSON is the agent identity key (K1).** `aip_core::store`
serialized `StoredIdentity { aid, keypair }` — private key included — through
`serde_json::to_string_pretty` and `std::fs::write`, with **no mode, no
exclusive create, and no policy**. `aip-cli` called it on every
`create-identity`.

The root cause underneath both: **six of seven production signer types had
independently implemented the correct pattern — a private field, a `sign()`
method, no accessor — and none of them was named.** An unnamed convention
followed six times is a convention the seventh implementer breaks. One already
had.

A second, separate defect of the same class in the service (K3):
`KeyPair::load_or_generate` generated a **new** key on *any* load error,
silently rotating the service identity and invalidating every JWT and audit
bundle ever signed, while reporting success.

## 3. Key inventory

| # | Key | Crate | Before | After |
|---|---|---|---|---|
| K1 | Agent identity keypair | aip-core | **BROKEN** — plaintext JSON, `fs::write`, no mode | Private field, no accessor, never persisted without an explicit development policy; file at 0600 |
| K2 | Collector / observer signing key | aip-observe | UNDEFINED CUSTODY | `KeyCustody`, reports `Development`, refused by a production policy |
| K3 | Service Ed25519 seed | aip-service | **WEAK** — `load_or_generate`, write-then-chmod, `signing_seed()` accessor, raw seed in `AppState` | `load_or_create`, `O_EXCL` at 0600, permission-checked, no accessor, `Arc<dyn SigningCustodian>` in state |
| K4 | Decision point key | aip-authorize | UNDEFINED CUSTODY | `KeyCustody` |
| K5 | Warrant authority key | aip-warrant | UNDEFINED CUSTODY | `KeyCustody` |
| K6 | Containment authority key | aip-containment | UNDEFINED CUSTODY | `KeyCustody` |
| K7 | NEXORA signer + proof assembler | aip-nexora | UNDEFINED CUSTODY | `KeyCustody` |
| K8 | Test keys | (tests) | ad hoc | `DevCustodian`, classified `Development` |

## 4. Custody options evaluated

Six options against twelve dimensions; full matrix in `KEY_CUSTODY_INVENTORY.md`
§2.

| Option | Verdict |
|---|---|
| **A** OS keyring / platform credential store | Rejected — unavailable on a headless edge collector; needs a session bus |
| **B** Passphrase-wrapped file | Rejected as the primary — an unattended collector must hold the passphrase where the same process can read it, so the wrapped file plus the stored passphrase is exactly as strong as the unwrapped file, with an added appearance of protection |
| **C** TPM-backed non-exportable key | Deferred — ADR-002 territory; a new trust anchor, not a storage detail |
| **D** HSM | Deferred — same, plus cost and availability incompatible with edge deployment |
| **E** External KMS | Rejected — breaks offline and air-gapped operation, which the observer model requires |
| **F** Hybrid: one interface, pluggable backends | **Selected** |

## 5. Selected architecture

`aip-custody`: one signing boundary, backends behind it, **no key accessor**.

```
KeyCustody                       SigningCustodian: KeyCustody
  key_id()                         sign(&[u8]) -> [u8; 64]
  key_version()
  public_key()
  custody_class()
```

- `CustodyClass::{Development, OsProtectedFile, HardwareBacked}` —
  `HardwareBacked` is **reserved and unconstructible**; `is_implemented()`
  returns `false`.
- `CustodyPolicy::{Development, Production}` — Production is the default when
  unconfigured and refuses `Development` custody with an error. **No downgrade
  path exists.**
- `FileCustodian` — `O_EXCL` creation at mode 0600; on load, checks the file is
  regular (not a symlink), its own mode grants nothing to group or other, and
  its directory is not writable by others (sticky directories excepted); a
  hand-parsed fixed binary layout with no `serde`; a self-consistency check that
  the stored public key belongs to the stored private key.
- `DevCustodian` — in-memory, classified `Development`, refused in production.

The invariant is structural, not conventional:

```
private key → no Serialize on any custodian
            → no accessor on either trait
            → used through a controlled signing operation
            → signature returned
            → verification remains independent (public key only)
```

## 6. Why it was selected

**F over B** because the problem was never one file. Seven key types, four
deployment classes and one already-broken path need a *boundary*, and a boundary
lets C or D arrive later as a backend rather than a rewrite.

**B as the only production backend now** because it is the strongest thing that
is actually true today on the target deployment (a headless edge collector, no
session bus, no TPM guarantee, offline-capable), and shipping an honest
`OsProtectedFile` beats shipping a dishonest `HardwareBacked`.

**The trait split** was not in the original decision. Building K2/K4–K7 showed
that giving the six domain authorities a general `sign(&[u8])` would hand each a
raw-signing oracle: a caller could obtain the warrant authority's signature over
bytes that are a valid containment-record preimage, and the containment verifier
would accept it. Cross-protocol signature confusion, introduced by the
abstraction meant to tighten key handling. `KeyCustody` gives the inventory and
the policy check without the oracle. A narrow, domain-separated signing surface
is stronger than a general one.

## 7. Production / development distinction

| | Development | Production |
|---|---|---|
| Set by | `AIP_CUSTODY_POLICY=development` (or `dev`), explicitly | anything else, including unset, empty, unparseable |
| Admits `Development` custody | yes | **no** |
| Admits `OsProtectedFile` | yes | yes |
| Admits `HardwareBacked` | no (not implemented) | no (not implemented) |
| Store may write private keys | via `with_file_and_plaintext_keys` | **refused** |

The policy is passed as a parameter into the core, never read from the
environment inside a core function. `from_env()` is called once, at the process
edge (`aip-cli`, `aip-service/main.rs`). An ambient process-global switch would
be untestable in a parallel test binary and invisible at the call site.

## 8. Observer-key treatment

- The key **stays in `aip-observe`**, in the private field it was already in.
- `CollectorSigner` implements `KeyCustody` only. Structurally asserted: no
  `impl SigningCustodian for CollectorSigner` may be added, and no crate outside
  `aip-observe` may implement its custody. Both are enforced by a test that
  walks every `.rs` file in the workspace.
- **Nothing moved** into AIRI, reconciliation, `aip-platform` or packaging.
- **Verifier trust is untouched.** `ObserverTrustAnchors` still decides what is
  trusted, keyed by `(observer_id, key_version)`. No custody code adds, removes
  or consults an anchor. Custody is a property of the signer; it is not evidence.
- Honest classification: an operator-supplied in-memory observer key reports
  `Development` custody and a production policy refuses it. That refusal is the
  point — it says out loud that the observer key has no secure provisioning path
  yet.

## 9. Provisioning lifecycle

```
INITIALIZATION → GENERATION → REGISTRATION → OPERATION → ROTATION → REVOCATION → REPLACEMENT
```

| Event | Behaviour | Enforced by |
|---|---|---|
| First boot | No key → generate in place, `O_EXCL` at 0600 | `FileCustodian::load_or_create` |
| Reboot | Load, permission-check, **fail closed** on any defect | `check_secret_file_permissions` |
| Process restart | Identical to reboot; no state carried in memory | test `t10` |
| Key absent | The **only** condition under which generation happens | test `t12` |
| Key unreadable / corrupt / bad mode | Error. **Never** regenerated | tests `t12`, `t18` |
| Host replacement | New key, new observer id; inherits no coverage, chain restarts at sequence 1 | test `t09` |
| Key loss | Fail closed. A new key is a new version, never a substitution | test `t12` |
| Key compromise | Verifier removes the `(id, version)` anchor | test `t08` |
| Backup / recovery | **Operator's responsibility over the key file.** This code refuses to paper over a lost key by minting a new one | documented only |

## 10. Rotation and revocation lifecycle

The existing `ObserverTrustAnchors` model is reused rather than a second scheme
invented — two rotation schemes in one system is two schemes to get wrong.
Custody's `(key_id, key_version)` deliberately matches it.

| State | Representation | Verifier outcome |
|---|---|---|
| old | anchored, superseded | verifies — **history stays verifiable** |
| new | anchored, current | verifies |
| revoked | anchor removed | `UntrustedObserverKey` |
| unknown | never anchored | `UntrustedObserverKey` |

Revocation is a **trust** failure, kept distinct from a cryptographic one, so an
operator can tell forgery from revocation. Re-anchoring the same key restores
verification with no change to the batch — proof that revocation is a policy
decision and not damage to the record. **No historical proof package is
invalidated by any change in this work.**

## 11. Files changed

48 files, ~+4400 / −250. New crate `aip-custody` (6 source files, 1 test file).

| Area | Files |
|---|---|
| New crate | `aip-custody/{Cargo.toml, src/{lib,policy,error,custodian,dev,file}.rs, tests/custody_invariants.rs}` |
| K1 repair | `aip-core/src/{store.rs, lib.rs, simulation.rs}`, `aip-core/tests/key_custody.rs` |
| K3 repair | `aip-service/src/{keys,lib,main,evidence,test_support,tokens,wellknown}.rs`, `aip-service/tests/key_custody.rs` |
| K2, K4–K7 | `aip-{observe,authorize,warrant,containment,nexora}` — one `impl KeyCustody` each, no key moved |
| Bundle signing | `aip-protocol/src/bundle.rs`, `aip-protocol/tests/bundle.rs` |
| Envelope dedupe | `aip-crypto/src/lib.rs` (`signature_signed_bytes`) |
| CLI | `aip-cli/src/main.rs` — per-identity `FileCustodian`, fail-closed store open |
| Fixtures isolated | `aip-test/src/lib.rs`, `aip-real-tests/src/e2e.rs` |
| Docs | `KEY_CUSTODY_INVENTORY.md` (+343), this report |

## 12. Tests added

**48 new tests.** Mandated list, all present and passing:

| # | Requirement | Test |
|---|---|---|
| 1 | plaintext persistence rejected in production | `t01_plaintext_persistence_refused_under_production_policy`, `t01_saved_file_contains_no_private_key_bytes`, `t01_store_file_is_0600` |
| 2 | private key not returned through normal API | `t02_debug_never_prints_key_material`, `t02_structural_no_serialize_derive_on_custodians`, `t02_structural_stored_identity_has_no_key_accessor`, `t02_store_debug_reports_counts_not_contents` |
| 3 | signing works through the abstraction | `t03_signing_works_through_the_abstraction`, `t03_structural_sign_routes_through_the_custodian` |
| 4 | verification still works | `t04_verification_is_independent_of_custody`, `t04_envelope_through_custodian_verifies_normally` |
| 5 | wrong identity cannot use signer | `t05_a_batch_cannot_be_relabelled_as_another_observer` |
| 6 | unauthorized caller cannot export key | `t06_structural_trait_exposes_no_key_accessor`, `t06_structural_backends_expose_no_key_accessor` |
| 7 | key rotation | `t07_rotation_keeps_history_verifiable`, `t07_rotation_refuses_a_bad_key_and_leaves_the_old_one` |
| 8 | revoked key | `t08_revoked_key_stops_verifying_and_says_why`, `t08_unknown_key_version_is_refused` |
| 9 | replacement key | `t09_a_replacement_observer_is_a_new_identity` |
| 10 | reboot / reload lifecycle | `t10_reload_after_restart_keeps_the_same_key`, `t10_create_refuses_to_replace_an_existing_key`, `first_boot_creates_and_restart_reloads_the_same_key` |
| 11 | missing key | `t11_missing_key_is_absent_and_load_never_creates` |
| 12 | corrupt key storage | `t12_corrupt_storage_is_refused_and_never_regenerated` (8 shapes), `t12_load_or_create_generates_only_when_absent`, `corrupt_key_file_is_fatal_and_never_regenerated` |
| 13 | wrong key type | `t13_wrong_key_length_is_refused_at_creation`, `t13_empty_key_id_is_refused` |
| 14 | wrong key identity | `t14_wrong_key_under_a_trusted_identity_is_rejected` |
| 15 | observer-key ownership in aip-observe | `t15_collector_reports_custody_without_surrendering_the_key`, `t15_structural_collector_has_no_general_signing_oracle`, `t15_structural_no_other_crate_holds_the_observer_key` |
| 16 | dev backend clearly non-production | `t16_dev_backend_is_classified_development_and_refused_in_production`, `t16_file_backend_is_admitted_in_production`, `t16_hardware_backed_is_reserved_and_unimplemented` |
| 17 | no silent fallback to plaintext JSON | `t17_legacy_plaintext_store_is_refused_not_silently_stripped`, `t17_reload_without_keys_is_public_only_and_says_so`, `t17_in_memory_key_is_development_custody`, `t17_structural_save_writes_keys_from_one_guarded_branch` |
| 18 | secure-custody failure fails closed | `t18_permissive_mode_fails_closed` (6 modes), `t18_created_key_is_0600`, `t18_group_writable_directory_fails_closed`, `t18_symlink_fails_closed`, `t18_unset_policy_defaults_to_production`, `permissive_key_file_fails_closed` |

Source-scanning guards strip `//` and `/* */` comments before matching, so a
guard cannot fire on the prose describing the thing it forbids.

## 13. Mutation results

Every mutation was applied to the real source, the suite run, and the source
reverted. **All 14 caught.**

| # | Mutation | Failing tests | Result |
|---|---|---|---|
| M1 | remove plaintext-storage rejection | 2 | CAUGHT |
| M2 | permit insecure fallback (`Production` admits `Development`) | 4 | CAUGHT |
| M3 | allow private-key export (add an accessor) | 1 (structural) | CAUGHT |
| M4 | bypass custody abstraction — store `sign()` uses the raw key | 1 (structural) | CAUGHT **after a guard was added** — see below |
| M4b | bypass custody abstraction — `build_zip` signs with a raw key | 2 | CAUGHT |
| M5 | skip identity check (`sig.signer_id` vs `observer_id`) | 1 | CAUGHT |
| M5b | skip identity check (accept any anchored key for the version) | 3 | CAUGHT |
| M6 | accept a revoked key (`revoke()` becomes a no-op) | 3 | CAUGHT |
| M7 | bypass rotation validation (accept a malformed key) | 1 | CAUGHT |
| M8 | drop the policy check on plaintext persistence | 1 | CAUGHT |
| M8b | silent fallback to plaintext JSON on `PlaintextKeysPresent` | 2 | CAUGHT |
| M9 | `load_or_generate` shape — mint a key on a permission error | 1 | CAUGHT |
| M9b | `load_or_generate` shape — mint a key on a corrupt file | 1 | CAUGHT |
| M10 | drop the file-permission check on load | 2 | CAUGHT |

**Documented limitation (M4).** Bypassing `StoredIdentity::sign`'s custodian and
signing with the raw key produces a **byte-identical signature**, so no
behavioural test can detect it; the first run of M4 left the whole suite green.
The property is structural and is now guarded structurally
(`t03_structural_sign_routes_through_the_custodian`). It matters because the
bypass reintroduces the exact shape this work removed: key material named,
borrowed and passed as an argument at a call site — which is how the field
became public, and how it reached `fs::write`.

## 14. Three consecutive full-suite results

`aip-standalone` and `aip-service` are **separate Cargo roots on this branch**,
so each run is two commands.

| Run | `aip-standalone` | `aip-service` |
|---|---|---|
| 1 | 98 suites, **967 passed, 0 failed, 4 ignored** | 4 suites, **46 passed, 0 failed, 0 ignored** |
| 2 | 98 suites, **967 passed, 0 failed, 4 ignored** | 4 suites, **46 passed, 0 failed, 0 ignored** |
| 3 | 98 suites, **967 passed, 0 failed, 4 ignored** | 4 suites, **46 passed, 0 failed, 0 ignored** |

Identical across all three. Combined: **1013 passed, 0 failed, 4 ignored.**

Baseline at `197ea5a` was 925 / 0 / 4 and 39 / 0 / 0 — **964 passed**. Delta
**+49** is the 48 new custody tests plus one existing test that gained a
companion assertion. No pre-existing test was removed, skipped, or weakened.

Standalone observer/verifier suites, run separately: `aip-observe` all green
including `key_custody` (10 passed); `aip-protocol` `bundle` 6 passed / 1
ignored, `evidence_packet` 43 passed; `aip-verify` builds and its suites pass.

CLI verified end to end by hand: `create-identity` writes the key to
`<store>.keys/<aip-id>.key` at 0600 in a 0700 directory and the store contains
zero occurrences of `keypair`/`private_key`; `sign`, `verify` and `challenge`
succeed through the custodian; a 0644 key file and a corrupt store both fail
closed with the remedy named.

## 15. fmt result

`cargo fmt --all -- --check` — **clean** in `aip-standalone` and in
`aip-service`.

## 16. clippy result

`cargo clippy --workspace --all-targets --all-features -- -D warnings` —
**clean (exit 0)** in `aip-standalone` and in `aip-service` (the latter
including the `postgres` feature).

## 17. Security classification

### CODE-PROVEN — enforced by the type system or by construction

- No method on `KeyCustody` or `SigningCustodian` returns key material.
- `StoredIdentity::keypair`, `ServiceKey::seed` and `ServiceKey::private_pem`
  are private with no accessor.
- No custodian type derives `Serialize` or `Deserialize`.
- `CustodyClass::HardwareBacked` is reachable from no backend;
  `is_implemented()` is `false` and both policies refuse it.
- `AppState` holds `Arc<dyn SigningCustodian>`; there is no raw key in shared
  HTTP state.
- The six domain authorities **cannot** sign arbitrary bytes — they do not
  implement `SigningCustodian`.
- `admits()` is a free function, so an implementation cannot override the policy
  check by reporting a class it does not have.
- `IdentityStore::save` reads key material from exactly one branch, guarded by
  `KeyPersistence::DevelopmentPlaintext`, which only
  `with_file_and_plaintext_keys` can set and which a production policy refuses.

### TEST-PROVEN — demonstrated by an executing assertion

- All 18 mandated behaviours (§12).
- 14 mutations each fail at least one test (§13).
- A signature is byte-identical across backends and through `sign_envelope`;
  verification cannot tell which custody produced it.
- Fail-closed on: absent, unreadable, corrupt (8 shapes), mismatched key pair,
  permissive mode (6 modes), group-writable directory, symlink, wrong key
  length, empty key id.
- Rotation keeps history verifiable; revocation is a trust failure distinct from
  a cryptographic one; a replacement observer inherits no coverage.
- A legacy plaintext store is refused rather than silently stripped, and is
  byte-identical after the refusal.

### DOCUMENTED — asserted in writing, not enforced by code

- The provisioning lifecycle table (§9) as an operational contract.
- Backup and recovery are the operator's responsibility.
- The migration procedure (`KEY_CUSTODY_INVENTORY.md` §8).
- What `OsProtectedFile` protects against and what it does not.

### INFERRED — follows from platform semantics, not verified here

- That `root` and same-uid processes can read a 0600 key file. POSIX semantics.
  **The test environment runs as `root`**, so cross-user denial is asserted on
  the *mode bits* rather than on an actual `EACCES`.
- That `rename(2)` is atomic within a filesystem, which `write_secret_file`
  relies on. POSIX guarantee.
- That Ed25519 signing is deterministic (RFC 8032 §5.1.6), which the file
  self-consistency probe and the cross-backend equality test rely on.

### UNKNOWN

- Behaviour on non-Unix. The code fails closed by construction there and no
  non-Unix target was built or run.
- Behaviour on a filesystem without POSIX permission semantics (FAT, some NFS
  and overlay configurations). `check_mode` reads whatever the filesystem
  reports, and a filesystem that reports 0600 while enforcing nothing would
  defeat the check silently.
- Whether operators have secure backup for key files, and whether a 0600 file
  survives their container image rebuild or orchestration. Deployment concerns
  this code cannot see.
- Whether the PostgreSQL-backed evidence store path interacts with any of this
  — it compiles but has never been exercised against a database.

## 18. Remaining risks

1. **The production backend is plaintext on disk.** Anyone with `root`, the same
   uid, the disk, a snapshot or a backup has the key. This is the honest limit
   of `OsProtectedFile` and is the single largest remaining gap.
2. **K2 and K4–K7 are inventoried, not securely provisioned.** The collector,
   decision point, warrant, containment and NEXORA keys still arrive as `&[u8]`
   from their operator and correctly report `Development` custody — which a
   production policy refuses. Giving them `FileCustodian`-backed constructors is
   the next step and is **not done**. Until it is, no production deployment of
   those components passes its own policy check, by design.
3. **`jsonwebtoken` requires the private key as a PKCS#8 PEM string.** That
   export path is confined to `keys.rs` and handed out only as an opaque
   `EncodingKey`, but the material is materialised in process memory and the
   path is not removable without replacing the JWT library.
4. **No zeroization on drop.** Outside what `OsProtectedFile` claims, and a
   reallocated `Vec<u8>` cannot be reliably wiped. Stated rather than papered
   over.
5. **Root-run tests.** Permission enforcement is asserted on mode bits. A test
   under a non-root uid confirming an actual `EACCES` would be stronger and does
   not exist.
6. **Two Cargo roots.** No single command validates the whole repository on this
   branch. Unrelated to key custody; reported, not fixed.
7. **`aip-cli`'s key directory is derived from the store path** (`<store>.keys`).
   Simple and predictable, but it is a convention rather than a configured
   location, and an operator moving the store without the key directory loses
   the ability to sign.

## 19. Git commits

All on `claude/codebase-production-readiness-wm6idp`, ahead of `197ea5a`:

| Commit | Subject |
|---|---|
| `0ce28b3` | docs: private key custody inventory and decision |
| `03716cc` | feat(custody): private key custody boundary — one interface, no key accessor |
| `276b058` | test(custody): the 18 mandated custody tests |
| `cd1bb43` | test(custody): structural guard for the custodian-bypass mutation |
| `ebe4c88` | style(custody): rustfmt and clippy fixes in the custody tests |
| `fa773c7` | docs(custody): as-built architecture and migration requirements |
| (this) | docs(custody): implementation report |

## 20. Explicit confirmation

- **main untouched** — `main` and `origin/main` are both `872dbf3`, unchanged.
  No commit in this work is on `main`.
- **ADR-002 remains PROPOSED** — the ADR files live on
  `claude/autonomous-accountability-skills-16-30`, not on this branch. This
  branch adds, modifies and deletes **no ADR file** (`git diff --name-only
  197ea5a..HEAD | grep -i adr` returns nothing). `CustodyClass::HardwareBacked`
  is reserved, unconstructible, and reported by no backend.
- **Observer keys remain in `aip-observe`** — no key moved crate; enforced by a
  test that walks every `.rs` file in the workspace.
- **No plaintext production fallback** — `CustodyPolicy::Production` refuses
  `Development` custody with an error and there is no downgrade path; verified
  by mutations M2, M8 and M8b.
- **No Skill 11 started.**
- **No Skill 21 started.**
- **No reconciliation redesign** — `aip-reconcile` is not in the diff.
- **No EvidenceStrength weakening** — `EvidenceStrength` is not in the diff.
- **No promotion performed** — no branch merged, no status upgraded, no
  production-readiness claim made.
