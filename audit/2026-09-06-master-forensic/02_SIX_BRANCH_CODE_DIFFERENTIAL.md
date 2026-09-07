# Six-Branch Code Differential

Companion to `00_EVIDENCE_BASE.md`. Every figure here is CODE-PROVEN unless
labelled otherwise.

## 1. Topology

| Alias | HEAD | Merge-base with `main` | Ahead | Behind | Files Δ | +Lines | −Lines |
|---|---|---|---:|---:|---:|---:|---:|
| main | `872dbf375838` | `872dbf375838` | 0 | 0 | 0 | 0 | 0 |
| prod | `82da7a6af110` | `872dbf375838` | **103** | 0 | 168 | **66,074** | 225 |
| audit | `16493c58aed3` | `872dbf375838` | 1 | 0 | 8 | 945 | 0 |
| importot | `6cc439f19016` | `872dbf375838` | 1 | 0 | 116 | 35,673 | 0 |
| valladder | `ae46a3a2f4e2` | **`cd660f6bd626`** | 29 | **17** | 191 | 22,925 | 11,622 |
| aipv4 | `73bf70cf9e68` | **`cd660f6bd626`** | 7 | **17** | 124 | 11,136 | 11,684 |

`cd660f6bd626` is the repository's **initial commit**. `valladder` and
`aipv4` are therefore not branches off main's line of development; they are
architectural forks from the repository's origin. Each is 17 commits behind
main and shares none of main's subsequent work.

## 2. Authorship and chronology

| Branch | Commits ahead | Authors | Date span |
|---|---:|---|---|
| prod | 103 | `Claude <noreply@anthropic.com>` (103) | 2026-08-23 → 2026-09-06 |
| importot | 1 | `richardrich999888-rgb` (1) | 2026-08-28 |
| valladder | 29 | `richardrich999888-rgb` (29) | 2026-05-31 → 2026-06-03 |
| aipv4 | 7 | `richardrich999888-rgb` (7) | 2026-05-31 → 2026-06-03 |

**Finding D-1 (P4, CODE-PROVEN).** `valladder` and `aipv4` are the *oldest*
work in the repository, not the newest: their commits predate main's tip by
roughly three months and fork from the initial commit. The brief's caution
against assuming newer code is better is resolved here in the opposite
direction — these two branches are historical experiments, and the audit
treats them as such on evidence, not on branch names.

**Finding D-2 (P2, CODE-PROVEN).** All 103 commits on `prod` — 66,074 added
lines — carry a single machine author identity. Commit metadata records no
independent human review of any commit. This is a governance fact, not a
code defect, and it is material to Report 08.

## 3. Language and size inventory

| Branch | Files | `.rs` files | Rust LOC | TS LOC | MD LOC | Total LOC |
|---|---:|---:|---:|---:|---:|---:|
| main | 116 | 50 | 16,653 | 0 | 6,901 | 27,780 |
| **prod** | **266** | **139** | **58,268** | 0 | 30,847 | 93,629 |
| audit | 124 | 50 | 16,653 | 0 | 7,846 | 28,725 |
| importot | 232 | 100 | 37,389 | 12,166 | 7,820 | 63,453 |
| valladder | 157 | 66 | 19,709 | 0 | 4,613 | 46,538 |
| aipv4 | 92 | 52 | 16,466 | 0 | 3,359 | 27,237 |

`audit` differs from `main` by exactly the 945 lines of `.claude/skills/`
added in commit `16493c5`; its Rust tree is byte-identical to main's, and
its test run is identical (143/0/1). It contributes no product code.

## 4. Crate inventory

### 4.1 Crates present on `prod` and absent from `main`

| Crate | Rust LOC | Workspace member |
|---|---:|---|
| `aip-observe` | 7,313 | yes |
| `aip-reconcile` | 4,070 | yes |
| `ghost-demo` | 1,861 | yes |
| `aip-agent` | 1,612 | yes |
| `aip-containment` | 1,537 | yes |
| `aip-authorize` | 1,194 | yes |
| `aip-nexora` | 1,020 | yes |
| `aip-warrant` | 638 | yes |

Growth in pre-existing crates: `aip-core` 5,179 → 6,155; `aip-types`
619 → 949; `aip-crypto` 309 → 394; `aip-test` 329 → 451.

### 4.2 Crates present on `valladder` / `aipv4` and absent from `main` and `prod`

`aegis-quantum/` is a **third independent Cargo root** (neither
`aip-standalone` nor `aip-service` reaches it).

| Crate | valladder LOC | aipv4 LOC |
|---|---:|---:|
| `aegis-quantum-userspace` | 1,674 | 1,540 |
| `aegis-quantum-circuit-breaker` | 757 | 757 |
| `aegis-quantum-common` | 417 | 405 |
| `aegis-quantum-ebpf` | 322 | 322 |
| `stress-tests` | 156 | absent |
| `benchmarks` | 1 | 1 |

`valladder`'s `aegis-quantum` is a strict superset of `aipv4`'s: it adds
`stress-tests/`, `scripts/`, `VALIDATION_LADDER.md`, and
`benchmarks/examples/`. `valladder` additionally carries `airon-verify`
(948 LOC) as an `aip-standalone` workspace member.

**Finding D-3 (P3, CODE-PROVEN).** `AUDIT_CORRECTIONS.md` §1 on `main`
states that an `aegis/` component does not exist. That statement is true of
`main` and false of the repository: `aegis-quantum/` exists on two branches
totalling roughly 3,300 Rust LOC. A reader taking that document as
repository-wide would conclude the component was never written.

## 5. Workspace membership and test reachability

| Branch | `aip-standalone` members |
|---|---|
| main | aip-types, aip-crypto, aip-core, aip-protocol, aip-test, aip-cli, aip-verify, aip-real-tests, banking_demo |
| prod | + aip-authorize, aip-observe, aip-reconcile, aip-agent, aip-warrant, aip-nexora, aip-containment, ghost-demo |
| valladder | aip-types, aip-crypto, aip-core, aip-protocol, **airon-verify**, aip-test, aip-cli, aip-real-tests (no `aip-verify`) |
| aipv4 | aip-types, aip-crypto, aip-core, aip-protocol, aip-test, aip-cli, aip-real-tests (no `aip-verify`) |

**Finding D-4 (P2, CODE-PROVEN).** `aip-service` is a separate Cargo package
on every branch and is a member of no workspace. `cargo test --workspace`
run in `aip-standalone` — the command the repository's documentation and CI
use — never compiles or tests the HTTP service. The service must be tested
by a second, separate invocation. Every unremediated service-tier finding in
Report 03 lives in code that the primary test command does not reach.

## 6. Implementation differential on shared components

Classification per the brief: **A** stronger than main · **B** weaker ·
**C** complementary · **D** duplicate · **E** superseded · **F** experimental ·
**G** unsafe · **H** incomplete · **I** incompatible.

### 6.1 `aip-core/src/capability.rs` — `canonical_token_payload`

| Branch | Signed payload covers `expires_at`? | Encoding | Domain tag | Class |
|---|---|---|---|---|
| main | **no** | raw concatenation | none | baseline |
| **prod** | **yes** | prefix-free (`aip_types::canonical`) | `AIP/ScopedToken/v1` | **A** |
| audit | no | raw concatenation | none | **D** (identical to main) |
| importot | no | raw concatenation | none | **D** |
| valladder | no | raw concatenation | none | **D** |
| aipv4 | no | raw concatenation | none | **D** |

`prod` replaces the ad-hoc encoder with `put_domain`/`put_str`/
`encode_scope`/`put_u64`/`put_opt_u64` and threads `expires_at` through both
`issue_scoped_token` and `verify_scoped_token`. Three adversarial tests pin
the property (extend, `Some`→`None`, `None`→`Some`), plus injectivity tests
for adjacent identifiers, interior-NUL custom actions, and expiry presence.

### 6.2 `aip-core/src/delegation.rs` — `canonical_delegation_payload` and chain verification

| Branch | `expires_at` signed | Temporal attenuation enforced | Issuer↔grantee bound | Class |
|---|---|---|---|---|
| main | no | no | **no** | baseline |
| **prod** | **yes** | **yes** (`AttenuationViolation`) | **no** | **A** (partial) |
| audit / importot / valladder / aipv4 | no | no | no | **D** |

`prod` adds `verify_delegation_token_signature` as the single correct hop
check, and rule 5: a bounded parent cannot yield an unbounded or
later-expiring child. It does **not** add the check
`chain[i].issuer_id == chain[i-1].grantee_id`. See Report 03, invariant I-3.

### 6.3 `aip-protocol/src/verification.rs`

`prod` is main + 64 lines. The whole of the difference is:

- import of `aip_types::EXECUTION_BINDING_VERSION`;
- a new rule **R15 EXECUTION_BINDING** (`prod/…/verification.rs:480-533`),
  which validates a self-reported binding's version, agent match, and
  non-degenerate process/executable identity, and which explicitly does not
  affect the trust floor;
- `check_structure` problem strings widened from `&str` to `String` to
  report the offending version number.

`check_temporal_validity` is **byte-identical** between main and prod
(51 lines, SHA-256 prefix `dbafa0086c1b34af` on both). `VerificationContext`
is byte-identical. Classification: **A**, narrowly — R15 adds a
well-formedness rule and adds no trust.

### 6.4 `aip-protocol/src/bundle.rs`

Byte-identical between main and prod (673 lines). `verify_bundle_signature`
at `:437` still verifies the manifest against
`manifest.signer_public_key` — a key carried by the object being verified.
Classification: **D**.

### 6.5 `aip-service/src/handlers.rs`

| Branch | Lines | SHA-256 (first 16) |
|---|---:|---|
| main | 400 | `b5341baf3c4e0b03` |
| prod | 400 | `b5341baf3c4e0b03` |
| audit | 400 | `b5341baf3c4e0b03` |
| importot | 400 | `b5341baf3c4e0b03` |
| valladder | 631 | `3b75c84fafecc369` |
| aipv4 | 400 | `b99f81cbd3071a80` |

**Finding D-5 (P1, CODE-PROVEN).** `prod`'s 103 commits and 66,074 added
lines did not change one byte of the HTTP request handlers. `keys.rs` is
likewise byte-identical (`affac328a2977622`) on main, prod, audit and
importot. `IdentityStore::save` is byte-identical on all four branches that
have it. Every service-tier and key-at-rest finding carried forward from the
base audit is therefore unremediated on `prod`.

`valladder` diverges by +231 lines, adding `issue_passport`,
`verify_passport`, `viewer()`, `token_from_headers_or_body`, `unauthorized`,
`now_unix_seconds` and `metadata_string`. Classification: **C**
(complementary — a passport surface main does not have) and **F**
(experimental — it predates the EvidencePacket service layer).

`valladder` and `aipv4` lack `auth.rs`, `authority.rs`, `evidence.rs`,
`lib.rs`, `store.rs`, `store/` and `test_support.rs` entirely. They are not
reduced versions of main's service; they are earlier ones.
Classification: **E** (superseded) for the shared surface.

### 6.6 `aip-service/src/evidence.rs`

`prod` is main + 47 lines: a trust-boundary doc comment on `verify_request`
and one characterization test,
`weakness_generate_then_verify_accepts_self_issued_authority`
(`prod/aip-service/src/evidence.rs:588-624`). The test asserts that a caller
holding only its own key can self-issue an ADMIN root token, have the
service seal a packet exercising it, and have `verify_request` return
`valid` by naming its own key as the trusted issuer.

**Finding D-6 (P2, CODE-PROVEN).** This is a *pinned known weakness*, not a
fix. The test's own comment says the endpoint "is unchanged". Classification:
**A** for honesty of documentation, **D** for behaviour.

## 7. Summary judgment per branch

| Branch | Judgment | Basis |
|---|---|---|
| **prod** | **The only branch carrying material new capability.** Class **A** on the cryptographic core, class **D** on the service tier. | §4.1, §6.1–6.6 |
| **main** | Baseline. Nothing on any other branch is subsumed by it except by age. | §1 |
| **audit** | Class **D**. Adds tooling only, no product code. | §3 |
| **importot** | Class **C** and **I**. 35,673 lines in four unbuilt Rust roots plus a Python SDK and 12,166 TS LOC; wire-incompatible chaining (see base audit PR #3 section). Adds zero tests to `aip-standalone` (143/0/1, identical to main). | §3, §5 |
| **valladder** | Class **F** and **C**. Oldest line; unique `aegis-quantum` and `airon-verify`; carries every main-era cryptographic defect. | §2, §4.2, §6.1–6.2 |
| **aipv4** | Class **F** and **E**. Strict subset of valladder's contribution. | §4.2 |
