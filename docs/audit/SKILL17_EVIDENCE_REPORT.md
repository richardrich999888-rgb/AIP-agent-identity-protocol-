# Skill 17 — Autonomous System Model: Evidence Report

**Branch** `claude/autonomous-accountability-skills-16-30`
**Specification** `docs/architecture/SKILL17_AUTONOMOUS_SYSTEM_MODEL.md`
(written before implementation, per the skill's workflow step 2)

This report states what is proven and by what. Nothing is upgraded past what
was executed, and the abstraction existing is not treated as the capability
existing.

---

## 1. Source files

### Read before designing (reuse inspection)

`aip-types/src/lib.rs` (`ProcessInstance`, `ExecutionBinding`,
`ProvenanceTriple`), `aip-types/src/canonical.rs` (encoders),
`aip-crypto/src/lib.rs` (`derive_aip_id`, `validate_aip_id`),
`aip-airi/src/event.rs` and `src/ids.rs` (`execution_id`,
`parent_execution_id`, `ExecutionId`), `aip-reconcile/src/result.rs` and
`src/inputs.rs`, `aip-warrant/src/warrant.rs`, `aip-containment/src/contain.rs`.

### Changed

| File | Change |
|---|---|
| `Cargo.toml` (root) | +1 workspace member |
| `aip-standalone/aip-system/Cargo.toml` | new |
| `aip-standalone/aip-system/src/{lib,ids,system,execution,lifecycle,profile,error}.rs` | new |
| `aip-standalone/aip-system/tests/{identity_separation,compatibility}.rs` | new |
| `docs/architecture/SKILL17_AUTONOMOUS_SYSTEM_MODEL.md` | new |

**No existing source file was modified.** No public structure changed, no wire
format changed, no existing serialized data is reinterpreted.

## 2. What was reused rather than reinvented

Agent identity (AIP-ID), execution identity and lineage (`aip-airi`), process
instance and execution binding (`aip-types`), provenance triple, canonical
encoders, and AIP-ID validation are all **used verbatim**. This crate defines
no identity derivation, no encoder, and no second execution identifier.

Four identifiers are added because nothing existing represented them:
`SystemId`, `PlatformId`, `HardwareId`, `MissionId`. The reasoning for each is
in the specification's §1; the sharpest is `HardwareId` — `boot_id` identifies
a *boot*, not a *machine*, so a model conflating them reports a hardware change
on every restart and misses a real one.

## 3. Invariants and how each is enforced

| ID | Invariant | Enforcement | Class |
|---|---|---|---|
| S17-1 | Agent ≠ platform identity | distinct types, no conversion; AIP-IDs do not parse as namespaced ids | TEST-PROVEN (t01) |
| S17-2 | Execution ≠ hardware identity | `[u8;16]` vs namespaced string | TEST-PROVEN (t02) |
| S17-3 | Mission ≠ agent identity | distinct types | TEST-PROVEN (t03) |
| S17-4 | Construction grants no authority | no key/token/scope field exists on either type | CODE-PROVEN + TEST-PROVEN (t04, t15) |
| S17-5 | Lineage transfers no permission | `parent_execution_id` is data; no code reads it for a decision | TEST-PROVEN (t05), mutation-checked |
| S17-6 | One agent, many executions | per-execution record | TEST-PROVEN (t06) |
| S17-7 | One platform, many agents over time | `platform_id` is per-execution | TEST-PROVEN (t07, t07b) |
| S17-8 | No silent platform change | platform inside canonical bytes | TEST-PROVEN (t08) |
| S17-9 | Transplantation is detectable | every id in the injective encoding | TEST-PROVEN (t09, t09b, t09c), mutation-checked |
| S17-10 | Round trip preserves relationships | serde + canonical equality | TEST-PROVEN (t10, t10b, t10c) |
| S17-11 | Malformed ids fail closed | validated constructors, private fields, serde `try_from` | TEST-PROVEN (t11, t11b), mutation-checked |
| S17-12 | Unknown versions refused | explicit check, not implied by serde | TEST-PROVEN (t12, t12b), mutation-checked |
| S17-13 | Unknown system types refused | closed enum, no `Other` | TEST-PROVEN (t12c) |
| S17-14 | AIP identity semantics unchanged | no edit to core crates | TEST-PROVEN (compatibility) |
| S17-15 | AIRI semantics unchanged | no edit; identifier reused verbatim | TEST-PROVEN (compatibility) |
| S17-16 | Lifecycle is not a trust anchor | nothing branches on it | TEST-PROVEN (t16, t16b) |
| S17-17 | Domain-separated, injective encoding | `put_domain` + length prefixes + presence bytes | TEST-PROVEN (t09b, t09c, compatibility) |
| S17-18 | Registered ≠ executed platform | separate fields, both encoded | TEST-PROVEN (t18) |

## 4. Adversarial cases

`t09` sweeps every substitution an attacker would attempt, each asserted to
change the canonical bytes and each asserted distinct from the others:

- agent A + platform B, and agent B + platform A
- execution X + mission Y
- execution X + hardware Y
- system 1 → system 2

`t09b` attacks injectivity directly: without presence bytes, a record with
hardware `"x"` and no platform would encode identically to one with no
hardware and platform `"x"` — letting an attacker move a value between
identity slots for free. `t09c` attacks the adjacent-field case that
length-prefixing exists to stop.

`t11b` attacks the deserialization bypass: if serde skipped validation, JSON
would be a way to build an identifier the constructor refuses.

**What these tests establish, precisely.** `AutonomousSystem` and
`SystemExecution` are unsigned descriptors. An unsigned descriptor cannot stop
anyone writing what they like into it, and the tests do not pretend otherwise.
What they establish is that a substitution **changes the canonical bytes**, so
any signature over those bytes stops verifying and a transplant cannot be
*silent*. Prevention belongs to whatever signs the bytes, which is
deliberately not this crate.

## 5. Mutation results

A test that passes against a broken model proves nothing. Each load-bearing
invariant was checked by reintroducing the defect:

| Mutation | Expected to break | Result |
|---|---|---|
| Drop presence bytes from optional ids | slot-shifting invisible | **t09b fails** ✓ |
| Skip AIP-ID validation on construction | malformed agent accepted | **t11 fails** ✓ |
| `with_parent` copies parent's authority | lineage grants permission | **t05 fails** ✓ |
| `TryFrom<String>` accepts unconditionally | serde bypasses validation | **t11b fails** ✓ |
| Version check always passes | future versions read as known | **t12, t12b fail** ✓ |
| Add `aip-system` to `aip-warrant` deps | isolation argument void | **compatibility fails** ✓ |

One mutation attempt was discarded as invalid rather than counted: removing
the `#[serde(try_from)]` attribute changed the *wire shape* (string → struct)
rather than the validation, so the test passed for a reason unrelated to the
property. It was replaced by the unconditional-`TryFrom` mutation above, which
is the real bypass.

## 6. Test results

```
cargo test -p aip-system    32 passed, 0 failed   (25 identity, 7 compatibility)
cargo test --workspace     106 suites, 1056 passed, 0 failed, 5 ignored
cargo clippy --workspace --all-targets   clean
cargo fmt --all -- --check               clean
```

Workspace members: 19 → **20**.

### One flake observed and diagnosed, not hidden

The first full-workspace run after adding the crate failed one test:
`aip-containment::live_freeze::f_p_a_proven_warrant_freezes_the_bound_process_and_release_thaws_it`,
at `assert!(t.bytes_in(Duration::from_millis(200)) > 0, "ticker runs")`.

Diagnosis, not assumption: it passes in isolation, and an immediately
following identical full-workspace run passed 1056/1056. The assertion gives a
spawned child a 200 ms wall-clock window to emit bytes; under a fully parallel
20-crate run the child is not always scheduled in time. It is the same class as
the known `aip-observe fa05_live_*` flake.

Causally unrelated to this work: `aip-system` is depended on by nothing,
spawns nothing, and touches no cgroup. Recorded as a pre-existing
load-sensitive flake in §9 rather than treated as a regression or as noise.

## 7. Compatibility findings

- **No wire format changed.** Two new domain tags,
  `SYNTRIASS/AUTONOMY/SYSTEM/v1` and `SYNTRIASS/AUTONOMY/EXECUTION/v1`,
  asserted distinct from each other and from the existing reconciliation,
  warrant and AIRI tags.
- **No existing serialized data is reinterpreted.** The new types have no
  existing instances.
- **Versioning follows the repository philosophy.** `check_version` refuses an
  unknown version rather than guessing, and the test pins that serde alone
  does *not* enforce it — a reader must call the check.
- **Dependency direction is asserted, not documented.** `no_crate_in_the_verdict_path_depends_on_this_one`
  reads the manifests of `aip-reconcile`, `aip-warrant`, `aip-containment`,
  `aip-nexora`, `aip-airi` and `aip-observe`. This is the mechanical basis for
  the claim that Skill 17 cannot cause a semantic regression in the verdict
  path: those crates cannot see this one. If that ever changes, the test fails.

## 8. Security impact

**Reduced attack surface, no new trust.** No signing key, no token, no scope,
no signature is introduced. No new trust anchor exists, so the STOP condition
on new trust anchors was not reached.

The security value delivered is negative-space: identity confusions that were
previously expressible are now compile errors or encoding differences. The
model cannot itself be attacked into granting something, because there is
nothing in it to grant.

**No security semantic regression.** Reconciliation, warrant, containment,
NEXORA and AIRI semantics are untouched — not by argument, by the dependency
graph and the absence of any edit to those crates.

## 9. Unresolved assumptions and known limitations

1. **Descriptors are unsigned by design (D17-3).** Integrity depends entirely
   on a *future* consumer embedding the canonical bytes in something signed.
   Until such a consumer exists, these records carry no integrity of their own.
   That is intended, and it is the single largest caveat on this work: the
   abstraction exists; the binding of it to a signed artifact does not yet.
2. **`HardwareId` and `PlatformId` are claims, not attestations.** Nothing
   here attests that a TPM EK or a tail number is genuine. Hardware
   attestation is Skill 19.
3. **Profiles are commitments only.** Nothing resolves a `ProfileRef` digest,
   and a committed profile is not an enforced one.
4. **Lifecycle transitions are descriptive.** `may_precede` is not called by
   anything. A caller may record any state; that is deliberate — a model that
   refuses to represent what happened is a model that gets bypassed — but it
   means lifecycle bookkeeping is not enforced here.
5. **No integration with the accountability core yet.** By D17-6 nothing
   consumes `AutonomousSystem`. The universal abstraction is the whole of
   Skill 17; wiring it is later work and is not claimed.
6. **Pre-existing load-sensitive flakes** (§6): `live_freeze::f_p_a_*` and
   `aip-observe fa05_live_*`. Both are wall-clock assertions about scheduled
   children under parallel load. Neither is caused by this work; both remain.

## 10. Gate evaluation

| Acceptance criterion | Status |
|---|---|
| UAS, UGV, robot, industrial edge, spacecraft and enterprise agent all representable without a schema fork | **MET** — `every_environment_is_representable_without_a_schema_fork` covers nine types, each encoding distinctly, one type pair, no per-vertical field |
| Identity/authority/execution/hardware relationships explicit and non-confusable | **MET** — S17-1/2/3/9, four mutations |
| Parent-child creation never implies authority | **MET** — S17-5, mutation-checked |
| Existing AIP/AIRI artifacts remain verifiable | **MET** — no existing file modified; compatibility suite asserts it |

### Is Skill 18 permitted?

**Not from this report alone.** Skill 18 (Autonomy Execution Profile) is
permitted once this work passes its own audit gate — which, on the evidence
here, it does for the criteria the skill sets. What this report does *not*
authorise is treating §9.1 and §9.5 as closed: the descriptors are unsigned
and nothing consumes them. Skill 18 will need a signed carrier or it will be
building a profile on a record no one can trust.

That is the first thing Skill 18 should settle, and it should settle it
deliberately rather than by adding a key to `aip-system` in passing — that
would be a new trust anchor and a STOP condition.

**Production readiness is not claimed and is not implied by this report.**
