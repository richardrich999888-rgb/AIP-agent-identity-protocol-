# Skill 28 — Autonomous System Conformance: Evidence Report

**Specification** `.claude/skills/28-autonomous-system-conformance/SKILL.md`
**Baseline** `b5c401a` · **Branch** `claude/skill-25-implementation-xbz0t3`
**Plan** `docs/architecture/SKILL28_PLAN_AND_INVARIANTS.md` (written before implementation)
**Related** ADR-011 (assigned the profile-kit extraction here), ADR-014 (why it was not performed)

This report states what is CODE-PROVEN, TEST-PROVEN, EXECUTION-PROVEN,
DOCUMENTED, INFERRED and UNKNOWN. Nothing is promoted to a stronger class
because a fixture was built to demonstrate it.

---

## 1. Acceptance criteria

| # | criterion (from the specification) | status | where |
|---|---|---|---|
| R1 | The universal invariant set — twelve named invariants | met | `aip-conformance/src/invariant.rs`; `tests/universal.rs` (14 tests) |
| R2 | A machine-readable domain conformance matrix for the seven named domains | met | `src/{domain,matrix}.rs`; `docs/audit/CONFORMANCE_MATRIX.{json,csv}` |
| R3 | Cross-domain substitution tests — identity, execution, model, framework, parameter, observer evidence | met | `tests/substitution.rs` (6 tests, s1–s6) |
| R4 | Version and compatibility tests for adapters and proof packages | met | `tests/versioning.rs` (5 tests, v1–v5) |
| R5 | An audit artifact generator labelling claims by evidence class | met | `src/bin/emit-conformance.rs` |
| G1 | All supported domains pass the same core invariants | met | 84/84 cells `SATISFIED`; `tests/matrix.rs` |
| G2 | A new domain cannot silently weaken the central semantics | met | `tests/substitution.rs::s6`; `tests/no_second_architecture.rs` |
| G3 | Conformance output is independently reviewable | met | JSON + CSV committed; the generator is deterministic |

## 2. What the matrix says

Seven domains × twelve invariants = **84 cells, all filled, all `SATISFIED`**,
under these evidence classes:

| class | cells |
|---|---:|
| EXECUTION-PROVEN | 8 |
| TEST-PROVEN | 69 |
| CODE-PROVEN | 7 |
| DOCUMENTED / INFERRED / UNKNOWN | 0 |

No cell rests on prose. `EvidenceClass::supports_a_conformance_claim()` returns
`false` for `Documented`, `Inferred` and `Unknown`, so a cell resting on one
would be reported as a shortfall regardless of its `Conformance` label.

### 2.1 The number a reader should actually use

**Seven names are realised by five crates.** Skill 24 covers UGV *and*
robotics; Skill 25 covers industrial *and* critical edge. Two pairs share a
crate, so two of the seven rows are **not independent evidence**.

The matrix carries `realised_by` and `shared_with` in every row, the generator
prints the distinct-crate count, and
`tests/universal.rs::the_domain_set_reports_its_own_double_counting` fails if a
shared pair stops declaring the sharing. Reporting "seven domains conformant"
without that mapping would overstate coverage by two.

## 3. Evidence classification

**EXECUTION-PROVEN** — the containment crossing (`aip-containment/tests/
engine_to_containment.rs`, five tests against a live process) and the enterprise
local-effect path. Eight cells.

**TEST-PROVEN** — the twelve invariants as executed in `tests/universal.rs`,
the six substitution tests, the five version tests. Sixty-nine cells.

**CODE-PROVEN** — properties enforced by shape and read by inspection: the
absence of a `Waived` variant, the `Serialize`-without-`Deserialize` rule on
every artifact type, the dependency direction — here, the AIRI framework-identity rule, which is a
non-overridable method rather than a runtime check. Seven cells.

**DOCUMENTED** — this report, the plan, ADR-014. Not counted as conformance.

**INFERRED** — that a sixth domain would fit the same matrix. Nothing depends
on it.

**UNKNOWN** — everything in §5.

## 4. Architectural discipline

The conformance program is in an unusual position: it depends on everything and
is trusted to report on everything. Two guards keep that from becoming a second
source of truth, and both execute.

- **It states no semantics.** `tests/no_second_architecture.rs` reads this
  crate's own library source, comments stripped, and fails if it defines a
  verdict, a ceiling, an observation class, a mechanism, a reconciler or a
  verifier — or if it references a signing key, a private key or an identifier
  mint.
- **Nothing depends on it.** The same suite reads every manifest under
  `aip-standalone/` plus `aip-service/` and fails if any names
  `aip-conformance`. A conformance program something depended on could change
  what it is checking.

Unchanged and verified: one reconciler, one verifier, one `EvidenceCeiling`,
one `ObservationClass`, one keypair primitive, no new signer, no new trust
anchor, no wire change.

## 5. Known limitations

Stated as findings, not as reassurance.

1. **Seven rows, five crates.** Two rows are not independent evidence. The
   matrix says so in every row; a summary that quotes "7/7 conformant" without
   the mapping is overstating by two, and §2.1 exists so nobody does.

2. **Eleven of the twelve invariants are properties of the core, so their
   cells are identical across domains.** That sameness *is* the conformance
   claim — there is no per-domain identity model, reconciler or proof tree —
   but it means the matrix's per-domain granularity is real for exactly one
   invariant, `Attribution`. A reader could mistake 84 cells for 84
   independent checks. They are twelve checks and one axis.

3. **The axis that varies is embodiment, not domain.** ADR-011 found this and
   the matrix encodes it (`Domain::is_embodied`). Four embodied verticals made
   an embodiment-specific property look universal; enterprise disconfirmed it.
   A sixth domain should be checked against that axis before its row is
   trusted.

4. **`Containment` is not re-tested here.** Its cell is EXECUTION-PROVEN
   against `aip-containment/tests/engine_to_containment.rs`, and the cell says
   so. Reaching the crossing needs a live process and an actuator; duplicating
   that fixture for one property would have added a second way to be wrong.
   The related open finding — that actuation is unreachable from genuine
   reconciliation (Skill 16, B-3) — is unchanged and untouched by this work.

5. **The matrix is not mutation-tested.** The two previous milestones
   established that a passing test says nothing until it is shown capable of
   failing. `tests/matrix.rs::every_witness_naming_a_test_in_this_crate_names_
   one_that_exists` is the closest thing here — it fails if a cited test is
   renamed away — but no mutation has been run against `aip-conformance`
   itself. **This is the natural next milestone**, and it matters more than
   usual: an audit artifact whose generator is untested is an audit artifact
   that can lie confidently.

6. **The profile-kit extraction was not performed.** ADR-011 assigned it here;
   ADR-014 records why it was not done and, more importantly, that it is now
   **unassigned**. Covered by a normative check is not the same as removed;
   five copies of three rules still exist.

7. **No physical validation, deployment, or TRL position** is claimed or
   approached by this milestone.

## 6. Migration and versioning notes

- **No wire change.** `AIP_VERSION 0x0004`, `EXECUTION_BINDING_VERSION 1`,
  `LeafKind::ALL` = 9, and all five profile versions are pinned by
  `tests/versioning.rs` and unchanged.
- **New workspace member** `aip-standalone/aip-conformance`, last in the
  dependency order. Nothing depends on it, enforced by test.
- **New artifact schema** `CONFORMANCE_SCHEMA_VERSION = 1`, carried in the
  emitted JSON so a reviewer diffing two artifacts can tell a schema change
  from a semantic one.
- **The committed artifact is checked against the code** on every test run
  (`tests/matrix.rs::the_committed_artifact_is_current`). A conformance change
  without a regenerated artifact fails the build, because a stale audit
  artifact is worse than none.
- **Regenerate with** `cargo run -p aip-conformance --bin emit-conformance`.
## 7. Test results

### 7.1 The conformance program

| suite | tests | covers |
|---|---:|---|
| `tests/universal.rs` | 14 | R1 — the twelve invariants plus the set's own totality |
| `tests/substitution.rs` | 6 | R3 — s1 identity, s2 execution, s3 framework, s4 parameter, s5 observer evidence, s6 the verdict itself |
| `tests/versioning.rs` | 5 | R4 — v1 wire constants, v2 domain separation, v3 profile versions, v4 unknown proof version, v5 artifact schema |
| `tests/matrix.rs` | 7 | R2, R5 — totality, witness↔test correspondence, determinism, artifact currency |
| `tests/no_second_architecture.rs` | 5 | the program's own discipline and the dependency direction |
| **Total** | **37** | 0 failures |

### 7.2 Full workspace

```
cargo fmt --all -- --check                                            EXIT 0
cargo clippy --workspace --all-targets --all-features -- -D warnings  EXIT 0
cargo test --workspace                                                EXIT 0
  2117 passed · 0 failed · 6 ignored   (190 result blocks, 0 FAILED blocks)
```

| | previous | this milestone | delta |
|---|---:|---:|---:|
| passed | 2,080 | **2,117** | **+37** |
| failed | 0 | **0** | 0 |
| ignored | 6 | **6** | 0 |

The +37 is the conformance crate's own suites exactly. No pre-existing test
changed status.

### 7.3 Two defects the run found in this work

Recorded because a report that only lists successes is not evidence of care.

- **`i02` contained a tautology.** An assertion of the form
  `x.is_ok() || x.is_err()` is true for every `x`. It was removed rather than
  repaired; the load-bearing assertion (a child identity appears in no
  authority chain) stands on its own.
- **The CSV writer did not quote its fields.** A cell whose `reason` is a
  sentence contains commas, and the first version would have emitted a row
  with the wrong field count. Fixed by implementing RFC 4180 quoting rather
  than by forbidding commas in prose — the reason is the part a reviewer
  reads, and distorting it to fit the format would have been the wrong trade.
  `tests/matrix.rs::emission_is_deterministic` now parses every row's
  separators outside quotes and asserts the field count, and asserts that at
  least one reason contains a comma so the test cannot pass vacuously.

Two further corrections were made to my own drafts before publication: the
evidence-class counts in §2 were wrong (62/14 where the artifact says 69/7),
and three matrix witnesses named tests that did not exist. The witness↔test
guard was written precisely so that the second class of error cannot survive a
test run.

## 8. Architecture verification

| Invariant | Result |
|---|---|
| One reconciler | **UPHELD** — `pub fn reconcile_*` in one file; the conformance crate defines none |
| One verifier | **UPHELD** — NEXORA remains authoritative and untouched |
| One evidence hierarchy | **UPHELD** — one `ReconciliationResult` |
| One `EvidenceCeiling` / `ObservationClass` | **UPHELD** — one definition each |
| One crypto primitive | **UPHELD** — `SigningKey::generate` appears once, in `aip-crypto` |
| No new signer or trust anchor | **UPHELD** — the conformance crate's library references neither, by test |
| No second source of truth | **UPHELD** — it states no semantics, and nothing depends on it, both by test |
| No wire/protocol change | **UPHELD** — every constant pinned by `tests/versioning.rs` |
| No production dependency expansion | **UPHELD** — the new crate is the only manifest change besides the workspace member list |

## 9. Exact git state

| | |
|---|---|
| HEAD at start | `b5c401a9748913e940fbb3c525680c653042213c` |
| Branch | `claude/skill-25-implementation-xbz0t3` |
| Working tree at start | clean |
| **Existing production source files changed** | **0** |
| Files added | the `aip-conformance` crate (9), two artifacts, three documents |
| Files modified | `Cargo.toml` (one workspace member) |
