# Skill 29 — Implementation Plan and Invariant Matrix

**Written before implementation**, per the skill's required workflow step 2.

**Baseline** `cc70add` · **Branch** `claude/skill-25-implementation-xbz0t3`
**Specification** `.claude/skills/29-autonomous-edge-threat-model/SKILL.md`
**Source of truth** the revised forensic audit (blockers B-1a … B-10), the
AIRI threat model, and the non-establishments N-1 … N-11

---

## 1. What Skill 29 asks for

| # | Required work | Where it lands |
|---|---|---|
| R1 | Threat-model thirteen named threats | `aip-conformance/src/threat.rs` |
| R2 | Map each to AIP / AIRI / observation / reconciliation / warrant / containment / NEXORA | the same, seven layers per threat |
| R3 | Trust roots, key custody, transport authenticity, recovery obligations | `docs/architecture/EDGE_TRUST_AND_CUSTODY.md` |
| R4 | Scenario-driven adversarial tests across UAS, robotics, industrial, disconnected | `aip-conformance/tests/threat.rs` |
| R5 | Track inherited blockers until closure is **independently verified** | `aip-conformance/src/blocker.rs` + `tests/blocker.rs` |

Acceptance gate: every high-impact threat has an explicit system response **or**
an explicit `CANNOT_PROVE` boundary; **no threat is marked mitigated merely
because a log or callback exists**.

## 2. Discovery findings that shape the design

### 2.1 A threat model exists, and it has a shaped hole

`docs/architecture/AUTONOMOUS_EXECUTION_THREAT_MODEL.md` carries T1 … T15 and
is good. Mapped against the thirteen threats Skill 29 names:

| Skill 29 threat | existing | note |
|---|---|---|
| compromised agent | T1 | |
| compromised framework | T2 | |
| compromised model runtime | T5 | |
| compromised tool | T4 | |
| compromised process | T6 | |
| compromised host | T8 | |
| forged telemetry | T14, T15 | partial — runtime binding and physical-effect claims |
| replay | T10 | |
| stale authority | T12 | |
| **lost connectivity** | **absent** | zero matches for "connectivity" |
| **partial observation** | **absent** | zero matches |
| **observer failure** | **absent** | zero matches |
| **sensor deception** | **absent** | zero matches for the phrase |

**Four of the thirteen are not modelled at all**, and the hole is not random:
it is exactly where Skill 20 (observation profile), Skill 25 (industrial) and
Skill 26 (disconnected/space) landed. The document predates the
observation-integrity work and the space profile, so it models an attacker who
subverts the *actor* and not one who subverts or removes the *observer*.

Closing that hole is the substance of this milestone.

### 2.2 The disposition vocabulary is dictated by the gate

The specification says every threat maps to *prevention, detection,
uncertainty, or explicit non-detectability*, and that no threat is marked
mitigated merely because a log exists. Those two clauses together settle the
type:

```
Disposition ::= Prevented | Detected | Uncertainty | NotDetectable
```

**There is no `Mitigated`.** Skill 28 removed `Waived` from the conformance
vocabulary for the same reason and it worked: the way to guarantee a rule is
to leave the type no way to express its violation. A reviewer cannot write
"mitigated — we log it" because the word does not exist, and `Detected` must
name the mechanism that detects.

### 2.3 Where this lives

`aip-conformance`, as a second module and a second artifact — not a new crate.

It is the same shape: it asks questions of the core by calling the core, it
states no security semantics of its own, and nothing depends on it. The
crate's existing discipline guards (`tests/no_second_architecture.rs`) already
enforce all three and will cover the new module for free. ADR-014 argued
against duplication three days ago; standing up a parallel crate with a
duplicate set of guards would contradict it.

### 2.4 Inherited blockers — verified, not copied

The specification says *until their closure is independently verified*, so the
register was re-checked against current code rather than carried forward:

| id | register says | independently verified at `cc70add` |
|---|---|---|
| B-1a | CLOSED | **confirmed** — `verification_time_ms` and `future_tolerance_ms` are wired through `aip-service/src/evidence.rs` |
| B-3 | **OPEN** | **still open** — actuation remains unreachable from genuine reconciliation |
| B-4 | CLOSED | **confirmed, and stronger than recorded** — `SignedHead` has no public-key field at all, so a bundle-supplied signer is not merely refused but unrepresentable |
| B-5 | CLOSED | confirmed — mode comes from `OpenOptions::mode`, not a later `chmod` |
| B-6 | CLOSED | confirmed — custody load is fail-closed |
| B-7 | CLOSED | **confirmed** — `/v1/evidence/generate` is not mounted unless `AIP_ALLOW_MANAGED_SIGNING=1`; the route is chosen at router-build time, so on the refusing path no extractor exists and a seed sent to a default deployment is never deserialised |
| B-8 | CLOSED | confirmed — `ProofSeen` ledger |
| B-9 | CLOSED | confirmed — `#[non_exhaustive]` plus a private provenance field |
| B-10 | CLOSED | confirmed — `aip-service` is a workspace member |

One correction to my own first reading, recorded because the discipline cuts
both ways: B-7's seed fields still exist in the request type, and I initially
read that as an unclosed blocker. It is not. The endpoint is off by default and
the refusing path has no extractor. Verification changed my answer, which is
what verification is for.

## 3. The threat matrix

Thirteen threats × seven layers. Each cell carries a disposition, the mechanism
or boundary that produces it, and — where the answer is `Uncertainty` or
`NotDetectable` — the non-establishment (N-1 … N-11) that says so.

Layers: `Aip`, `Airi`, `Observation`, `Reconciliation`, `Warrant`,
`Containment`, `Nexora`.

**A layer that does nothing about a threat says `NotDetectable` with a
reason.** Filling it with `Prevented` because some *other* layer prevents the
threat would be the "mitigated because a log exists" failure one level up.

## 4. Test plan

| suite | covers | shape |
|---|---|---|
| `tests/threat.rs` | R1, R2, R4 | the matrix is total; every `Detected` names a mechanism; every `Uncertainty`/`NotDetectable` cites a non-establishment; scenario tests drive UAS, robotics, industrial and disconnected fixtures through the threats that reach them |
| `tests/blocker.rs` | R5 | each blocker's status is re-derived from the repository, not read from the register; an open blocker cannot be recorded closed |

## 5. What this milestone will not claim

- **Not** that a modelled threat is a defeated threat. The matrix records what
  the system does, including where it does nothing.
- **Not** that the four newly modelled threats are newly *defended*. They were
  always defended by Skills 20, 25 and 26; they were never written down here.
- **Not** any post-quantum property (N-10 stands).
- **Not** that B-3 is closed.
