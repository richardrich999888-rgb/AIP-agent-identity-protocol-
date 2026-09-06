# Skill 19 — Edge Hardware Identity and Binding: Evidence Report

**Branch** `claude/autonomous-accountability-skills-16-30`
**Analysis** `docs/architecture/PLATFORM_BINDING_TRUST_MAP.md`
**ADRs** ADR-001 (untouched), **ADR-002 (new, PROPOSED / NOT IMPLEMENTED)**

---

## 1. Baseline

Established fresh, not assumed: **111 suites, 1099 passed, 0 failed, 6
ignored.** The first run showed one failure —
`aip-observe::fanotify::fa05_live_*` — which passes in isolation and passed on
an immediate identical rerun. It is the known load-sensitive flake, unchanged.

## 2. The central finding

Reached by experiment against unmodified code, before any design work, and it
determined the scope of the whole skill:

> **T13's host-level case was already closed.**

`ObservedProcess::matches_process_of` compares `self.process == binding.process`,
and `ProcessInstance` derives `PartialEq` over `{pid, pid_start_time_ticks,
boot_id}`. `boot_id` is host-scoped, kernel-generated per boot, and read by the
probe from `/proc/sys/kernel/random/boot_id` — measured, never claimed by the
agent.

Probe result, existing code:

```
SAME HOST      → VerifiedExecution   / Attested / Match{1}
DIFFERENT HOST → IdentityDivergence  / Attested / Divergent{1}
```

The two differed only in `boot_id`.

**Consequences:** no reconciler change (Part 15's precondition was not met), no
new verdict class, no new trust anchor for this case. What was missing was not
a mechanism but a test — and an untested, undocumented property is
indistinguishable from an absent one to anyone reading the audit.

## 3. Trust-boundary classification

Every identifier classified in the trust map by what the system can establish
about it, not by what the field is named. The two entries that decide T13:

- `ExpectedExecution.execution_binding` is **AUTHORITATIVE as an
  authorization** — the DP signs what it permitted; it never looked at a host.
- The measured `boot_id` is **OBSERVATIONAL** — the only value distinguishing
  one machine-boot from another that is produced by something other than the
  subject.

Full table in the trust map, covering 20 identifiers across DESCRIPTIVE,
AUTHORITATIVE, OBSERVATIONAL, ATTESTED, DERIVED and UNTRUSTED.

## 4. Mechanism selection

Nine mechanisms (A–I) compared across attacker capability, what each proves and
does not prove, trust anchor required, operational cost, and offline, Linux,
UAS, robotics and space suitability.

**Selected: I — anchored observer evidence plus a verifier-supplied deployment
registry.** It is the minimum that closes the remaining gap, and the only
candidate that needs no new trust anchor. Every mechanism closing durable
hardware identity (E, F, G, H) requires one.

## 5. Gaps, and which were closed

| Gap | Status |
|---|---|
| Host-level T13 | **Already closed.** Now tested (9 tests) |
| G2 — measured `boot_id` unconnected to `PlatformId`/`HardwareId` | **Closed by `aip-platform`**, no new trust anchor |
| G1 — no durable hardware identity across reboots | **OPEN.** Needs a new trust anchor → ADR-002, STOP |
| G3 — single host, no off-host collector | **OPEN.** Same ADR |

## 6. ADR-002

**Required, and it exists: PROPOSED / NOT IMPLEMENTED.** No hardware
attestation code is on this branch.

All seventeen questions answered. The three that matter most:

- **Q10/Q13 — attestation unavailable ⇒ `NotEvaluated`.** A fleet where most
  nodes lack a TPM must not become a fleet where absence of attestation reads
  as absence of a problem.
- **Q12 — no software-only fallback, and none may be invented.** A
  software-only "attestation" is a self-report by the thing being attested;
  naming it attestation would convert `SelfReported` into `Attested` by
  relabelling.
- **Q14 — whether attestation raises evidence strength is left OPEN** under
  ADR-001, not settled by an implementation detail. It is close to ADR-001
  §Q13's equivocation shape and must not be decided implicitly.

## 7. New types

| Type | Purpose |
|---|---|
| `PlatformRegistry`, `HostRegistration` | The verifier's map, time-bounded |
| `PlatformBinding`, `PlatformDisposition` | What may honestly be said about where an execution ran |
| `BindingMethod` | How a binding was reached — `SelfDeclared` / `DeploymentRegistry` / `HardwareAttested` (unconstructible) |

Reused verbatim: `PlatformId`, `HardwareId` (`aip-system`), `boot_id` /
`ProcessInstance` / `ExecutionBinding` (`aip-types`), execution id
(`aip-airi`), canonical encoders, observer and DP trust models. Asserted by
`no_primitive_is_duplicated`.

## 8. Invariants

| ID | Invariant | Class |
|---|---|---|
| S19-1 | Platform ≠ hardware identity | TEST-PROVEN (a04) |
| S19-2 | Agent identity absent from a platform binding | TEST-PROVEN (a06) |
| S19-3 | Mission absent from a platform binding | TEST-PROVEN (a07) |
| S19-4 | A self-reported platform establishes nothing | TEST-PROVEN (t13_03, a23b), mutation-checked |
| S19-4a | An `ObservedBoot` exists only after verification against anchors | CODE-PROVEN + TEST-PROVEN (a16b, a16c, a16d), mutation-checked |
| S19-5 | An unregistered host is unknown, not wrong | TEST-PROVEN (a22, t13_06), mutation-checked |
| S19-6 | No observation ⇒ `NotEvaluated` | TEST-PROVEN (a21), mutation-checked |
| S19-7 | A platform mismatch is named, not absorbed | TEST-PROVEN (t13_04, t13_08), mutation-checked |
| S19-8 | Hardware replacement does not preserve old trust | TEST-PROVEN (a09), mutation-checked |
| S19-9 | Overlapping registrations refused, not resolved | TEST-PROVEN (a09b) |
| S19-10 | `HardwareAttested` unconstructible | CODE-PROVEN + TEST-PROVEN (a14/a15, a16), mutation-checked |
| S19-11 | Substitution changes the digest | TEST-PROVEN (a03, a05, a17/a18, a19, a20) |
| S19-12 | Unknown versions refused | TEST-PROVEN (a25b) |
| S19-13 | This crate reads no clock | TEST-PROVEN (compatibility) |
| S19-14 | This crate signs nothing | TEST-PROVEN (compatibility) |
| S19-15 | A binding carries no registry state | TEST-PROVEN (a23) |
| S19-16 | One platform may hold many compute modules | TEST-PROVEN (a24) |
| S19-17 | Verdict path cannot see this crate | TEST-PROVEN (compatibility) |

## 9. Mutation results

Run with `--no-fail-fast`, after discovering that cargo stops at the first
failing target and had been hiding two thirds of one mutation's effect.

| Mutation | Result |
|---|---|
| Unregistered host silently binds | **4 fail** ✓ |
| Mismatch reported as bound | **3 fail** ✓ |
| No observation treated as bound | **1 fails** ✓ |
| Closed registration still applies | **2 fail** ✓ |
| `HardwareAttested` becomes constructible | **2 fail** ✓ |

## 10. Test results

```
cargo test -p aip-platform      44 passed, 0 failed   (9 t13, 27 adversarial, 8 compatibility)
cargo test --workspace         116 suites, 1143 passed, 0 failed, 6 ignored
cargo test -p airon-aip         79 passed, 0 failed
cargo clippy --workspace --all-targets   clean
cargo fmt --all -- --check               clean
```

Workspace members: 21 → **22**. Net: +44 tests over the 1099 baseline.

## 10a. A defect in this crate, found by re-audit and fixed

`PlatformBinding::resolve` originally took the observed boot id as a bare
`Option<[u8; 16]>`. Nothing required those bytes to have come from an anchored
observer, so a caller could pass the boot id out of the agent's own
self-reported `ExecutionBinding` and receive a `Bound` disposition — exactly
the failure **acceptance criterion 4** prohibits. The property held only by
caller discipline, which is not prevention.

Fixed by `ObservedBoot`: a private field whose only constructors verify an
`AttestedBatch` against the verifier's anchors first. No `from_bytes`, no
`new`, no `From<[u8; 16]>`.

This also closes matrix case 16 — *attestation signed by an untrusted key* —
in the form this architecture actually has one: a validly signed batch from an
observer the verifier does not anchor (`a16b`).

Mutation results for the fix: skipping verification fails 2. Adding a public
`from_bytes` escape hatch was caught by **nothing**, which is an honest limit
of a type-system invariant — the compiler stops external callers, not a later
edit inside the crate. A structural guard now catches it.

Two of my own guard tests fired falsely during this fix and were made precise
rather than worked around: they scanned raw manifests, where "load-bearing"
contains "ring" and a comment mentioning `aip-reconcile` read as a dependency.
Rewording the comments to dodge the scan would have been backwards.

`aip-observe` became a runtime dependency, deliberately: it is the observation
layer rather than a verdict engine, `aip-reconcile` already depends on it, and
it is what enforces the property. The verdict-engine guard is unchanged in
force.

## 11. An error of mine, recorded

One assertion was wrong and was corrected rather than accommodated: I asserted
the canonical encoding *starts with* the domain tag's text. `put_domain`
length-prefixes it, so the encoding leads with a u32 length. The assertion was
wrong, not the encoding; the test now checks the length prefix and the tag at
their real offsets.

## 12. Compatibility

- **No existing source file modified.** No wire format changed. No existing
  serialized data reinterpreted.
- **Reconciliation untouched** — verified by `git diff` over `aip-reconcile`,
  `aip-warrant` and `aip-containment/tests`: empty.
- **NEXORA untouched.** The property a future integration would rely on —
  bindings resolving to different platforms have different digests — is
  asserted (`t13_09`) rather than the proof format being changed
  speculatively.
- Dependency direction asserted both ways. `aip-reconcile` and `aip-observe`
  appear under **dev-dependencies only**, so the T13 tests drive the real
  engine without the crate reaching the verdict path at runtime.
- Unknown versions refused, including a binding claiming an unimplemented
  method.

## 13. Remaining risks

1. **G1 — no durable hardware identity.** A reboot breaks the binding
   legitimately, so a reboot cannot be distinguished from a hardware
   replacement. ADR-002.
2. **G3 — single-host deployments.** With no off-host collector, `boot_id` is
   procfs content under the same root as everything else (T8). The `Attested`
   cap is load-bearing.
3. **The registry is a verifier assertion.** It inherits the verifier's trust
   model rather than improving on it. Nothing here reads a serial number.
4. **Nothing consumes `PlatformBinding` yet.** The registry and binding exist;
   no producer emits them into a reconciler input path or a NEXORA proof. The
   capability is the mechanism, not its use.
5. Pre-existing load-sensitive flakes unchanged (`fa05_live_*`,
   `live_freeze::f_p_a_*`).
6. PostgreSQL store still never compiled.

## 14. Gate

| Criterion | Status |
|---|---|
| 1. T13 explicitly addressed | **MET** — host-level proven already closed (9 tests); platform-level closed by the registry |
| 2. Platform ≠ hardware identity | **MET** — S19-1 |
| 3. Agent ≠ execution identity | **MET** — S19-2, and no agent field exists |
| 4. Self-reported platform cannot establish binding | **MET** — S19-4, mutation-checked |
| 5. Execution→platform binding has a defined trust boundary | **MET** — anchored observer + verifier registry, bounded in the trust map |
| 6. Platform substitution adversarially tested | **MET** |
| 7. Hardware substitution adversarially tested | **MET** |
| 8. Lifecycle explicit | **MET** — time-bounded registrations, replacement, reboot, restart, staleness |
| 9. Offline supported | **MET** — portable data, no clock, no network |
| 10. No accidental trust anchor | **MET** — asserted structurally (no signing dependency, no signing code) |
| 11. ADR-002 exists before implementation | **MET** — and the mechanism is NOT implemented |
| 12. Reconciliation semantics not weakened | **MET** — unchanged, verified by diff |
| 13. NEXORA sound | **MET** — untouched |
| 14. All tests pass | **MET** — 1138 / 0 |
| 15. Production readiness unclaimed | **MET** |

**Skill 19: PASS.**

### Is Skill 20 permitted?

**Yes.** Skill 20 (Autonomous Observation Profile) is the natural next step:
this skill's entire binding rests on an anchored observer having measured the
execution, and Skill 20 is where that observation profile is specified.

Two conditions carried forward, stated so they are not discovered late:

1. **ADR-002 remains PROPOSED.** Skill 20 must not introduce hardware
   attestation by another name — an observer that reports a TPM quote is
   relaying an attestation, and the trust anchor question is unchanged by
   which process carries the bytes.
2. **Observer keys stay in `aip-observe`.** `EffectEvidence` (Skill 18) and
   `PlatformBinding` (Skill 19) both reference observations without holding
   keys. Skill 20 must not move that boundary.

**Production readiness is not claimed and nothing was merged to main.**
