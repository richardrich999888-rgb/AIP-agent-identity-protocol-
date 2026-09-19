# Skills 26 and 27 — Discovery, Plans and Invariant Matrices

**Specifications** `.claude/skills/26-disconnected-space-autonomy-profile/SKILL.md`
and `.claude/skills/27-enterprise-autonomy-profile/SKILL.md` — one authoritative
document each, byte-identical on `claude/codebase-production-readiness-wm6idp`
and `claude/autonomous-accountability-skills-16-30`. No reconciliation required.

**Baseline** `742517c` · **Branch** `claude/skill-25-implementation-xbz0t3` ·
**Main** `872dbf3`, untouched.

---

## 1. Shared-primitive reuse map

The single most important discovery result: **most of what both skills require
already exists in the core.** Neither profile may reimplement any of it.

### Skill 26 reuses

| requirement | existing primitive | where |
|---|---|---|
| continuity gaps, explicit and sticky | `ObserverLedger` + `ContinuityStatus::GapObserved` — once a gap is admitted, a later contiguous batch **does not** restore `Verified` | `aip-observe/src/continuity.rs` |
| missing middle segment | `ContinuityFault::Gap { expected, offered }` | same |
| branch / fork history | `ContinuityFault::Fork { .. }` → permanent quarantine | same |
| replayed segment | `ContinuityFault::Replay { sequence }` | same |
| late segment after later evidence | `ContinuityFault::Rollback { last, offered }` | same |
| forged continuity restoration | `ObserverLedger::resume_at` leaves status `Unverified` | same |
| offline packaging and transport | `export_proof` / `import_proof`, anchors moved separately | `aip-nexora/src/export.rs` |
| duplicate submission across contacts | `ProofLedger`, `ReplayStanding`, `record_submission` | `aip-nexora/src/replay.rs` |
| delayed ground command / stale authority | `AuthorityStanding` against a verifier-supplied present time; `grants_authority_now()` | same |
| observation time as an upper bound on event time | `ObservationRecord::attested_at_ms` — "an event inside cannot have happened after this moment" | `aip-observation/src/record.rs` |
| system type | `SystemType::Space` (0x08) | `aip-system/src/system.rs` |
| profile slot | `ProfileKind::Environment`, `ProfileRef` | `aip-system/src/profile.rs` |
| authority commitment | `ActionParameters` → `ExpectedExecution.parameter_digest` | `aip-authorize` |
| proof tree | `CommitmentLog`, `LeafKind` (9, frozen) | `aip-nexora/src/merkle.rs` |

**What Skill 26 genuinely adds:** an *arrival and reassembly layer above the
ledger*. The ledger is strict and single-chain — a late segment is a `Rollback`
and is refused. Store-and-forward legitimately delivers segments out of order
across contacts. The profile buffers bundles, orders segments before offering
them to the ledger, and accounts for gaps that remain unfilled. **The ledger
stays the authority; the profile never repairs a fault.**

### Skill 27 reuses

| requirement | existing primitive | where |
|---|---|---|
| framework identity, and it not being a trust anchor | `FrameworkIdentity` — "**Not a trust input**: a popular framework earns no authority here, and nothing in this crate branches on `name` to grant anything" | `aip-airi/src/provenance.rs` |
| model mapping | `ModelProvenance` | same |
| tool / API mapping | `ToolInvocation`, `ToolReport`, `ReportedOutcome` | same |
| subprocess mapping | `SubprocessReport` — path is committed, and "a same-path different binary is a different program and this field cannot tell the difference. `aip-observe` can" | same |
| context propagation | `ContextPropagation` + `PropagationBoundary` (AsyncTask, Thread, Process, Subprocess, WorkerQueue) | same |
| the cryptographic binding a copied token cannot forge | `ExecutionBinding::identity_bytes` — agent AIP-ID + process instance + exe **content** hash | `aip-types/src/lib.rs` |
| filesystem effect | `SourceMechanism::Fanotify` → `ObservationClass::FilesystemEffect` | `aip-observe`, `aip-observation` |
| network effect | `ProcNetTable`, `SockStateTracepoint`, `SockSendTracepoint` | same |
| system type | `SystemType::Enterprise` (0x09) | `aip-system` |
| thin-adapter pattern | `aip-airi` adapters; `aip-industrial::ProtocolAdapter` | existing |

**What Skill 27 genuinely adds:** tenant/workload binding as a *commitment that
covers the execution identity digest*, and the local-vs-remote effect split.

---

## 2. The finding that shapes both profiles

**Enterprise is the first vertical whose top evidence tier is partially
reachable.**

UAS, robotics and industrial all bottom out at `PhysicallyObserved`, which no
mechanism implements. Enterprise does not: a file write is `Fanotify`, a socket
is `ProcNetTable`, bytes accepted are `SockSendTracepoint`. Those are
implemented mechanisms observing real effects.

What remains unreachable for enterprise is the **remote** effect: that a row
changed in a database on another host, that an API call had its intended
consequence at the far end. That is outside every mechanism, exactly as a valve
is.

So the enterprise profile must split `EnterpriseEffect` into **local**
(observable, `Attested`) and **remote** (unobservable, `CANNOT_PROVE`), and the
cross-vertical guard must not assert "the top tier is unreachable" across all
five — because that assertion is embodiment-specific, not universal.

**This is the disconfirming instance ADR-009 asked for.** See §7.

---

## 3. Skill 26 — implementation plan

New crate `aip-standalone/aip-space`. Domain tag
`SYNTRIASS/AUTONOMY/SPACE_PROFILE/v1`, version 1, profile id `vanian.space.v1`,
`ProfileKind::Environment`.

| required object | module | shape |
|---|---|---|
| `SpaceExecutionProfile` | `profile.rs` | the profile document; declares sources, link model, autonomy modes; projects into `ObservationProfile` |
| `AutonomyModeTransition` | `mode.rs` | a committed record of a mode change, with the rule that a transition is *declared* and its cause is not established |
| `DelayedEvidence` | `delayed.rs` | wraps evidence with `attested_at_ms` / `received_at_ms` / `verified_at_ms`; latency establishes nothing |
| `StoreAndForwardBundle` | `bundle.rs` | versioned, domain-separated, injectively encoded; carries a contiguous segment run; `BundleLedger` detects duplicates across contacts |
| `GroundVerificationContext` | `ground.rs` | the ground station's present time and what it may conclude; delegates authority staleness to `AuthorityStanding` |

Supporting: `error.rs`, `link.rs` (`LinkState`, `ContactWindow`), `segment.rs`
(the reassembly layer over `ObserverLedger`), `sensing.rs`, `corroborate.rs`,
`state.rs`.

### Skill 26 invariant matrix

| # | invariant | enforced at | pinned by |
|---|---|---|---|
| S1 | Receipt time is never event time | `DelayedEvidence::event_time_established()` → `false` | `delayed::tests` |
| S2 | Latency establishes nothing about the event | `DelayedEvidence::latency_ms()` is reported and feeds no decision | `delayed::tests` |
| S3 | A gap, once observed, is never closed by later evidence | delegates to `ObserverLedger` sticky `GapObserved`; profile adds `SegmentLedger::unfilled_gaps()` which only grows | `segment::tests`, adversarial 1, 2 |
| S4 | A gap is never bridged by later evidence | `SegmentLedger` refuses to mark a gap filled unless the exact missing sequences are supplied | adversarial 1, 2 |
| S5 | A missing segment never implies non-occurrence | `SegmentLedger::non_occurrence_admissible()` → `false` always | adversarial 1 |
| S6 | Reconnection never upgrades evidence | `LinkState::Reconnected` grants nothing; `ContinuityStatus` unchanged by link state | adversarial 9 |
| S7 | A replayed segment after reconnection is refused | `ContinuityFault::Replay` surfaced, never repaired | adversarial 3 |
| S8 | A duplicate bundle is refused | `BundleLedger` keyed on bundle digest | adversarial 4 |
| S9 | A forked history is never silently collapsed | `ContinuityFault::Fork` → permanent quarantine, surfaced | adversarial 6 |
| S10 | A delayed command's authorization time, contact time, receipt time and execution time stay distinct | `CommandTiming` carries four fields and computes no causal order | adversarial 7, 8 |
| S11 | Forged bundle metadata fails the digest | `StoreAndForwardBundle::digest()` covers every field | adversarial 10 |
| S12 | A malformed or truncated bundle is refused, not partially accepted | constructor validation + `verify_segments_contiguous()` | adversarial 11, 12 |
| S13 | Agreement never raises a ceiling | `SourceAgreement::ceiling_after_agreement` returns base | cross-vertical |
| S14 | A state claim may only echo or weaken | `MissionState::assertable` | cross-vertical |
| S15 | No second reconciler, verifier, ledger, proof tree, key or identifier | crate structure | `no_second_architecture.rs` |

---

## 4. Skill 27 — implementation plan

New crate `aip-standalone/aip-enterprise`. Domain tag
`SYNTRIASS/AUTONOMY/ENTERPRISE_PROFILE/v1`, version 1, profile id
`vanian.enterprise.v1`, `ProfileKind::Environment`.

| required mapping | module | shape |
|---|---|---|
| agent, model, tool, API, database, filesystem, container, cloud execution | `resource.rs` | `EnterpriseResource` — eight members, each declaring its observing mechanism (or none) and its effect locality |
| framework adapters | `adapter.rs` | `EnterpriseAdapter` trait over `aip-airi::FrameworkIdentity`; no adapter may raise a ceiling |
| tenant/workload binding | `binding.rs` | `WorkloadBinding` — commits tenant, workload **and** `ExecutionBinding::identity_bytes` digest |
| context propagation | `context.rs` | `ContextChain` over `aip-airi::PropagationBoundary`; container modelled as a `Process` crossing plus a declared, unmeasured container attribution |
| effect | `effect.rs` | `EnterpriseEffect` split local (observable) / remote (unobservable) |

Supporting: `error.rs`, `state.rs`, `corroborate.rs`, `profile.rs`.

### Skill 27 invariant matrix

| # | invariant | enforced at | pinned by |
|---|---|---|---|
| E1 | A workload binding is not transplantable across tenants | `WorkloadBinding` digest covers the tenant | adversarial 1 |
| E2 | …nor across agents | digest covers the execution identity digest, which covers the agent AIP-ID | adversarial 2 |
| E3 | …nor across frameworks | digest covers the framework identity | adversarial 3 |
| E4 | A copied workload identity without the matching execution binding fails | digest covers `ExecutionBinding::identity_bytes` | adversarial 4, 5 |
| E5 | A subprocess boundary substitution changes the chain digest | `ContextChain` links each hop to the previous digest | adversarial 6 |
| E6 | A container attribution is declared, never measured | `ContainerAttribution::is_measured()` → `false` | adversarial 7 |
| E7 | Tool/API identity substitution changes the commitment | resource commitment covers the resource identity | adversarial 8 |
| E8 | A database/filesystem operation does not transplant between workloads | effect binding covers the workload binding digest | adversarial 9 |
| E9 | A stale context is refused | `ContextChain` window + `admit_at` | adversarial 10 |
| E10 | A remote effect is never established | `EnterpriseEffect::remote` has no mechanism, computed | `effect::tests` |
| E11 | A framework name grants nothing | no code branches on `FrameworkIdentity::name`; guard test | `no_second_architecture.rs` |
| E12 | No enterprise-only reconciler, verifier or trust score | crate structure | `no_second_architecture.rs` |
| E13 | Agreement never raises a ceiling | `SourceAgreement::ceiling_after_agreement` | cross-vertical |
| E14 | A state claim may only echo or weaken | `WorkloadState::assertable` | cross-vertical |

---

## 5. Wire / version impact assessment

**No wire change for either skill. No core file is modified.**

| candidate change | verdict | reasoning |
|---|---|---|
| add `PropagationBoundary::Container` to `aip-airi` | **REJECTED** | It is encoded into the `AiriEvent` signing preimage, so it is a wire change. It is also dishonest: the core's settled position is that a container is **not an established identity** — no mechanism measures a namespace set or a cgroup, and a namespace inode is reused after it is freed (`aip-robotics::RobotIdentityKind::Container`). A container crossing **is** a process crossing at the kernel level, so the existing `Process` boundary already represents it faithfully, and the container attribution is recorded in the profile as declared-and-unmeasured. Adding a variant would imply a boundary the core cannot see. |
| add a `receipt_at_ms` field to `ObservationRecord` | **REJECTED** | Receipt is a fact about the *verifier's contact*, not about the observation, and the spacecraft cannot sign it. `DelayedEvidence` wraps the record instead. No signed field changes. |
| add a `SourceMechanism` for a spacecraft sensor or a cloud audit log | **REJECTED** | The schema fork ADR-003 exists to prevent, refused for the fifth and sixth time (ADR-005 avionics, ADR-006 encoders, ADR-008 transmitters, ADR-010 cameras). |
| new `LeafKind` for a store-and-forward bundle | **REJECTED** | `LeafKind::ALL.len() == 9` is asserted by three existing tests. A bundle's contents are already committable as `AttestedBatch`, `SignedHealth`, `Expectation` and `Reconciliation` leaves; the bundle is a *container*, and containers are not evidence. |

New domain tags: two, both in new crates, with structure discriminants inside
each preimage. New action-parameter keys: four, each versioned in the key.
`OBSERVE_PROTOCOL_VERSION` stays 9; every other version constant is untouched.

---

## 6. Threat / adversarial matrix

### Skill 26 — the twelve required cases

| # | attack | expected outcome |
|---|---|---|
| 1 | missing middle segment | `Gap` recorded, permanent; non-occurrence refused |
| 2 | delayed middle segment arriving after later evidence | `Rollback` from the ledger; the gap stays recorded |
| 3 | replayed old segment after reconnection | `Replay` fault |
| 4 | duplicated store-and-forward bundle | `BundleLedger` refuses the second |
| 5 | reordered evidence | reassembled by sequence, or refused; never silently accepted out of order |
| 6 | forked history A/B | `Fork` → permanent quarantine |
| 7 | delayed ground command | four timestamps stay distinct; no causal order manufactured |
| 8 | observation arrives after command | ordering by observation time refused as a causal claim |
| 9 | forged continuity restoration | `resume_at` leaves `Unverified`; link state grants nothing |
| 10 | forged bundle metadata | digest mismatch |
| 11 | malformed bundle | constructor refusal |
| 12 | truncated bundle / missing tail | contiguity check refusal |

### Skill 27 — the ten required cases

| # | attack | expected outcome |
|---|---|---|
| 1 | cross-tenant transplantation | binding digest mismatch |
| 2 | cross-agent transplantation | execution identity digest mismatch |
| 3 | cross-framework transplantation | framework commitment mismatch |
| 4 | copied workload identity | no matching execution binding → mismatch |
| 5 | copied execution context | chain digest mismatch |
| 6 | subprocess boundary substitution | chain link mismatch |
| 7 | container boundary substitution | container attribution is unmeasured; establishes nothing either way |
| 8 | API/tool identity substitution | resource commitment mismatch |
| 9 | database/filesystem op transplanted between workloads | effect binding mismatch |
| 10 | stale context replay | freshness refusal |

**Required property for both: no test may turn uncertainty into success.**

---

## 7. ADR-009's trigger has fired, and what this session does about it

ADR-009 deferred the shared profile-kit extraction and moved the trigger to
*"the first non-embodied vertical or the first cross-vertical consumer,
whichever arrives first"*. **Skill 27 is the first non-embodied vertical.**

The evidence the trigger was waiting for is now in:

| rule | generalises to a non-embodied vertical? |
|---|---|
| agreement never raises a ceiling | **yes** — enterprise has multiple correlated telemetry sources and the rule applies unchanged |
| a state claim may only echo or weaken over an ordered evidence ladder | **yes** — the ladder shape holds |
| independence without an implemented mechanism establishes nothing | **yes** — a cloud audit log is external to the workload and has no mechanism here |
| **"the top tier is unreachable"** | **NO — this one is embodiment-specific.** Enterprise's local effects *are* observable through implemented mechanisms. |

So three rules generalise and a fourth property that the two-vertical and
three-vertical guards happened to share does **not**. That is exactly the
disconfirming instance ADR-009 said was missing, and the extraction is now
justified on evidence rather than deferred on argument.

**This session does not perform it.** The extraction edits four shipped,
validated crates (`aip-uas`, `aip-robotics`, `aip-industrial`, and whichever of
the two new ones ships), and riding it along with two skill implementations
would violate *"implement the smallest compatible change"* and would put four
validated suites at risk inside a change gated on something else.

ADR-011 records that the trigger has fired, what the evidence says, and that the
extraction is **owed** — scoped to Skill 28, which is the cross-vertical
consumer and its natural home. The cross-vertical guard is widened to five
verticals in the meantime, and it is now explicitly *two* guards: the three
universal rules, and the embodiment-specific properties asserted only over the
four embodied verticals.

---

## 8. Exact acceptance checklist

### Skill 26

- [ ] `SpaceExecutionProfile`, `AutonomyModeTransition`, `DelayedEvidence`, `StoreAndForwardBundle`, `GroundVerificationContext` — exact names
- [ ] connected / disconnected / reconnection / delayed arrival / continuity transitions represented
- [ ] event-time / observation-time / receipt-time distinctions preserved
- [ ] gaps explicit, unbridged, never non-occurrence, never upgraded by reconnection
- [ ] delayed command: authorization / contact / receipt / execution / observation / ground-verification times distinct
- [ ] store-and-forward: collect offline, package, transfer, verify after reconnection
- [ ] forked histories not silently collapsed
- [ ] replay across contacts refused
- [ ] NEXORA reused; no new proof tree; offline reconstruction flows through the existing verifier
- [ ] all twelve adversarial cases
- [ ] **acceptance gate: a simulated disconnected mission executes, collects locally, loses link, continues, regains link, bundles, transfers, is reconstructed and verified offline, with gaps preserved**

### Skill 27

- [ ] mappings for agent, model, tool, API, database, filesystem, container, cloud execution
- [ ] thin framework adapters; no framework is a trust anchor
- [ ] tenant/workload binding separate from global identity; the four identities not collapsed
- [ ] context propagation across worker / subprocess / container; downstream context not forgeable by copying a string
- [ ] all ten adversarial cases
- [ ] **acceptance gate: enterprise workloads map into the same core; no enterprise-only reconciler, verifier, trust score or evidence hierarchy; cross-vertical compatibility demonstrated by tests**
