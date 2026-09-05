# SNIFFER DOG 2.0 — AGENT RUNTIME INTEGRITY & PROVENANCE ARCHITECTURE

> **Status: DESIGN_ONLY.** This document specifies an architecture. Writing it
> implements nothing. Every component below carries a classification taken
> from the repository at `0b737d9`, and every classification other than
> `PRODUCTION` / `PARTIAL` means the component does not exist. Nothing here
> may be cited as capability until an implementation report says so.
>
> Governing rule, unchanged from Skill 6.5: **the agent may describe itself,
> the authority may authorize it, but only independent evidence can establish
> what it actually did.**
>
> **Implementation status** is tracked in `SNIFFER_DOG_2_0_IMPLEMENTATION_REPORT.md`
> and `SNIFFER_DOG_2_0_GAP_MATRIX.md`. Phase B (`aip-agent`: SD-01 reuse,
> SD-05 projection, SD-02 skeleton) and Phase C1 (SD-04: identity, authority
> and process lineage without a reconciled verdict) and Phase D (SD-06:
> delegation graph over verified chains) are implemented in the
> reduced form those documents state; every other component remains as
> classified below. Out-of-tree branches were reviewed in
> `OUT_OF_TREE_HARVEST_REVIEW.md`; nothing from them is merged.

## 0. Why this document exists

Stages 0–7c built an evidence pipeline: corrected AIP authority (Skill 3),
process-instance execution identity (Skill 4), an independent decision point
(Skill 5), an observer with an off-host signer (Skill 6), kernel-mediated
sensing with provenance and loss accounting (Skill 6.5, "Sniffer Dog"), a
reconciler whose default is `CANNOT_PROVE` (Skill 7), and action evidence for
two classes (Stages 7/7b/7c). Each answers one narrow question about one
execution.

Sniffer Dog 2.0 asks a wider question about one **agent**:

> Who is this autonomous intelligence, where did it come from, what is it
> allowed to do, what did it actually do, and what evidence proves its
> history?

The upgrade is a layer **around** the existing architecture, not a change to
it. The separation of authorities built so far — decision point signs what is
permitted, observer signs what happened, reconciler interprets and signs
nothing — is the thing this document exists to protect. If any section below
would require an existing boundary to move, that section is wrong.

## 1. The six dimensions, and the rule that they never collapse

| Dimension | Question | Who may establish it | Existing home |
|---|---|---|---|
| **IDENTITY** | Which agent is this? | the identity's key holder plus its issuer's signature | `aip-crypto::derive_aip_id`, `ProvenanceTriple`, `AgentIdentitySummary` |
| **AUTHORITY** | What may it do, under whose authority? | issuer and delegators, by signature | `ScopedToken`, `DelegationToken`, `DecisionPoint` → `ExpectedExecution` |
| **OBSERVATION** | What did an independent observer record? | the collector, by signature over probe facts | `aip-observe` (`AttestedBatch`, `SignedSensorHealth`) |
| **EXECUTION** | Did the authorized action correspond to an observed one? | the reconciler, by rule, from the two above | `aip-reconcile::Reconciliation` |
| **LINEAGE** | Who created it, who authorized its creator? | kernel facts (process) + token chain (authority) | `ProcessSpawn`/`ProcessExec` events; `DelegationToken.parent_jti` |
| **EXPERIENCE** | What is its evidence-backed operational history? | derived, mechanically, from EXECUTION records only | **MISSING** |

**Rule E1 — orthogonality.** No component may combine two dimensions into one
number, grade, tier, badge or boolean. Prohibited outputs include, without
limitation: `trust_score`, `reputation`, `risk_score`, `confidence: f32`,
`trusted: bool`, `severity × confidence`, `experience_level`, any ranking of
agents against each other. This is I12 applied to the whole profile.

**Rule E2 — experience is not trust.** An agent with 100,000
`VERIFIED_EXECUTION` records is an agent for which 100,000 authorized actions
were independently observed. It says nothing about the 100,001st. No consumer
of this architecture may derive an authorization, a warrant, a containment
exemption or a "protected identity" status from experience.

**Rule E3 — the agent cannot write its own record.** Any field an agent
supplies about itself is labelled `SELF_DECLARED` and can never appear under
IDENTITY-issued, AUTHORITY, OBSERVATION, EXECUTION, LINEAGE or EXPERIENCE.
`ExecutionBinding` collected by the agent is the one deliberate exception
already in the system: it is a *claim* that the observer independently
measures and the reconciler compares (`EXECUTION_BINDING.md` §12).

**Rule E4 — absence stays absence.** A profile with no observed history is a
profile with no observed history. It is not a "new agent", not "clean", not
"unverified-but-probably-fine". It displays `CANNOT_PROVE` and the coverage
that was available.

## 2. Architecture

```
                         SNIFFER DOG 2.0
              AUTONOMOUS INTELLIGENCE INTEGRITY
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
  SD-01 AGENT IDENTITY   SD-05 CAPABILITY        SD-07 RUNTIME
  SD-02 AGENT PROFILE          PASSPORT                OBSERVATION
  SD-03 EXECUTION        SD-06 DELEGATION              (Sniffer Dog)
        IDENTITY               GRAPH                   │
        │                     │                        ▼
        │                     ▼                  kernel · process · socket
        │               Decision Point           (future: file, …)
        │                     │                        │
        │                     ▼                        │
        │              ExpectedExecution               │
        │                     │                        │
        ▼                     ▼                        ▼
  SD-04 LINEAGE  ─────►  SD-09 RECONCILIATION  ◄─── SD-08 ACTION EVIDENCE
  (process + authority)       │
                              ▼
                     Reconciliation record
                     (result · strength · reason · evidence refs)
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
      SD-10 EXPERIENCE  SD-11 AGENT     SD-12 EVIDENCE
            LEDGER            HISTORY         GRAPH
              └───────────────┼───────────────┘
                              ▼
                     SD-13 AGENT PROFILE API  (read-only)
```

Boundary placement, fixed:

| Boundary | Owns | Must never |
|---|---|---|
| **NEXORA** (Skill 10, MISSING) | persistent identity anchoring; portable, externally anchored commitment over SD-11 | authorize, observe, decide policy, contain |
| **Sniffer Dog** (Skills 6/6.5, PARTIAL) | independent runtime observation, provenance, loss, continuity | sign authorization claims; infer identity from a pid |
| **Decision Point** (Skill 5, PARTIAL) | adjudicate authority, emit `ExpectedExecution` | observe; attest execution |
| **Reconciliation** (Skill 7, PARTIAL) | compare and classify, default `CANNOT_PROVE` | grant, revoke, contain, sign evidence |
| **Warrant / Containment** (Skills 8/9, NOT STARTED) | response policy over (severity, strength) | read SD-10 as an input to lower the bar for any response |

The four questions in order — *who is this agent* (NEXORA + SD-01), *what did
it do* (Sniffer Dog), *what may it do* (Decision Point), *did they
correspond* (Reconciliation) — produce **agent history**. Nothing flows the
other way.

## 3. Component specification

Each component states: the question it answers; what exists today with the
classification vocabulary of the orchestrator (`PRODUCTION`, `PARTIAL`,
`DESIGN_ONLY`, `MISSING`, `UNMERGED`); the properties required; who may write
it; the `CANNOT_PROVE` boundary; and what the component must never claim.

### SD-01 Agent Identity

**Question.** Which persistent agent is this, independent of any one process?

**Today — `PRODUCTION` (identifier), `MISSING` (lifecycle).**
`derive_aip_id(public_key, ProvenanceTriple)` yields `aip1<fingerprint><checksum>`;
the fingerprint binds the agent's Ed25519 public key to commitments over
model, environment and toolchain. `validate_aip_id` is boundary-safe (Skill 3).
`AgentIdentitySummary { aip_id, public_key, provenance }` travels in every
`EvidencePacket`. `ExecutionBinding.agent_id` and `ExpectedExecution.agent_id`
carry the same string, which is how one identity spans many execution
instances today.

What does not exist: an identity **issuer** (the AIP-ID is self-derived from a
self-generated key; the only issuer signature in the system is on the
`ScopedToken` that names the agent), identity **lifecycle** (creation record,
suspension, retirement, key rotation for the agent key), an **organization**
binding, and any registry. `aip-service`'s `/v1/identity/*` routes issue and
revoke *tokens*, not identities, and sit on the duplicate authority model
flagged P1 in `GAP_MATRIX.md` §A.

**Required.**
- `AgentIdentity { aip_id, public_key, provenance, issuer: IssuerRef,
  protocol_version, created_at, lifecycle: Active | Suspended | Retired,
  lineage_ref: Option<LineageRef> }` — a signed object with its own domain
  (`SYNTRIASS/AGENT_IDENTITY/v1`), signed by the **issuer**, not the agent.
  The agent's own signature proves key possession, nothing more.
- The layering `Agent Identity → Execution Instance → Process Instance` is
  explicit: `ExecutionBinding` (SD-03) references `aip_id`; the observer's
  `ObservedProcess` never carries an `aip_id` of its own (it measures a
  process; identity is joined at reconciliation, I3/I5).
- Identity lifecycle events are evidence, not configuration: a retirement is a
  signed record, and a `VERIFIED_EXECUTION` after retirement is a finding.

**Who may write.** The issuer (a principal or an organization's authority) for
the identity record; NEXORA (once it exists) for anchoring. Never the agent,
never the observer, never the reconciler.

**`CANNOT_PROVE` boundary.** That two AIP-IDs belong to "the same model", that
a `ProvenanceTriple` is truthful (it is a commitment the agent presents; no
component recomputes model weights), that an identity is unique to one
deployment. Identity is a key-holder, not a mind.

**Never claim.** "Identity verified" for anything beyond: this signature was
made by the holder of the key this AIP-ID commits to.

### SD-02 Agent Profile

**Question.** What is the complete, dimension-separated picture of one agent?

**Today — `MISSING`.** No composed view exists. Its inputs are scattered:
identity in packets, authority in tokens, observation in collector output,
execution in unsigned, unstored `Reconciliation` values.

**Required.** A profile is a **view**, not a store, composed of exactly these
partitions, each labelled with its source and signer:

| Partition | Source | Label | May the agent influence it? |
|---|---|---|---|
| Declared | issuer-signed `AgentIdentity` (role, organization, parent) | `ISSUER_DECLARED` | no |
| Self-declared | free text the agent supplies | `SELF_DECLARED · UNVERIFIED` | yes — and only here |
| Authorized | current, verified token set (SD-05) | `AUTHORIZED` | no |
| Lineage | SD-04 edges | `PROCESS_LINEAGE` / `AUTHORITY_LINEAGE` | no |
| Observed history | SD-10 counts per (class, result, strength) | `OBSERVED` | no |
| Coverage | observer availability over the profile's period | `COVERAGE` | no |
| Status | lifecycle from SD-01 | `LIFECYCLE` | no |

The mock-up's "12,482 observed executions" is **not** a permitted line. The
permitted rendering is:

```
VERIFIED_EXECUTION · Attested
  ghost.net.connect.v1        842
  ghost.process.exec.v1     2,109
PHANTOM_CLAIM · Attested        3
IDENTITY_DIVERGENCE · Attested  0
CANNOT_PROVE                9,528   (of which ActionEvidenceUnavailable 9,301,
                                     ObservationUnavailable 227)
Coverage: 71.4 % of authorization windows had attested kernel-pushed coverage
```

Negative classes are part of the profile. Hiding `PHANTOM_CLAIM` from a
profile is falsification.

**`CANNOT_PROVE` boundary.** Everything in `SELF_DECLARED`. Every action class
without an evidence adapter (today: everything except TCP connect and process
exec). Every window without coverage.

**Never claim.** A summary word ("trusted", "experienced", "reliable",
"senior") anywhere in a profile.

### SD-03 Execution Identity

**Question.** Which process instance, running which binary, is this execution?

**Today — `PRODUCTION` (Skill 4).** `ExecutionBinding { version, agent_id,
process: ProcessInstance { pid, pid_start_time_ticks, boot_id },
exe_content_sha256, exe_path, bound_at_ms }`, canonical and domain-tagged,
inside the packet (R15) and inside the decision-point-signed
`ExpectedExecution`. The observer measures the same tuple independently
(`ObservedProcess`, pidfd-anchored) and the reconciler compares structurally
(`IdentityComparison`), never by pid.

**Required for 2.0.** Nothing new. The component is complete for its purpose.
2.0 only names the layering: an `ExecutionInstance` *is* an `ExecutionBinding`
whose `agent_id` resolves to an SD-01 identity.

**`CANNOT_PROVE` boundary.** The binding the agent presents is its claim; it
becomes established only when an observer's measurement matches
(`EXECUTION_BINDING.md` §11a table). PID reuse inside one `CLK_TCK` tick.

### SD-04 Parent / Child Lineage

**Question.** Where did this agent come from — which process spawned it, and
which authority permitted that?

Three different things are called "lineage" and must stay distinct:

| Kind | Fact | Source | Today |
|---|---|---|---|
| **Process lineage** | instance P forked instance C, which executed image H | kernel: `sched_process_fork` (parent bound) + `sched_process_exec` (child bound) | `PARTIAL` (Stage 7c) — both ends are recorded as separate `KernelLifecycleEvent`s; no `LineageEdge` object joins them; `LINEAGE_VIOLATION` is refused by the central guard (`precondition_holds` → `false`) |
| **Authority lineage** | token T_child was delegated from T_parent by issuer I | `DelegationToken.parent_jti`, `depth`, scope ⊆ parent, verified by `verify_delegation_chain` | `PRODUCTION` (chain verification), `MISSING` (graph) |
| **Agent lineage** | agent identity B was *created* by agent identity A | an SD-01 issuance record naming a creator | `MISSING`; the notion of "created" is **NOT DETERMINED** (see §8) |

**Required.**
- `LineageEdge { parent: ObservedProcess, child: ObservedProcess,
  fork_at: kernel time, exec_at: kernel time, image: [u8;32],
  mechanism: SchedTracepoint, batch refs }` — derived by the reconciler from
  attested batches exactly as `derive_executions` pairs fork and exec today.
  It is a **reconciler derivation over signed observer facts**, never a probe
  or collector statement about ancestry, and never the agent's `ppid`.
- `LINEAGE_VIOLATION` becomes reachable **only** when: a `LineageEdge` is
  derived with both ends bound; the child instance carries a claim for a
  decision whose `AuthorityRef` chain, when resolved, does **not** include a
  token whose `grantee_id` is the child's agent and whose `issuer_id` is the
  parent's agent (or a principal above it); and coverage over the window is
  attested. Otherwise `CANNOT_PROVE` with a reason that names which of the
  three was missing.
- A spawn edge is **never** a delegation edge. "A spawned B" is a kernel
  fact. "A authorized B" is a signature. Case 1 in §5 is the difference.

**`CANNOT_PROVE` boundary.** A parent that exited before the probe anchored it
(unbound). A child that exec'd again before anchoring. Re-parenting after the
parent's exit (the kernel fork event is the only durable record; `ppid` read
later is not lineage). Any hop across hosts. Agent lineage in every form until
§8 is decided.

**Never claim.** That a child "inherited" any capability by being spawned.

### SD-05 Capability Passport

**Question.** What is this agent authorized to do, by whom, until when?

**Today — `PRODUCTION` in `aip-core` (Skill 3 corrected).**
`ScopedToken { jti, issuer_id, agent_id, scope: CapabilityScope { allowed,
denied }, issued_at, expires_at, issuer_sig }` and `DelegationToken { jti,
parent_jti, issuer_id, grantee_id, scope, depth, issued_at, expires_at,
issuer_sig }`, expiry inside the signed preimage, injective canonical encoding,
explicit domains, `MAX_DELEGATION_DEPTH`, attenuation checked at every hop.
`Constraint { key, operator, value }` is the existing "restrictions" field.
`DecisionPoint` consumes the chain and emits `ExpectedExecution` with
`AuthorityRef { root_jti, chain_jtis }`.

**Required for 2.0.** The passport is a **read-only projection** of the
verified token set at a point in time — nothing more. Its fields (issuer,
subject, scope, restrictions, issued_at, expires_at, parent authority,
signature) already exist one-to-one on the tokens above. Introducing a new
signed "Capability" object would be a second authority model (I18) and is
forbidden. The one addition is `revocation status`, which requires the
`aip-service` duplicate authority engine (`GAP_MATRIX.md` §A, P1) to be
resolved first so that there is one revocation source.

**`CANNOT_PROVE` boundary.** That an authorized action was *performed* — a
passport says *may*, never *did* (`DECISION_POINT.md` §17). Whether an
action outside the passport occurred at all, unless an observer saw it
(SD-09, `UNATTRIBUTED_EFFECT`).

**Never claim.** "Capabilities verified" as a statement about behaviour.

### SD-06 Delegation Graph

**Question.** Which parent ultimately authorized this capability?

**Today — `PRODUCTION` (edges), `MISSING` (graph).** Every `DelegationToken`
is an edge `parent_jti → jti` with issuer, grantee, attenuated scope and depth,
and `verify_delegation_chain` walks one path to a leaf. No structure holds
many chains, indexes by agent, or answers "all authority reaching agent X".

**Required.**
- Nodes are token `jti`s; edges are `parent_jti` references; every node in
  the graph has a verified signature, or it is not in the graph.
- Queries: authority reaching an agent; agents reachable from a root; the
  effective (most-attenuated) scope at any node; expiry of every node on a
  path. All answered from signatures, none from configuration.
- The graph is rebuilt from tokens; it is never the source of truth for any
  of them.
- **Joins to SD-04**: a `LineageEdge` whose child agent has no incoming
  delegation edge from the parent agent or above is the input to
  `LINEAGE_VIOLATION`. A delegation edge with no corresponding spawn is
  ordinary (authority need not create processes).

**`CANNOT_PROVE` boundary.** Anything about a token the verifier has not seen.
The graph over the tokens in hand may be a subgraph of the real one, and
must say so (`ObservationSetIncomplete` already exists as a reason for
observation; an analogous `AuthoritySetIncomplete` is required).

### SD-07 Runtime Observation (the Dog)

**Question.** What did an observer the agent does not control record?

**Today — `PARTIAL` (Skills 6, 6.5; Stages 7b, 7c).** Probe / collector split
with no key on the host; `ProbePolicy::RegisteredOnly` gating declared
mechanisms; `SourceMechanism::{ProcfsPoll, PidFdAnchored, ProcConnector,
ProcNetTable, SockStateTracepoint, SchedTracepoint}` with `is_kernel_pushed`
and `covers_process_lifecycle`; loss (`ENOBUFS`, `PERF_RECORD_LOST`) folded
into `Degraded`; restart, sequence discontinuity, rollback and fork detected
at the collector; `SensorHealth.covered_by` per mechanism; three-clock anchor.
Observer protocol v5. `SNIFFER_DOG.md` is authoritative.

**Required for 2.0.** No change to the trust boundary. Additions are
adapters only, each gated by its own decision document as Stage 7c was
(`NEXT_ACTION_EVIDENCE_DECISION.md` is the template): file create/modify is
next-ranked. Every adapter must provide the eleven interface items of that
document's §3 (observation, event, action evidence, process binding, temporal
placement, provenance, coverage, loss, join keys, strength ceiling, failure
modes).

**`CANNOT_PROVE` boundary.** Unchanged and permanent for this design: a root
host can stop, filter or starve every source (the mechanism becomes absent or
`Degraded`, never silent coverage); procfs content is root-forgeable, capping
content facts at `Attested`; no payload, no arguments, no wire.

**Never claim.** eBPF, XDP, packet capture, zero loss, root-compromise
resistance.

### SD-08 Action Evidence

**Question.** Which authorized action does an observed fact correspond to?

**Today — `PARTIAL`, two classes.** `ghost.net.connect.v1` (presence +
transition) and `ghost.process.exec.v1` (transition; image content hash).
`ActionEvidenceSeal` constructors are `pub(crate)`; `ActionEvidenceKind::
{Presence, Transition}`; `TransitionEvidence` unifies socket and exec
handling; `Attested` is the ceiling.

**Required for 2.0.** The vocabulary in the passport (SD-05) and the
vocabulary the reconciler can observe (SD-08) are **different sets**, and the
profile must show the difference: an agent authorized for `database.read`
accumulates *nothing* under OBSERVED for that class until an adapter exists.
This gap is the honest content of a profile and must not be papered over by
counting authorizations as experience.

**`CANNOT_PROVE` boundary.** Every unobservable class; parameters beyond the
adapter's definition (bytes, arguments, rows read).

### SD-09 Reconciliation

**Question.** Did the authorized execution and the observed execution
correspond, and how strong is the evidence?

**Today — `PARTIAL` (Skill 7 + corrective + Stages 7/7b/7c).**
`Reconciliation { result, strength, reason, decision_id, availability,
identity, action, temporal, replay_detected, evidence: Vec<EvidenceRef>,
verification_time_ms }`. Reachable: `CANNOT_PROVE` (default), `PHANTOM_CLAIM`,
`IDENTITY_DIVERGENCE`, `SENSOR_INTEGRITY_FAILURE`, `CONTINUITY_FAILURE`,
`VERIFIED_EXECUTION` for two classes. `UNATTRIBUTED_EFFECT` requires a
`DecisionPointCoverageStatement` no production component emits.
`LINEAGE_VIOLATION` is unreachable. Records are **unsigned and unstored**.

**Required for 2.0.**
- **Signed reconciliation records.** SD-10/11/12 consume records; a consumer
  must be able to check who produced a record and that it was not altered.
  This is a new signed object (`SYNTRIASS/GHOST/RECONCILIATION/v1`; the
  canonical encoding already exists as `RECONCILIATION_DOMAIN`) signed by a
  **reconciler identity** that is neither the decision point, the collector,
  nor the agent. Signing a classification does not make the classification
  stronger; `strength` is unchanged by the signature.
- `LINEAGE_VIOLATION` per SD-04. `UNATTRIBUTED_EFFECT` when a decision point
  emits coverage statements — a Skill 5 follow-up, not a reconciler change.
- No new positive class. No relaxation of `Draft::precondition_holds`.

**`CANNOT_PROVE` boundary.** As documented in `RECONCILIATION_MODEL.md`; the
default does not move.

### SD-10 Experience Ledger

**Question.** What has this agent verifiably done, counted without
interpretation?

**Today — `MISSING`.** Preconditions absent: signed records (SD-09),
persistence, an append-only sequence.

**Required.**
- An entry **is** a signed `Reconciliation` record. The ledger adds nothing
  to it. It holds no free text, no weights, no decay, no normalization.
- **Counting rule.** Aggregates are computed per triple
  `(action_class, result, strength)`, per agent, per period, and the triple
  is never projected away. "Total actions" does not exist. A count of
  `VERIFIED_EXECUTION · Attested · ghost.process.exec.v1` may be displayed;
  a count of "executions" may not.
- **Every result class counts.** `CANNOT_PROVE` entries are ledger entries
  with their `reason`. A ledger that drops them has been curated by
  someone, and the profile must say by whom. Coverage (`availability`) is
  aggregated alongside so that "zero phantom claims" can be read against
  "12 % coverage".
- **No experience without an expectation or an observation.** The ledger
  cannot be written from a token (authorization is not action), from a
  packet alone (self-report), or from an observation alone (unattributed);
  it is written only from the reconciler's join of the two.
- **Order and integrity.** Entries are ordered by the reconciler's
  `verification_time_ms` and sequence-numbered; the ledger head is what
  NEXORA (SD-11) commits to. Until NEXORA exists the ledger is labelled
  `UNANCHORED` and its truncation is undetectable by a third party — stated,
  not hidden.

**Who may write.** The reconciler, by appending its own signed records. No
operator edit path. Corrections are new records that reference the corrected
one, never in-place changes.

**`CANNOT_PROVE` boundary.** Everything the reconciler could not prove, shown
as such. The ledger's completeness (that no records were withheld) until
anchored.

**Never claim.** Experience as competence. Experience as trust. Experience as
a factor in any warrant or containment decision (Skills 8/9 must not read
SD-10; a `PHANTOM_CLAIM` from a "very experienced" agent is a `PHANTOM_CLAIM`).

### SD-11 Agent History

**Question.** In what order did the entries occur, and can a third party
verify the sequence offline?

**Today — `MISSING`.** `NEXORA_BOUNDARY.md` §4 lists what is missing for a
commitment layer: tree builder, root over an actual set, inclusion proofs,
cross-record sequence, head anchoring, replay/uniqueness. Only `merkle_leaf`
/ `merkle_internal` exist, and per I15 those are primitives, not a protocol.

**Required.** SD-11 is exactly the NEXORA commitment over SD-10 and is
governed by `syntriass-nexora-integration` (Skill 10). It is listed here so
that the profile architecture has a named place for it and so that no other
component grows a hash chain of its own. Precondition per the orchestrator:
real `VERIFIED_EXECUTION` history exists (it does, for two classes) **and**
SD-10 exists to be committed.

**`CANNOT_PROVE` boundary.** Anything before the first anchored head.

### SD-12 Evidence Graph

**Question.** From any node — organization, agent, parent, child, capability,
execution — can a reader reach the signed evidence behind it?

**Today — `MISSING` (graph), `PRODUCTION` (edges).** `EvidenceRef` already
names batches (`BatchId`, `attested_at_ms`), health records, decisions
(`DecisionId`) and probe runs (`ProbeRunId`) by typed identifiers;
`AuthorityRef` names token `jti`s; `LineageEdge` (SD-04) will name two
`ObservedProcess`es and their batches. Every edge the graph needs already
exists as a reference inside a signed object.

**Required.** An index over those references and nothing else. Navigation:
`Organization → Agent (SD-01) → Delegation (SD-06) → Execution (SD-03) →
Decision (ExpectedExecution) → Reconciliation (SD-09) → Batches / Health
(SD-07) → Lineage (SD-04)`. Each hop terminates in a signed artifact that a
verifier can re-check with the public keys in its context; a node with no
signed artifact behind it is rendered as a gap, not as a node.

**`CANNOT_PROVE` boundary.** The graph shows what evidence exists; it never
infers an edge (no "probably the same agent", no pid-based joins).

### SD-13 Agent Profile API

**Question.** How does an enterprise read all of the above?

**Today — `MISSING`.** `aip-service` exposes token issuance and delegation,
evidence generate/verify/get/export, authority lookup and JWKS. None of these
compose a profile, and the service's authority routes duplicate `aip-core`
(P1 gap). The profile API must not be built on top of the duplicate model.

**Required.**
- **Read-only.** No route accepts anything that lands outside
  `SELF_DECLARED`. No route triggers any action.
- **Dimension-separated responses.** The response schema has one object per
  dimension in §1; there is no top-level scalar, grade or status word other
  than the SD-01 lifecycle state.
- **Evidence-carrying.** Every count is accompanied by the range of ledger
  sequence numbers it was computed from and the head it was computed under;
  every statement is a link into SD-12.
- **Coverage-carrying.** Every period reports `availability` alongside
  results.
- **Offline-verifiable export.** A profile export is a bundle of the signed
  artifacts it was computed from (the existing bundle format with per-file
  digests is the starting point), so that "the API said so" is never the
  evidence.

**Never claim.** Anything the underlying artifacts do not sign.

## 4. Mapping against Skills 3–8

| SD | Skill 3 (AIP correctness) | Skill 4 (binding) | Skill 5 (decision point) | Skill 6 / 6.5 (observer, Dog) | Skill 7 + 7/7b/7c (reconcile, action) | Skill 8 (warrant, NOT STARTED) | Net state |
|---|---|---|---|---|---|---|---|
| SD-01 Identity | AIP-ID derivation, validation | `agent_id` in binding | `agent_id` in expectation | attribution is `Claimed`, never established by the Dog alone | identity compared structurally | must not read | `PRODUCTION` id · `MISSING` lifecycle/issuer |
| SD-02 Profile | — | — | — | — | inputs only | must not read | `MISSING` |
| SD-03 Execution identity | — | **owner** | embedded, DP-signed | measured independently | compared | — | `PRODUCTION` |
| SD-04 Lineage | `parent_jti` chain | ppid rejected (§11a) | `AuthorityRef` | fork/exec events, both ends bound (7c) | `LINEAGE_VIOLATION` unreachable | — | `PARTIAL` process · `MISSING` graph/agent |
| SD-05 Passport | **owner** (tokens, expiry signed) | — | consumer | — | — | — | `PRODUCTION` (aip-core) · duplicate in service P1 |
| SD-06 Delegation graph | chain verification | — | one path per decision | — | — | — | `MISSING` (graph) |
| SD-07 Observation | — | — | — | **owner** | consumer | — | `PARTIAL` |
| SD-08 Action evidence | action vocabulary domain | image hash reuse | `parameter_digest` | transitions | **owner**, two classes | — | `PARTIAL` |
| SD-09 Reconciliation | — | — | expectation | evidence | **owner** | consumer (later) | `PARTIAL`, unsigned records |
| SD-10 Ledger | — | — | — | — | records are the entries | **must not read** | `MISSING` |
| SD-11 History | merkle primitives only | — | — | — | — | — | `MISSING` (Skill 10) |
| SD-12 Evidence graph | `jti` refs | binding refs | `DecisionId` | `BatchId`, `ProbeRunId` | `EvidenceRef` | — | `MISSING` (index) |
| SD-13 API | service routes exist on the wrong model | — | — | — | — | — | `MISSING` |

## 5. What the Dog catches — the five cases against today's code

| Case | Today (`0b737d9`) | 2.0 target | What must exist first |
|---|---|---|---|
| **1 Unauthorized child.** A spawns B; B acts; no delegation A→B | Process lineage is observed (fork with A bound, exec with B bound) but not joined; B's action reconciles against *B's* expectation if one exists, else `CANNOT_PROVE · ActionEvidenceUnavailable`. No component asks whether A authorized B. | `LINEAGE_VIOLATION · Attested` when the `LineageEdge` is derived, B's claimed decision resolves to a chain that does not pass through A or above, and coverage is attested; otherwise `CANNOT_PROVE` naming the missing piece. Never "malicious". | SD-04 edge derivation; SD-06 graph; guard change in SD-09 |
| **2 Ghost execution.** Authorized, never observed | **Implemented.** `PHANTOM_CLAIM · Attested` iff `RegisteredOnly`, `Active`, process-lifecycle coverage (`ProcConnector`) recomputed gap-free over the exact window; else `CANNOT_PROVE`. | unchanged | — |
| **3 Unauthorized runtime action.** Passport says `database.read`; runtime shows `network.connect` | An observed connect is not evidence for a `database.read` expectation (`ActionEvidenceUnavailable`); as an observation with no expectation it is `UNATTRIBUTED_EFFECT` **only** with a `DecisionPointCoverageStatement`, which nothing emits → `CANNOT_PROVE · ExpectedSideCompletenessUnknown`. | `UNATTRIBUTED_EFFECT · Attested` once the decision point signs completeness statements; the profile shows it under OBSERVED. `database.read` itself stays unobservable until an adapter exists. | Skill 5 follow-up (coverage statements); SD-08 adapters |
| **4 Identity cloning.** Another runtime presents as `AGENT-742` | **Implemented.** A measured instance carrying the claim whose identity fails the structural match, with no matching instance, under `Active` + `RegisteredOnly` → `IDENTITY_DIVERGENCE · Attested`; claim `agent_id` must name the expectation's agent (`ClaimInconsistent` otherwise). Two genuine matches → `AmbiguousObservations`, never a verdict (X-B). | unchanged; SD-01 lifecycle adds "acting after retirement" as a finding | SD-01 lifecycle |
| **5 Rogue child swarm.** Legitimate agent → child → 100 workers | Each fork/exec pair is observable and each worker's actions reconcile individually. Nothing constructs *who spawned whom* across generations, *who authorized whom*, or *what propagated*. | SD-04 tree over `LineageEdge`s; SD-06 over tokens; the join shows which workers hold authority and which hold only a parent. Per-worker results in SD-10; the swarm as a navigable subgraph in SD-12. | SD-04, SD-06, SD-12 |

## 6. Security chain for each new primitive (I20)

| Primitive | THREAT | ASSUMPTION | MECHANISM | IMPLEMENTATION | TEST (RED first) | LIMITATION |
|---|---|---|---|---|---|---|
| Signed `AgentIdentity` (SD-01) | an agent invents an identity, issuer or organization for itself | issuer key is off-agent | issuer signature over a domain-tagged canonical record | none | agent-signed identity refused; issuer-mutated fields fail; retired identity's later `VERIFIED_EXECUTION` is a finding | identity is a key-holder; provenance commitments are not recomputed |
| `LineageEdge` (SD-04) | a child claims a parent; a parent disowns a child | kernel fork/exec events are not injectable from user space; pidfd anchors hold | reconciler pairs bound fork and bound exec by `child_pid`, time order and start tick | none (pairing exists for exec evidence; edge type does not) | unbound parent → no edge; recycled child → no edge; `ppid` from procfs never used; edge with no delegation → violation only under coverage | root can starve the ring; cross-host lineage invisible |
| Delegation graph (SD-06) | an unsigned or expired token is presented as authority | tokens verify with issuer keys in context | graph built from verified tokens only | none | unsigned node refused; expired path reported; subgraph incompleteness stated | authority the verifier never saw |
| Signed `Reconciliation` (SD-09) | a ledger entry is fabricated or altered | reconciler key separate from DP, collector and agent | signature over `RECONCILIATION_DOMAIN` canonical bytes | none | mutated result/strength/reason/evidence refs fail; DP-key or collector-key signed record refused; signature never raises `strength` | signing a classification proves origin, not truth |
| Ledger (SD-10) | curation, truncation, re-weighting | append-only under one signer; head committed by SD-11 | sequence numbers; per-triple counting; corrections as new records | none | dropped `CANNOT_PROVE` entries detectable by sequence gap; no API returns a projected count; warrant code cannot link the ledger | unanchored until NEXORA |
| Profile API (SD-13) | a summary word or scalar leaks in; agent text presented as verified | read-only; schema enforced | dimension-separated schema; `SELF_DECLARED` partition | none | response schema has no numeric top-level field; agent-supplied text appears only under `SELF_DECLARED`; every count carries head + sequence range | evidence is the export, not the response |

## 7. Preconditions and permitted order

The orchestrator's stage order is unchanged: Skill 8 (warrant), 9
(containment) and 10 (NEXORA) remain their own gates. 2.0 work threads
between them as follows, each step RED-first and reported before the next:

1. **SD-04 process lineage edges** — smallest step; consumes only what Stage
   7c already records; adds `LineageEdge` derivation and the `LINEAGE_VIOLATION`
   precondition. Prerequisite for Case 1 and Case 5.
2. **Signed `Reconciliation` records** (SD-09) — a new signed object with the
   reconciler as a fourth, separate key holder; no change to any result rule.
   Prerequisite for SD-10/11/12.
3. **SD-06 delegation graph** — pure derivation over existing tokens; joins
   SD-04.
4. **Decision-point coverage statements** (Skill 5 follow-up) — unlocks
   `UNATTRIBUTED_EFFECT`; Case 3.
5. **SD-01 lifecycle** — after §8 decisions.
6. **SD-10 ledger (UNANCHORED)** → **Skill 10 NEXORA → SD-11**.
7. **SD-12 index**, **SD-13 read-only API** — last, over signed artifacts
   only, and only after the `aip-service` duplicate authority model is
   resolved.

Skills 8 and 9 may proceed on their own gates at any point; they must be
written so that no path from SD-10 reaches them.

## 8. Decisions this document cannot make — NOT DETERMINED

Per the orchestrator's decision format these stop dependent implementation
until a human decides:

| Decision | Why it matters | Options seen |
|---|---|---|
| **Who issues `AgentIdentity`?** | SD-01's signer is the root of the IDENTITY dimension | the `ScopedToken` issuer; a separate organization authority; NEXORA as registrar |
| **What is "agent creation" for agent lineage?** | SD-04's third kind has no kernel fact behind it | the issuance of a child identity signed by the parent's issuer; the first delegation to a new `grantee_id`; a process spawn by a bound parent that execs an image whose first decision names a new agent |
| **Who holds the reconciler key?** | SD-09 signed records need a fourth trust root | the verifier operator; the collector operator (weakens separation); a dedicated service |
| **Profile audience and privacy** | SD-13 exposes an agent's complete verified history | internal only; per-organization; public with opt-in |
| **Cross-host identity** | one AIP-ID across hosts and `boot_id`s | no linkage (each host independent); NEXORA-anchored |

## 9. Prohibited designs (permanent)

- Any scalar, grade, tier, badge, ranking or boolean summarizing more than
  one dimension (E1).
- Experience read by the warrant engine, containment, or any authorization
  decision (E2).
- Agent-supplied content outside `SELF_DECLARED` (E3).
- A profile that omits `CANNOT_PROVE`, `PHANTOM_CLAIM`, `IDENTITY_DIVERGENCE`
  or coverage (E4).
- A spawn edge treated as a delegation edge, or a delegation edge treated as
  a spawn.
- A new signed capability object beside `ScopedToken`/`DelegationToken`
  (I18).
- A hash chain in any component other than NEXORA (I15).
- PID, path, `comm`, IP or port as a join key anywhere in SD-04/06/12 (I2).
- Silence, outage or missing coverage rendered as "no incidents" (I8).
- The words *trusted*, *experienced*, *reliable*, *safe* or *senior* in any
  machine-produced field.

## 10. Positioning, and what it may be said to rest on

Product description permitted **once every component it names has an
implementation report**: an independent runtime integrity and provenance
system for autonomous AI agents that establishes cryptographically verifiable
agent identity, lineage, capabilities, execution evidence, and evidence-backed
operational history.

Permitted today, on `0b737d9`: independent observation with provenance and
loss accounting; execution identity resistant to PID reuse; an external
decision point; reconciliation with a `CANNOT_PROVE` default; verified
execution for two action classes at `Attested`, live-demonstrated.

Not permitted today: identity lifecycle, lineage findings, delegation graph,
experience, history, profile, API — every one is `MISSING` above.

"AI agents can claim anything. Sniffer Dog checks the trail." — true for the
trail it can see, which this document enumerates.

## 11. Glossary

| Term | Meaning here |
|---|---|
| Agent identity | AIP-ID: key + provenance commitments; SD-01 |
| Execution instance | an `ExecutionBinding`: agent + process instance + image content |
| Process instance | `(pid, pid_start_time_ticks, boot_id)` |
| Process lineage | kernel fork/exec relation between two bound instances |
| Authority lineage | verified `parent_jti` chain of tokens |
| Agent lineage | creation relation between identities — NOT DETERMINED |
| Passport | read-only projection of the verified token set |
| Experience | per-`(class, result, strength)` counts of signed reconciliation records |
| History | the NEXORA-committed, ordered ledger |
| `SELF_DECLARED` | the only partition an agent may write; always labelled unverified |
