# INVENTION DISCLOSURE FORM (IDF)

**Docket Reference:** SYNT-IDF-2026-001 *(placeholder — assign per counsel's docketing convention)*
**Date:** 2026-08-27
**Inventors:** *TO CONFIRM* — see §0.2
**Assignee:** *TO CONFIRM* — see §0.2
**Status:** Engineering disclosure draft for review by licensed patent counsel

---

## 0. Preliminary Notices

### 0.1 Non-Legal-Advice Disclaimer

This document is an **engineering disclosure assessment** prepared to brief licensed
patent counsel. It is **not** a legal opinion, not a patentability opinion, and not a
freedom-to-operate analysis. No formal prior-art search has been performed. All
novelty statements herein mean "no directly anticipating art was identified during
engineering review" — establishing novelty under 35 U.S.C. § 102 and non-obviousness
under § 103 requires a professional search and analysis by counsel.

### 0.2 Unresolved Filing Metadata (action required before filing)

| Field | Conflict found in workspace | Action |
|---|---|---|
| Assignee | `Cargo.toml` declares `authors = ["Vanian Technologies Private Limited"]`; the supplied IDF template named *SYNTRIASS LABS PRIVATE LIMITED* | Confirm the correct filing entity and any assignment chain between entities |
| Inventorship | Several crates carry the header "Principal Inventor: K. Naga Sri Ganesh" (e.g. `crates/ot-propagator/src/spatial.rs:14`); `crates/ot-accountability-core/src/lifecycle.rs` carries **no** inventor header | Determine and record actual conception contributors for **this** subject matter. Inventorship is a legal determination with validity consequences — incorrect inventorship can render a patent unenforceable |

### 0.3 Disclosure / Bar-Date Warning

The subject matter is committed to a Git repository (first appearance in commit
`1246373`, 2026-08-27, on branch `claude/orbitaltrust-architecture-refactor-xa4bxk`).
**Counsel must determine whether that repository is or has ever been public**, and
whether any push, PR, package publication, or demonstration constitutes a public
disclosure starting the 35 U.S.C. § 102(b) one-year grace period (US) or defeating
absolute novelty (EP/IN, which have no general grace period). If the repository is
public, **absolute-novelty jurisdictions may already be foreclosed** and a priority
filing is time-critical.

---

## 1. Title

**System and Method for Enforcing Autonomous-Agent Authorization Invariants at
Compile Time via Linear-Typestate Transitions That Are Themselves the
Evidence-Sealing Operations**

*Short form:* Compile-Time-Enforced Authorization Lifecycle for Cryptographically
Sealed Autonomous-Agent Execution.

---

## 2. Technical Field

The invention lies in computer security and software-system architecture, specifically
in the integrity verification and access control of autonomous computational agents
(including but not limited to machine-learning-driven agents invoking external tools).

**Candidate CPC/IPC classifications** (for counsel's refinement):

| Code | Scope |
|---|---|
| `G06F 21/64` | Protecting data integrity (e.g. using checksums, certificates or signatures) |
| `G06F 21/62` | Protecting access to data via a platform / access control |
| `H04L 9/32` | Cryptographic mechanisms for authentication; message authentication |
| `H04L 9/50` | Cryptographic protocols using hash chains / distributed ledger structures |
| `G06F 8/41` | Compilation; static/type checking as an enforcement stage |
| `G06N 20/00` | Machine learning (as the field of application, not the mechanism) |

`G06F 8/41` is included deliberately: the enforcement stage of this invention is the
**compiler**, which distinguishes it from art classified purely under runtime access
control.

---

## 3. Background and Prior-Art Deficiencies

### 3.1 Conventional approach A — runtime permission checks

The dominant architecture for constraining an autonomous agent's tool invocations is a
runtime guard: before executing a tool, the system evaluates a policy predicate
(`if !authorized(agent, tool) { return Err(...) }`) and conditionally proceeds.

**Failure modes intrinsic to this design:**

1. **Omission is silent.** A newly added execution path that simply does not call the
   guard compiles, tests green (nothing asserts on a check that was never written),
   ships, and executes unauthorized actions. The defect is an *absence*, and absences
   are invisible to conventional testing.
2. **Ordering is unverified.** Nothing structurally forces `check → execute → record`.
   A refactor that moves the sealing call above the guard, or that returns early
   between execution and recording, produces an unrecorded executed action. Only
   discipline and code review prevent it.
3. **Time-of-check/time-of-use (TOCTOU) exposure.** Authorization is evaluated at an
   instant; execution occurs later. A revocation landing in that window is not observed
   by the in-flight operation.
4. **Evidence and enforcement are separable.** Because the guard and the audit-write are
   distinct statements, an execution can succeed while its audit record is dropped by an
   early return, an exception path, or a swallowed error — precisely the paths least
   exercised by tests.

### 3.2 Conventional approach B — tamper-evident audit logging

Hash-chained and signed audit logs (in the lineage of Haber & Stornetta's digital
timestamping, 1991, and Schneier & Kelsey's secure audit logs, 1998; and in practice
Git object graphs, certificate-transparency logs, and blockchain ledgers) make *recorded*
history tamper-evident.

**Deficiency:** such structures secure the record *conditional on the record having been
written*. They are silent about whether a given execution was authorized, and silent
about whether an execution occurred that was never recorded at all. A perfectly verifying
hash chain is fully consistent with an agent that executed a hundred unauthorized actions
and logged none of them. **Tamper-evidence is not completeness.**

### 3.3 Conventional approach C — typestate / session-typed APIs

Encoding protocol state in the type system is a known technique (Strom & Yemini,
"Typestate: A Programming Language Concept for Enhancing Software Reliability," 1986;
session types; and idiomatic Rust builder/embedded-HAL patterns using move semantics
to enforce ordering).

**Deficiency:** in the known art this technique is applied to *protocol correctness and
resource safety* — preventing use-after-free, double-close, out-of-order I/O, uninitialized
peripheral access. Engineering review identified no art applying it as the **authorization
and evidentiary enforcement mechanism** for autonomous agents, and — critically — no art
in which the type transition *is itself* the cryptographic sealing operation rather than a
precondition to a separate one.

### 3.4 The gap this invention addresses

Approach A can be forgotten; approach B secures only what was written; approach C is
known but has not been applied to close A and B together. The unmet need is an
architecture in which **an unauthorized or unrecorded execution is not a defect to be
detected but a program that cannot be constructed.**

---

## 4. Summary of the Technical Solution

The invention relocates authorization enforcement from run time to **compile time** by
representing each authorization state of an agent as a **distinct nominal type**, and by
making each state transition a **linear (move) transition that simultaneously performs
the cryptographic sealing** of the transition into two cross-bound hash chains.

### 4.1 The four typestates and the transition graph

```
                    born()
                      ↓
              ┌──AgentGenesis──┐
              │  (no execute)  │
     delegate()│               │revoke()
              ↓                ↓
      ┌─DelegatedAgent─┐   RevokedAgent
      │                │   (terminal: no
      │  begin_        │    methods out)
      │  execution()   │        ↑
      ↓                │revoke()│
  ActiveExecution──────┴────────┘
      │  (no revoke, no read access)
      └─complete() ──► (DelegatedAgent, packet_hash)
```

### 4.2 The four structural invariants

**Invariant I — Execution requires delegation, structurally.**
The evidence-sealing routine `complete()` is implemented **only** on the type
`ActiveExecution`. The type `ActiveExecution` has private fields and is therefore
constructible **only** within its defining module, and the sole constructing expression is
`DelegatedAgent::begin_execution()`. A `DelegatedAgent` is obtainable **only** from
`AgentGenesis::delegate()`, which seals a `SUPERVISOR_DELEGATION` anchor as a side effect
of the transition. Therefore possession of the capability to seal an execution is
**proof of a completed, recorded delegation** — enforced by the type checker, not by a
predicate. Code attempting to execute without delegation does not fail at run time; it
**fails to compile**.

**Invariant II — Terminal revocation is a type with no exits.**
`RevokedAgent` exposes only read accessors (`anchors()`, `packets()`, `did()`). It has no
`delegate`, no `begin_execution`, no `complete`, and no transition returning any other
state. Because `revoke()` **consumes** its receiver by value, the pre-revocation state is
moved-from and statically unusable thereafter. A kill-switch in this architecture is not a
flag that subsequent operations must remember to consult; it is a **type-level dead end**
from which no executing code path exists.

**Invariant III — Evidence cannot be dropped by racing the kill-switch.**
`ActiveExecution` deliberately exposes **no** `revoke()` method. An execution in flight
must transit `complete()` — which seals both the evidence packet and its acknowledging
anchor — before the agent is again in a state from which revocation is expressible. The
TOCTOU window of §3.1(3) is closed structurally: there is no expressible program in which
a revocation discards an in-flight execution's evidence.

**Invariant IV — A blocked execution cannot report state mutation.**
For `ExecutionStatus::BlockedByPolicy`, the sealing routine ignores the caller-supplied
post-state entirely and assigns `post_state_hash := pre_state_hash`:

```rust
let post_state_hash = match status {
    ExecutionStatus::BlockedByPolicy => self.pre_state_hash.clone(),
    _ => sha256_hex(&canonical_json(post_state)),
};
```

A refused action provably did not run, because the record of a refused action is
**incapable of expressing** a state change — even when the calling code supplies a
mutated post-state. This is verified by the test
`a_blocked_execution_cannot_mutate_state_by_construction`, which passes a deliberately
falsified post-state and asserts the sealed record still shows `pre == post`.

### 4.3 The transition-as-sealing coupling (the core of the invention)

In each transition, the state change and the cryptographic sealing are a **single
indivisible operation**:

| Transition | Consumes | Produces | Seals as a side effect |
|---|---|---|---|
| `born()` | — | `AgentGenesis` | `AGENT_GENESIS` anchor binding `modelDigest` |
| `delegate()` | `AgentGenesis` | `DelegatedAgent` | `SUPERVISOR_DELEGATION` anchor (scope, clearance) |
| `begin_execution()` | `DelegatedAgent` | `ActiveExecution` | captures `preStateHash` at *begin* time |
| `complete()` | `ActiveExecution` | `DelegatedAgent` + packet hash | evidence packet **and** `ACTION_EXECUTION_SEAL` anchor |
| `revoke()` | `AgentGenesis` \| `DelegatedAgent` | `RevokedAgent` | terminal `AUTHORITY_REVOCATION` anchor |

Because the transition and the seal are the same function call, **there is no expressible
program in which an authorization state changes without a corresponding sealed record**,
and none in which an execution is sealed without the authorization state having been
legitimately reached. This coupling — not the typestate pattern alone, and not the hash
chain alone — is the claimed advance.

### 4.4 Dual cross-bound chains produced by the transitions

The transitions maintain two independent SHA-256 hash chains over canonical JSON, where
canonical form is compact serialization with recursively sorted object keys:

- **Anchor chain (lifecycle):** `anchorHash_n = SHA-256( anchorHash_{n-1} ‖ C(A_n) )`
- **Packet chain (evidence):** `packetHash_n = SHA-256( packetHash_{n-1} ‖ C(P_n) )`

where `C(·)` denotes canonical serialization of the record **excluding its own two chain
fields**, and both chains begin at a published genesis constant of 64 hexadecimal zeros.

The two chains are **mutually cross-bound**:

1. Every evidence packet embeds `anchorHash := engine.anchor_tail` — the lifecycle chain's
   head **at execution time**, binding the action to the exact authorization state under
   which it ran.
2. Every completed execution appends an `ACTION_EXECUTION_SEAL` anchor whose payload
   embeds that packet's `packetHash`, binding the lifecycle chain forward to the action.

Consequently, tampering with either chain in isolation breaks its cross-reference to the
other: rewriting authorization history invalidates every packet bound to it, and altering
an action contradicts the anchor that named its hash.

### 4.5 Determinism (enabling multi-target reduction to practice)

The machine takes timestamps as **caller-supplied parameters** and derives record
identifiers deterministically from the agent DID and sequence number
(`format!("{did}#anchor-{sequence}")`, `format!("{did}#packet-{sequence}")`). It reads no
clock and consumes no randomness. Two consequences follow: (a) an identical input
sequence reproduces byte-identical chains, making the record independently replayable; and
(b) the same compiled logic runs unmodified in environments lacking ambient clock or
entropy access — notably `wasm32-unknown-unknown` — which is what permits one
implementation to serve native, browser, and server verifiers.

---

## 5. Exemplary Implementation & Source-Code Mapping

Primary embodiment: **`crates/ot-accountability-core/src/lifecycle.rs`** (Rust 2021).

| Element | Location | Notes |
|---|---|---|
| `AgentGenesis` | `lifecycle.rs` §"A born agent" | `pub struct`, private `engine` field |
| `DelegatedAgent` | `lifecycle.rs` §"An agent holding delegated authority" | carries `scope`, `model_digest` |
| `ActiveExecution` | `lifecycle.rs` §"An execution in flight" | private fields ⇒ externally unconstructible |
| `RevokedAgent` | `lifecycle.rs` §"A terminally revoked agent" | read accessors only |
| `LifecycleEngine` | `lifecycle.rs` | **private** struct; holds both chain tails; sole writer path is `append_anchor()` |
| `AgentGenesis::born()` | `lifecycle.rs` | seals `AGENT_GENESIS` binding `modelDigest` |
| `AgentGenesis::delegate()` | `lifecycle.rs` | `mut self` → `DelegatedAgent`; seals `SUPERVISOR_DELEGATION` |
| `DelegatedAgent::begin_execution()` | `lifecycle.rs` | `self` → `ActiveExecution`; captures `pre_state_hash` |
| `ActiveExecution::complete()` | `lifecycle.rs` | the **only** evidence-packet constructor; returns `(DelegatedAgent, String)` |
| `revoke()` | `lifecycle.rs` (on `AgentGenesis` and `DelegatedAgent`) | `mut self` → `RevokedAgent`; `{"terminal": true}` |
| `record_accessors!` macro | `lifecycle.rs` | applied to Genesis/Delegated/Revoked — **deliberately not** to `ActiveExecution` |
| `canonical_json`, `sha256_hex`, `seal_hash`, `chain_payload_bytes`, `GENESIS_HASH` | `crates/ot-accountability-core/src/lib.rs` | shared canonical-bytes primitives |
| Independent chain verifiers | `crates/ot-accountability-core/src/chain.rs` | `verify_anchor_chain`, `verify_packet_chain` |
| Evidence-set commitment | `crates/ot-accountability-core/src/merkle.rs` | `merkle_root` |
| WASM embodiment | `crates/ot-accountability-core/src/wasm.rs` (feature `wasm`) | same core compiled to `wasm32-unknown-unknown` |
| Offline verifier embodiment | `crates/ot-verifier/` | exit 0 = verified, exit 1 = breach |

### 5.1 Tests evidencing reduction to practice

| Test | File | Establishes |
|---|---|---|
| `the_full_lifecycle_produces_chains_the_shared_verifier_accepts` | `lifecycle.rs` | end-to-end genesis→delegation→2 executions→revocation; both chains verify under the independent verifier; anchor type sequence exact; seal anchor names the packet hash |
| `a_blocked_execution_cannot_mutate_state_by_construction` | `lifecycle.rs` | Invariant IV against a deliberately falsified post-state |
| `the_lifecycle_law_holds_and_rejections_never_advance_the_tail` | `crates/ot-api/tests/governance_hub.rs` | server-side enforcement of the same law on records arriving over a network boundary |
| `a_chain_built_by_the_python_sdk_verifies_under_the_rust_core` | `crates/ot-verifier/tests/python_sdk.rs` | cross-language byte-identity of the produced records |

### 5.2 Known implementation gap (disclosed for candor)

**The compile-time guarantees are currently evidenced by API surface and by the absence
of the corresponding methods, not by an executable compile-fail test suite.** The test
module states this explicitly (`lifecycle.rs`, closing comment). For prosecution it is
**recommended** to add a `trybuild` compile-fail suite asserting that, e.g.,
`revoked.begin_execution(...)` and `genesis.complete(...)` fail to compile with the
expected diagnostics. Such a suite would convert the central negative limitation from an
architectural assertion into a **machine-checked, reproducible demonstration** — materially
stronger evidence of reduction to practice, and directly responsive to any examiner
challenge that the claimed impossibility is merely asserted.

### 5.3 Scope note

The described enforcement binds code compiled against this API in a language with
affine/linear move semantics and module-private constructibility (Rust). It does not, and
does not purport to, constrain a process that bypasses the library and forges records
directly. Defense against that adversary is the role of the separately disclosed
cross-bound chain verification, the signed attestation envelope
(`crates/ot-pqc/src/attestation.rs`), and server-side re-verification
(`crates/ot-api/src/governance.rs`). **Counsel should scope claims to the enforcement
architecture rather than to an unqualified assertion of unforgeability.**

---

## 6. Key Distinguishing Inventions (Novelty & Non-Obviousness)

1. **Authorization violation as a compilation failure rather than a runtime rejection.**
   The known art evaluates authorization as a predicate at execution time. Here, the
   capability to execute is a *typed value* obtainable only through a recorded delegation,
   so an unauthorized execution is not a rejected call but **a program that cannot be
   built**. This eliminates the entire class of "the guard was never called" defects,
   which are invisible to conventional testing because they are absences.

2. **The state transition IS the sealing operation.** Engineering review found no art in
   which a typestate transition and the cryptographic sealing of that transition are the
   same indivisible operation. This structurally eliminates the gap in §3.1(4) — the
   possibility of an executed-but-unrecorded action — because reaching the next
   authorization state and writing its evidence are not two statements that a refactor
   can separate.

3. **A terminal authorization state expressed as a type with no outgoing transitions.**
   Revocation in the known art is state consulted by later operations; here it is a type
   from which no continuing program exists, and (via move semantics) the pre-revocation
   value is statically unusable after the transition. The kill-switch cannot be "forgotten
   to check" because there is nothing to check.

4. **In-flight executions structurally cannot be discarded by revocation.** Omitting
   `revoke()` from `ActiveExecution` — an *absence* of a method as a deliberate security
   mechanism — forces evidence sealing to complete before revocation becomes expressible,
   closing the TOCTOU evidence-loss window without any locking, transaction, or runtime
   coordination.

5. **A refusal record incapable of expressing state mutation.** Assigning
   `post := pre` for blocked status makes "this action was refused and therefore changed
   nothing" a property of the data structure rather than a claim by the reporting party —
   robust against a caller that supplies falsified post-state, as the corresponding test
   demonstrates.

6. **Determinism as an enabling constraint for multi-target verification.** Excluding
   clock and entropy from the state machine (caller-supplied timestamps, sequence-derived
   identifiers) is what permits one implementation to be compiled to native, WASM, and
   server targets and to reproduce byte-identical records — the property the cross-language
   proofs in §5.1 rest on.

### 6.1 Anticipated examiner objections and responsive positioning

| Likely objection | Responsive positioning |
|---|---|
| § 101 / *Alice*: "abstract idea of tracking permissions, applied on a computer" | The claims recite a **specific improvement to how the software system itself is constructed and checked** — enforcement relocated to the compiler's type checker — not an outcome achieved by a generic computer. This is the *Enfish* line: an improvement to computer functionality rather than the use of a computer as a tool. Claims should recite the move/consumption semantics and module-private constructibility explicitly, since those are the technical mechanism. |
| § 103: "typestate is known; hash chains are known; combining them is obvious" | The advance is not the co-presence of two known techniques but their **fusion into one indivisible operation**, which produces a property neither yields alone: the structural impossibility of an executed-but-unrecorded, or unauthorized-but-executed, action. Argue the absence of any teaching or suggestion to make the sealing operation the type transition itself, and the unexpected result — the elimination of an entire defect class rather than its detection. |
| § 112: "the impossibility limitation is not enabled/demonstrated" | Add the `trybuild` compile-fail suite of §5.2 **before filing** and cite it in the specification. |
| Section 3(k) (India): "computer programme per se" | Emphasize the technical effect on the operation of the computing system (defect class eliminated at build stage; deterministic multi-target reproducibility; verification cost reduced to O(1) memory per agent in the companion streaming disclosure) rather than any business or administrative outcome. |

---

## 7. Draft Technical Claim Set

> Structural drafts for counsel to refine, narrow against the results of a formal search,
> and conform to filing practice. Claim numbering assumes this subject matter is filed
> alone; if combined with the cross-bound-ledger or streaming-verification disclosures,
> renumber and re-scope accordingly.

### Independent Claim 1 (Method)

A computer-implemented method for enforcing authorization invariants of an autonomous
computational agent, the method comprising:

- (a) instantiating, in a memory of a computing system, a first data structure of a first
  nominal type representing an un-delegated agent, and computing a first chain record
  comprising a cryptographic digest binding a model identifier of the agent, the first
  chain record being appended to a lifecycle chain anchored at a predetermined genesis
  digest;
- (b) executing a first state transition that **consumes** the first data structure and
  produces a second data structure of a second nominal type representing a delegated
  agent, wherein the first state transition, as a single indivisible operation, both
  produces the second data structure and appends to the lifecycle chain a second chain
  record encoding a delegated scope, each said chain record having a digest computed over
  a canonical serialization of that record excluding its own chain-linkage fields
  concatenated to the digest of the immediately preceding record;
- (c) executing a second state transition that consumes the second data structure and
  produces a third data structure of a third nominal type representing an in-flight
  execution, and computing, at the time of said second state transition, a pre-execution
  state digest over a canonical serialization of a state of the computing system;
- (d) performing, by an operation defined exclusively upon the third nominal type, an
  evidence-sealing operation that (i) computes a post-execution state digest, (ii) forms an
  evidence record comprising the pre-execution state digest, the post-execution state
  digest, an execution-status field, and a current head digest of the lifecycle chain,
  (iii) appends the evidence record to an evidence chain distinct from the lifecycle chain,
  and (iv) appends to the lifecycle chain a further record whose payload comprises the
  digest of the appended evidence record, whereby the lifecycle chain and the evidence
  chain are mutually cross-bound; and
- (e) consuming, upon revocation, a data structure of the second nominal type to produce a
  data structure of a fourth nominal type upon which no operation producing a data
  structure of the first, second, or third nominal type is defined;

wherein the operation of step (d) is defined exclusively upon the third nominal type, the
third nominal type is constructible only by the second state transition of step (c) by
reason of module-private field visibility, and the second nominal type is producible only
by the first state transition of step (b), such that a program attempting said
evidence-sealing operation without a preceding delegation recorded in step (b) **is
rejected by a type checker of a compiler prior to execution**.

### Independent Claim 2 (System)

A computing system comprising: one or more processors; and non-transitory memory storing
type definitions and instructions that, when compiled by a compiler enforcing affine
ownership semantics and module-private field visibility and executed by the one or more
processors, cause the system to perform the method of Claim 1; wherein the type
definitions define first, second, third, and fourth nominal types as recited, and wherein
the compiler is configured to reject, prior to producing an executable, any instruction
sequence invoking the evidence-sealing operation upon a value not of the third nominal
type.

### Independent Claim 3 (Non-Transitory CRM)

A non-transitory computer-readable medium storing instructions that, when compiled and
executed by a computing system, cause the computing system to perform the method of
Claim 1.

### Dependent Claims

4. The method of Claim 1, wherein the third nominal type defines no operation producing a
   data structure of the fourth nominal type, whereby an in-flight execution must complete
   the evidence-sealing operation of step (d) before a revocation transition becomes
   expressible, thereby preventing loss of evidence for an execution concurrent with a
   revocation.

5. The method of Claim 1, wherein when the execution-status field indicates refusal by
   policy, the post-execution state digest is assigned the value of the pre-execution state
   digest independently of any post-execution state supplied by a caller, whereby an
   evidence record of a refused action is structurally incapable of encoding a state
   mutation.

6. The method of Claim 1, wherein the fourth nominal type defines only read accessors and
   no state-transition operation, and wherein the data structure consumed by the revocation
   transition is rendered statically unusable by the affine ownership semantics of the
   compiler.

7. The method of Claim 1, wherein each timestamp incorporated into a chain record is
   received as a parameter of the corresponding state transition and each record identifier
   is derived deterministically from an agent identifier and a monotonic sequence number,
   such that the method reads no system clock and consumes no random source and an
   identical input sequence yields byte-identical chain records.

8. The method of Claim 7, wherein the instructions are compiled to a WebAssembly target
   lacking ambient clock and entropy access, and produce chain records byte-identical to
   those produced by the same instructions compiled to a native target.

9. The method of Claim 1, wherein said canonical serialization comprises a compact
   serialization with recursively lexicographically ordered object keys, and wherein a
   second implementation of said canonical serialization in a second programming language
   produces byte-identical chain records verified by a verification process of the first
   implementation.

10. The method of Claim 1, further comprising computing a Merkle root over the digests of a
    plurality of evidence records of the evidence chain, wherein a node having no sibling at
    a given tree level is promoted unchanged to the next level.

11. The method of Claim 1, further comprising transmitting each appended record to a
    verification service that maintains, per agent, a verification state consisting of a
    head digest and a sequence counter, and that rejects a received record failing to extend
    said head digest without advancing said verification state.

12. The method of Claim 11, wherein the verification service returns, for each accepted
    record, an attestation comprising a post-quantum digital signature computed over a
    canonical serialization of a payload comprising the advanced head digest, and wherein a
    verifying key embedded in said attestation is rejected unless a digest of said embedded
    verifying key equals an identity value asserted within the attestation.

13. The method of Claim 11, wherein the verification service, upon restart, reconstructs
    said per-agent verification state by replaying a persisted append-only journal of
    previously accepted records through the same acceptance path, and refuses to enter
    service if any replayed record fails acceptance.

14. The method of Claim 1, further comprising forming a compliance record mapping the
    execution-status field and a tool identifier of the evidence record to one or more
    identified regulatory control identifiers, and incorporating said compliance record into
    a certified document body prior to computing a root digest over said body, whereby
    modification of the compliance record invalidates the root digest.

---

## 8. Recommended Next Actions

1. **Resolve §0.2** (assignee, inventorship) — blocking for any filing.
2. **Resolve §0.3** (public-disclosure status of the repository) — potentially time-critical
   for absolute-novelty jurisdictions.
3. **Implement the `trybuild` compile-fail suite of §5.2** before filing; it converts the
   central negative limitation into machine-checked evidence.
4. **Commission a formal prior-art search** focused on: typestate/session-typed APIs
   applied to access control; capability-based security with unforgeable tokens (note:
   object-capability systems are the nearest conceptual neighbor and should be searched
   specifically — the distinction to articulate is that a capability is a *runtime* value
   whereas the present mechanism is checked *before an executable exists*); tamper-evident
   audit logs for autonomous agents; and compiler-enforced security-policy verification.
5. **Decide filing strategy across the related disclosures** — this typestate mechanism,
   the cross-bound dual-ledger construction, the journal-replay-as-tamper-detection
   recovery method, and the multi-implementation canonical-serialization verification method
   may be filed as one application with multiple independent claims or as a family; counsel
   should advise on restriction-requirement risk and claim-scope economics.
