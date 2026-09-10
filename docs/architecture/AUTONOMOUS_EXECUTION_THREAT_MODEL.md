# Autonomous Execution Threat Model

**Scope** Skill 18, the environment-neutral execution model.
**Companion** `AUTONOMOUS_EXECUTION_MODEL.md`.

Each entry states what the attacker controls, what they do not, what the
system should do, and what evidence would be required to say more. The last
column is the important one: where it says NOT AVAILABLE, the honest
disposition is `CANNOT_PROVE`, and no amount of the evidence that *is*
available substitutes for it.

A recurring result below is that a compromised agent produces perfectly valid
self-reports. That is not a defect in the signing; it is the reason
self-reports are not evidence.

---

## T1 — Compromised autonomous agent

| | |
|---|---|
| **Attack** | The agent's own process is under attacker control and authors AIRI events describing an execution that did not happen, or omitting one that did. |
| **Trust boundary** | Agent self-report ↔ independent observation (stages 4-7 ↔ 8-11). |
| **Controls** | Every field of every AIRI event; the signing key, since it is in the process; timing; which events to omit. |
| **Cannot control** | The decision point's signature over `ExpectedExecution`. The observer's key. Whether an anchored observer measured the host. Past events already chained and exported. |
| **Expected disposition** | The claim is recorded and verifies as *authored by that agent*. It never becomes evidence of occurrence. With no corroboration: `CANNOT_PROVE`. |
| **Evidence required** | An anchored observer's attested measurement of the process instance over the claimed window. |

Note: the agent can sign a *coherent lie* but cannot sign a *coherent
contradiction* without leaving both halves in evidence. That is the structural
opening ADR-001 §Q13 identifies, and it is why the chain matters even though
the content is untrusted.

## T2 — Compromised AI framework

| | |
|---|---|
| **Attack** | The framework (LangChain, an agent SDK) is malicious or backdoored and emits `ModelInvocationRequested` / `ModelInvocationObserved` for calls never made, or suppresses real ones. |
| **Trust boundary** | Framework claim ↔ model runtime reality. |
| **Controls** | `model_id`, `runtime`, `accelerator`, `inference_request_id`, prompt and output commitments, and whether an event is emitted at all. |
| **Cannot control** | Anything outside the process. The provider's own records. Network-level observation. |
| **Expected disposition** | `ModelInvocationObserved` is named "Observed" by the AIRI specification and is **not** independent observation — the observer is the framework, inside the process under scrutiny. Treated as a self-report like every other. |
| **Evidence required** | Provider-side attestation, or independent network observation of the inference call. **NOT AVAILABLE** in this architecture. |

## T3 — Malicious adapter

| | |
|---|---|
| **Attack** | The adapter between framework and AIRI mislabels an action — reports `action_kind: "read"` for a write, or commits to parameters other than those sent. |
| **Trust boundary** | Adapter ↔ the authorized action vocabulary. |
| **Controls** | `tool_id`, `action_kind`, `parameter_commitment`, `target`. |
| **Cannot control** | The `ExpectedExecution.parameter_digest`, which the decision point signed before the action. |
| **Expected disposition** | A mismatch between the claimed `parameter_commitment` and the authorized `parameter_digest` is visible to the reconciler as a parameter divergence. A *consistent* lie — mislabelled on both sides — is not caught here and needs observation of the actual effect. |
| **Evidence required** | Independent observation of the effect's parameters, e.g. the socket tuple actually opened. |

## T4 — Malicious tool

| | |
|---|---|
| **Attack** | The tool returns 200 without performing the effect, or performs a different effect. |
| **Trust boundary** | Software response ↔ external effect (stage 7 ↔ 10). **The boundary this skill exists to draw.** |
| **Controls** | The response body, the status code, timing. |
| **Cannot control** | Whether a counterparty or an observer independently records the effect. |
| **Expected disposition** | `EffectDisposition::NotEvaluated`. A `RuntimeAction` carrying a 200 **cannot construct** `Confirmed` — the constructor requires `EffectEvidence`, which cannot be built from agent-authored material. |
| **Evidence required** | Counterparty attestation (a countersigned receipt), or independent observation of the effect. |

## T5 — Compromised model runtime

| | |
|---|---|
| **Attack** | The runtime serves a different model than requested, or loads different weights, while reporting the requested identifiers. |
| **Trust boundary** | `model requested` ↔ `model served` ↔ `weights loaded` ↔ `accelerator executed`. |
| **Controls** | `model_id`, `model_digest`, `runtime_version`, `accelerator` — all self-reported. |
| **Cannot control** | Attested measurement of loaded weights, where such a mechanism exists. |
| **Expected disposition** | All four rungs remain distinct and unproven. A `model_digest` is a claim about a file, never proof those bytes entered runtime memory. |
| **Evidence required** | Runtime attestation of loaded weights. **NOT AVAILABLE.** Recorded as such rather than approximated. |

## T6 — Compromised process

| | |
|---|---|
| **Attack** | Another process on the host emits events claiming to be the authorized execution. |
| **Trust boundary** | Claimed execution identity ↔ measured process instance. |
| **Controls** | Its own event contents, including `execution_id` and the self-reported process fields. |
| **Cannot control** | The `ExecutionBinding` the decision point signed — pid *and* start ticks *and* boot id *and* executable content hash. A different process differs in at least the first three. |
| **Expected disposition** | `IDENTITY_DIVERGENCE` when an observer measured the real instance; `CANNOT_PROVE` when none did. |
| **Evidence required** | Observer measurement of the instance under a pidfd anchor. |

## T7 — Compromised container

| | |
|---|---|
| **Attack** | The workload is moved into a different container or namespace while continuing to claim the same execution. |
| **Trust boundary** | Execution identity ↔ execution environment. |
| **Controls** | Everything inside the container. |
| **Cannot control** | `boot_id` and pid start ticks as the host reports them. |
| **Expected disposition** | Divergence from the signed binding, or `CANNOT_PROVE`. |
| **Evidence required** | Host-level observation outside the container. A container cannot attest its own boundary. |

## T8 — Compromised host (root)

| | |
|---|---|
| **Attack** | Host root forges procfs content, suppresses observations before the collector signs them, or manipulates the clock. |
| **Trust boundary** | Observed *content* ↔ recomputable *arithmetic*. |
| **Controls** | Everything procfs-derived: process tables, socket tables, executable contents as read. Which observations reach the collector. |
| **Cannot control** | The collector's signing key, if it is held off-host. Signature and hash-chain arithmetic over already-signed batches. |
| **Expected disposition** | Observation content is capped at `Attested` precisely because of this actor — the cap is not conservatism, it is this threat. `Proven` is reserved for facts recomputable from held bytes, which root cannot retroactively alter. |
| **Evidence required** | Off-host collector signing; hardware roots of trust. Partially **NOT AVAILABLE**; this is the actor that makes absence arguments unable to reach `Proven` (ADR-001 §B.1). |

## T9 — Compromised edge device

| | |
|---|---|
| **Attack** | The whole device, including any local observer, is under attacker control, in a disconnected deployment where nothing external can check. |
| **Trust boundary** | The device ↔ everything outside it. |
| **Controls** | All local evidence generation. |
| **Cannot control** | Previously exported and externally held proof. Anything a remote party independently recorded. |
| **Expected disposition** | Everything generated after compromise is `CANNOT_PROVE` to an external verifier. **A locally self-consistent record is exactly what a compromised device produces**, so local consistency must never be read as integrity. |
| **Evidence required** | Hardware attestation with an off-device root; external corroboration. **NOT AVAILABLE** in this skill. |

## T10 — Replay attacker

| | |
|---|---|
| **Attack** | A genuine, validly signed execution record is resubmitted, or resubmitted under a different context. |
| **Trust boundary** | Record identity ↔ record freshness. |
| **Controls** | Which bytes to resubmit, and when. |
| **Cannot control** | Any signature over the record, so the record cannot be altered — only repeated. |
| **Expected disposition** | Every identity is inside the canonical preimage, so a replay into a different context breaks the signature. Repetition in the *same* context is a stateful question: R18 `REPLAY_SCOPE` (B-8) answers it where a verifier supplies history, and reports NOT EVALUATED where none is supplied. |
| **Evidence required** | Verifier-held observation history. |

## T11 — Substitution attacker

| | |
|---|---|
| **Attack** | Splice a valid component from one execution into another — agent A's claim under agent B's expectation, execution X's record onto platform B, a model event presented as an effect. |
| **Trust boundary** | Every field boundary in every canonical encoding. |
| **Controls** | Which valid pieces to combine. |
| **Cannot control** | The canonical bytes. Every identity participates, length-prefixed, with presence bytes on optionals. |
| **Expected disposition** | Refused. Any substitution changes the preimage, so any signature over it stops verifying. The 25-case adversarial matrix exists to prove this field by field rather than by argument. |
| **Evidence required** | None — this is the one class the encoding itself defeats, which is why the encoding is tested this hard. |

## T12 — Stale authority

| | |
|---|---|
| **Attack** | Execute under an expectation whose window has passed, or under a revoked or expired token. |
| **Trust boundary** | Authorization ↔ temporal validity. |
| **Controls** | When to act. |
| **Cannot control** | `issued_at` and `valid_until`, both inside the DP signature. |
| **Expected disposition** | `TemporalStatus::Expired`; the reconciler's temporal comparison refuses it. R16 additionally bounds the *verifier's* own time (B-1a). |
| **Evidence required** | A verifier-supplied verification time. Absent one, R16 reports NOT EVALUATED rather than passing. |

## T13 — Malicious platform identifier

| | |
|---|---|
| **Attack** | Claim to be on a platform or hardware the execution is not on — a fleet vehicle claiming another's tail number. |
| **Trust boundary** | Authorized context ↔ attested context. **The sharpest limitation of Skill 18.** |
| **Controls** | The self-reported `platform_id` and `hardware_id`. |
| **Cannot control** | The DP's signature over the `ActionParameters` binding, once made — so the context cannot be swapped *after* authorization. |
| **Expected disposition** | The binding establishes what was **authorized**, not what **is**. A DP signature over "platform P" is a statement about permission, not about physics. An execution that is authorized for P and running on Q is **not detected by this skill**. |
| **Evidence required** | Hardware attestation (Skill 19) or independent observation binding the execution to the platform (Skill 20). **NOT AVAILABLE.** Stated plainly rather than left for a reader to infer from an absence. |

## T14 — Forged runtime binding

| | |
|---|---|
| **Attack** | Present a self-collected `ExecutionBinding` describing a process instance that is not the executing one. |
| **Trust boundary** | Self-reported binding ↔ observer-attested binding. |
| **Controls** | Every field of a self-collected binding. |
| **Cannot control** | An observer's independent measurement under a pidfd anchor. |
| **Expected disposition** | A self-reported binding is never upgraded into evidence that the execution occurred — the type's own documentation says so and nothing in this model changes it. |
| **Evidence required** | Observer attestation of the same instance. |

## T15 — False physical-effect claim

| | |
|---|---|
| **Attack** | Claim a physical action occurred — a valve closed, a waypoint reached, a payload released — with no independent evidence. |
| **Trust boundary** | Software layer ↔ physical world. **The widest gap in the whole architecture.** |
| **Controls** | Every self-reported field, including any sensor value the agent relays. |
| **Cannot control** | An independent sensor with its own trust anchor, where one exists. |
| **Expected disposition** | `EffectDisposition::NotEvaluated`. Structurally enforced: `Confirmed` cannot be constructed without `EffectEvidence`. |
| **Evidence required** | An independently anchored physical sensor. **NOT AVAILABLE** in Skill 18 and not simulated by it. The AI/physical-effect boundary rule applies in full: a successful tool invocation is not proof that the external effect occurred. |

---

## Cross-cutting: what none of these threats can do

Two properties hold against every actor above, and they are what the
architecture actually delivers today:

1. **They cannot make a substitution silent.** Every identity participates in
   a canonical, prefix-free preimage. Splicing changes the bytes; any
   signature over them stops verifying.
2. **They cannot convert absence into confirmation.** `NotEvaluated`,
   `Unconfirmed` and `CANNOT_PROVE` are distinct states, and no code path
   promotes one to a positive finding.

## Cross-cutting: what none of them needs to do

Six of the fifteen threats above are dispositioned `CANNOT_PROVE` with the
required evidence marked **NOT AVAILABLE** (T2, T5, T8 partially, T9, T13,
T15). That concentration is the honest summary of where this architecture
stands: it is very good at refusing to be fooled, and it is not yet able to
confirm much about the physical world or about what a model runtime actually
did.

A reader looking for the system's weakest point should read T13 and T15
together. Both are gaps that later skills are meant to close, and neither is
closed by anything in Skill 18.
