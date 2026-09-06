# AIRI — Autonomous Intelligence Runtime Interface, v1

**Status:** implemented, not promoted. See `AIRI_LIMITATIONS.md` for what is
established and what is not, and `AIRI_MIGRATION.md` for versioning.

## 1. What AIRI is

A framework-neutral schema for what an AI agent's own runtime *says* it did:
which model it asked for, which tool it invoked, with which parameters, under
which authorization, in which process.

One schema covers LangChain, LangGraph, LlamaIndex, AutoGen, CrewAI,
OpenAI-style tool calling and bespoke runtimes. Adapters are thin translators
into these types. **No framework is a trust anchor**, and nothing in the
implementation branches on a framework's name to grant anything.

## 2. What AIRI is not

An AIRI event is **not evidence that anything happened**. It is evidence that
the agent said so.

The signing key belongs to the agent. The clock belongs to the agent. The
process that emits the event is the process under scrutiny. Every guarantee
is of the form *"this statement was made by this agent about this execution
and has not been altered since"* — never *"this occurred"*.

This is enforced structurally, not by convention:

| Guarantee | Mechanism |
|---|---|
| An event cannot claim independence | No constructor, field or enum variant exists by which it could |
| "Independent evidence agreed" is unforgeable | `CorroborationSeal` is `#[non_exhaustive]`; only `corroborate()` can produce one |
| AIRI cannot move a verdict | `corroborate` and `integrate` contain no expression producing a `ReconciliationResult` or an `EvidenceStrength` |

## 3. Position in the chain

```
AIP Identity → Authority/Delegation → Authorization → ExpectedExecution
                                                            │
                        ┌───────────────────────────────────┴──────────────┐
                        │                                                  │
                ── AIRI (agent-signed) ──                  ── aip-observe (collector-signed) ──
                self-authored claims about                 off-host, keyless probe,
                model / tool / framework / subprocess       kernel-pushed events
                        │                                                  │
                        └───────────────────┬──────────────────────────────┘
                                            ▼
                              aip-reconcile (semantics unchanged)
                                            ▼
                          Warrant → Containment → NEXORA Proof
```

The two inputs are asymmetric on purpose. Reconciliation is where the
asymmetry is spent.

## 4. Event model

Nine kinds. The discriminant is inside the signed preimage, so an event of
one kind cannot be re-presented as another.

| Kind | Code | Payload | Externally observable? |
|---|---|---|---|
| `AgentExecutionStarted` | `0x01` | `AgentStart` | no |
| `ModelInvocationRequested` | `0x02` | `ModelProvenance` | no |
| `ModelInvocationObserved` | `0x03` | `ModelProvenance` | no |
| `ToolInvocationRequested` | `0x04` | `ToolInvocation` | **yes** |
| `ToolExecutionReported` | `0x05` | `ToolReport` | **yes** |
| `SubprocessExecution` | `0x06` | `SubprocessReport` | **yes** |
| `ExecutionCompleted` | `0x07` | `Completion` | no |
| `ExecutionFailed` | `0x08` | `Completion` | no |
| `ExecutionContextPropagated` | `0x09` | `ContextPropagation` | no |

`ModelInvocationObserved` is named "observed" by the specification and **is
not independent observation**. The observer is the framework, inside the
process under scrutiny. It carries no more weight than any other self-report,
and `corroborate` will not accept it as corroboration of itself.

"Externally observable" means a host observer could in principle see a
matching kernel event. A hosted-model inference leaves a socket, but that
socket is the *tool* layer's evidence; attributing it to the model layer
would count one fact twice.

## 5. Binding fields

Every event carries:

| Field | Type | Meaning |
|---|---|---|
| `version` | `u16` | Structure version. An unknown value is refused, not guessed. |
| `agent_id` | `String` | AIP-ID. Must equal `signature.signer_id` — an agent signs only for itself. |
| `execution_id` | `[u8;16]` | The AIRI execution instance. |
| `parent_execution_id` | `Option<[u8;16]>` | Application lineage, for worker/subprocess handoff. |
| `decision_id` | `Option<[u8;16]>` | The `ExpectedExecution` this run claims. `None` is a statement a verifier can act on. |
| `sequence` | `u64` | Position in this execution's chain, from 0. |
| `prev_event_hash` | `[u8;32]` | SHA-256 of the previous event's preimage; zero at sequence 0. |
| `emitted_at_ms` | `u64` | The agent's own clock. Carried, never trusted to order or place anything. |
| `framework` | `FrameworkIdentity` | Name, version, adapter version. Provenance, not authority. |
| `runtime_binding` | `Option<ExecutionBinding>` | The process the agent *believes* it is in. Self-reported. |
| `payload` | `AiriPayload` | One of the nine bodies. |
| `signature` | `Signature` | Ed25519 over the preimage below. |

### Three lineages kept apart

* **identity lineage** — `aip-agent`, which agent document descends from which
* **authority lineage** — delegation chains, who granted what to whom
* **application lineage** — `parent_execution_id`, which run spawned which

Nothing in AIRI reads `parent_execution_id` to widen scope. Being spawned by
a run confers no authority; a child carries the same expectation or none.

## 6. Canonical encoding

```
preimage = put_domain("SYNTRIASS/AIRI/EVENT/v1")
         ‖ put_u16(version)
         ‖ put_str(agent_id)
         ‖ execution_id                      (fixed 16, length-prefixed)
         ‖ put_opt_bytes16(parent_execution_id)
         ‖ put_opt_bytes16(decision_id)
         ‖ put_u64(sequence)
         ‖ prev_event_hash                   (fixed 32, length-prefixed)
         ‖ put_u64(emitted_at_ms)
         ‖ framework.encode()
         ‖ put_opt(runtime_binding.identity_bytes())
         ‖ put_u8(kind_code) ‖ payload.encode()
```

Every variable-length field is length-prefixed (u32 LE) and every optional
field carries a presence byte, so the encoding is injective. The domain tag
leads, so an AIRI signature cannot verify as a `ScopedToken`, a
`DelegationToken`, an observer head, a reconciliation record or a warrant,
and none of theirs can verify here.

### Domains introduced

| Domain | Use |
|---|---|
| `SYNTRIASS/AIRI/EVENT/v1` | Event signing preimage |
| `SYNTRIASS/AIRI/PARAM_COMMITMENT/v1` | Parameter, prompt, output and argv commitments |

Neither collides with any of the fifteen domains already in the repository.

## 7. Commitments, not payloads

Prompts, tool arguments, model outputs and argument vectors never enter an
event. Only commitments do:

```
commit(x) = SHA-256( put_domain("SYNTRIASS/AIRI/PARAM_COMMITMENT/v1") ‖ put_bytes(x) )
```

Domain-separated rather than a bare SHA-256, so a digest computed elsewhere
in the system — a packet hash, an observer head, a Merkle leaf — cannot be
presented as a parameter commitment.

The Python SDK commits JSON with `sort_keys` and fixed separators, so the
same logical arguments commit identically regardless of dict ordering. Without
that, a verifier comparing two commitments of identical arguments would see a
substitution that never happened.

## 8. Chains

Events for one execution form a hash chain. `prev_event_hash` is the SHA-256
of the previous event's signed preimage.

Detected: replay, duplication, drop, reordering, splicing from another
execution or agent, and deletion hidden by renumbering.

**Not detected: truncation at the head.** A prefix of a valid chain is a
valid chain, and nothing inside the chain distinguishes "the run ended here"
from "the rest was withheld". Closing this needs either an observer or a
verifier that insists on a signed completion. The limit is tested
(`chain.rs::dropping_the_last_event_is_not_detectable_and_that_is_documented`)
rather than papered over.

## 9. Corroboration

`corroborate()` compares one claim against collector-signed observation.

| Outcome | Meaning |
|---|---|
| `NotEvaluated(reason)` | Not compared. Carries why, so silence is never read as "clean". |
| `Corroborated(seal)` | Independent evidence covering the window and the instance is consistent with the claim. |
| `Uncorroborated{reason}` | The observer covered the claim and did not see it. **The epistemically valuable case.** |
| `Contradicted{detail}` | Observation contradicts the agent's own account. |

Order of evaluation, each step failing toward "cannot say":

1. Is this kind externally observable? → `NotExternallyObservable`
2. Is there a runtime binding to join on? → `NoRuntimeBinding`
3. Did the observer declare coverage? → `ObserverUnavailable`
4. Do any batches overlap the window? → `WindowNotCovered`
5. Is the action class mappable? → `ActionClassNotComparable`
6. Does any observation refer to the claimed instance? → `InstanceNotObserved`
7. Does any observation match the class? → `Corroborated` / `ActionClassAbsent`

Step 5 matters more than it looks: an unmappable action class returns
`NotEvaluated`, never `Uncorroborated`. Turning a vocabulary gap into a
phantom claim would be the worst false positive this system can make.

## 10. The three tool layers

```
1. Requested invocation    ToolInvocationRequested
2. Runtime execution       ToolExecutionReported
3. External effect         — no event asserts this —
```

An HTTP 200 is evidence of layer 2. A proxy, a stub, a replayed cassette, a
compromised client, a load balancer that acknowledged and dropped, or a
database that returned success and rolled back all produce a 200. There is no
method in the SDK and no variant in the Rust types that asserts layer 3,
because the process that made the call cannot know.

Only independent observation can speak to layer 3, and even then the ceiling
is `Attested` — content read from the observed host is root-forgeable.

## 11. NEXORA

Two carriage points, both live.

**As a Merkle leaf.** An AIRI event commits under `LeafKind::AiriEvent`
(code `0x09`), appended to the frozen set rather than renumbering it.

**As a proof component.** `NexoraProof` (package version **2**) carries an
optional `AiriBundle` under `Component::Airi` (`0x0A`): the agent id, the key
the package says signed the events, and the events themselves in emission
order.

In both cases what is committed is the event's **signing preimage** — the
exact bytes the agent signed — so a verifier checks one artefact rather than
trusting a re-serialisation round-trip.

### What the offline verifier does with it

`verify_nexora_proof` **re-derives**:

1. every event's signature, against the key the *verifier* anchored;
2. the chain, re-walked from the package's own bytes;
3. that every event's `agent_id` is the bundle's.

The result is a `ComponentVerdict` — `Verified`, `Absent`, or
`Unverifiable(reason)` — plus `airi_events_verified`. It is never an upgrade
to any other component.

**The package cannot choose the key it is judged against.** If the verifier
anchored a key for this agent, that key is used and the package's must match
it; a package naming a different key is refused with "does not anchor", not
quietly verified against the one it supplied. Without that rule an assembler
could sign a fabricated chain with its own key, put that key in the bundle,
and have every signature check out.

A `Verified` verdict reached under a *self-supplied* key (verifier anchored
none) means "internally consistent", which is weaker than "signed by the
agent the verifier trusts" and must not be read as the latter.

### Symmetry

AIRI cannot raise a verdict and a broken AIRI bundle cannot lower one. The
reconciliation rests on the observer's evidence; a defect in the agent's own
account is recorded as its own component verdict rather than leaking into the
result. Both directions are tested (`aip-nexora/tests/airi.rs`).

## 12. Reconciliation

AIRI produces an `AiriAnnotation` that sits beside a `Reconciliation`, never
inside it. `annotate()` takes the reconciliation by shared reference and
returns a new value; it contains no expression producing a
`ReconciliationResult` or an `EvidenceStrength`.

`tests/reconcile_integration.rs` drives the real engine and asserts the
verdict and strength are identical with and without AIRI evidence present, in
every corroboration shape.

**A `reconcile_airi_claim` entry point that could reach `PHANTOM_CLAIM` from
an uncorroborated AIRI claim is deliberately not implemented.** See
`AIRI_MIGRATION.md` §4.
