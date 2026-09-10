# AIRI Threat Model

## 1. The one principle

> **The actor should not control the evidence used to judge the actor.**

Everything below follows from it.

## 2. Trust boundaries

| Party | Holds | Trusted for | Not trusted for |
|---|---|---|---|
| **Agent process** | its own Ed25519 key, its own clock | authorship of its own statements | anything it asserts about the world |
| **Framework / adapter** | nothing | translating callbacks into AIRI | any judgement whatsoever |
| **Host probe** | **no key** | offering observations to the collector | its own honesty (assumed hostile) |
| **Collector** | the observer key, **off-host** | sequence, timestamp, attestation | the content of what the probe reported |
| **Decision point** | its own key | issuing `ExpectedExecution` | observing execution |
| **Reconciler** | nothing | comparing, deriving a verdict | — (pure, clock-free) |
| **Verifier** | anchors it chose | everything it re-derives | anything it was handed as a conclusion |

The agent and the collector are the two signing parties that matter, and the
architecture's entire value is that the agent cannot reach the collector's
key.

## 3. Adversary

**Capability:** full control of the agent process — arbitrary code, the
agent's private key, the process clock, all framework instrumentation, all
Python-level telemetry, and root on the observed host.

**Goal:** have Vanian certify an action that did not happen, or fail to
record one that did.

**Out of scope:** compromise of the collector, of the decision point, or of
the verifier's anchors. Those are different trust boundaries with their own
controls; AIRI assumes them intact and is worthless if they are not.

## 4. Attacks and dispositions

### 4.1 Forge a claim

| Attack | Disposition |
|---|---|
| Emit an event describing work never done | **Succeeds at the claim layer, by design.** The agent may say anything. Detection is `corroborate` returning `Uncorroborated` where an observer covered the window. |
| Sign an event with a key the verifier does not anchor | Fails. Verification is against the anchored key. `adversarial.rs::a_forged_event_signed_by_a_key_the_verifier_does_not_anchor_fails` |
| Sign a statement *about another agent* | Fails: `signature.signer_id` must equal `agent_id`. `AiriError::SignerIsNotTheAgent` |

### 4.2 Relabel a true statement

Cheaper and quieter than forging a false one. All fail, because every field
below is inside the signed preimage:

| Substitution | Test |
|---|---|
| Another agent | `an_event_does_not_verify_under_another_agents_key` |
| Another execution | `an_event_cannot_be_moved_to_another_execution` |
| Another `ExpectedExecution` | `an_event_cannot_be_moved_to_another_expected_execution` |
| Different parameters | `parameter_substitution_is_detected` |
| Different model | `model_substitution_is_detected` |
| Different model digest | `model_digest_substitution_is_detected` |
| Different framework | `framework_identity_substitution_is_detected` |
| Different event kind | `an_event_of_one_kind_cannot_be_presented_as_another` |

### 4.3 Manipulate the narrative

| Attack | Disposition |
|---|---|
| Replay an event | Detected — `SequenceDuplicate` |
| Duplicate an event | Detected — `SequenceDuplicate` |
| Drop a middle event | Detected — `SequenceGap` |
| Reorder events | Detected — `SequenceOutOfOrder` / `SequenceGap` |
| Delete and renumber to close the gap | Detected — `PrevHashMismatch`. This is the attack sequence numbers alone miss. |
| Splice an event from another run | Detected — `ExecutionMismatch` / `PrevHashMismatch` |
| **Truncate at the head** | **NOT DETECTED.** A prefix of a valid chain is valid. See §6. |
| **Never emit the event at all** | **NOT DETECTED by AIRI.** An agent that stays silent produces a perfectly intact chain with the incriminating link absent. Only independent observation speaks to this. |

The last two are the honest limits of self-reporting and are the reason
AIRI is not, and cannot be, the accountability story on its own.

### 4.4 Manufacture corroboration

| Attack | Disposition |
|---|---|
| Claim a `runtime_binding` for a process the observer saw doing something | Fails: the join is on the full `ProcessInstance` (pid + start ticks + boot id). `an_observation_of_a_different_instance_does_not_corroborate` |
| Rely on an unbound kernel event that names the right pid | Fails: an unbound event names a pid, and a pid is not an instance. `a_kernel_event_the_probe_could_not_bind_does_not_corroborate` |
| Use "the process was alive" as evidence it acted | Fails: presence is a fact about the observer's sampling. `process_presence_alone_never_corroborates_an_act` |
| Use an unrelated observation of the right instance | Fails: the action class must match. `an_observation_of_the_wrong_class_does_not_corroborate` |
| Hand the verifier a `Corroborated` value directly | Impossible: `CorroborationSeal` is `#[non_exhaustive]`; only `corroborate()` constructs one |
| Claim a socket proves the *model* ran | Fails: model events are `NotExternallyObservable`. `a_model_invocation_is_never_corroborated_by_a_host_observer` |

### 4.5 Exploit the framework layer

| Attack | Disposition |
|---|---|
| Claim a "more trusted" framework | No framework is a trust anchor. `no_framework_is_a_trust_anchor` sweeps five names and asserts identical outcomes. |
| Transplant a CrewAI event as LangGraph output | Fails: framework identity is in the signed preimage |
| Register a malicious adapter | Changes nothing. An adapter has no privileges; it produces events signed by the agent's key, which is what the agent could do anyway. |

### 4.6 Exploit the SDK

| Attack | Disposition |
|---|---|
| Read the observer's private key from the agent process | Impossible: the SDK has no API for one, and `_reject_observer_key` raises |
| Call `prove()` / `issue_warrant()` / `authorize()` | Impossible: no such method. `test_boundary.py` asserts absence by introspection |
| Destroy the key file to get a fresh identity | Fails closed: `IdentityUnavailable`, and the test asserts no key file is created |
| Read a world-readable key file | Refused by default; waiving requires an explicit `require_owner_only=False` |
| Extract secrets from evidence | Prompts, arguments and outputs are committed, never carried. Tested with a synthetic secret. |
| Read the key from a child's environment | The environment carries identifiers only; tested. |
| Race two threads to corrupt the chain | The emitter serialises sequence and head under a lock |

### 4.7 Resource and denial

| Attack | Disposition |
|---|---|
| Oversized field to force allocation | Refused at 4096 bytes, both sides — `FieldTooLong` |
| Unknown structure version | Refused, not interpreted — `UnsupportedVersion` |
| Malformed public key | Refused, never a pass — tested with 0, 31, 32 and 33 byte keys |
| Flood the collector with events | **NOT ADDRESSED.** Rate limiting is a deployment obligation. |

## 5. Deployment obligations

Not code properties. A deployment that skips these gets less than the tests suggest.

1. **Transport authenticity from probe to collector.** `aip-observe` states this: the registry lives at the collector, but proving a batch really came from the registered probe is the transport's job.
2. **Observer key custody.** Off-host, in an enclave or HSM. An observer key on the observed host reduces the whole system to self-report.
3. **Agent key custody.** Mode 0600 or tighter, ideally an HSM. The SDK refuses group- and world-readable files but cannot defend a key already read.
4. **Anchor distribution.** Verifiers must obtain agent, observer and decision-point public keys through a channel the agent cannot influence.
5. **Rate limiting and back-pressure** at the collector.
6. **Commitment policy.** Which fields are committed, and the retention of the plaintext they commit to, is a deployment decision with privacy consequences.

## 6. Known limitations

Stated as limitations, not as gaps to be argued away.

| # | Limitation | Consequence |
|---|---|---|
| L-1 | Chain truncation at the head is undetectable | An agent can stop reporting at any point |
| L-2 | Silence is undetectable from AIRI alone | An action never reported leaves no AIRI trace |
| L-3 | `runtime_binding` is self-reported | A match with the observer is consistency, not proof |
| L-4 | `emitted_at_ms` is the agent's clock | Never used to order or place events |
| L-5 | Model provenance is unverifiable for hosted inference | `model_digest` is `None`, honestly |
| L-6 | Accelerator execution is not observable from the process | `accelerator` is a self-reported string |
| L-7 | An unmappable action class cannot be compared | Returns `NotEvaluated`, never an accusation |
| L-8 | Corroboration cannot reach `Proven` | Content from the observed host is root-forgeable |
| L-9 | AIRI contributes nothing to a verdict today | By design at this stage — see `AIRI_MIGRATION.md` §4 |
| L-10 | Gateways are not yet trust anchors | An MCP/API gateway report is another self-report from a different self |

## 7. What AIRI actually buys

Given all of the above, the honest summary:

AIRI does not make an agent's claims trustworthy. It makes them
**specific, bound, and checkable** — so that when independent observation
exists, the two can be compared, and when it does not, the system says so
rather than guessing. The valuable output is not `Corroborated`; it is
`Uncorroborated` and `NotEvaluated`, which are the two answers a
self-reporting system normally cannot produce at all.
