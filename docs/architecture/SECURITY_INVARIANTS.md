# VANIAN Security Invariants

> **Completion mandate, final state.** Gates 1–11 are complete;
> `SNIFFER_DOG_COMPLETE_IMPLEMENTATION_REPORT.md` is the single record of
> what exists, what was measured, what may be claimed and what may not.
> Final status: **VALIDATED RUNTIME**, scoped there — the evidence
> machinery, not a shipped product.

**This file is the single authoritative invariant numbering system.**

Numbers I1–I20 correspond exactly to the invariants enforced by the
`ghost-architecture-orchestrator` and `syntriass-ghost-implementation` skills.
I21–I23 are additional invariants that originated in this document and have no
counterpart in those skills; they are preserved here verbatim in meaning and
are equally binding.

No other invariant numbering exists. Cite invariants by these numbers only.

---

I1.
An agent must not be the authority that decides whether its own execution is
permitted. The decision point must lie outside the agent's authority boundary.
A library linked into the agent is not an independent decision point.

I2.
Executions must be bound using cryptographic execution identity, not incidental
operating-system identifiers. Do not use, as identity: PID alone, IP address,
port, process name, executable path, or mutable labels.

I3.
An observed execution must be attributable to a specific execution instance.
If attribution cannot be established, the result is CANNOT_PROVE. Never
manufacture attribution.

I4.
PID reuse must not transfer identity or execution attribution from one process
instance to another. A valid execution binding must incorporate sufficient
process-instance information, such as PID plus process start identity plus boot
identity.

I5.
Observation must come from an observer whose trust boundary is independent of
the agent being observed. An agent reporting "I executed X" is not independent
observation.

I6.
Every security-sensitive authority field must be cryptographically covered by
the authority's signature. In particular `expires_at` must never be mutable
after authorization. If a field influences authorization or validity, the
issuing authority's signature must bind it.

I7.
Never claim tamper resistance, post-quantum security, hardware attestation,
Merkle commitment, independent observation, provenance, or containment
authorization unless the implementation actually provides the property.

I8.
Failure to observe an event is not equivalent to proof that the event did not
occur. Missing or unattested observation yields CANNOT_PROVE. A PHANTOM_CLAIM
requires independently attested sensor coverage over the exact execution window.

I9.
Observer health must be represented explicitly, at minimum distinguishing
ACTIVE, DEGRADED, RECOVERING, CONTINUITY_UNVERIFIED and QUARANTINED. A sensor
outage is not malicious execution and must never be upgraded into a malicious
verdict.

I10.
The observer signing key must not be accessible to the observed agent. A
software key stored on the observed host is not an acceptable sole trust anchor
against a root-compromised host.

I11.
No containment or enforcement capability may be built before the evidence
pipeline can independently establish the facts that response requires.

I12.
Detection confidence/severity and evidentiary strength are orthogonal and must
never be collapsed into a single score. Evidence strength must remain capable of
expressing Heuristic, Correlated, Attested and Proven.

I13.
Containment requires a warrant and sufficient evidence strength. The
architecture `anomaly → kill` is forbidden. The default implementation must be
advisory.

I14.
Security-sensitive signed structures must use canonical encoding that is
injective. Ambiguous raw concatenation is forbidden: `("ab","c")` and
`("a","bc")` must never serialize to the same signing bytes. Variable-length
values require explicit length or presence encoding.

I15.
A cryptographic primitive is not itself a cryptographic protocol. A Merkle leaf
helper is not a Merkle commitment protocol; Ed25519 signing is not an
attestation protocol; SHA-256 is not a tamper-evident audit system; a hash chain
is not externally anchored history.

I16.
Every architectural security claim must have implementation evidence, test
evidence, or an explicit documented limitation. Where none exists, the answer is
NOT DETERMINABLE FROM CURRENT CODEBASE. Documentation does not establish
implementation reality, and the gap must never be filled by assumption.

I17.
Anything present only on an unmerged branch, pull request or remote branch is
DESIGN INPUT ONLY and must not be represented as production capability.

I18.
Ghost must not duplicate AIP identity or authorization logic. Where AIP already
owns an authority primitive, Ghost integrates with it rather than creating a
second competing security model. Duplicate authority engines are architectural
defects.

I19.
Observation and authorization are different authorities. The decision point
answers "was this execution permitted?"; the observer answers "what execution
did I observe?". Neither may impersonate the other. The observer signs what it
saw, never what is permitted.

I20.
Every claimed security property must have a complete chain:
THREAT → ASSUMPTION → MECHANISM → IMPLEMENTATION → TEST → LIMITATION.
If one element is missing, the security claim is incomplete.

---

The following invariants originated in this document and have no counterpart in
the orchestrator or implementation skills. They remain binding.

I21.
Authorization validity must include explicit temporal semantics. Expiry
enforcement must rest on an explicit contract, not on ambient system time, and
signature integrity of an expiry field is distinct from trusted wall-clock
enforcement of it.

I22.
Observed execution and authorized execution are separate evidence sources and
must be kept separate. Neither may be derived from, or substituted for, the
other.

I23.
Application-layer encrypted payloads must not be represented as
kernel-observable plaintext evidence. Network metadata and application payload
are distinct; metadata must never be silently promoted to payload evidence. Any
design requiring exact parameter comparison must document whether it assumes
cooperation from the agent runtime or an in-path proxy that terminates TLS.

---

## Provenance note

This file previously used a numbering system that diverged from the skills for
five entries. It was normalized so that one authoritative numbering exists.

Two former entries — "agent identity must not be inferred solely from network
address" and "PID alone must never establish process identity" — are both
stated explicitly inside the prohibition list of **I2**, which enumerates PID
alone and IP address among the identifiers that may not serve as identity.
Their substantive requirements are preserved in full; they are no longer
separately numbered.

The before/after mapping is recorded in the commit that performed the
normalization.

---

## The completion mandate's twenty rules, mapped to executable evidence

Rule 20 of the mandate requires every architectural claim to map to
executable evidence. This table is that map. It does not replace the
invariant numbering above; it shows where each standing rule is enforced
and which test fails if the enforcement is removed.

| # | Rule | Enforced in | Test |
|---|---|---|---|
| 1 | `CANNOT_PROVE` is the default under insufficient observation | `aip-reconcile::reconcile` — every path that cannot establish its precondition returns it | `aip-reconcile` lib `default_result_is_cannot_prove`; `adversarial` (30) |
| 2 | Agent self-report is never independent observation | `aip-observe` imports no type from `aip-authorize`; `AgentClaim` is separate from measurement | `aip-observe/tests/adversarial.rs`; `blind_spots.rs` |
| 3 | Observer signing keys are not agent-controlled | `ProcfsProbe` has no key field or signing method; `ObservationBatch` has no signature field; `verify_attested_batch_independent_of_agent` refuses an anchor equal to the agent's key | `aip-observe/tests/adversarial.rs` |
| 4 | `ExpectedExecution` stays decision-point signed | `aip-authorize::decision` | `aip-authorize/tests/adversarial.rs` (32) |
| 5 | `ExecutionBinding` stays structurally bound | `aip-types::ExecutionBinding::identity_bytes`, `aip-core::execution_binding` | `aip-core` lib; `aip-reconcile/tests/adversarial.rs` |
| 6 | Domain separation is explicit | every signed preimage opens with `put_domain(..)`: `OBSERVER_HEAD_DOMAIN`, `OBSERVER_HEALTH_DOMAIN`, `KERNEL_EVENT_DOMAIN`, `CONTINUITY_REPORT_DOMAIN`, `WARRANT_DOMAIN`, `CONTAINMENT_DOMAIN`, NEXORA `LEAF`/`HEAD`/`PROOF` | cr09, c15, `nexora` x01–x08, `warrant` |
| 7 | Canonical encoding is injective | `aip-types::canonical` length-prefixes every variable field, tags every `Option`, counts every collection | `aip-protocol/tests/evidence_packet.rs` collision vectors |
| 8 | Expiry lives inside signed authority material | `aip-core::capability`, `::delegation` | `aip-core` lib expiry-mutation tests |
| 9 | Revocation is checked where required | `ObserverTrustAnchors::revoke`, `WarrantTrustAnchors`, `ContainmentTrustAnchors` | `aip-observe/tests/adversarial.rs`; c03 |
| 10 | PID reuse never silently produces attribution | `PidFd` held across every measurement; `aip-containment::attribute` compares start ticks and boot id | `aip-observe/tests/sniffer_dog.rs`; c06 |
| 11 | Ambiguous evidence never becomes proof | `ActionOutcome::Unresolved`, `WireCorroboration::Ambiguous`, `LineageComparison` | `wire_corroboration` (15), `send_evidence` (13), `file_evidence` (15) |
| 12 | Missing evidence never becomes proof | `ObservationAvailability::Unavailable`; `PHANTOM_CLAIM` requires kernel-pushed coverage of the exact window | `aip-reconcile/tests/adversarial.rs`; `aip-observe/tests/blind_spots.rs` |
| 13 | Degraded observation never becomes proof | `ObserverState::permits_attested_use` is true only for `Active`; coverage is dropped on loss, gap or restart | `aip-observe` lib; `restart_continuity` (8); cr01–cr10 |
| 14 | Containment is never triggered from weak evidence | `aip-containment::contain` gates 3–8: `Contain`, `Workload`, `Proven` by explicit match, workload-violation result, availability, citation | c01, c02 |
| 15 | No duplicate authority engine | `aip-warrant` and `aip-containment` reuse `ProtectedIdentitySet`; containment issues no warrant | c09; `aip-containment` has no warrant constructor |
| 16 | No duplicate identity engine | one `derive_aip_id`; one `ExecutionBinding` | repository-wide search recorded in `CURRENT_SYSTEM.md` §3 |
| 17 | NEXORA cannot become an authorisation bypass | `aip-nexora` imports no authority type; a `VerifiedInclusion` states where and what digest, never truth or permission | `nexora` x04, x05 |
| 18 | Application logs never silently become independent truth | no such sensor exists; the decision and its fence | `APPLICATION_LOG_SENSOR_DECISION.md`; g5a–g5d |
| 19 | Every positive verdict names its trust root | every record carries `EvidenceRef`s naming observer, key version, sequence, batch and decision point | `aip-reconcile/tests/transition_evidence.rs` (22) |
| 20 | Every architectural claim maps to executable evidence | this table; `SNIFFER_DOG_COMPLETE_IMPLEMENTATION_REPORT.md` §§3–5 | 787 tests in `aip-standalone`, 39 in `aip-service` |

## Skill 10 additions — invariants the proof layer introduced

Each is enforced by a named test that fails if it stops holding.

| # | invariant | enforced by |
|---|---|---|
| N1 | A verifier re-derives the verdict; it never reads the claimed one. | `adversarial.rs::t`, `verify.rs` re-derivation |
| N2 | `CANNOT_PROVE` cannot become `PROVEN` through packaging, export, import or transport. | `adversarial.rs::t`, `live_nexora.rs::g14_04` |
| N3 | A refused package establishes nothing: no result, no strength. | `adversarial.rs::establishes_nothing`, used by every refusal case |
| N4 | A carried component is never reported `Absent`. | `adversarial.rs::g`, `v`; `verify.rs::NOT_REACHED` |
| N5 | A package cannot tell a verifier what it will accept, or what time it is. | `adversarial.rs::n`, `export.rs::import_anchors` |
| N6 | Coverage is derived by the verifier; a package has no field for it. | `adversarial.rs::s`, `coverage.rs::g6_06` |
| N7 | Exactly one coverage state licenses a statement about absence. | `ObservationCoverage::licenses_absence_claim`, `adversarial.rs::q` |
| N8 | Any continuity break the collector reports reads as `Discontinuous`. | `adversarial.rs::i`, exhaustive over the variants |
| N9 | A revoked token asserts no authority link. | `adversarial.rs::u`, `LineageStanding::Revoked` |
| N10 | Withdrawing an observer's anchor withdraws its evidence and its coverage. | `adversarial.rs::v` |
| N11 | A delegation chain is verified from its root, not from an assumed one. | `aip-core::delegation::tests::the_root_token_a_chain_starts_from_must_be_authentic` |
| N12 | A signature made for one purpose does not verify for another. | `adversarial.rs::k`, `audit.rs::a01` |
| N13 | An unimplemented algorithm identifier is refused, never checked as Ed25519. | `audit.rs::a07`, `a08` |
| N14 | Offline verification is deterministic and grants no authority. | `adversarial.rs::j`, `m`; `AuthorityStanding::grants_authority_now` |
| N15 | No engine-producible record warrants autonomous containment. | `aip-containment/tests/reachability.rs` |

The full statement of what each of these does *not* establish is in
`NEXORA_IMPLEMENTATION_REPORT.md` §12 and §13.
