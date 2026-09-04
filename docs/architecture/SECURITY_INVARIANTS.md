# VANIAN Security Invariants

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
