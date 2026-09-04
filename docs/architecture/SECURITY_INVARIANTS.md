# VANIAN Security Invariants

I1.
An agent cannot be the sole authority for attesting its own execution.

I2.
Agent identity must not be inferred solely from network address.

I3.
PID alone must never establish process identity.

I4.
PID reuse must not silently transfer execution attribution.

I5.
Authorization validity must include explicit temporal semantics.

I6.
Security-critical authorization fields must be cryptographically
covered by the authorization signature.

I7.
Observed execution and authorized execution are separate evidence
sources.

I8.
Failure to observe an event is not equivalent to proof that the event
did not occur.

I9.
Sensor degradation must be represented explicitly.

I10.
Observer attestation keys must not be accessible to the observed
agent.

I11.
Application-layer encrypted payloads must not be represented as
kernel-observable plaintext evidence.

I12.
Detection confidence and evidentiary strength must remain separate.

I13.
Containment requires an explicit warrant/policy decision.

I14.
Cryptographic commitments require canonical serialization.

I15.
A cryptographic primitive is not itself a cryptographic protocol.

I16.
Documentation does not establish implementation reality.

I17.
Unmerged code must not be represented as production capability.

I18.
AIP identity and authorization semantics must not be duplicated inside
Ghost/Sentinel without architectural justification.

I19.
Ghost/Sentinel runtime observation must not silently become an
authorization authority.

I20.
Every claimed security property must have:
THREAT → ASSUMPTION → MECHANISM → IMPLEMENTATION → TEST → LIMITATION.
