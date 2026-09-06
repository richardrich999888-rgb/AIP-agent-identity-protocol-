# ADR-002 — Hardware-Rooted Attestation

**Status** PROPOSED / NOT IMPLEMENTED — **STOP recorded before implementation**
**Date** 2026-09-06
**Branch** `claude/autonomous-accountability-skills-16-30`
**Evidence base** `docs/architecture/PLATFORM_BINDING_TRUST_MAP.md`
**Related** ADR-001 (autonomous containment evidence boundary)

Skill 19's brief is explicit: if hardware-rooted attestation is required, STOP
before implementing and record the decision. It is required for one of three
gaps, and this ADR is that stop. **No hardware attestation code exists on this
branch, and none is added by Skill 19.**

---

## Context

Skill 19 set out to close T13 — *authorized on platform P, executed on Q*.
Investigation found the gap smaller than assumed and, in one part, already
closed.

**Already closed, verified by experiment against unmodified code:** the
existing reconciler compares the full `ProcessInstance`, `boot_id` included.
An execution measured on a different host-boot than the one authorized yields
`IdentityDivergence` / `Attested`. No change was needed; a test was.

**Closed by Skill 19 without a new anchor:** the measured `boot_id` had no
connection to Skill 17's `PlatformId` / `HardwareId`. A verifier-supplied
deployment registry supplies it, in the same shape as `ObserverTrustAnchors` —
verifier-asserted, portable, offline-capable, no new signer.

**Not closed, and the subject of this ADR:**

- **G1 — no durable hardware identity.** `boot_id` identifies a *boot*. A
  reboot legitimately breaks the binding, so the system cannot say "the same
  machine as yesterday" and therefore cannot distinguish a reboot from a
  hardware *replacement*.
- **G3 — single-host deployments.** Where no off-host collector exists, the
  measured `boot_id` is procfs content under the same root as everything else
  (T8). The cap at `Attested` is load-bearing, and no software mechanism lifts
  it.

Both need a root of trust below the operating system. That is a new trust
anchor.

---

## The seventeen questions

### 1. Why existing AIP + execution binding + observer evidence is insufficient

Each existing mechanism fails G1 for a structural reason, not for want of
effort:

- **AIP identity** is derived from a public key and a provenance triple. It
  identifies an *intelligence*, and is deliberately portable across machines —
  the opposite of what a hardware identity must be.
- **`ExpectedExecution.execution_binding`** is authoritative as an
  *authorization*. The decision point signs what it permitted; it never looked
  at a host.
- **Observer evidence** measures `boot_id`, which is per-boot by construction
  and procfs-sourced. It cannot survive a reboot and cannot outrank host root.
- **The Skill 19 registry** is a verifier assertion about a boot, inheriting
  the verifier's trust model rather than improving on it. Correct for G2,
  silent on G1.

No composition of these produces a statement that survives a reboot or host
root, because none of them has a secret the host cannot reach.

### 2. What exact property hardware attestation establishes

Precisely one, and it is narrower than the name suggests:

> A key resident in a specific hardware root signed a challenge, and that root
> was provisioned with the identity H.

That is **identity continuity of a compute element**. It is not evidence that
software on it behaved, that an execution occurred, or that any effect
happened. It supplies the durable anchor `boot_id` cannot.

### 3. What hardware/root key is trusted

The verifier anchors an **attestation-root public key per hardware element**,
resolved through a registry of the same shape as `ObserverTrustAnchors`:
`(hardware_id, key_version) → public key`. Never a key supplied by the
attestation itself — that is B-4's defect, and it must not be reintroduced one
layer down.

### 4. Who provisions it

The platform owner, at manufacture or commissioning, off the operational path.
Provisioning is where the identity is *asserted*; attestation only proves the
key still lives in that root. **A provisioning process that can be performed by
the running system is not provisioning** — it is the system asserting its own
identity, which is where this started.

### 5. Who verifies it

The same party that already anchors decision points and observers. Verification
is offline and requires only the anchored root key and the attestation.

### 6. Where the trust anchor lives

With the verifier, alongside the existing anchors — never in the artifact, the
device, or the agent. A device that carries its own trust anchor is a device
that asserts its own trustworthiness.

### 7. How keys rotate

`(hardware_id, key_version)`, matching `ObserverTrustAnchors` exactly, so
rotation does not invalidate history: an attestation under key version 1
remains verifiable after version 2 is issued. Reusing the observer model here
is deliberate — two rotation schemes in one system is two schemes to get wrong.

### 8. How revocation works

Removal of one `(hardware_id, key_version)` pair. Revocation is not
retroactive by default: an attestation made while the key was anchored stays
verifiable, and whether a past attestation is still *acceptable* is policy the
verifier applies, not a property of the record.

### 9. What happens offline

Everything above is offline. The attestation is a signature over a challenge
and an identity; verification needs the anchored root key and nothing else. No
online-only requirement is introduced, which is a hard constraint for the space
and disconnected profiles.

The challenge must be verifier-derivable without a round trip — for example,
derived from the `ExpectedExecution.decision_id`, which both sides already
hold. A network-sourced nonce would make attestation online-only and is
rejected for that reason.

### 10. What happens if TPM/HSM is unavailable

`NotEvaluated`. Not a failure, not a pass, and not an inference from absence.
This is the single most important answer in this ADR: a fleet where most nodes
lack a TPM must not become a fleet where absence of attestation reads as
absence of a problem.

### 11. How UAS/UGV/robotics deployments handle it

Attestation is **optional per hardware element**, and elements are enumerated
per platform. A UAS with a TPM on its mission computer and none on its flight
controller yields attested identity for one and `NotEvaluated` for the other —
recorded separately, never summed. SWaP-constrained and rad-hard platforms
frequently have no TPM at all, and the model must remain usable there, which
means attestation cannot be a precondition for any existing capability.

### 12. Whether a software-only fallback exists

**No, and none may be invented.** A software-only "attestation" is a
self-report by the thing being attested. Naming it attestation would convert
`SelfReported` into `Attested` by relabelling, which is the exact failure mode
this architecture exists to prevent.

The honest software-only position is the one Skill 19 implements: the
verifier-supplied registry, correctly labelled as a verifier assertion.

### 13. What happens when attestation is unavailable

Same as 10, and it bears repeating in its own answer because the two questions
get conflated: `NotEvaluated`. Every capability that works today continues to
work. Attestation adds a statement; its absence removes none.

### 14. Whether attestation raises evidence strength or merely establishes identity

**It establishes identity. Whether it raises strength is deferred and is not
decided here.**

An attestation signature is recomputable from held bytes, so it *looks* like
`Proven` material under the ADR-001 contract. But what it proves is that a key
signed a challenge — a fact about a key, not about an execution. Promoting an
execution verdict on that basis would be the "trusted hardware → trusted
execution" collapse this ADR exists to prevent.

The narrow question — whether an *identity divergence* between an attested
hardware identity and an authorized one could reach `Proven`, since both sides
would then be held signatures — is exactly the shape ADR-001 §Q13 identifies
as the legitimate route to a `Proven` workload violation. It is **not decided
here**, must not be decided implicitly by an implementation, and is subject to
ADR-001's prohibitions in full.

### 15. How this interacts with AIP identity

Not at all, by design. AIP identity is portable across machines; hardware
identity is bound to one. They are different objects answering different
questions, and neither derives from the other. An attested hardware identity
never authenticates an agent, and an AIP identity never attests hardware.

### 16. How it interacts with independent observation

They are **independent evidence sources that must not be merged**. Observation
says which process instance ran; attestation says which hardware the root key
lives in. Corroboration between them is valuable and is a reconciler input;
substitution of one for the other is not permitted. In particular, an
attestation must never populate an observation slot, and hardware attestation
must not be routed through the observer's key — a second use of the observer
anchor would make one compromise reach two evidence classes.

### 17. How it interacts with NEXORA proof

An attestation may travel in a NEXORA proof as evidence, under the rules B-4
established: the verifier authenticates it against **its own** anchored root
key, never a key the package supplies. A package-supplied trust anchor is
refused, and a malformed or substituted attestation fails closed.

---

## Decision

**Hardware-rooted attestation is REQUIRED to close G1 and G3, and is NOT
implemented.** This ADR records the stop.

Skill 19 implements only what needs no new trust anchor:

1. adversarial tests proving the host-level T13 case is caught (it already
   was, untested);
2. the verifier-supplied deployment registry closing G2;
3. an explicit, unconstructible-by-software `HardwareAttested` binding method,
   reserved so that its absence is *visible in the model* rather than silently
   missing.

### Prohibited by this ADR

- Implementing a hardware key without this ADR moving to ACCEPTED.
- Any software-only mechanism named "attestation".
- `trusted hardware → trusted execution` in any form.
- Deriving a hardware trust anchor from an artifact that carries it.
- Reusing the observer key as the attestation root.
- Treating unavailable attestation as anything but `NotEvaluated`.

### Open, deliberately

Q14 — whether attested identity divergence may reach `Proven`. Governed by
ADR-001 and not to be settled by an implementation detail.

---

## Status rationale

**PROPOSED / NOT IMPLEMENTED.** Its prohibitions bind now; its mechanism does
not exist. It becomes ACCEPTED only when a hardware root of trust is actually
required by a deployment, is provisioned by a named owner, and Q14 is settled
with code-backed evidence.

**This ADR does not make the system production-ready and must not be cited as
though hardware attestation exists.**
