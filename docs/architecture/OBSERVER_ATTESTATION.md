# OBSERVER_ATTESTATION

> **Status update (Stage 3, Skill 6).** The anchor selection deferred in §3
> and the threat-model questions left open in §4 were decided when Skill 6 was
> authorized: **remote collector**, per this document's own recommendation.
> The implementation, threat model, assumptions, key lifecycle and limitations
> now live in `OBSERVER_IMPLEMENTATION_REPORT.md`; the crate is
> `aip-standalone/aip-observe`. Sections 1–6 below are preserved as the
> discovery record that motivated the design, including the adjacent code in
> §1 that still must not be mistaken for attestation.

## 1. Current state

`OBSERVER_ATTESTATION = MISSING`. Zero occurrences in production code. There is
no observer, therefore no observer key, therefore no trust root.

Adjacent code that must **not** be mistaken for attestation:

| Symbol | Location | Reality |
|---|---|---|
| `evaluate_hardware_trust` | `aip-standalone/aip-core/src/lib.rs:658-680` | computes `sha256(att.attestation_report)` then **string-matches a "measured boot marker"** in caller-supplied bytes and can return `HardwareTrustLevel::FullEnclave`. No vendor certificate chain, no quote signature verification. Disclaimed in a doc comment at `lib.rs:11-13`, but not in the type system |
| `HardwareAttestation` | `aip-types/src/lib.rs:452-459` | `device_id`, `attestation_report: Vec<u8>`, `report_hash`, `bound_aip_id` — **no signature field at all** |
| `RuntimeBinding` | `aip-core/src/runtime.rs:10-26` | self-measured by the process under scrutiny; no signature; never reaches evidence |

`HardwareTrustLevel` derives `Ord` (`aip-types:475-480`), which invites `>=`
comparisons on a value an attacker fully controls. Treat any use of it as a
finding until the enum is gated behind real quote verification.

## 2. The requirement

**I10:** the observer's signing key must not be accessible to the observed
agent. This is the property that makes an observation *evidence* rather than a
second self-report. If the agent can reach the key, Ghost adds attack surface
and no assurance.

Corollary **I19:** the observer signs *what it saw*. It must never sign *what
is permitted*. Observation and authorization are different authorities; merging
them recreates the problem AIP already has, where the acting party controls
both sides.

## 3. Candidate trust anchors — none selected

Selection is deferred until the threat model below is decided by a human. Each
option is recorded with what it costs, per the skill's §14 requirement.

| Anchor | Key custody | Resists a root-compromised host? | Cost |
|---|---|---|---|
| **Remote collector** (observer streams to an off-host signer) | off-host | **Yes** for anything already transmitted; loses the tail on partition | needs network availability; ordering/continuity must be explicit |
| **TPM 2.0** | hardware, non-exportable | Partially — root can *ask* the TPM to sign, but cannot extract the key | TPM provisioning, PCR policy, no key mobility |
| **TEE / enclave** | enclave-sealed | Yes, if quote verification is real | vendor dependency, attestation service, the exact thing `evaluate_hardware_trust` only pretends to do |
| **Hardware-backed local key** (e.g. sealed keyring) | on-host, protected | No against root | cheap, weakest |
| **Software key on the observed host** | on-host, plaintext | **No** | **fails I10 — not acceptable as the sole anchor** |

**Recommendation for the first slice:** *remote collector*. It is the only
option that satisfies **I10** without hardware provisioning, and it degrades
honestly — a partition produces `OBSERVATION_UNAVAILABLE`, which the
reconciliation model already handles, rather than silent forgery.

## 4. Threat model to document before selecting

Required by §14; recorded here as open, not answered:

- **THREAT** — root on the observed host; agent with the ability to spawn, kill and inspect processes; attacker with filesystem write access; attacker able to manipulate the host clock.
- **ASSUMPTIONS** — what is the observer's TCB? Does the design assume the kernel is intact? Does it assume the agent is unprivileged?
- **MECHANISM** — which anchor from §3, and where the key physically lives.
- **KEY LIFECYCLE** — generation, provisioning, rotation, revocation, expiry.
- **RECOVERY** — behaviour after observer restart, host reboot, key loss.
- **FAILURE MODE** — must be `OBSERVATION_UNAVAILABLE`, never a silent pass.
- **ATTACK SURFACE** — the signer becomes a new target; what does compromising it buy?

`NOT DETERMINABLE FROM CURRENT CODEBASE` — none of these questions has an
implementation to appeal to. They are product decisions.

## 5. Sensor self-integrity and continuity states

An observer that can be silently stopped is not an observer. The design must
represent its own health as a first-class, signed value:

| State | Meaning | Reconciliation consequence |
|---|---|---|
| `ACTIVE` | attesting, continuity verified across the window | observations usable at `Attested` strength |
| `DEGRADED` | running, known gap or dropped events | window-scoped `OBSERVATION_UNAVAILABLE` |
| `RECOVERING` | restarted, replaying, continuity not yet re-established | `OBSERVATION_UNAVAILABLE` |
| `CONTINUITY_UNVERIFIED` | resumed with no verifiable link to prior state (amnesia) | `OBSERVATION_UNAVAILABLE` + a sealed continuity finding |
| `QUARANTINED` | integrity failure proven arithmetically | `SENSOR_INTEGRITY_FAILURE` at `Proven` strength |

Per **I9**, degradation must be *represented*, not inferred and not hidden.
Per the skill's §15, degraded observation must **never** be auto-classified as
malicious execution — a sensor outage is not a ghost.

Attacks the design must survive: disabling or killing the observer, modifying
its binary or configuration, erasing its state, reordering events, clock
manipulation, buffer exhaustion, telemetry loss, host reboot, and restoration
of a stale state file. The last three are why continuity must be anchored
off-host or in hardware; a state file the attacker can roll back proves
nothing about itself.

## 6. Interface sketch (not implemented)

```rust
trait ObserverAttestor {
    /// Signs an observation batch. The key MUST NOT be reachable by the
    /// observed agent (I10).
    fn attest(&self, batch: &ObservationBatch) -> Result<Signature, AttestError>;
    /// Current, signed health. Absence of a recent health attestation is
    /// itself evidence — silence must degrade coverage, not extend it.
    fn health(&self) -> SignedSensorHealth;
}
```

Note the existing AIP seam: `aip-crypto::sign_ed25519_raw` /
`verify_ed25519_raw` (`aip-standalone/aip-crypto/src/lib.rs:102,115`) are
already used for detached signatures over arbitrary bytes in `bundle.rs:161`,
and are a suitable primitive here. A *primitive* is not a protocol (**I15**) —
domain separation must be added, since no signed payload in AIP currently
carries a type tag.
