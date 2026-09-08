# Edge Trust Roots, Key Custody, Transport Authenticity and Recovery

**Skill 29, R3.** Written at `cc70add`.

Companion to `docs/audit/THREAT_MODEL_MATRIX.{json,csv}`, which says what each
layer does about each threat. This document says what the deployment must do
for those answers to hold. **Every obligation here is a deployment obligation:
the code cannot enforce any of them, and saying so is the point.**

---

## 1. Trust roots

Four, and they are separate on purpose. Collapsing any two removes the
independence that makes the fourth column of the threat matrix mean anything.

| root | holds | who must hold it | what collapsing it costs |
|---|---|---|---|
| **Issuer** | the key that signs `ScopedToken` | the authorising principal | authority becomes self-granted |
| **Decision point** | the key that signs `ExpectedExecution` | a party that is not the agent | the agent authorises itself; the reconciler refuses this when it can see both keys (`ExpectedVerifyError::DecisionKeyIsAgentKey`) |
| **Observer / collector** | the key that signs batches and health | a party that is not the observed host | the actor writes the evidence used to judge it; the reconciler refuses when it can see both (`ReasonCode::ObserverKeyIsAgentKey`) |
| **NEXORA** | the key that signs commitment heads | the party operating the log | a bundle could vouch for itself — though `SignedHead` has no key field, so this one is unrepresentable rather than merely refused (B-4) |

Two of these four collapses are **detectable by the code** and two are not.
The verifier can only compare keys it has been given: `agent_public_key` is
optional in `ReconciliationContext`, and a verifier that does not supply it
gets no independence check. `Independence::NotChecked` is reported rather than
assumed, which is the honest half; supplying the key is the deployment's job.

## 2. Key custody

| key | generation | at rest | rotation |
|---|---|---|---|
| agent | `generate_ed25519_keypair`, client-side | the agent's own custody; never in a request body by default (B-7) | a new key is a new AIP-ID: identity is derived from the key |
| decision point | operator-provisioned | service custody, mode set at creation not by later `chmod` (B-5) | anchors are `(id → key)`; rotation means re-provisioning verifiers |
| collector | operator-provisioned, off the observed host | collector custody | anchors are `(observer_id, key_version)`; a retired version stops verifying, which is the point of the version being in the anchor |
| NEXORA | operator-provisioned | log operator's custody | `(signer_id, key_version)` pairs, same rule |

**What the code enforces.** Failure to load a key does not mint a new identity
(B-6). The seed file's mode comes from `OpenOptions::mode`, so there is no
window in which it exists world-readable (B-5). Managed signing — the service
holding an agent's key — is off unless a deployment sets
`AIP_ALLOW_MANAGED_SIGNING=1`, and the route is chosen at router-build time, so
on the default path there is no extractor and a seed sent to it is never
deserialised (B-7).

**What it does not.** Nothing here protects a key from the host that holds it.
A rooted host holds every key on it, which is why every observation class
resting on host-measured content is capped at `Attested` rather than `Proven`.

## 3. Transport authenticity

**The protocol does not depend on transport.** Every artifact a verifier
consumes carries its own signature and is verified against anchors the verifier
provisioned, so a hostile transport can withhold, reorder or replay — it cannot
forge.

What transport is still responsible for:

- **Withholding.** A truncated chain is a valid prefix of a valid chain
  (N-7). The observer layer detects it against the signed health record's head;
  transport cannot be relied on to deliver everything.
- **Confidentiality.** Signatures are not encryption. Evidence content is
  visible to anything on the path.
- **Availability.** Losing the link is modelled (X08) and answered by
  uncertainty, not by a failure.

TLS is a deployment requirement for confidentiality and for the managed-signing
endpoint if it is enabled. It is **not** part of any integrity argument, and no
threat in the matrix is answered by "TLS".

## 4. Recovery obligations

| event | what the system does | what the operator must do |
|---|---|---|
| collector restart | continuity is `Unverified` until the next contiguous batch; a restart never re-establishes a link | nothing — the conservative answer is automatic |
| collector state loss | the ledger lives at the collector, off the observed host, so a wiped host cannot re-assert a position; the archive head is adopted and the gap reported | investigate the gap; it will not close itself |
| proven fork | the observer is quarantined permanently and cannot be un-quarantined by later well-formed traffic | replace the collector and re-provision its key; a fork is an integrity failure of the record, not a transient |
| key compromise | nothing automatic | withdraw the anchor. Evidence signed under it stops verifying, including evidence that was true — this is the intended cost |
| agent key loss | a new key is a new identity | re-issue authority to the new AIP-ID; there is no identity recovery, by design |

## 5. What none of this establishes

- No post-quantum property (N-10). No PQC exists on this branch.
- No protection of a key from the host that holds it.
- No physical observation. Sensor deception (X10) is answered by uncertainty at
  every layer and by no defence anywhere, because no implemented mechanism
  observes a physical quantity.
