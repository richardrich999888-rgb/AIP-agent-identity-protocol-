# Attestation Keys

The hardest unsolved problem in the design, and the one most often skipped because the
field `sensor_attestation` looks complete once it exists in a schema.

## The requirement

> The observed agent must not possess, derive, or control the cryptographic signing
> authority used to attest its own observations.

Test any proposed deployment against a single question: **can the agent process read the
signing key?** If yes, the attestation proves nothing beyond what the agent chose to
attest, and every claim built on it is a claim the agent could have manufactured.

## Custody options, ranked

| Option | Agent can reach key? | Notes |
|---|---|---|
| Remote signer — observer ships facts to an off-host service that signs | No | Simplest to reach correctly. Cost is availability and latency; the network is now in the attestation path. |
| TPM-resident key, sealed to a PCR state | No, if sealing is correct | Requires the agent to lack `/dev/tpm` access and lack the ability to satisfy the PCR policy. Verify both. |
| TEE-resident key with measured launch | No | Strongest and most operationally expensive. |
| Observer process, separate uid, key at mode 0600 | **Yes, if agent has root** | Adequate only where the agent is confidently non-root and confidently cannot escape its namespace. State that assumption or do not use this. |
| Observer process, same uid as agent | **Yes** | Not independent. Do not deploy and do not raise the trust floor on it. |

Root on the host defeats every host-local option. Agents that spawn subprocesses, run
package installs, or execute model-authored code should be assumed to be reaching for root
eventually, which pushes the realistic choice toward remote signing or a TEE.

## What the attestation commits to

Signing over too little is the common error — a signature over observed facts alone can be
lifted and replayed as a statement about a different execution.

Commit to at minimum:

| Element | Why |
|---|---|
| `execution_id` | Ties the statement to one execution. Chosen by the authorization layer before the action, not by the agent. |
| `packet_hash` | Ties it to the specific authorization record. |
| observed physical identity tuple | The substance. |
| observation time, from the observer's clock | Not the agent's clock, and not a timestamp the agent supplied. |
| observer identity and key id | So verification can locate the key and rotation is possible. |
| sequence number in the observer's chain | Makes gaps and reordering detectable. |

The observer's clock matters independently. The audit's AIP-C-02 exists because every
timestamp in AIP is agent-supplied and the verifier reads no clock. Reproducing that on the
observation side would waste the layer: an attestation timestamped by the observed party
tells you nothing about when observation occurred.

## Rotation, from the start

The service layer's current key handling shows the cost of deferring this: one seed for two
purposes, no `kid` in JWKS, no selection at verify, and a load failure that silently
regenerates and invalidates everything (`keys.rs:350,:399`).

For observer keys:

- publish a key id with every attestation and select on it at verify
- support an overlap window so rotation does not invalidate in-flight attestations
- a key load failure is a startup error, never a regeneration — a regenerated observer key
  silently breaks continuity, which is the exact property the observer exists to provide

## Verification path

`observer_public_keys` on the verification context, alongside `issuer_public_keys`. Same
TOFU model as the rest of AIP (`AIP_SPEC.md §8`), and the same caveat applies: the
verifier's answer is worth exactly the caller's key list. Do not let the observer's key
arrive in the same request as the attestation it verifies — that is the anti-pattern the
audit found at `bundle.rs:437` (bundle signature key read from the object under
verification) and at `evidence.rs:307-310`.

## Degradation, stated honestly

Not every deployment will have a TPM or a remote signer. The layer should still run there,
but it must not claim what it cannot support.

Encode custody strength in the attestation and make the trust floor derive from it:

```
custody = Hardware | RemoteSigner | HostLocalSeparateUid | HostLocalSameUid

ExecutionObserved (floor 4)  requires Hardware or RemoteSigner
                             HostLocalSeparateUid caps below it
                             HostLocalSameUid contributes nothing
```

This mirrors the derivation the audit called the most intellectually honest piece of design
in the repository — trust derived from what the evidence supports rather than asserted.
Applying it here means a weak deployment produces weak claims automatically, instead of
producing strong claims that a reviewer has to know to discount.
