---
name: execution-binding-engineer
description: Own the contract that ties an AIP agent identity to a concrete execution on a machine — ExecutionBinding, ObserverAttestation, the physical identity tuple, executable measurement, observation states, and the attestation signing key's custody. Use whenever the user mentions execution binding, observer attestation, runtime identity, workload identity, PID reuse, process start time, cgroup or namespace binding, executable measurement, exe_hash, TrustFloor::ExecutionObserved, sensor keys, TPM or TEE attestation, or a synthetic observer — and also when they describe the intent, such as binding an agent to a process, proving which binary ran, or letting something other than the agent sign for what happened. Consult this before writing any observer, sensor, or reconciliation code, because a binding designed loosely here makes every downstream Ghost detection unfalsifiable.
---

# Execution Binding

AIP establishes who an agent is and what it may do. It establishes nothing about what ran
on a machine. This skill owns the layer between those two facts: the structures and rules
by which a physical execution is tied to a cryptographic identity, and by which a party
other than the agent can commit to having seen it.

Everything here is new construction. No symbol in this skill is asserted to exist in the
repository today — the audit found `RuntimeBinding` (`runtime.rs:11,38,78`) is self-reported
and unsigned, and `exe_hash` hashes the executable's *path string* rather than the binary.
That is a field shaped like a measurement that measures nothing, and it is the specific
mistake this skill exists to prevent repeating at a larger scale.

## Read before building

| Task | Read |
|---|---|
| The physical identity tuple, PID reuse, binding lifecycle, executable measurement | `identity-binding.md` |
| Who signs an attestation, where that key lives, what it commits to | `attestation-keys.md` |

## The one property that makes this layer worth building

> The observed agent must not possess, derive, or control the cryptographic signing
> authority used to attest its own observations.

If that fails, the whole layer collapses into a more elaborate way for the agent to report
on itself, which is what AIP already has. Every design decision here is subordinate to it.
When a shortcut would breach it, the shortcut is wrong regardless of what it buys.

Corollary worth stating explicitly, because it is the failure mode teams reach for under
deadline: an observer running as the same user, on the same host, with its key on the same
filesystem, is not independent. It is a second process the agent can read from. Reaching
this property needs a key the agent cannot read — TPM, TEE, or a remote signer — and until
one exists, attestations produced by the layer are labelled as such rather than presented
as observation. See `attestation-keys.md`.

## Three structures

Define these as the stable contract. Downstream reconciliation and warrant code depends on
their shape, so changes to them are protocol changes and go through
`aip-protocol-change-guard`.

**`ExecutionBinding`** — carried on the packet as an optional field at the wire break.
Opaque `execution_id: [u8;16]` minted *before* the action, plus `Vec<ObserverAttestation>`.
Minting before is what makes it usable as a correlation key; an id assigned afterwards can
only ever describe what already happened.

**`ObserverAttestation`** — a signature by an observer over `(execution_id, packet_hash,
observed facts, observation time)`. Signed by an observer key, verified against
`observer_public_keys` on the verification context.

**`PhysicalIdentity`** — the tuple that names a running process. Never a bare PID. See
`identity-binding.md` for the full tuple and the reuse argument.

## Observation is three-valued

`OBSERVED` / `NOT_OBSERVED` / `OBSERVATION_UNAVAILABLE`.

The two-valued version conflates "did not happen" with "we did not see it," and every
practical cause of the second — ring-buffer overflow, sensor restart, container churn,
sampling gap, degraded continuity — then presents as evidence of wrongdoing. A system that
cannot say `OBSERVATION_UNAVAILABLE` produces false accusations at a rate that gets it
switched off in its first production week.

`OBSERVATION_UNAVAILABLE` is a first-class result carrying the continuity state that
produced it, not an error and not a null. Reconciliation consumes it directly; see
`ghost-reconciliation-engineer`.

## Build the synthetic observer first

Define the `Observer` trait and implement it synthetically before any kernel work. A
deterministic in-process observer that emits scripted observations lets the binding,
reconciliation, and warrant layers be built and tested end to end while the kernel layer
does not exist.

This is not a scaffold to be thrown away. It is the permanent test harness: adversarial
cases like forged observations, replayed attestations, and clock manipulation are far
easier to drive through a synthetic observer than through eBPF, and they need to keep
running after the real sensor lands.

The trait must not leak kernel concepts. If `Observer` mentions a ring buffer, a BPF map,
or a perf event, the abstraction has already failed and the eventual kernel implementation
will dictate the interface rather than satisfy it.

## Bind the action before it executes, not after

The audit and the encrypted-payload problem force this. An out-of-band observer cannot read
a transfer amount inside TLS, so parameter-level divergence cannot be detected by
inspecting traffic without becoming the proxy the architecture rejects.

The workable shape commits first:

```
agent requests action
  -> canonicalize the action           (prefix-free, per aip-protocol-change-guard)
  -> action_digest = SHA-256(canonical bytes)
  -> execution_id minted
  -> authorization signed over (execution_id, action_digest, scope, now_ms)
  -> execution
  -> observer attests (execution_id, packet_hash, physical identity, observation time)
```

The claim this supports is narrower and true: whether an execution event corresponds to a
signed authorization, and whether the process that performed it is the one the authority
was issued to. It does not support claiming the payload matched without a cooperating
agent. State that limitation in the design document rather than letting it be discovered
by a customer.

## Rules

- Never bind on PID alone, and never on a 4-tuple alone. `identity-binding.md` gives the
  minimum tuple.
- A binding has a lifetime and an expiry. An unbounded binding is an unbounded authority by
  another name — the same defect as AIP-C-01.
- Measure the binary, not the path. A path-string hash is not a measurement; say so in the
  field name so nobody mistakes it later.
- Absence of an attestation is `OBSERVATION_UNAVAILABLE` unless continuity proves the
  observer was healthy across the interval. Continuity is what converts absence into
  evidence.
- `TrustFloor::ExecutionObserved = 4` is reached only when an attestation verifies against
  a key the agent cannot reach. An attestation signed by a key on the agent's own host,
  readable by the agent, does not raise the floor. Encode that check; do not leave it as a
  deployment convention.
