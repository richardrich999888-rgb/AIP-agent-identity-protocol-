# TARGET_ARCHITECTURE

The smallest coherent architecture that satisfies `SECURITY_INVARIANTS.md`,
expressed as a delta from what `CURRENT_SYSTEM.md` proves exists.

## 1. The one-sentence problem

AIP can prove *an authorized key-holder claimed it did X*. It cannot prove
*X happened*, and — because `/v1/evidence/generate` seals whatever it is told
using a private key supplied in the request body — it cannot currently prove
that anyone other than the agent decided X was permissible.

Ghost exists to break the closed loop in which the agent is producer, signer
and (via caller-supplied trust anchors) effectively the verifier of its own
evidence.

## 2. Target boundary set

```
       ┌──────────────────────────────────────────────┐
       │ PRINCIPAL / ISSUER          (human authority)│
       └───────────────┬──────────────────────────────┘
                       │ signs ScopedToken  (expires_at MUST be covered)
       ┌───────────────▼──────────────────────────────┐
       │ DECISION POINT              ** NEW, P0 **    │
       │ adjudicates: chain valid? scope permits?     │
       │ emits ExpectedExecution, signs with ITS key  │
       └───────────────┬──────────────────────────────┘
                       │ ExpectedExecution(decision_id, binding, valid_until)
       ┌───────────────▼──────────────────────────────┐
       │ AGENT (untrusted)                            │
       │ executes; emits EvidencePacket as today      │
       └───────────────┬──────────────────────────────┘
                       │                     ┌────────────────────────┐
                       │                     │ OBSERVER  ** NEW **    │
                       │                     │ independent trust root │
                       │                     │ emits ObservedExecution│
                       │                     └───────────┬────────────┘
       ┌───────────────▼─────────────────────────────────▼────────────┐
       │ RECONCILER                  ** NEW **                        │
       │ join on decision_id + ExecutionBinding → result + strength   │
       └───────────────┬──────────────────────────────────────────────┘
                       │
       ┌───────────────▼──────────────────────────────┐
       │ WARRANT ENGINE              ** NEW **        │
       │ severity ⊥ strength; containment needs Proven│
       └───────────────┬──────────────────────────────┘
                       │
       ┌───────────────▼──────────────────────────────┐
       │ NEXORA — portable commitment over history    │
       └──────────────────────────────────────────────┘
```

## 3. What is reused unchanged

Per the skill's §5 instruction to find extension points before redesigning:

| Asset | Location | Why it survives |
|---|---|---|
| `verify_packet` + 14 rules | `aip-protocol/src/verification.rs:92` | pure, offline, deterministic, no short-circuit, derived floor. Correct as-is |
| Packet canonical encoder | `aip-protocol/src/canonical.rs` | injective, length-prefixed. The template for all new signed types |
| `derive_aip_id` | `aip-crypto/src/lib.rs:49` | single implementation, spec-exact |
| `decision_id` binding | `evidence_packet.rs:117-126`, `verification.rs:531` | already the correct reconciliation join key |
| External-anchor verifier design | `aip-verify/src/main.rs:77-78` | the correct trust boundary; the service endpoint is the deviation |
| Adversarial test pattern | `aip-protocol/tests/evidence_packet.rs:163-173` | `assert_rule_failed` pins named rules; reuse for Ghost rules |

## 4. What changes in AIP itself

Minimum set — nothing here is Ghost-specific; all of it is AIP correctness that
Ghost would otherwise inherit as a weakness (**skill §6**: Ghost must never be
used to conceal an AIP authority weakness).

| Change | File | Why it cannot wait |
|---|---|---|
| Cover `expires_at` in both signing payloads | `aip-core/src/capability.rs:208`, `delegation.rs:369` | otherwise every `ExpectedExecution.valid_until` sits on top of a forgeable window |
| Adopt the length-prefixed encoder in `aip-core` | same files + `aip-core/src/lib.rs:119-161` | **I14**; new signed types must not inherit a non-injective pattern |
| Add domain-separation tags | `aip-crypto/src/lib.rs:151-162` | `ExpectedExecution` and `ObservedExecution` must not be confusable with packets or tokens |
| Add `ExecutionBinding` to `EvidencePacket` | `aip-protocol/src/evidence_packet.rs:210-334` | the join key must be inside signed evidence |
| Optional `ctx.verification_time` | `aip-protocol/src/verification.rs:28-42` | absolute expiry is currently unenforceable |

All are one wire break. Bump `PACKET_VERSION` **once**.

## 5. What is deliberately *not* in the first target

| Deferred | Reason |
|---|---|
| eBPF / XDP kernel sensor | needs a trust root and a binding first; building it now yields telemetry nobody can attribute |
| Containment / actuation | requires a warrant, which requires evidence strength, which requires an attested observer |
| PQC | reserved algorithm byte; no security benefit until the above holds |
| Real Merkle commitment layer | NEXORA boundary; premature until there is a history worth committing to |
| The unmerged `aegis-quantum` XDP work | 29 commits ahead / 22 behind, absent from HEAD; it observes inbound packets keyed on a bare 4-tuple with no process identity — it cannot attribute, so it cannot feed reconciliation as written |

## 6. Architectural rules carried forward

1. The decision point must not be the agent, and must not be a library the
   agent links (**I1**).
2. The observer signs what it saw, never what is permitted (**I19**).
3. Observation absence is never execution absence (**I8**).
4. Severity and evidence strength stay orthogonal (**I12**).
5. Ghost must not re-implement AIP identity or authorization (**I18**) — the
   `aip-service` duplication is the cautionary example already in-tree.
