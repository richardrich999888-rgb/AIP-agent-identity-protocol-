# Platform and Hardware Binding — Trust-Boundary Map

**Status** ANALYSIS. Produced before any code was modified, per Skill 19's
required workflow.
**Question** What establishes that `SystemExecution` X executed on Platform P
/ Hardware H?

---

## 1. Every identifier, classified

Classification is by *what the system can actually establish about the value*,
not by what the field is named. Authority is never inferred from a field's
existence.

| Identifier | Where | Class | Why |
|---|---|---|---|
| `agent_id` (AIP-ID) | `aip-crypto`, derived | **DERIVED** | A function of a public key and a provenance triple. Recomputable by anyone holding both; carries no authority by itself |
| `ScopedToken`, `DelegationToken` | `aip-core` | **AUTHORITATIVE** | Signed by an issuer the verifier anchors. This is where authority lives |
| `decision_point_id` | `ExpectedExecution` | **AUTHORITATIVE** | Resolved against `DecisionPointTrustAnchors`, verifier-supplied |
| `ExpectedExecution` (whole) | `aip-authorize` | **AUTHORITATIVE** | DP-signed over a fixed preimage |
| `ExpectedExecution.execution_binding` | `aip-authorize` | **AUTHORITATIVE (as an authorization)** | The DP signs *which instance it authorized*. It is not a measurement — the DP did not look at the host |
| `ExecutionBinding` collected by the agent | `aip-types` | **UNTRUSTED** | Self-report. The type's own documentation says a verifier must never upgrade it into evidence that the execution occurred |
| `ProcessInstance{pid, start_ticks, boot_id}` — **as measured** | `aip-observe::ProcfsProbe` | **OBSERVATIONAL** | Read from `/proc` by the probe. Root-forgeable content, so capped at `Attested` (T8) |
| `boot_id` — **as measured** | `/proc/sys/kernel/random/boot_id` | **OBSERVATIONAL** | Kernel-generated per boot. Host-scoped: two machines, and two boots of one machine, differ |
| `exe_content_sha256` — as measured | `aip-observe` | **OBSERVATIONAL** | Hash of `/proc/<pid>/exe` contents |
| `AttestedBatch` | `aip-observe` | **ATTESTED** | Collector-signed off-host, chained. `(observer_id, key_version)` anchored by the verifier |
| `observer_id` | `aip-observe` | **ATTESTED** | Meaningful only through `ObserverTrustAnchors`; naming an observer grants nothing |
| `probe_id` | `aip-observe` | **UNTRUSTED** | Explicitly documented as not a trust anchor — the probe cannot sign |
| `AiriEvent` (all payloads) | `aip-airi` | **UNTRUSTED as to occurrence** | Agent-signed: establishes authorship and integrity, never occurrence |
| `ModelProvenance.accelerator`, `.model_digest` | `aip-airi` | **UNTRUSTED** | Self-reported, labelled as such in the type |
| `system_id`, `platform_id`, `hardware_id`, `mission_id` | `aip-system` (Skill 17) | **DESCRIPTIVE** | Unsigned descriptors. Bound to *nothing measured* |
| Those four, inside a DP-signed `ActionParameters` (Skill 18) | `aip-execution` | **AUTHORITATIVE (as an authorization)** | The DP signed the context it authorized. Still not a measurement |
| `ExecutionProfile` | `aip-execution` | **DESCRIPTIVE** unless bound | Integrity comes solely from the Skill 18 binding |
| `NexoraProof` | `aip-nexora` | **ATTESTED** | Export/offline re-derivation |
| `Reconciliation` | `aip-reconcile` | **DERIVED** | Engine-produced, sealed by `Provenance` |

Two entries deserve emphasis because they are the crux of T13:

- **`ExpectedExecution.execution_binding` is AUTHORITATIVE as an
  *authorization*, not as a *measurement*.** The decision point signs which
  instance it permitted. It never looked at a host.
- **The measured `boot_id` is OBSERVATIONAL and host-scoped.** It is the only
  value in the entire system that distinguishes one machine-boot from another
  *and* is produced by something other than the subject.

---

## 2. The finding: T13's host-level case is already closed

This was established by experiment against the existing engine, before any
design work, and it changes the scope of this skill.

`ObservedProcess::matches_process_of` compares `self.process == binding.process`,
and `ProcessInstance` derives `PartialEq` over `{pid, pid_start_time_ticks,
boot_id}`. **`boot_id` is therefore already compared.**

Probe result, existing code, unmodified:

```
SAME HOST      → VerifiedExecution   / Attested / Match{1}
DIFFERENT HOST → IdentityDivergence  / Attested / Divergent{1}  reason=IdentityDiverged
```

The "different host" case differed *only* in `boot_id` — same pid, same start
ticks, same executable hash. The engine caught it.

So the T13 attack — *authorized on P, executed on Q* — already reaches a
correct disposition today:

| Situation | Disposition | Correct? |
|---|---|---|
| Observer covering Q measures the execution; binding names P's boot | `IdentityDivergence` | Yes — the instance measured is not the instance authorized |
| Only an observer covering P is anchored; execution ran on Q | no reference → `CannotProve` | Yes — nothing was observed, and nothing is claimed |
| No observer at all | `CannotProve` | Yes |

**Consequences for this skill:**

- **No reconciler change.** Part 15's precondition is not met — the existing
  inputs and semantics are sufficient for the host-level case.
- **No new verdict class.** `IdentityDivergence` already means exactly this.
- **No new trust anchor** for this case.
- What was missing was not a mechanism but **a test**. The property was
  undocumented and unexercised, which is indistinguishable from absent to
  anyone reading the audit.

---

## 3. What remains genuinely open

Closing the host-level case leaves three gaps, and they are different from
each other.

### G1 — `boot_id` identifies a *boot*, not a *machine*

A reboot produces a new `boot_id`, so a binding legitimately stops matching.
That is correct fail-closed behaviour, and it means the system has **no
durable hardware identity**. It cannot say "the same machine as yesterday",
and therefore cannot detect hardware *replacement* — only that the previous
binding no longer holds.

### G2 — Skill 17's `PlatformId` / `HardwareId` are connected to nothing

They are `DESCRIPTIVE`. Skill 18 made them `AUTHORITATIVE as an
authorization` by binding them into the DP signature — the decision point
signs that it authorized execution *for platform P7*. Nothing compares that
to anything measured, because nothing measured carries a platform name.

**The missing link is a mapping from the measured `boot_id` to the declared
`PlatformId` / `HardwareId`.**

### G3 — single-host deployments where the observer shares the compromised host

Host root forges procfs content (T8). `boot_id` is procfs content. On a
disconnected single-board system with no off-host collector, the measured
`boot_id` is exactly as forgeable as everything else, and the cap at
`Attested` is doing real work.

---

## 4. Mechanism comparison

Assessed against G2 — the one gap this skill can close — and G1/G3, which it
may not be able to.

| | **A** self-reported ids | **B** ExpectedExecution binding | **C** runtime binding (self-collected) | **D** observer evidence | **E** hardware-rooted attestation | **F** TPM | **G** HSM | **H** device-signed attestation | **I** observer + verifier deployment map |
|---|---|---|---|---|---|---|---|---|---|
| **Attacker capability** | full control | can request any context | full control | must compromise an anchored collector key | must extract a hardware key | must defeat the TPM | must defeat the HSM | must compromise the device key | must compromise the collector key *or* the verifier's own registry |
| **Proves** | nothing | what was *authorized* | nothing | which process instance ran, on which host-boot | the hardware identity is genuine | as E, with a per-machine root | as E, with a removable root | the device asserts an identity | the execution was observed on the host the verifier anchored to platform P |
| **Does not prove** | anything | that it ran there | anything | *which named platform* that host is; anything across reboots | that the software behaved; that an action occurred | same | same | that the device is where it says | durable hardware identity across reboots (G1) |
| **Trust anchor** | none | DP key (**exists**) | none | observer key (**exists**) | **NEW** hardware root | **NEW** | **NEW** | **NEW** | DP + observer keys (**both exist**) |
| **Operational cost** | none | none | none | collector deployment (**already required**) | provisioning, key management, supply chain | TPM per node + provisioning | HSM per site | device PKI | registry authoring only |
| **Offline** | yes | yes | yes | yes (collector may be local, signed off-host) | yes | yes | yes | yes | **yes** — the registry is portable data |
| **Linux** | yes | yes | yes | yes (procfs, pidfd) | varies | common | rare at edge | varies | yes |
| **UAS** | yes | yes | yes | yes | heavy for SWaP | often absent | no | possible | yes |
| **Robotics** | yes | yes | yes | yes | varies | sometimes | no | possible | yes |
| **Space** | yes | yes | yes | yes | rad-hard TPM is rare | mostly absent | no | possible | **yes** |

### Selection

**Mechanism I — anchored observer evidence plus a verifier-supplied deployment
registry — is the minimum architecture that closes G2.**

The reasoning is that the verifier *already* decides which observer keys it
trusts. Deciding "and the host that observer covers, at boot B, is platform P7
with hardware H-004" is a statement of the same kind, made by the same party,
carrying no new signer. It is portable data, so it works disconnected, and it
costs nothing beyond authoring it.

Every alternative that closes G1 (durable hardware identity across reboots)
requires a **new trust anchor**: E, F, G and H all do. That is a STOP
condition, so G1 is **not implemented in this skill** and is documented in
`ADR-002-HARDWARE-ATTESTATION.md` instead.

---

## 5. What mechanism I does and does not establish

Stated at the same volume as the benefit, because this is where an
accountability system is most tempted to overclaim.

**Establishes** — evidence class `Attested`, origin `IndependentlyObserved`:

> An anchored observer measured this execution on a host-boot that the
> verifier has registered as platform P, hardware H.

**Does not establish:**

- That the registry is correct. It is a verifier assertion, exactly like an
  anchored issuer key, and inherits that trust model rather than improving on
  it.
- That the host is physically platform P. Nothing here reads a serial number.
- Anything across a reboot (G1).
- That the hardware is genuine (G1, needs attestation).
- That the software on it behaved, or that any action occurred. **Hardware
  identity is not proof that a particular action occurred**, and no
  combination of the above changes that.

**Where binding cannot be established, the disposition is `NotEvaluated` or
`Unregistered` — never a pass.** Registration is not observation, and an
unregistered host is an unknown host, not a wrong one.

---

## 6. Trust-boundary diagram

```
  VERIFIER-SUPPLIED ANCHORS                     (outside every attacker below)
  ┌──────────────────────────────────────────────────────────────────┐
  │ DecisionPointTrustAnchors   ObserverTrustAnchors                 │
  │ trusted_issuers             PlatformRegistry  ← new, same kind   │
  └──────────────────────────────────────────────────────────────────┘
        │ anchors                    │ anchors           │ resolves
        ▼                            ▼                   ▼
  ┌───────────┐              ┌──────────────┐     boot_id → (platform, hardware)
  │ Decision  │  signs       │  Collector   │  signs
  │  Point    │──────────┐   │ (off-host)   │──────────┐
  └───────────┘          │   └──────────────┘          │
                         ▼          ▲                  ▼
              ExpectedExecution     │ measures    AttestedBatch
              (AUTHORITATIVE:       │             (ATTESTED)
               what was authorized) │                  │
                         │          │                  │ carries
                         │   ┌──────┴───────┐          ▼
                         │   │ ProcfsProbe  │    ObservedProcess
                         │   │ (UNTRUSTED — │    {pid, ticks, boot_id}
                         │   │  cannot sign)│    (OBSERVATIONAL)
                         │   └──────────────┘          │
  ═══════════════════════│═══════ HOST BOUNDARY ═══════│═══════════════
                         │   ┌──────────────┐          │
                         │   │  the agent   │ authors  │
                         │   │ (UNTRUSTED   │──────────┘ (self-reports:
                         │   │  as to       │             never compared
                         │   │  occurrence) │             as evidence)
                         │   └──────────────┘
                         ▼
                  ┌─────────────────────────────┐
                  │  the one reconciliation     │  compares AUTHORIZED
                  │  engine (unchanged)         │  with OBSERVED
                  └─────────────────────────────┘
                         │
                         ▼  IdentityDivergence when the measured instance
                            is not the authorized one — already, today
```

The agent is inside the host boundary and authors nothing that crosses it. The
registry sits with the verifier, outside every attacker in the threat model,
which is what makes it usable as a trust input without being a new signer.
