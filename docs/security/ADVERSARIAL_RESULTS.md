# Ghost adversarial results

> A detection is real when an attack against it has been executed and recorded
> as failing. Until then it is a design intention, and it is described as one.
> — `.claude/skills/ghost-adversarial-tester`

This is the standing record of attacks run against the Sniffer Dog observation
and reconciliation stack, one row per attack: the claim it targets, the
attacker model, the exact commands, the raw classification emitted, the result
label, and the claim revised to what the evidence supports.

Result vocabulary (from the skill): `DETECTED` (attack performed, correct
classification emitted); `MISSED` (performed, nothing or the wrong
classification); `DEGRADED` (performed, correctly emitted `CANNOT_PROVE` — no
false accusation and no detection); `NOT_RUN`; `DEFERRED` (blocked on a
component that does not exist yet — the component is named).

Attacker models: **A1** confused agent; **A2** adversarial agent, unprivileged;
**A3** adversarial agent, root on host; **A4** compromised observer. The
tracepoint-gate attacks below require `CAP_BPF` — model **A2+/A3**: an
unprivileged agent that has been granted `CAP_BPF`, or any root process on the
host.

Host for every run below: Linux 6.18.44 (virtual). Signing keys are held by the
demo collector in-process; the off-host key-custody boundary (defeating **A3**
tampering after collection) is a deployment property, **not** exercised here.

---

## OI — Observation-integrity: foreign eBPF tracepoint gate

**Threat.** A foreign eBPF program returning `0`, attached to a tracepoint the
observer samples through `perf_event_open`, suppresses that tracepoint's perf
submission host-wide — for every consumer of the tracepoint — with **no
`PERF_RECORD_LOST` accounting and no continuity break**. The observer is live,
its chain is intact, and it is blind. Minimal cause, isolated to two BPF
instructions, in `validation/observation_integrity/tracepoint_interferer.c`.

**Claim targeted (external form).** *"An independent observer records what
executed; when it was not watching it says so, and its silence is never read as
non-occurrence."*

The attack is against the **"it says so"** half. Absence being read as
non-occurrence is separately prevented by the reconciler's `CANNOT_PROVE`
default and the `EvidenceCeiling`; those are not what these rows test.

| id | attacker | gate on tracepoint | pipeline | classification emitted | result |
|----|----------|--------------------|----------|------------------------|--------|
| OI-01 | A2+/A3 | `sched:sched_process_exec` | exp01 recorder (single sensor) | pre-fix `12767ea`: observer `integrity_unknown`; 0/8 execs, 0 loss | **DETECTED** |
| OI-02 | A2+/A3 | `sock:inet_sock_set_state` | ghost-demo live (agent + `CollectorSigner` + reconciler), T-P connect | pre-fix: observer stayed `Active`, silent fallback to polled `Presence`, **no integrity signal** | **MISSED** |
| OI-03 | A2+/A3 | `sock:sock_send_length` | ghost-demo live, S-P send | pre-fix: `CannotProve` / `WindowNotCovered` — safe, but by the coverage predicate, **not** an observer-reported integrity failure | **MISSED** (safe, dishonest) |
| OI-04 | A2+/A3 | `sock:inet_sock_set_state` | ghost-demo live, T-P connect | post-fix: observer `IntegrityUnknown` → reconciler `CannotProve(ObserverIntegrityUnknown)`, `Unavailable { ObserverIntegrityUnknown }` | **DETECTED** |
| OI-05 | A2+/A3 | `sock:sock_send_length` | ghost-demo live, S-P send | post-fix: observer `IntegrityUnknown` → `CannotProve(ObserverIntegrityUnknown)` | **DETECTED** |
| OI-06 | — (control) | none | ghost-demo live, T-P connect | post-fix: `VerifiedExecution` (Attested) | **no false positive** |
| OI-07 | A4 (key holder) | n/a | synthetic `CollectorSigner` | a forger holding the collector key can relabel `IntegrityUnknown`→`Active` (valid signature over the lie) but **cannot mint the gate-independent coverage** it never had | key custody is the separate boundary; see note |
| OI-08 | A3 (root/kernel) | patched kernel hides the program from `PERF_EVENT_IOC_QUERY_BPF` | — | detection queries shared kernel state a root attacker can defeat | **DEFERRED** — off-host/hardware observer (options D/E/F, decision record) |

### Commands (verbatim)

OI-01 (single-sensor mechanism proof, both arms):

```
RUN_ID=20260917T_sched_repro DURATION_MS=6000 NEXECS=8 \
  ./validation/observation_integrity/reproduce_interference.sh
```

OI-02..OI-06 (the real pipeline, one gate held per arm):

```
# pre-fix arms captured on tree 50dca61 (aip-observe unchanged):
RUN_ID=20260917T_sock_gate_prefix \
  validation/observation_integrity/pipeline_under_gate.sh tp_gated sock/inet_sock_set_state live_transition t_p_
RUN_ID=20260917T_sock_gate_prefix \
  validation/observation_integrity/pipeline_under_gate.sh sp_gated sock/sock_send_length live_send s_p_

# post-fix arms captured with the sock detector + per-mechanism collector:
RUN_ID=20260917T_sock_gate_postfix \
  validation/observation_integrity/pipeline_under_gate.sh tp_gated sock/inet_sock_set_state live_transition t_p_
RUN_ID=20260917T_sock_gate_postfix \
  validation/observation_integrity/pipeline_under_gate.sh sp_gated sock/sock_send_length live_send s_p_
RUN_ID=20260917T_sock_gate_postfix \
  validation/observation_integrity/pipeline_under_gate.sh tp_control none live_transition t_p_
```

### Raw output (post-fix, OI-04, the reconciler's own `{r:?}`)

```
Reconciliation { version: 5, result: CannotProve, strength: Heuristic,
  reason: ObserverIntegrityUnknown, ...,
  availability: Unavailable { reason: ObserverIntegrityUnknown },
  identity: Match { observations: 3 }, action: Unobservable,
  temporal: WithinWindow, ..., provenance: Engine }
```

Sealed artifacts (per-arm `*_summary.json`, `*_pipeline.log`,
`*_environment.txt`, `*_interferer.log`, `verdict.json`, `SHA256SUMS`):

- `validation/observation_integrity/results/20260917T_sched_repro/`
- `validation/observation_integrity/results/20260917T_sock_gate_prefix/`
- `validation/observation_integrity/results/20260917T_sock_gate_postfix/`

### Revised claim (what the evidence now supports)

*Sniffer Dog samples three perf tracepoints — `sched:sched_process_{fork,exec}`,
`sock:inet_sock_set_state`, `sock:sock_send_length`. For **each**, a live check
(`PERF_EVENT_IOC_QUERY_BPF`) enumerates foreign eBPF programs on the shared
per-tracepoint gate; a found gate, or a refused query, makes the collector sign
`ObserverState::IntegrityUnknown` for that mechanism instead of a false
`Active`. The reconciler maps that to `CANNOT_PROVE(ObserverIntegrityUnknown)`.
This is demonstrated against a real no-op BPF gate on each tracepoint, through
the real reconciliation engine.*

Bounds that must travel with the claim:

- **A3 defeats it.** Detection reads shared kernel state a root or
  kernel-module attacker can hide (OI-08). The guarantee is against a
  `CAP_BPF` adversary, not root. The only vantage independent of a host-kernel
  compromise is an off-host or hardware-rooted observer — decision record
  options D/E/F, not built.
- **A4 (key holder) is a different boundary.** A forger with the collector key
  signs any state (OI-07); the defence that does not rest on the signer's
  honesty is that the blinded health carries no gate-independent coverage to
  stand on. Off-host key custody is a deployment property, unbuilt.
- **Global, not per-action.** One non-capable perf mechanism drives the whole
  observer to `IntegrityUnknown`, even for an action a gate-independent source
  (netlink connector, fanotify, AF_PACKET) still covers. This is the
  conservative choice; a per-mechanism availability refinement is future work.
- **TOCTOU between checks.** The check runs each drain; a gate applied and
  removed entirely between two drains is not seen. A liveness canary would
  narrow this and is **DEFERRED** (decision record option C), with its own
  documented false-assurance trap against a targeted gate.

---

## RA — Reconciliation attestation (SD-09)

**Claim targeted.** *"A committed reconciliation verdict is attributable to the
reconciler that produced it, and cannot be forged or altered without detection."*

The verdict is signed by a fourth authority (`aip_reconcile::ReconcilerSigner`)
and verified offline against anchors the verifier supplies. These attacks are
executed as tests in `aip-reconcile/src/attest.rs` (synthetic verdict) and
`ghost-demo/tests/signed_verdict.rs` (real-engine verdict).

| id | attacker | attack | result |
|----|----------|--------|--------|
| RA-01 | forger, no key | mutate a signed verdict's `result`/`reason` | **DETECTED** — `PayloadHashMismatch` (synthetic + real-engine) |
| RA-02 | forger, no key | swap `reconciler_id` on a signed verdict | **DETECTED** — `UntrustedReconciler` (and signer-id bind) |
| RA-03 | forger, no key | claim a different `key_version` | **DETECTED** — `UntrustedReconciler` |
| RA-04 | A-key holder ≠ reconciler | re-sign under a key not in the anchor set | **DETECTED** — `SignatureInvalid` |
| RA-05 | forger | present a signature over the verdict's *own* canonical bytes as an attestation (domain confusion) | **DETECTED** — `PayloadHashMismatch`; the attestation domain wrapper is load-bearing |
| RA-06 | forger | downgrade the envelope version | **DETECTED** — `UnsupportedVersion` |

**Revised claim (what the evidence supports).** *A reconciler's verdict can be
signed and verified offline against caller-supplied anchors; mutation, identity
or key-version swaps, foreign-key re-signing, domain confusion, and version
downgrade are each refused. The signature attributes the verdict and never
strengthens it.* Bound, stated: attribution is only as trustworthy as the
reconciler key's custody (wrapped-file today; HSM is future), and **nothing
commits the signed verdict to NEXORA automatically yet — SD-10**.

---

## Backlog (declared, not silently omitted)

Each is `NOT_RUN` or `DEFERRED` with the blocking component named. An omitted
attack reads as a passed attack six months later.

| id | attack | status | blocked on |
|----|--------|--------|------------|
| RB-01 | ring-buffer exhaustion vs. reported loss | NOT_RUN | — (runnable; loss accounting exists) |
| PID-01 | PID reuse across the network sensor | NOT_RUN | per-sensor run (process sensor covered by `adversarial.rs`) |
| CLK-01 | host clock manipulation vs. temporal correlation | NOT_RUN | — |
| KO-01 | kernel-module hiding of the gating program (OI-08) | DEFERRED | off-host / hardware-rooted observer |
| NS-01 | namespace / container-boundary evasion | DEFERRED | container deployment target |
| KEY-01 | observer key compromise weaponised as DoS against an agent | partly (OI-07) | off-host key custody + containment path |
