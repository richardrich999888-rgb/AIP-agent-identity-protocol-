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
| OI-09 | A2+/A3 | any perf tracepoint, **two-host split** | `aip-probe` → transport → `aip-collector` sink (`aip-collector/src/sink.rs`, synthetic batch) | probe's `ForeignTracepointGate` report inside the batch → collector `IntegrityUnknown`, signed health `attested_coverage: None` | **DETECTED** (previously **unreachable** in the daemon pair: the batch had no field for the finding) |
| OI-10 | A2 (probe omits the check) | any perf tracepoint, two-host split | `aip-collector` sink | batch declares a gate-able sensor active with **no** finding → sink notes `Unverifiable` → `IntegrityUnknown` | **DETECTED** (fail closed on silence) |
| OI-11 | A2 (probe clears a stale slot) | `sock:inet_sock_set_state`, two-host split | `aip-collector` sink | gate reported, then a `Verified` report for a sensor the batch no longer declares active | **DETECTED** — `Verified` counts only for an active mechanism; state stays `IntegrityUnknown` |
| OI-12 | — (control) | none | `aip-collector` sink | `Verified` for every open sensor / no tracepoint sensors at all | **no false positive** |

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

### OI live, two-daemon pair — the Phase 4 item, executed

Rows OI-01..OI-08 were run against the single-host demonstrator; OI-09..OI-12
cover the two-host path with **synthetic** batches. This block is the same
attack against the **two real daemons**: `aip-collector` and `aip-probe` as
separate processes, the probe holding no key, the link the authenticated and
confidential transport, and the evidence examined afterwards the collector's
own **signed health archive**.

Reproduce with `validation/pilot_e2e/run.sh`; raw output in
`validation/pilot_e2e/results/sealed/`. Host: Linux 6.18.44-fc-v37 (x86_64,
4 CPU), tracefs mounted, `sched:sched_process_exec` id 256. Probe sensors
open: `sched`, `sockstate`, `socksend`, `connector`.

| id | attacker | attack | signed result | outcome |
|----|----------|--------|---------------|---------|
| OI-13 | — (control) | none; real workload of execs and TCP connects | health #2: `Active`, `attested_coverage` present, sequence 12 | **no false positive** |
| OI-14 | A2+/A3 | foreign eBPF program returning 0 attached to `sched:sched_process_exec` while both daemons run | health #3: **`IntegrityUnknown`**, `attested_coverage` **withdrawn**, sequence 39 | **DETECTED** live, across the process and host boundary |
| OI-15 | — (control) | attack detached, workload continues | health #4: `Active`, coverage present, sequence 66 | **recovers**; the attacked window stays `IntegrityUnknown` in the archive |

**What makes OI-14 the load-bearing row.** The sequence number advances
throughout — 12, 39, 66 — so the observer was never down and the chain never
broke. This is not loss and not a continuity failure: it is a live,
continuous observer stating, in a record signed by a *different process
holding the only key*, that it cannot establish its own capability over that
window. Absence of an exec in that window therefore carries no information,
which is exactly what stops it from becoming a `PHANTOM_CLAIM` against an
innocent workload.

**One attach is enough.** The instrument reported
`INTERFERER_ATTACHED tracepoint_id=256 cpus=1`, with `EEXIST` on the other
three CPUs. That is the mechanism, not a partial failure: the BPF array is
keyed on the tracepoint (`trace_event_call`), so the first attach installs the
gate and every later attach to the same tracepoint is refused. A single
successful attach suppresses the sample for **every** perf consumer of that
tracepoint host-wide. The adversary needs one attach, not one per CPU per
victim.

**Bounds, unchanged.** The attack is *detected*, not *prevented* — a CAP_BPF
adversary can blind the sensor and this demonstration does not claim
otherwise. A full-root attacker can additionally hide the program from the
detection query (OI-08, still deferred). And this ran on a development
virtual machine: **the same run on a regulated entity's own hosts remains
outstanding**, and is what row C6 of the coverage matrix still tracks.

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
reconciler key's custody (wrapped-file today; HSM is future).

### CV — committed verdicts (SD-10)

**Claim targeted.** *"A third party holding only an inclusion proof, the signed
verdict and its own anchors can establish that this exact attributed verdict
was committed under an anchored NEXORA head."* Executed as tests in
`aip-nexora/tests/committed_verdict.rs` over real-engine verdicts.

| id | attacker | attack | result |
|----|----------|--------|--------|
| CV-01 | — (control) | commit a signed real verdict; verify offline | verifies; result/strength carried verbatim |
| CV-02 | forger | present a bare `Reconciliation` leaf (old kind) as an attributed verdict | **DETECTED** — `WrongLeafKind(Reconciliation)` |
| CV-03 | forger | offer a valid proof for verdict A with signed verdict B | **DETECTED** — `RecordMismatch` (bytes recomputed from the struct, not read from the proof) |
| CV-04 | forger, no anchored key | verdict from a reconciler the verifier does not anchor | **DETECTED** — `Attestation(UntrustedReconciler)`, refused before the log is consulted |
| CV-05 | forger | relabel a committed verdict's `result` after commit | **DETECTED** — `Attestation(PayloadHashMismatch)` |
| CV-06 | forger | proof under a NEXORA head the verifier does not anchor | **DETECTED** — `Commitment(..)` |
| CV-07 | — (property) | committed bytes vs. signing preimage vs. bare verdict bytes | all three distinct — domain separation is load-bearing |

**Revised claim.** *An attributed verdict can be committed and checked offline;
relabelling a bare leaf, binding a proof to a different verdict, an
unanchored reconciler or head, and post-commit tampering are each refused.*
Bounds: the log's truncation resistance still rests on an **external anchor
for heads** (a deployment property, unbuilt), and **nothing commits verdicts
automatically in a running pipeline** — SD-11/SD-12 remain.

---

### CS — decision-point coverage statements (expected-side completeness)

**Claim targeted.** *"An observed effect with no expectation can be named
`UNATTRIBUTED_EFFECT` only when the decision point itself signs, from its own
ledger, that no decision exists for that agent over the observed window — and
that statement cannot be forged, widened, or later falsified."* Executed live
(`ghost-demo/tests/live_coverage.rs`, `ghost-demo/tests/live.rs` B / B-U: a
real process, the real observer, the real reconciler, the decision point's
real ledger) and synthetically against the producer
(`aip-authorize/tests/coverage.rs`, P-01..P-14).

| id | attack
---

### CI — container identity: a blind observer cannot manufacture a divergence

**Claim targeted.** *"When the observer and the authorizing side disagree
about which container a workload ran in, that is a positive finding; when
one of them simply could not see, the system says so instead of accusing."*

The attack here is not against the kernel — it is against the **comparison**.
Before protocol 11 only the authorizing side recorded `ContainerIdentity`,
so a "different container" claim rested on one party's word. Adding the
observer's own reading (`ObservedProcess.container`, B3) creates a new way
to be wrong: an observer that cannot read `/proc/<pid>/ns/*` records
nothing, and if absence compared as inequality, **a degraded or hostile
observer could manufacture `DifferentContainer` out of its own blindness** —
an accusation with no fact behind it. These rows test the refusal.

Attacker models: **A2** unprivileged adversarial agent; **A4** compromised
observer (here, one that reports a partial or absent reading).

| id | attacker | attack | classification emitted | result |
|----|----------|--------|------------------------|--------|
| CI-01 | — (control) | both sides read the placement and agree | `ExecutionMatch::Same` | **no false positive** |
| CI-02 | A2 | two workloads genuinely in different namespaces (any one of pid/mnt/net differing) | `DifferentContainer` — a positive finding | **DETECTED** |
| CI-03 | A4 (blind observer) | exactly one side recorded a placement; absence offered as a difference | `ContainerNotComparable`, **never** `DifferentContainer` | **DETECTED** (refused) |
| CI-04 | A4 | neither side recorded a placement | `Same` — nothing to compare, no accusation | **no false positive** |
| CI-05 | A4 (partial read) | a half-read identity (some namespaces, not all) offered as a placement | unreachable: `aip-core` records the namespaces all-or-nothing, so a partial read is `None` | **DETECTED** (by construction) |
| CI-06 | A4 (privilege asymmetry) | a seeing observer and a blind one measuring **one** process, hoping the identity digests differ | identical `identity_digest` — the placement is deliberately excluded from `identity_bytes` | **DETECTED** (refused) |
| CI-07 | A2 | move a process between cgroups and offer it as a changed workload | `Same` — the cgroup id is context, not identity | **no false positive** |
| CI-08 | A4 | drop or edit the placement after the observer signed | inside the attested bytes (`ObservedProcess::encode`); changing it changes the canonical bytes | **DETECTED** |

*Reproduced by `aip-observe/tests/container_identity.rs` (10, including a
live reading of the host's own namespaces).* Bounds: this is a statement
about the **comparison**, not about the kernel. A root attacker on the
observed host can still lie to the observer about the namespaces it reads,
exactly as it can about every other `/proc` source here (N1); what these
rows establish is that an observer which cannot see is never able to turn
that into an accusation.
