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

## CL — Attested clock discipline (protocol 12)

**Claim targeted.** *"A verifier reading a sealed record can establish
whether the collector's wall clock was being steered when it signed, and by
how much the collector's own kernel thought it might be out."*

The collector stamps `attested_at_ms` on every batch and `emitted_at_ms` on
every health record. Those stamps place the evidence in time. The clock
behind them was checked — `ntp_adjtime` at daemon start and on every health
cycle, a fail-closed startup gate, CERT-In Direction 20(3)/2022 — and the
answer went to the daemon's log. **A log is not evidence a verifier holds.**
The brief said so plainly: *"the clock-discipline reading is operational, not
attested"*.

The failure mode is what makes this worth a protocol bump rather than a
documentation note. An undisciplined collector does not produce one wrong
timestamp. It produces an archive that is wrong *together* and perfectly
self-consistent, and nothing inside the sealed bytes reveals it.

Protocol 12 puts the reading in `SensorHealth.clock` as
[`AttestedClock`] — synchronised flag, the kernel's error bound, and the raw
`ntp_adjtime` return code — inside the canonical bytes the key signs. The
daemon reads the clock at its own boundary and hands the reading to the
signer; the signing crate performs no syscalls on that path, so what is
signed is what this process observed and not something the library fetched
for itself.

Tests: `aip-observe/tests/attested_clock.rs`.

| id | attacker | attack | result |
|----|----------|--------|--------|
| CL-01 | — (control) | sign a real reading and verify it | **accepted**; the reading is in the record |
| CL-02 | operator, no key | improve the error bound in an exported record | **DETECTED** — `PayloadHashMismatch` |
| CL-03 | operator, no key | delete the reading from a record that carried one, so the archive says nothing about a clock that was adrift | **DETECTED** — `PayloadHashMismatch` |
| CL-04 | operator, no key | insert a good reading into a record that carried none | **DETECTED** — `PayloadHashMismatch` |
| CL-05 | — (encoding) | a record with no reading versus one with a good reading | **distinguishable**; absence is encoded, not omitted, so a collector that never read its clock cannot pass as one that read it and found it fine |
| CL-06 | — (encoding) | an unsynchronised reading versus a synchronised one with the same bound | **distinguishable**; it is the `STA_UNSYNC` flag, not the number, that says anything is steering the clock |
| CL-07 | — (predicate) | a stale bound on a clock nothing is steering | **refused by the budget predicate**, however small the bound; the verifier applies the same rule as the daemon's startup gate |
| CL-08 | — (encoding) | a negative `maxerror`, which `c_long` permits | **round-trips exactly**; no saturation, no wrap to an enormous positive |
| CL-09 | — (live) | this host's real `ntp_adjtime` reading, signed and verified | **round-trips into signed evidence** |

**What signing it does not buy.** It is the kernel's own view, and root on the
collector host can call `adjtimex` itself and clear `STA_UNSYNC` on a clock it
has just moved. This raises the bar from "trust the operator's log" to "the
key signed this claim"; it does not make the claim unforgeable by a party
holding both the key and the kernel. That is the same boundary as every other
`/proc` and syscall source here (N1), and it is not narrowed by being signed.

**Reported, never judged.** `aip-observe-verify` prints three counts —
records that said the clock was steered, records that said it was not, and
records that said nothing — and the worst error bound any record asserted.
It does not turn any of that into a pass or a failure, because what bound is
acceptable is the institution's policy. What it will not do is let silence
read as a good reading.

---

## EA — Evidence archive, verified offline (Phase 1 exit gate)

**Claim targeted.** *"An auditor holding only the observer's public key and
the collector's archive files can establish that these records are what the
off-host collector signed, in this order, and that nothing has been added,
removed or altered since."*

Until now the collector attested a batch, returned its sequence number in the
acknowledgement and **dropped it**. The chain position was persisted, which
proves a batch existed; the batch itself was not, so there was nothing on
disk for a verifier to accept. The Phase 1 exit gate's third clause — *the
verifier accepts it offline* — was therefore not reachable, whatever the
tests in this repository said about the library functions behind it.

Two things close it. The collector appends every `AttestedBatch` to
`attested.archive.jsonl` and publishes its evidence **public** key as
`observer.pub` beside the state (the private half stays wrapped; an operator
previously had to unwrap it with the passphrase to learn the anchor, which is
what custody exists to prevent). And `aip-observe-verify` is the verifier: a
separate binary, given two files and one public key, opening no socket and
reading no environment.

Attacks are executed as tests in `aip-observe-verify/tests/verify.rs` against
a **real attested chain** — an actual `CollectorRuntime`, actual attestations,
actual archive files. No hand-written fixture: a fixture the author wrote can
agree with a verifier that is wrong in the same way.

| id | attacker | attack | result |
|----|----------|--------|--------|
| EA-01 | — (control) | verify an untouched chain against the published key | **no false positive** — accepted; chain start reported as the observer's epoch |
| EA-02 | forger, no key | present an archive signed by a different observer key | **DETECTED** — every record `SignatureRejected` |
| EA-03 | host with root | edit one attested observation's content | **DETECTED** — `SignatureRejected` on that line; the attestation covers the batch's canonical bytes |
| EA-04 | archive holder | delete one record from the middle | **DETECTED** — `SequenceNotContiguous` **and** `ChainBroken`; every surviving signature is still genuine, so only the chain catches it |
| EA-05 | archive holder | reorder two records | **DETECTED** — `SequenceNotContiguous`; no signature finding, which is the point |
| EA-06 | archive holder | duplicate a record | **DETECTED** — `SequenceNotContiguous` |
| EA-07 | archive holder | truncate a line to garbage | **DETECTED** — `Unparseable`, reported rather than skipped; a verifier that skips bad lines passes a half-destroyed archive |
| EA-08 | archive holder | present an empty archive | **REFUSED** — `Empty`; "nothing to verify" is never a pass |
| EA-09 | collector (A4) | sign a health record whose head disagrees with the attested batch at the same chain position | **DETECTED** — `HealthHeadMismatch`; both signatures are valid in isolation and only the cross-archive comparison exposes it |
| EA-10 | — (control) | verify a window that begins mid-chain | **accepted, and reported as a window** — the verifier does not claim to have seen what preceded the first record |

**What a pass does not mean.** That the observations are true. A host with
root can lie to its own probe; the collector attests what it received, not
what happened. Nor that the window was continuously covered — that is what the
health records state, including the windows the observer could not see
(`IntegrityUnknown`, coverage withdrawn: rows OI-13..OI-15 above).

**Heads are recomputed, never read.** `AttestedBatch::head()` derives the head
from the record's own bytes, so a forged `prev_head` cannot be made to agree
with a doctored predecessor. There is no supplied hash for the verifier to
trust.

**Live, not only in tests.** Phase D of `validation/pilot_e2e/run.sh` runs the
verifier as a separate process against the archives the live collector just
wrote, using only the published `observer.pub`, and then runs the same
verifier against the same archive with one record deleted, which must be
refused. A verifier that accepts everything is worth nothing, so the negative
control is part of the demonstration rather than an appendix to it.

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

---

## Phase 4 — ATT&CK coverage against a third-party corpus (Atomic Red Team)

Every row above tests AIP against attacks **AIP's authors wrote**. A CERT-In
assessor's first objection (blocker B2) is that a system graded against its own
red-team is graded on a curve. This section grades the observer against an
**external, MIT-licensed corpus** — Atomic Red Team
(`github.com/redcanaryco/atomic-red-team`) — mapped to MITRE ATT&CK.

The artefact is an ATT&CK Navigator layer
(`adversarial/atomic/aip-attack-coverage.layer.json`), generated
deterministically from an auditable map (`adversarial/atomic/coverage.tsv`) by
`adversarial/atomic/gen_layer.py` (10 unit tests). It colours each technique by
the observer's **coverage class**, not by a fabricated verdict:

| class | colour | meaning |
|-------|--------|---------|
| attributed | green | the primitive is recorded and bound to a process instance (strongest) |
| effect-observed | amber | the effect is recorded; attribution may be partial |
| not-covered | grey | no AIP sensor observes the primitive — shown, never hidden |

**Honesty of the map.** Of 20 techniques mapped, 8 are attributed, 6 are
effect-observed and **6 are not-covered**. The not-covered rows are the point:
AIP is a runtime *execution* observer, so at-rest content (T1027, T1552.001),
in-memory-only execution (T1055, T1620) and un-hooked syscalls (T1070.004,
T1222.002) are genuine blind spots stated plainly. A coverage map with no grey
would be the lie B2 warns against.

**What was executed, and what was not.** No atomic is run on the build host.
Destructive techniques (T1070 indicator removal, T1222 permission changes) fall
under the adversarial safety rules and are reproduced only from `atomics/<ID>/`
in the pinned corpus, in a controlled environment. The rows marked
`phase1-sealed` are the exception: their **primitives** were demonstrated live
by the real LangGraph run in Phase 1 and are attested in
`integrations/agents/results/sealed/` (offline-verifiable) and derived as a
delegation chain in `results/sealed/delegation_chain.txt`.

| id | ATT&CK | technique | AIP primitive | class | executed? |
|----|--------|-----------|---------------|-------|-----------|
| ARTK-01 | T1059 | Command and Scripting Interpreter | process_exec | attributed | **live** (phase1-sealed) |
| ARTK-02 | T1059.004 | Unix Shell | process_exec | attributed | **live** (phase1-sealed) |
| ARTK-03 | T1059.006 | Python | process_exec | attributed | **live** (phase1-sealed) |
| ARTK-04 | T1071 | Application Layer Protocol | socket_connect | effect-observed | **live** (phase1-sealed) |
| ARTK-05 | T1074.001 | Local Data Staging | file_write | effect-observed | **live** (phase1-sealed) |
| ARTK-06 | T1106 | Native API (execve) | process_exec | attributed | reconciler-tests |
| ARTK-07 | T1036.003 | Masquerading: Rename System Utilities | exe_content_sha256 | attributed | reconciler-tests (content hash defeats rename) |
| ARTK-08 | T1053.003 | Scheduled Task/Job: Cron | process_fork_exec | attributed | reproduction-only (`atomics/T1053.003/`) |
| ARTK-09 | T1543 | Create or Modify System Process | process_fork_exec | attributed | reproduction-only |
| ARTK-10 | T1548.001 | Setuid/Setgid | process_exec | attributed | reproduction-only |
| ARTK-11 | T1041 | Exfiltration Over C2 Channel | socket_send | effect-observed | reproduction-only |
| ARTK-12 | T1048 | Exfil Over Alternative Protocol | socket_connect | effect-observed | reproduction-only |
| ARTK-13 | T1105 | Ingress Tool Transfer | socket_connect+file_write | effect-observed | reproduction-only |
| ARTK-14 | T1070.006 | Indicator Removal: Timestomp | file_write | effect-observed | reproduction-only |
| ARTK-15 | T1070.004 | Indicator Removal: File Deletion | — | **not-covered** | blind-spot |
| ARTK-16 | T1222.002 | File/Dir Permissions Modification (Linux) | — | **not-covered** | blind-spot |
| ARTK-17 | T1027 | Obfuscated Files or Information | — | **not-covered** | blind-spot |
| ARTK-18 | T1552.001 | Credentials In Files | — | **not-covered** | blind-spot |
| ARTK-19 | T1055 | Process Injection | — | **not-covered** | blind-spot |
| ARTK-20 | T1620 | Reflective Code Loading | — | **not-covered** | blind-spot |

*Reproduced by `bash adversarial/atomic/run.sh` (regenerates the layer from the
map, asserts byte-identical, runs the generator's 10 tests). Bounds: this is a
**coverage** statement about the observer's sensor architecture, not a claim
that every atomic executed and reconciled. The attributed/effect classes say
what the observer records; the not-covered rows say where it is blind. Only the
`phase1-sealed` primitives carry attested live evidence.*

---

## Independent corroboration — observers we did not build

Every row above this section tests AIP against attacks AIP's authors wrote, and
every sensor that had ever agreed with AIP was a sensor AIP's authors built.
This section is the second half of the answer to that objection (the first is
the external ATT&CK corpus above): **two independently built runtime observers
watched the same kernel, over the same window, as AIP's own probe.**

| | |
|---|---|
| Observer 1 | **bpftrace 0.20.2** — independent eBPF implementation on `sched:sched_process_exec` |
| Observer 2 | **auditd 3.1.2** — the kernel audit subsystem (`-S execve`), a *different mechanism* |
| Comparison | `aip-corroborate`, which verifies the archive under its anchor **before** comparing |
| Evidence | `validation/external/corroborate/results/sealed/`, reproduced by `validation/external/corroborate/run.sh` |

| id | observer | independence | agreed | AIP only | recorded by them, absent from AIP | result |
|----|----------|--------------|--------|----------|-----------------------------------|--------|
| XC-01 | bpftrace | independent implementation, **same** kernel mechanism | 113 | 1 | **0** | **no AIP blind spot** |
| XC-02 | auditd | **different** kernel subsystem | 112 | 2 | **0** | **no AIP blind spot** |
| XC-03 | auditd | scope difference, not a defect | — | — | 938 failed execve **attempts** excluded | **stated, not hidden** |

"AIP only" is not a defect: the third-party tracers start and stop as processes
of their own and are configured for a narrower scope.

**The two independence classes are not equal, and the tool refuses to let them
read as one claim.** bpftrace corroborates that AIP faithfully reported what
the tracepoint emitted; a foreign eBPF gate on that tracepoint (rows OI-13 to
OI-15 above) would blind **both** observers identically. auditd does not share
that mechanism, so a tracepoint gate does not blind it — which is why it is
carried alongside bpftrace rather than instead of it.

### Two defects the exercise found — in the harness, not in AIP

Recorded because the way they were found is the reason to trust the result.

| id | defect | why it was not AIP's | guard |
|----|--------|----------------------|-------|
| XC-H1 | 275 fabricated "AIP blind spots" | auditd records every execve **attempt**; `/usr/bin/env true` makes `env` search `$PATH` and each miss returns ENOENT. AIP's tracepoint fires only on a **successful** exec, correctly. The split was exact: 106 successes against 106 agreed, 275 failures with `exit=-2` | `x15_a_failed_execve_attempt_is_not_an_aip_blind_spot`; `x16` proves the exclusion cannot hide a real **successful** gap |
| XC-H2 | one apparent gap, a `/usr/bin/sleep` | recorded by auditd **3 ms** before the window closed. **bpftrace missed it too**, which identified it as a teardown boundary artefact: AIP batches on an interval, so an execution received milliseconds before the probe stops has not necessarily reached an attested batch | the window now closes at the end of the workload, with both observers still running through a settle period |

Neither correction weakens a verdict. The first stops the tool demanding that
AIP record executions that never happened; the second stops it measuring a
flush race instead of observer agreement.

### Bounds

**Falco and Tetragon were not used.** They are the first-choice observers named
in the pilot plan; their distribution channels are unreachable from this build
environment and neither is in the distribution archive. The comparison core is
source-agnostic and carries a `Falco` variant; an adapter for its JSON output
is the only missing piece. Stated rather than quietly substituted.

This establishes that AIP's observations survive comparison with observers it
did not author, including one not sharing its kernel mechanism. **It does not
make the host kernel trustworthy** — two observers raise the cost of a
consistent lie, they do not eliminate it — and it is a single run of ~113
executions over a few seconds on a development virtual machine: not a soak
test, not representative load, and not an institution's hardware (B8).
