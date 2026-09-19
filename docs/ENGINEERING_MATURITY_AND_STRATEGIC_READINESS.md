# ENGINEERING MATURITY, TRL & STRATEGIC READINESS
## POST-VALIDATION ADDENDUM

**To:** *AIP Six-Branch Forensic Audit* (revised 2026-09-06)
**Addendum date:** 2026-09-07
**Author posture:** engineering assessment, evidence-bounded

---

> **This addendum reflects engineering and validation progress after the original
> forensic audit baseline. It does not retroactively alter the original forensic
> findings.**

> **ENGINEERING STATUS**
> TRL 5 overall; AIRI/Sniffer Dog software accountability core approaching TRL 6;
> physical autonomous-system validation pending.

---

### What this document is, and is not

It **is** a maturity, readiness and commercial-positioning assessment written on
top of the forensic audit, using the same evidence discipline the audit used.

It **is not** a revision of the audit. Every finding in Reports 00–17 stands as
filed. Where a finding has since been closed on the production-readiness branch,
that is recorded here as *subsequent work*, with the original finding left intact
and citable. Where a finding remains open, it is listed in §P.

Nothing here upgrades a **TEST-PROVEN** property into a real-world one, a
**designed** capability into a deployed one, a **patent application** into a
granted patent, a **target market** into a customer, or a **fundraising target**
into committed capital.

---

## Authoritative engineering checkpoint

| item | value | verification |
|---|---|---|
| Production-readiness branch | `claude/codebase-production-readiness-wm6idp` | `git ls-remote` → `12767eab64ff…` |
| Latest production-validation checkpoint | `12767ea` | `security(observe): close the observer-integrity boundary in production` |
| Latest observation-integrity / validation work | `ff52dc2` | ancestor of `12767ea`, verified |
| Forensic-audit baseline for that branch | `82da7a6` | ancestor of `12767ea`; **125 commits behind current head** |
| `main` | `872dbf3` | **untouched** — 228 commits behind the production branch |

**Consequence, stated first because it governs everything below.** Every
capability assessed in this addendum lives on the production-readiness branch.
A reader who clones the default branch sees `main`, and `main` contains none of
the observation, reconciliation, AIRI, UAS or robotics work. This is the audit's
own finding **D-1**, unchanged, and it is a diligence fact rather than a code
defect.

---

# A. Executive maturity summary

The Vanian programme has moved, since the forensic baseline, from *"a
disciplined evidence architecture with an untested observation story"* to *"a
disciplined evidence architecture whose observation story has been exercised
against an independent external observer on a real Linux kernel, was found
defeatable, and was then repaired in production."*

Five things are materially true now that were not true at the audit baseline:

1. **Real Linux runtime evidence exists.** Sniffer Dog 2.0 captured live
   `sched:sched_process_exec` / `sched_process_fork` samples via
   `perf_event_open` on kernel 6.18.44-fc-v24, with sealed, digested run
   artifacts.
2. **AI-agent accountability has been exercised, not asserted.** A real AIRI
   subject agent emitted a correctly signed event chain and lied about the
   correspondence between claim and reality. Ten adversarial scenarios ran;
   ten behaved as required.
3. **Mechanism-independent observation was demonstrated.** A third-party eBPF
   observer (A3S Observer 0.11.0, MIT) at `syscalls:sys_enter_execve` — a
   different probe site, a different project, a different decoder — agreed with
   Sniffer Dog on true events and refused to corroborate a signed false claim.
4. **Observation interference was reproduced deterministically.** A
   two-instruction eBPF program attached to the sampled tracepoint suppressed
   perf submission host-wide. Sniffer Dog observed 0 of 8 execs and reported
   **zero loss** — silence indistinguishable from non-occurrence.
5. **The observation-integrity weakness was mitigated in production.** The
   observer now enumerates foreign eBPF programs on its own tracepoints, carries
   `ObserverState::IntegrityUnknown` inside its signed health record, requires a
   gate-independent kernel-pushed mechanism before coverage licenses a
   non-occurrence claim, and maps the unknown state to
   `cannot_prove(ObserverIntegrityUnknown)` in every reconciler state gate.

One thing is equally true and is not softened anywhere in this document:

6. **Physical autonomous-system validation remains outstanding.** No robot, no
   airframe, no external tracker, no hardware root of trust. The UAS and
   robotics profiles are honest about this in their own text — the robotics
   profile's closing gap reads, verbatim, *"No robot was involved."*

---

# B. Current engineering state

## B.1 Maturity dimensions

Evidence classes follow the forensic audit's discipline, extended with two
labels this addendum needs:

| label | meaning |
|---|---|
| **CODE-PROVEN** | read directly from source at a cited path |
| **TEST-PROVEN** | a test exercises the property itself, not a stand-in |
| **EXECUTION-PROVEN** | demonstrated by running code across a real boundary |
| **EXTERNAL-CORROBORATED** | an independent party or tool outside this repository confirmed it |
| **DOCUMENTED** | asserted by a repository document; not independently verified |
| **INFERRED** | a conclusion drawn from proven facts; the inference is stated |
| **UNKNOWN** | not determinable from the current codebase |

| # | dimension | classification | what supports it | where it stops |
|---|---|---|---|---|
| A | Architecture | **CODE-PROVEN**, **TEST-PROVEN** | 28-crate workspace with explicit boundaries: identity (`aip-core`) / authority (`aip-authorize`) / execution (`aip-execution`) / observation (`aip-observe`, `aip-observation`) / reconciliation (`aip-reconcile`) / response (`aip-warrant`, `aip-containment`) / proof (`aip-nexora`); verticals (`aip-uas`, `aip-robotics`) compose over the core without adding a signer, verdict class or engine (asserted by `tests/no_second_architecture.rs`) | Architecture quality is not deployment evidence |
| B | Cryptographic / protocol | **CODE-PROVEN**, **TEST-PROVEN**, **EXTERNAL-CORROBORATED** | prefix-free, domain-separated canonical encoding; 26 distinct domain tags; RFC 6962 Merkle with leaf/node separation; Ed25519 + SHA-256 only, no in-tree primitives; the six-branch audit read the encoders line by line and confirmed the prod-branch rewrite closes L-1…L-6 | **No post-quantum cryptography exists on this branch.** Any PQC claim is unsupported here |
| C | AIRI | **TEST-PROVEN**, **EXECUTION-PROVEN**, **EXTERNAL-CORROBORATED** | 34 established properties with cited tests; Rust/Python byte parity across 9 vectors; a real subject agent run against two independent observers over 10 adversarial scenarios, 10/10 as required | Model-invocation claims are **structurally** self-reported; no host observer can attribute a hosted inference call |
| D | Sniffer Dog 2.0 | **EXECUTION-PROVEN**, **EXTERNAL-CORROBORATED** | live `perf_event_open(PERF_TYPE_TRACEPOINT)` capture, kernel 6.18.44-fc-v24, sealed run artifacts with `SHA256SUMS`; agreement with A3S Observer and with an ftrace reader | One host, one kernel, one architecture; `# CONFIG_KPROBES is not set` removes exit evidence |
| E | Observation integrity | **EXECUTION-PROVEN**, **TEST-PROVEN** | threat reproduced deterministically by a 2-instruction BPF gate; two independently built experiments agree; mitigation shipped at `12767ea` and re-verified in a sealed run (`baseline=verified`, `interfered=integrity_unknown`) | Detection is enumeration of foreign BPF programs; a **root/kernel-level** adversary that hides programs is not defeated, and this is stated in the decision record |
| F | NEXORA evidence / proof | **CODE-PROVEN**, **TEST-PROVEN**, **EXECUTION-PROVEN** | the offline verifier ignores the carried verdict and **re-derives** it, refusing `ClaimNotDerivable`; 20 adversarial cases A–T; a live package mutated 8 ways and refused 8 times by a separate verifier process | Anchor distribution is a deployment obligation, not a code property |
| G | Linux runtime | **EXECUTION-PROVEN** | three-process live reference (workload / observer / verifier) reaching `VERIFIED_EXECUTION` on real kernel evidence; process-instance identity is `(pid, pid_start_time_ticks, boot_id)` | Single-host, single-kernel; no fleet, no scale, no long-run stability data |
| H | AI-agent runtime validation | **EXECUTION-PROVEN** (subprocess execution only) | signed false claim refused corroboration by two mechanism-independent observers; replay, omission, duplication, delayed evidence, contradictory observers all handled | `REAL_WORLD_VALIDATION_PROVEN` is **withheld**: synthetic subject, unobservable model layer, no egress ordering |
| I | UAS profile | **CODE-PROVEN**, **TEST-PROVEN**, **DOCUMENTED** | `aip-uas`: six identities kept apart, eleven telemetry sources with declared ceilings, mission commitment through the existing `ExpectedExecution` signer, eleven mission states with the physical tier unreachable | 2 of 11 sources can produce an `ObservationRecord`; **no PX4, no SITL, no HITL, no flight** |
| J | Robotics profile | **CODE-PROVEN**, **TEST-PROVEN**, **DOCUMENTED** | `aip-robotics`: eight-rung embodied chain with `unobserved_boundaries_to_outcome() == 5`; 14 sensing sources, 12 with no mechanism; nine semantic claims computed as unestablishable; live integration test runs the Linux reference *as a companion computer* | The live run proves the **computer**, never the machine; task `Completed` resolves to `Unknown` at every tier |
| K | Physical robotics | **UNKNOWN** | — | *"No robot was involved. Nothing here has been validated against physical hardware."* (`ROBOTICS_ACCOUNTABILITY_PROFILE.md` §12.6) |
| L | Physical-effect accountability | **CODE-PROVEN** (the boundary), **UNKNOWN** (the effect) | `aip-effect` implements the request ≠ execution ≠ effect separation; `effect_establishable()` is false for all nine robotics safety responses; `support_for` returns `Bears`, never `Establishes` | No external physical observation mechanism exists in this build |
| M | Hardware-rooted trust | **DOCUMENTED** | ADR-002 (hardware attestation) is **PROPOSED**; `PlatformBinding` / `ObservedBoot` exist in software | No TPM, no secure element, no measured boot. `INVENTION_REGISTER.md` states plainly that hardware-backed key storage is not implemented |
| N | Production / deployment | **DOCUMENTED**, partially **TEST-PROVEN** | single workspace root (audit blocker B-10 closed); CI with fmt/clippy/test/`cargo audit`/`cargo deny`; gitleaks and trivy in the security workflow; signed release pipeline; offline verifier binary | `PRODUCTION_READINESS.md` still shows TLS, rate limiting, KMS/HSM, DR/BCP, metrics and runbook as not started. **No field deployment evidence exists** |
| O | Independent validation | **EXTERNAL-CORROBORATED** (tooling), **UNKNOWN** (security assessment) | A3S Observer 0.11.0 (`06105bb`, MIT) built from source and run as an independent witness; the six-branch forensic audit is itself an adversarial read | **No third-party security assessment or penetration test has been performed.** `PRODUCTION_READINESS.md` lists it as a pre-deployment blocker |

## B.2 The engineering achievement chain

```
Identity
  → Authority
    → Expected Execution
      → Runtime
        → Independent Observation
          → Observation Integrity
            → Reconciliation
              → Effect Assessment
                → NEXORA Evidence / Proof
```

The architecture exists to keep six things apart that most systems collapse:

```
claim  ≠  authorization  ≠  execution  ≠  independent observation
                         ≠  physical effect  ≠  proof
```

Stage by stage, with the ceiling stated rather than implied:

| stage | crate | what it establishes | what it does **not** establish |
|---|---|---|---|
| Identity | `aip-core` | which key speaks for which agent document | that the holder is who they say offline |
| Authority | `aip-core`, `aip-authorize` | a signed, attenuating delegation chain bound issuer-to-grantee | that the authority was exercised |
| Expected execution | `aip-authorize` | what a decision point authorised, signed, before the fact | that anything ran |
| Runtime | `aip-execution`, `aip-edge` | a process instance `(pid, start ticks, boot id)` | that the process did what it claimed |
| Independent observation | `aip-observe` | that an off-host collector attested these kernel-sourced bytes | the *content's* truth — content from the observed host is root-forgeable and capped below `Proven` |
| Observation integrity | `aip-observe` (new at `12767ea`) | whether the observation mechanism was itself intact | integrity against a root/kernel adversary |
| Reconciliation | `aip-reconcile` | one verdict, through one choke point, fail-closed to `CannotProve` | anything the evidence in hand does not license |
| Effect assessment | `aip-effect` | that a requested effect is separated from an observed one | that a physical effect landed — no mechanism exists |
| Proof | `aip-nexora` | that a third party, offline, re-derived the verdict from the package's own bytes | that the package's anchors are the right ones |

No stage is overstated: five of the nine carry an explicit "does not establish"
column that is enforced in code, not in prose.

---

# C. Current Technology Readiness Level

**NASA-style TRL terminology is used here as an engineering assessment. This is
not an official certification, and no certifying body has assessed this
programme.**

## OVERALL VANIAN PROGRAM: approximately **TRL 5**

TRL 5 — *component and/or breadboard validation in a relevant environment.*
The accountability core has been validated on a real Linux kernel, against an
independently built external observer, under adversarial scenarios including a
reproduced attack on the observation path itself. That is a relevant
environment for *software autonomy*. It is not a relevant environment for
*physical autonomy*, and the programme's TRL is therefore not uniform.

## Differentiated maturity

| element | assessment | basis |
|---|---|---|
| AIRI + Sniffer Dog software accountability core | **~TRL 5, approaching TRL 6** | real Linux execution; independent external observer; 10/10 adversarial scenarios; interference reproduced and mitigated in production. Reaching 6 requires a non-synthetic agent under representative load |
| Linux runtime observation | **~TRL 5** | live perf-tracepoint capture, sealed artifacts, cross-mechanism agreement — on one host, one kernel |
| Observation-integrity mechanism | **~TRL 5** | threat reproduced deterministically, mitigation shipped and re-verified in a sealed run; not yet exercised outside the reproduction environment |
| NEXORA evidence / proof infrastructure | **~TRL 5** | offline re-derivation demonstrated end to end from a live run; 20 adversarial cases; no external verifier deployment |
| UAS accountability profile | **~TRL 4** | component validation in a laboratory environment: the crate, its tests and its evidence-boundary ADR exist; no PX4, no SITL, no airframe |
| Robotics accountability profile | **~TRL 4** | same shape: profile, tests, ADRs, and a live run that proves the companion computer only |
| Physical autonomous-system accountability | **~TRL 2–3 until actually demonstrated** | the concept is formulated and partially implemented in software; nothing physical has been observed. This stays at 2–3 regardless of code quality until a real machine is in the loop |
| Full integrated autonomous-system product | **~TRL 4–5** | the integrated chain runs end to end in software; the physical half of the integration does not exist |

## Why not TRL 6, 7, 8 or 9

**Do not state that all of Vanian is TRL 6, 7, 8 or 9.** The reasons are
specific:

- **TRL 6** would require a system/subsystem model demonstrated in a
  *relevant* environment. For the software core that is close — arguably one
  non-synthetic agent deployment away. For anything physical, the relevant
  environment has not been entered at all.
- **TRL 7** would require a prototype demonstration in an *operational*
  environment. There is no operational deployment. `PRODUCTION_READINESS.md`
  lists TLS, rate limiting, KMS/HSM, backups, DR/BCP, metrics and a runbook as
  not started.
- **TRL 8/9** would require a completed, qualified, mission-proven system.
  No third-party security assessment has been performed; no certification
  mapping exists; no field deployment has occurred.

What genuinely supports TRL 5, restated so the number is auditable:

1. **Real Linux runtime evidence exists** — sealed captures, not simulation.
2. **AI-agent accountability has been exercised** — a signed false claim was
   refused corroboration.
3. **Mechanism-independent observation has been demonstrated** — a different
   probe site, reached by a different mechanism, decoded by a different project.
4. **Observation interference was reproduced** — deterministically, with a
   minimal-cause interferer, and with audit-subsystem ground truth proving the
   suppressed events really occurred.
5. **The observation-integrity weakness was mitigated** — in production, with a
   single deliberate wire-version bump (`OBSERVE_PROTOCOL_VERSION` 8 → 9), and
   the mitigation was re-verified against the reproduction.
6. **Physical autonomous-system validation remains outstanding** — and the
   robotics profile says so in its own text rather than being made to say so
   here.

---

# D. AIRI / Sniffer Dog 2.0 validation achievements

Source: `docs/AIRI_REAL_WORLD_VALIDATION.md` (status `EXPERIMENT_PASSED`, not
`REAL_WORLD_VALIDATION_PROVEN`), `docs/AIRI_INDEPENDENT_OBSERVATION_REPORT.md`,
`validation/scenarios/airi_independent_observation_001/`.

| achievement | evidence class | note |
|---|---|---|
| Real Linux execution | **EXECUTION-PROVEN** | kernel 6.18.44-fc-v24, x86_64, root; sealed traces with `SHA256SUMS` |
| AI-agent independent-observation experiment | **EXECUTION-PROVEN** | `AIRI-INDEPENDENT-OBSERVATION-001`; observers attach first, window opens only when each reports attached |
| Signed false claim scenario | **EXECUTION-PROVEN** | Scenario 1: a correctly signed, chain-consistent claim that a tool ran; two mechanism-independent observers covered the window and saw nothing → `SELF_REPORTED`, never `PROVEN` |
| Replay handling | **TEST-PROVEN** | `chain.rs` — `SequenceDuplicate` |
| Omission handling | **TEST-PROVEN / stated limit** | a middle drop is `SequenceGap`; **head truncation is undetectable and is documented as such**, with a test that pins the limit |
| Duplication handling | **TEST-PROVEN** | `SequenceDuplicate`; renumbering after deletion caught by `PrevHashMismatch` |
| Delayed evidence | **EXECUTION-PROVEN** | evidence arriving outside the coverage window is *outside coverage*, never a miss |
| Contradictory observers | **EXECUTION-PROVEN** | conflict is surfaced, never resolved by majority, recency or self-reported confidence |
| Mechanism-independent Linux Audit witness | **EXECUTION-PROVEN** | `NETLINK_AUDIT` established as independent of the tracepoint path and used as ground truth in the interference analysis |
| A3S cross-check | **EXTERNAL-CORROBORATED** | A3S Observer 0.11.0 (`06105bb`, MIT), built from source, 23/24 probes working |
| Observation-interference discovery | **EXECUTION-PROVEN** | found by running the independent observer, not by reading the code |
| Deterministic tracepoint-interference reproduction | **EXECUTION-PROVEN** | a 2-instruction BPF program (`r0 = 0; exit`) attached via `PERF_EVENT_IOC_SET_BPF`; arm A = 8 execs observed, arm B = 0 observed, reported loss 0 |
| Observation-integrity mitigation | **CODE-PROVEN**, **TEST-PROVEN**, **EXECUTION-PROVEN** | shipped at `12767ea`; sealed re-run reports `arm_a_baseline_integrity: "verified"`, `arm_b_interfered_integrity: "integrity_unknown"`, `fix_detected_the_gate: true` |
| `IntegrityUnknown` state | **CODE-PROVEN** | `ObserverState::IntegrityUnknown`, code `0x06`, non-`Active`, fails `permits_attested_use`, carried **inside the signed** `SensorHealth` |
| Fail-closed `CANNOT_PROVE` behaviour | **CODE-PROVEN**, **TEST-PROVEN** | maps to `cannot_prove(ObserverIntegrityUnknown)` in every reconciler state gate; `aip-reconcile` `t03d`/`t03e` assert a blinded observer cannot accuse |

## D.1 The distinction that matters

> **The system does not treat a valid signature over a false statement as proof
> of the underlying execution.**

This is not a slogan; it is the observed behaviour of Scenario 1. The AIRI
event verified — authorship and integrity *were* intact, and
`verify_airi_event` correctly returned `Ok`. The claim still resolved to
`SELF_REPORTED` with a cardinality divergence flagged (1 claimed, 0 observed),
because two mechanism-independent observers covered the window and saw nothing.
A perfect signature over a false statement bought the actor nothing.

The converse case is equally load-bearing. Scenario 6 claimed an act that
leaves no host-visible mark. The correct answer is "cannot be established"; the
tempting wrong answer is "unsupported, therefore false". It stayed
`SELF_REPORTED` and was never called false.

## D.2 The boundary that moved

> **Observation integrity is now treated as part of the evidence boundary.**

Before `12767ea`, a live, continuity-verified observer could be silently blind
and still sign `Active` coverage — and a blinded window could drive a false
`PhantomClaim`, which is an accusation that a claimed execution did not happen.
After `12767ea`, the coverage assertion is a function of the observer's own
integrity state, and that state is inside the signed record.

The fix is **fail-safe and strictly monotone**: every part can only turn a
coverage claim into `CannotProve`, never the reverse, and it touches no verdict
on the trusted-observation side. It preserves `CANNOT_PROVE`, `EvidenceCeiling`
and the single reconciler authority.

---

# E. The observation-integrity milestone

## THE ACCOUNTABILITY OBSERVER MUST ITSELF BE ACCOUNTABLE.

This is the programme's most consequential engineering result to date, and it
was produced by the validation work rather than by design review.

| phase | what happened | evidence |
|---|---|---|
| **1** | An agent claims an action. | AIRI event chain, agent-signed, verifying |
| **2** | Sniffer Dog observes runtime behaviour. | live perf tracepoint samples on a real kernel |
| **3** | An independent mechanism corroborates the observation. | A3S at `syscalls:sys_enter_execve`; ftrace; `NETLINK_AUDIT` |
| **4** | Observation interference is deliberately introduced. | a 2-instruction no-op eBPF program on `sched:sched_process_exec` |
| **5** | Sniffer Dog's blind state is detected. | `PERF_EVENT_IOC_QUERY_BPF` enumerates the foreign program; `mechanism_integrity` → `ForeignTracepointGate`, fail-closed if the query is refused |
| **6** | `IntegrityUnknown` causes fail-closed `CANNOT_PROVE`. | signed `SensorHealth` carries `0x06`; reconciler state gates map it to `cannot_prove(ObserverIntegrityUnknown)` |

**Why the kernel behaves this way, stated once so the finding is checkable
rather than anecdotal.** The kernel gates a tracepoint's *perf* submission on
the attached BPF program's return value in `perf_trace_run_bpf_submit()`, keyed
per `trace_event_call` — per tracepoint, host-wide. Every `perf_event_open`
consumer of that tracepoint therefore stops receiving samples. The ftrace
submission path is separate and unaffected, which is exactly the asymmetry
observed, and is what makes the diagnosis certain rather than plausible.

**What was engineered in response, and what was deliberately not.** Four
options shipped — detect (H), attest (G), require cross-mechanism coverage (A),
fail closed (I). Four did not: the canary (C) carries a specific trap, because
a passing canary against a *targeted* gate is false assurance; remote (D),
off-host (E) and hardware-backed (F) observation raise the ceiling against root
and kernel compromise but introduce new trust anchors and belong to the
observer-attestation roadmap. Selecting them now would have been a guess with
the reasoning written afterwards.

This is presented as an engineering evolution. It is not a marketing claim, and
the residual is stated in §P: a **root or kernel-level adversary that hides
programs from enumeration is not defeated**, and neither is an adversary who
gates both mechanisms.

---

# F. Architectural differentiation

## WHY THE ARCHITECTURE IS DIFFERENT

Conventional AI-agent security and observability systems primarily address one
or more of: **policy enforcement**, **access control**, **prompt/input
security**, **model security**, **agent observability**, **logging**,
**traceability**, **governance**. These are real problems and the products that
address them are, in general, good at them.

Vanian's architectural target is a different question:

## AUTONOMOUS INTELLIGENCE ACCOUNTABILITY

The differentiating chain:

```
WHO
 → WHAT WAS AUTHORIZED
   → WHAT WAS EXPECTED
     → WHAT ACTUALLY EXECUTED
       → WHAT WAS INDEPENDENTLY OBSERVED
         → WAS OBSERVATION INTEGRITY ESTABLISHED
           → WHAT EFFECT CAN BE ESTABLISHED
             → WHAT CAN BE CRYPTOGRAPHICALLY PROVEN
```

Four structural commitments make that chain more than a diagram, each
CODE-PROVEN and TEST-PROVEN on the production branch:

1. **The actor does not control the evidence used to judge the actor.** The
   probe on the observed host holds **no key** and has **no signing method**;
   the collector holds the key **off-host**, assigns the sequence, and stamps
   its own clock. Root on the observed host can suppress or corrupt what is
   *offered* and cannot forge an attestation of it.
2. **Coverage is re-derived, never read from the artifact being judged.** A
   NEXORA package has **no field** in which to state its own coverage; the
   verifier computes it from signed inputs. Exactly one of five outcomes —
   `AvailableAndEmpty` — licenses a statement about something *not* having
   happened.
3. **Severity and evidence strength are never composed into a score.** There is
   no `confidence: f32` anywhere in the evidence path. The permitted response
   is a `min` of independent caps. A confident-sounding guess cannot cross a
   boundary meant for proven facts.
4. **The proof layer re-derives rather than trusts.** The offline verifier
   ignores the carried result, strength and coverage, re-runs the reconciler
   over the package's own inputs under the *verifier's* anchors, and refuses
   `ClaimNotDerivable { claimed, rederived }` on mismatch. `CANNOT_PROVE`
   cannot become `PROVEN` through packaging, export, import or transport.

**This section makes no claim that other companies cannot do these things.**
It claims only that this is the problem Vanian is architected around, and that
the mechanisms above are present in code with tests that exercise them.

---

# F.1 Unique selling proposition

## PRIMARY USP

> **Vanian makes autonomous systems cryptographically accountable.**

The ten components of that claim, each with the honest bound attached. The term
used throughout is **architectural differentiation**, not "best in the market" —
because no external benchmark has been run against any competing product.

| # | element | what it means | bound |
|---|---|---|---|
| 1 | **Actor-independent accountability** | the evidence used to judge an actor is not authored, signed, sequenced or timestamped by that actor | the collector's key custody is a deployment obligation, and a holder of that key can still lie |
| 2 | **Independent runtime observation** | kernel-sourced observation by a keyless probe, attested off-host | demonstrated on one kernel; model invocations are structurally unobservable |
| 3 | **Observation-integrity awareness** | the observer reports whether its own observation mechanism was intact, inside its signed record | defeats a `CAP_BPF` adversary and accidental interference; **not** a root or kernel-level one |
| 4 | **Explicit execution/effect separation** | no event type exists that can assert an external or physical effect | the physical side of the boundary has no mechanism yet |
| 5 | **Evidence ceilings and `CANNOT_PROVE`** | content read from the observed host cannot reach the top evidence class; the default verdict is "cannot prove" | this is a refusal to over-claim, not a detection capability |
| 6 | **Cryptographically bound accountability** | 26 domain-separated, prefix-free signed objects; offline re-derivation of a verdict from a package's own bytes | Ed25519 and SHA-256 only; **no post-quantum cryptography exists** |
| 7 | **Framework-neutral design** | one schema across LangChain, LangGraph, LlamaIndex, AutoGen, CrewAI, OpenAI-style tool calling and bespoke runtimes; no framework is a trust anchor | validated by a five-name sweep, not by production integrations |
| 8 | **One accountability architecture across software and physical autonomy** | the verticals add no signer, verdict class or engine — asserted mechanically over comment-stripped source | the physical verticals are unvalidated against hardware |
| 9 | **Defence / UAS / robotics applicability** | profiles exist, with evidence-boundary ADRs, honest ceilings and their own suites | **application targets and roadmap**, not deployments |
| 10 | **AI-agent applicability** | exercised against a real subject agent and an independent external observer over ten adversarial scenarios | the subject is synthetic; `REAL_WORLD_VALIDATION_PROVEN` is withheld |

**No claim of universal superiority is made anywhere in this document.** Where a
comparison appears, it is a comparison of *architectural target* — see §G and
`docs/COMPETITIVE_POSITIONING.md`, which states explicitly that its readings
are about public positioning, not about what any company is capable of.

---

# G. Competitive and adjacent landscape

Full analysis with per-vendor treatment: **`docs/COMPETITIVE_POSITIONING.md`**.

Summary of the strategic reading:

- The **AI-agent security** market (Zenity, Noma, Lasso, WitnessAI, and the
  platform consolidators) is dense, well funded, and centred on discovery,
  posture, policy and runtime *defence*. Its output is prevention and alerting.
- The **machine/agent identity** market (SPIFFE/SPIRE, Aembit, Astrix→Cisco,
  Entro→SailPoint, Oasis→Cyera, Okta Cross App Access, Auth0 Auth for MCP,
  Microsoft Entra Agent ID) has consolidated hard through 2026 and answers
  *who is acting and on whose behalf*. It is **complementary** to Vanian, not
  competitive: Vanian consumes identity and authority and asks what happened
  next.
- The **agent observability** market (LangSmith, Langfuse→ClickHouse, Arize,
  Braintrust, OTel GenAI conventions) is telemetry authored inside the actor's
  own process. It is not competitive with an accountability layer whose first
  principle is that such telemetry is a claim.
- The **eBPF runtime security** market (Falco, Tetragon, Tracee, Sysdig) is the
  closest neighbour on *independent runtime observation* and is the right place
  to look for overlap. It targets detection and, for Tetragon, in-kernel
  enforcement. Vanian's observation layer targets *evidence* — attested,
  re-derivable, and now integrity-aware. Notably, a co-resident eBPF tool of
  exactly this class is what produced Vanian's observation-integrity finding.
- **Cryptographic provenance** (Sigstore, in-toto, SLSA, C2PA) is
  complementary: it attests artifacts and build pipelines, not runtime
  execution of an autonomous system.
- **Physical-AI security** (VicOne, Alias Robotics, Upstream, and the
  automotive/OT security vendors) addresses physical autonomy and is the
  nearest neighbour on that axis, generally through vulnerability, runtime
  protection and monitoring rather than an evidence/proof model.
- **Defence autonomy platforms** (Anduril Lattice, Shield AI Hivemind,
  Palantir) are the autonomy itself and the data backbone around it. They are
  **target integration partners and customers**, not competitors, for an
  accountability layer.

**The whitespace, stated conservatively:** no vendor surveyed publicly
positions the combination of (a) independent runtime observation, (b) explicit
observation-integrity semantics, (c) an execution-versus-effect distinction, and
(d) an offline, re-derivable cryptographic proof with a first-class
`CANNOT_PROVE` outcome, across **both** software and physical autonomy. That is
a statement about public positioning from the research cited in the companion
document — not a claim that no such capability exists anywhere.

---

# H. AI agents + physical AI: one accountability core

**Vanian is not an "AI-agent-only" company.** The category it is building in is:

## AUTONOMOUS INTELLIGENCE ACCOUNTABILITY INFRASTRUCTURE

Applications: **AI agents · robotics · UGVs · UAS · autonomous vehicles ·
industrial autonomous systems · defence autonomy · critical infrastructure ·
space systems.**

| | **SOFTWARE AUTONOMY** | **PHYSICAL AUTONOMY** |
|---|---|---|
| subjects | AI agents, digital agents | robots, UGVs, UAS, industrial machinery, autonomous vehicles, spacecraft |
| actions | tool execution, subprocesses, network/API calls | motion, manipulation, navigation, actuation |
| observation | kernel-pushed events on the host | an external mechanism that is not the machine itself |
| status | **validated in controlled real runtime** | **not validated — no physical mechanism exists in this build** |

The shared chain is one chain, not two:

```
Identity → Authority → Expected Execution → Runtime
        → Independent Observation → Observation Integrity → Effect → Proof
```

**One accountability core, many autonomous worlds.** The core does not know
whether it is watching a Python agent or a companion computer on a chassis —
`SystemType::UncrewedAerial` already existed at wire code `0x02` before the UAS
profile was written, and the profile added *no* identifier, record type, verdict
class, key, signer or proof tree. That reuse is asserted mechanically, over
comment-stripped source, in `tests/no_second_architecture.rs`.

**Physical validation is not complete and is not claimed to be.** The robotics
profile's own eight-rung table shows five unobserved boundaries between an
autonomy decision and a physical outcome, and `ExternalCamera` /
`ExternalTracking` — the shortest path to real robotics evidence — have no
implemented mechanism.

---

# I. Defence and mission-critical applications

**These are application targets and roadmap. They are not completed defence
deployments. No defence deployment, trial, or contract is evidenced in this
repository.**

| use case | what Vanian is **designed to support** | current status |
|---|---|---|
| Autonomous UAS | mission authority, expected execution, and post-mission evidence around a flight stack | validation target; `aip-uas` exists, no flight controller in the loop |
| UGVs | task authorisation and execution accountability on the companion computer | validation target; `aip-robotics` exists, no vehicle |
| Robotic systems | manipulation task plans committed into a signed `ExpectedExecution` | validation target |
| Mission computers | process-instance-bound execution evidence on a Linux mission computer | **demonstrated in controlled real runtime** for the Linux case |
| Autonomous edge systems | offline-capable evidence with no call-home and no foreign cloud in the trust path | designed; documented in the Linux edge reference |
| Distributed autonomous platforms | per-platform identity separate from per-compute-element identity | designed (`aip-platform`, `aip-system`) |
| Contested communications | evidence that survives partition; a break is reported, never bridged | designed; continuity break taxonomy implemented and tested |
| Mission execution accountability | reconciliation of what was authorised against what was independently observed | demonstrated for software execution |
| Post-mission forensic verification | offline, clock-free, network-free re-derivation of a verdict from a sealed package | **demonstrated end to end from a live run** |
| Operator / autonomy boundary | authorising an action is distinct from the machine performing it; four robotics safety responses are deliberately **not authorisable** | designed and implemented |
| Evidence preservation | hash-chained collector head with a four-kind break taxonomy carried as signed evidence | implemented and tested |

Sovereignty properties relevant to defence procurement, **CODE-PROVEN**: the
core depends only on standard open cryptography (Ed25519, SHA-256) through
permissively licensed libraries; verification is fully offline and
open-specified; there is no call-home and no foreign cloud in the trust path.

---

# J. Physical AI validation roadmap

Full stage-by-stage detail with acceptance criteria:
**`docs/TRL_AND_PHYSICAL_VALIDATION_ROADMAP.md`**.

| stage | objective | environment | independent evidence source | status / target |
|---|---|---|---|---|
| 1 | Real Linux AI-agent accountability | Linux host, real kernel | A3S eBPF observer; `NETLINK_AUDIT`; ftrace | **demonstrated in controlled real-runtime validation** |
| 2 | ROS2 + Gazebo | simulated robot, real autonomy stack | simulator ground truth as a *declared* non-independent reference | validation environment / next relevant stage |
| 3 | Physical UGV / mobile robot | real chassis, real controller | real controller boundary + external observation | target |
| 4 | ExternalCamera / ExternalTracking | instrumented cell | independent physical-state observation, anchored off-machine | target |
| 5 | PX4 SITL | software-in-the-loop flight stack | flight-stack logs treated as onboard, not independent | target |
| 6 | PX4 HITL | real flight controller, no airframe | real flight-controller boundary | target |
| 7 | Controlled UAS | flight range, representative mission | ground-station track + independent radio observation | target |
| 8 | Defence / industrial pilot | operationally representative site | operator-side independent evidence | target |

**What is not yet proven at any stage above 1:** that any physical quantity —
position, attitude, contact, grasp, task completion — can be established rather
than asserted. Until a mechanism exists whose observations reach
`from_attested`, every physical claim resolves to `CANNOT_PROVE`, and the
profiles say so.

---

# K. Commercialization roadmap

Full detail: **`docs/PRE_SERIES_A_10M_ROADMAP.md`**.

**Target round: USD 10M Pre-Series A.** This is a **TARGET**, not committed
capital, not a term sheet, and not an indication of interest from any named
party.

Purpose of the round, in the order the engineering requires it:

1. Physical validation (stages 2–4 above)
2. Defence / industrial pilots
3. Independent security validation (third-party assessment and remediation)
4. Hardware / edge deployment work
5. OEM and strategic integrations
6. Production hardening (the open items in `PRODUCTION_READINESS.md`)
7. Compliance and certification mapping
8. Deployment and field engineering
9. Expanded observer mechanisms (off-host, remote, hardware-rooted)
10. International go-to-market

Milestone-based capital deployment:

| milestone | what it buys | what it proves |
|---|---|---|
| **M1** AIRI + Sniffer Dog production validation | non-synthetic agents, real load, false-positive characterisation | the core is operable, not just correct |
| **M2** Physical robotics validation | ROS2/Gazebo → UGV → external tracking | that a physical claim can become evidence |
| **M3** UAS / PX4 validation | SITL → HITL → controlled flight | that the UAS profile is more than a document |
| **M4** First defence / industrial pilot | an operationally representative deployment | that the evidence model survives an operator |
| **M5** Recurring paid deployments | commercial references | that someone pays for accountability |
| **M6** OEM / platform integration | the accountability layer inside someone else's autonomy stack | distribution rather than direct sales |

---

# L. USD 10M Pre-Series A — value creation logic

```
TECHNICAL DE-RISKING
  → PHYSICAL VALIDATION
    → DEFENCE / INDUSTRIAL PILOTS
      → PRODUCTION HARDENING
        → COMMERCIAL REFERENCES
          → RECURRING REVENUE
            → OEM INTEGRATION
              → NEXT INSTITUTIONAL ROUND
```

**Planning assumption for the subsequent financing step:** a USD 8–10M
institutional round at an **illustrative** USD 40–60M pre-money range —
**only if** the milestone evidence supports it. This is a planning framework,
not a forecast, not a guarantee, and not a statement that any investor has
indicated such terms.

---

# M. Valuation planning framework

**These are internal strategic planning ranges. They are not third-party
valuations, fairness opinions, or guaranteed future company values. No
independent valuer has assessed this company.**

| frame | range | basis |
|---|---|---|
| Current engineering / technology reference assessment | **₹30–50+ Cr** internal strategic range | the code, the validation evidence, and the IP position as they stand |
| Current institutional fundraising planning | **₹30–35 Cr** pre-money target range | the round being planned |
| Strategic floor | **approximately ₹25 Cr** pre-money | the level below which the round is not worth the dilution |
| Potential strategic premium | **₹40 Cr+** | where a highly strategic investor materially accelerates validation or adoption |

Post-validation milestone planning ladder — each rung is contingent on the
evidence named beside it, not on elapsed time:

| milestone | planning class | evidence gate |
|---|---|---|
| Physical reference deployment | **₹50–80 Cr class** | a physical claim established by an independent mechanism |
| Defence / industrial pilot | **₹75–120 Cr class** | an operationally representative deployment with operator-side evidence |
| Recurring commercial deployments | **₹150 Cr+ class** | paid, renewing, referenceable |
| OEM / platform integration | **₹300 Cr+ potential strategic scale** | the layer embedded in a third-party autonomy platform |

---

# N. Technology moat

Each differentiator below is listed with the evidence class that supports it.
Nothing in this section is asserted at a level the repository does not carry.

| moat element | class | anchor |
|---|---|---|
| Fail-closed evidence semantics | **CODE-PROVEN**, **TEST-PROVEN** | `finish()` rewrites a failed proposal to `(CannotProve, Heuristic, InvariantNotSatisfied)` |
| `CANNOT_PROVE` as a first-class security outcome | **CODE-PROVEN**, **TEST-PROVEN** | `ReconciliationResult::default()` is `CannotProve`; the default is asserted by test |
| Independent observation | **CODE-PROVEN**, **EXECUTION-PROVEN** | keyless probe / off-host collector split; live capture on a real kernel |
| Observation-integrity handling | **CODE-PROVEN**, **EXECUTION-PROVEN** | `IntegrityUnknown` inside signed health; gate-independent mechanism required for coverage |
| Execution / effect distinction | **CODE-PROVEN**, **TEST-PROVEN** | `aip-effect`; three tool layers with **no** event asserting layer 3 |
| Evidence ceilings | **CODE-PROVEN**, **TEST-PROVEN** | content-derived verdicts require `strength == Attested` **exactly**; over-claiming is downgraded |
| Signed execution/event binding | **CODE-PROVEN**, **TEST-PROVEN** | process instance `(pid, start ticks, boot id)`; content-hashed executable, not path |
| Framework neutrality | **TEST-PROVEN** | `no_framework_is_a_trust_anchor` sweeps five framework names and asserts identical outcomes |
| Cryptographic evidence | **CODE-PROVEN** | 26 domain-separated tags; prefix-free canonical encoding; RFC 6962 Merkle |
| NEXORA offline verification | **EXECUTION-PROVEN** | a separate verifier process refused 8 mutations of a live package |
| Reusable vertical profile architecture | **TEST-PROVEN** | UAS and robotics add no signer, verdict class or engine; ADR-007 governs composition |
| Linux edge foundation | **EXECUTION-PROVEN** | three-process live reference reaching `VERIFIED_EXECUTION` |
| UAS / robotics extensions | **CODE-PROVEN**, **TEST-PROVEN** | `aip-uas`, `aip-robotics` with their own suites and ADRs |
| Patent portfolio | **see §O** | pending applications; **not** granted patents |

**Two moat elements are deliberately absent from the list above,** because the
repository does not support them: post-quantum cryptography (none exists on this
branch) and hardware-rooted trust (ADR-002 is PROPOSED).

---

# O. IP position

## O.1 Status discipline

- **Pending Indian patent applications** are described as *pending*. Nothing in
  this document says "patented", "granted", or "issued".
- The repository contains **attorney working documents**
  (`reports_and_patents/`), and its own `README.md` and
  `docs/idex_open_challenge/04_INNOVATION_AND_IP.md` state that *provisional
  filings exist relating to delegation-bound, scope-constrained audit binding*.
  **No filing receipt, application number, or filing date appears anywhere in
  the repository.** A due-diligence reader should ask for the filing particulars
  from counsel rather than from this document.
- Copyright in the source is recorded in the repository as owned by
  **K. NAGA SRI GANESH** (`README.md`, commit `6c407d0`). The relationship
  between that ownership and the Vanian Technologies entity is a corporate
  matter that this engineering document does not assert.

## O.2 The two applications identified

| # | subject | repository evidence | implemented in current code? |
|---|---|---|---|
| 1 | **Hardware-based AI monitoring / physical containment** | No dossier for this subject was located in `reports_and_patents/`. Adjacent design intent exists as **ADR-002 (hardware attestation, PROPOSED)** and in `aip-containment` (cgroup v2 freezer, advisory by default) | **No.** `INVENTION_REGISTER.md` states that hardware-backed key storage and kernel-resident eBPF/XDP sensing are not implemented |
| 2 | **AI-safe distributed consensus + post-quantum provenance** | `reports_and_patents/PATENT_DOSSIER_CCVL_AIP.md` — Cross-Channel Verification Logic with BFT quorum escalation and a PQC-signed audit trail, prepared for the Indian Patent Office (CRI 2025) and USPTO | **No.** No PQC and no consensus mechanism exists on `main` or on the production branch |

## O.3 Patent scope versus current code implementation

**These are different sets and must not be conflated.**

- **What the applications are intended to support:** independent hardware
  monitoring, physical containment, AI-safe distributed consensus, provenance
  verification, and cryptographic trust infrastructure.
- **What the current repository implements:** software-only independent
  observation, software containment gates (advisory by default and, per the
  audit's finding §13, deliberately unreachable from engine-produced evidence),
  Ed25519/SHA-256 provenance, and offline proof re-derivation.

**No patent claim should be presented as already reduced to practice in this
repository unless it is one of the nine mechanisms catalogued in
`docs/IP/INVENTION_REGISTER.md`** — and that register itself states, in its own
words, that no prior-art search has been performed, that no entry is asserted to
be novel or patentable, and that post-quantum cryptography, hardware-backed key
storage, kernel-resident eBPF/XDP sensing and field deployment "appear nowhere
above, because none of them is implemented."

**No monetary value is assigned to any patent in this document.** Any such
figure elsewhere should be read as an internal planning assessment only.

## O.4 Two IP risks carried forward from the audit, unchanged

- **IP-2:** the strongest mechanisms exist **only** on the unmerged
  production-readiness branch. Any filing must be anchored to that tree.
- **IP-3:** the commits carrying this work have a single machine author
  identity. A documented human conception and reduction-to-practice record,
  independent of the commit log, does not exist in the repository and should
  exist before it is asked for.

---

# O.5 Maturity scorecard

**Engineering maturity visualization — qualitative.** The bars are a reading
aid. They are **not** mathematical measurements, not percentages, not a score,
and nothing in this programme is derived from them. The authoritative
statements are the classifications in §B.1 and the TRL assessments in §C.

```
ARCHITECTURE              ██████████
CRYPTOGRAPHY              ██████████
AIRI                      █████████░
SNIFFER DOG               █████████░
OBSERVATION INTEGRITY     ████████░░
NEXORA                    ████████░░
REAL LINUX                ████████░░
AI AGENT                  ████████░░
ROBOTICS                  █████░░░░░
UAS                       █████░░░░░
PHYSICAL EFFECT           ███░░░░░░░
HARDWARE TRUST            ███░░░░░░░
FIELD DEPLOYMENT          ██░░░░░░░░
```

| row | why it sits where it does | what would move it |
|---|---|---|
| Architecture | boundaries are enforced by the compiler and by tests, not by convention | nothing pending |
| Cryptography | encoding, domain separation and Merkle construction are sound and adversarially tested | PQC, if it is ever required — none exists today |
| AIRI | 34 properties with cited tests; exercised against an independent observer | a non-synthetic agent under load |
| Sniffer Dog | live capture on a real kernel, corroborated by a third-party observer | more kernels, more architectures, multi-host |
| Observation integrity | reproduced, mitigated, re-verified — all within one environment | co-resident mainstream eBPF tooling, across kernels |
| NEXORA | offline re-derivation demonstrated end to end from a live run | a verifier operated by a third party |
| Real Linux | one host, one kernel, `CONFIG_KPROBES` absent | fleet-scale and long-run evidence |
| AI agent | subprocess execution corroborated; model layer structurally not | nothing can move the model layer without an external mechanism |
| Robotics | profile, ADRs, tests, and a live run that proves the computer | a real machine and an external tracker |
| UAS | profile, ADR-005, tests | PX4 SITL, then HITL, then flight |
| Physical effect | the boundary is implemented; the effect is unobservable | a mechanism reaching `from_attested` |
| Hardware trust | ADR-002 PROPOSED; nothing implemented | a TPM-measured sensor and attested boot |
| Field deployment | none | a pilot |

---

# P. Remaining gaps

Listed without softening. This section is the reason the rest of the document
is credible.

## P.1 Physical and hardware

1. **Physical autonomous-system validation is pending.** No robot, no vehicle,
   no airframe has been in the loop. `ROBOTICS_ACCOUNTABILITY_PROFILE.md` §12.6:
   *"No robot was involved."*
2. **External physical tracking is pending.** `ExternalCamera` and
   `ExternalTracking` are named in the profile and have **no implemented
   mechanism**; positional independence without a mechanism is nobody observing.
3. **Hardware-rooted observation trust is pending.** ADR-002 is PROPOSED. A TPM
   on a companion computer would strengthen claims about the *computer* and say
   nothing about the arm.
4. **Controller and chassis substitution are undetectable.** Nothing measures
   either; component replacement leaves process and boot identity untouched.

## P.2 Trust boundaries that remain open

5. **The collector key-custody boundary remains.** A forger holding the
   collector key can still sign a false state. This is stated in the decision
   record as a separate boundary, not closed by the integrity work.
6. **The root/kernel adversary boundary is not closed.** Detection is
   enumeration of foreign BPF programs; a root adversary that patches the kernel
   or hides programs defeats it, as does one that gates both mechanisms.
   *"Root is assumed benign. Nothing here survives a root-privileged adversary,
   and §6 shows `CAP_BPF` alone is enough."*
7. **Model invocations are structurally unobservable.** Half the AIRI chain
   cannot be corroborated by any host observer, by construction.
8. **Chain truncation at the head is undetectable**, and an agent that never
   emits an event leaves an intact chain. Only independent observation speaks to
   this.
9. **Bundle signer identity is unanchored.** The audit's B-4 sub-point remains:
   a bundle signature answers "this manifest matches this key", not "this
   manifest came from anyone in particular."
10. **Packet timestamps are the agent's assertion.** R16 bounds what a verifier
    will accept; it does not make any timestamp true.

## P.3 Programme and process

11. **Full defence deployment is not demonstrated.** No pilot, no trial, no
    contract is evidenced.
12. **Independent third-party security validation is pending.**
    `PRODUCTION_READINESS.md` lists it as a pre-deployment blocker; no
    penetration test or CERT-In assessment has occurred.
13. **CI maturity.** The primary gap the audit identified (B-10, two independent
    Cargo roots) is **closed** — there is now one workspace root and
    `aip-service` is a member. Remaining: no metrics/monitoring export, no
    runbook, and live-kernel tests are environment-sensitive (§Q.2).
14. **Production deployment evidence is still incomplete.** TLS termination,
    rate limiting, KMS/HSM for signing keys, backups, DR/BCP, retention controls
    and control-framework mapping are all open in `PRODUCTION_READINESS.md`.
15. **`REAL_WORLD_VALIDATION_PROVEN` is deliberately withheld.** The subject
    agent is synthetic and its lies are the ones it was written to tell. This is
    not a real agent framework under real load.
16. **Two of five named external validation tools were functionally
    unavailable** (`# CONFIG_KPROBES is not set` blocks Tetragon and OBI), and
    one was unavailable entirely.

---

# Q. Milestone gates

## Q.1 What must be true before each claim can be upgraded

| claim to be upgraded | gate | current state |
|---|---|---|
| Software core → TRL 6 | a non-synthetic agent framework under representative load, with corroboration rates and a characterised false-positive rate | not started |
| Robotics profile → TRL 5 | ROS2 + Gazebo with a declared, non-independent ground truth, then a real controller boundary | not started |
| Physical accountability → TRL 4 | one physical quantity established by a mechanism reaching `from_attested` | **blocked on an `aip-observation` mechanism that does not exist** |
| UAS profile → TRL 5 | PX4 SITL with the flight stack treated as onboard, not independent | not started |
| Observation integrity → TRL 6 | the detector exercised outside the reproduction environment, across kernels and co-resident tooling | not started |
| Production readiness | the seven-item pre-production blocker list in `PRODUCTION_READINESS.md` | open |
| Any defence claim | a pilot with operator-side independent evidence | not started |

## Q.2 Verification note on the test suite

The forensic audit recorded **787 passing / 0 failing** on the production branch
at baseline `82da7a6`, and `FINAL_AUDIT_RECONCILIATION.md` records **925 passing
/ 0 failing** in `aip-standalone` at `a56e5c1` plus **39 / 0** in `aip-service`.

An independent re-run of `cargo test --workspace` was performed for this
addendum on the current head `12767ea`, on `cargo`/`rustc` 1.94.1, Linux
6.18.44-fc-v24, x86_64.

- **First attempt: 964 passed / 32 failed.** All 32 failures shared one cause
  and were **not** product defects — the `aip-edge-observer` helper binary was
  not present beside the test binaries, and every one panicked with that
  message from `aip-edge/tests/common/mod.rs:58`.
- **After `cargo build -p aip-edge-observer -p aip-edge-workload`:
  1,691 passed / 0 failed / 6 ignored / 165 test binaries / 0 warnings /
  exit 0.**

The second run's binaries include `build_boundary`, `key_custody`,
`managed_signing`, `replay_ingest` and `temporal_bound` — the `aip-service`
suites — so a single command now spans the protocol and the tier that serves
it. That is audit blocker **B-10** closed, demonstrably rather than by
assertion.

The first attempt is recorded rather than omitted, because a live-kernel suite
whose result depends on build ordering is itself a CI maturity finding
(§P.3.13). Full reproduction record in
`docs/ENGINEERING_MATURITY_SOURCE_MAP.md` §0 and §5.

---

# R. Conclusion

The evidence supports a strong engineering position and does not support a
finished product.

**What is strong.** The epistemic discipline is real, implemented, and unusual:
a default verdict of "cannot prove", an evidence ceiling that structurally bars
host-derived content from the top class, coverage re-derived rather than read,
a response ceiling that refuses to compose severity with confidence, and an
offline verifier that re-derives instead of believing. That discipline survived
its first contact with an independent external observer, and — more tellingly —
that same observer exposed a way to silently blind the observation layer, which
was then reproduced deterministically and closed in production without weakening
a single one of those properties.

**What is not finished.** The physical half of the thesis is architecture and
documentation. There is no robot, no airframe, no external tracker, no hardware
root of trust, no third-party security assessment and no field deployment. The
UAS and robotics profiles are careful, honest and unvalidated against hardware.

**What follows.** The next value-creating milestone is not a feature. It is the
first physical quantity established by an independent mechanism rather than
asserted by the machine that moved — because that is the single step that turns
"one accountability core, many autonomous worlds" from a design statement into
an engineering result.

---

> **ENGINEERING STATUS**
> TRL 5 overall; AIRI/Sniffer Dog software accountability core approaching TRL 6;
> physical autonomous-system validation pending.

> **This addendum reflects engineering and validation progress after the
> original forensic audit baseline. It does not retroactively alter the original
> forensic findings.**

---

**Companion documents**

- `docs/ENGINEERING_MATURITY_SOURCE_MAP.md` — claim → source → evidence type → status
- `docs/COMPETITIVE_POSITIONING.md` — competitive and adjacent landscape
- `docs/PRE_SERIES_A_10M_ROADMAP.md` — commercialization and fundraising roadmap
- `docs/TRL_AND_PHYSICAL_VALIDATION_ROADMAP.md` — TRL and physical validation stages
