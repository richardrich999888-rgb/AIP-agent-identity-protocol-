# What the tests prove — and what they do not

> **Status: normative, September 2026.** Written to answer one question
> directly: *do the tests in this repository prove that this system solves the
> problems AI agents create in the RBI ecosystem?*
>
> Every row below is checkable. Where a claim rests on a test, the test is
> named and can be run. Where no test supports a claim, the row says so rather
> than leaving the reader to assume one exists. This document exists because a
> readiness claim that cannot be falsified is not a readiness claim.

---

## 0. The answer, in one paragraph

**No.** The tests do not prove that this system solves the problems AI agents
create in the RBI ecosystem, and nobody should say to the Reserve Bank that
they do. They prove something narrower and worth stating exactly: *given
evidence this system produced, tampering with that evidence is detectable, and
the system will not assert coverage it cannot justify.* That is an
**evidentiary** property, not an outcome property. It is the thing every RBI
instrument in `RBI_AGENT_RISK_MAP.md` §1 assumes somebody has already built —
the IT Governance direction's "audit trails sufficient for forensics, dispute
resolution and non-repudiation", the Responsible Business Conduct amendment's
burden of proof on the bank, FREE-AI's AI inventory and incident reporting —
and it is not the same as preventing an agent from doing harm. Two further
limits are structural and no amount of additional testing inside this
repository removes them: **no test here has ever run on a regulated entity's
hardware, and no test here has observed an agent doing an institution's real
work.** Since the previous revision the *framework* on the other end has been
real and not ours — an unmodified LangGraph 1.2.11 graph, observed end to end,
with 167 process exec/fork events in the collector-signed archive and verified
offline — but the task it carried out was written in order to be observed and
the load was not representative. That narrows the second limit; it does not
remove it.

---

## 1. Why "the tests pass" is a weaker statement than it sounds

Three independent reasons, in order of how badly each would mislead a
supervisor.

**1.1 The tests were written by the party being tested.** Every attack in
`docs/security/ADVERSARIAL_RESULTS.md` is an attack we thought of — **with one
exception added since**: the Phase 4 section states the observer's coverage
against *Atomic Red Team*, mapped to MITRE ATT&CK, a corpus we did not write.
That section is a **coverage map, not a run log** — it says which techniques
the observer's sensors record, not that each technique was executed here — and
it marks 6 of 20 techniques **not covered**. It removes the "you only tested
what you invented" objection for *scope*; it does not remove it for *outcome*. A suite in
which the author picks both the property and the adversary cannot establish
that the property set is complete; it establishes only that the properties
chosen hold against the adversaries chosen. This is why blocker **B2** — an
independent security assessment by a CERT-In empanelled auditor — is on the
list and why removing it would be dishonest. It is also why pilot **Phase 5**
asks the institution's own auditor to reproduce offline verification with
their own keys: the first verification performed by somebody with no stake in
the answer is the first one that carries external weight.

**1.2 Most of the suite is synthetic and in-process.** The majority of tests
construct inputs in memory and assert on outputs in the same process. That is
the right way to pin an encoding, a state machine or a refusal rule, and it is
not evidence about a host. A smaller set is live — real kernel sensors, real
`/proc`, real separate operating-system processes, real `ntp_adjtime` — and
those are named as live in §3 rather than counted together with the rest.

**1.3 Most of what is proven is a refusal, not a capability.** A large share
of these tests assert that the system *declines* to say something: it declines
to call an unobserved window empty, declines to assert coverage while blinded,
declines to convert a missing gateway receipt into a finding. Refusals are the
rare and valuable half of this design — an observer that never admits to being
blind is the failure mode, not the success one — but a refusal is an honesty
guarantee, not an efficacy guarantee. "This system will not lie to you about
what it saw" and "this system stops agents misbehaving" are different
sentences, and only the first is supported.

---

## 2. What "proven" means here: four rungs

A claim in this repository sits on exactly one of these. Mixing them is how
readiness briefs become marketing.

| Rung | Meaning | What it is worth to a supervisor |
|---|---|---|
| **R1 By construction** | The property follows from the encoding or the type, and a test pins it. Example: container placement is excluded from `ObservedProcess::identity_bytes`, so a blind observer and a privileged one produce the same identity digest and a read failure cannot become a divergence. | Strong, and permanent. It cannot regress silently because the test fails if the encoding moves. |
| **R2 Adversarially tested, synthetic** | An attack is executed against real code with constructed inputs, and the recorded outcome is the refusal. Most of the 55-row RED suite. | Real, but bounded by the imagination of the person who wrote the attack. |
| **R3 Demonstrated live, development host** | The property was produced by real processes on a real kernel, and the raw output is sealed in the repository. Example: the foreign-eBPF gate attack against the two real daemons, and the offline verification of the archive that run produced. | The strongest thing in this repository today. Still a development virtual machine, which is not an institution's host. |
| **R4 Demonstrated in the target environment** | The property was produced on a regulated entity's hardware, against that entity's agent, and verified by that entity's auditor. | **Nothing in this repository is at R4.** This is blocker B8 and pilot Phases 1 and 5. |

**There is no R4 row anywhere in this document.** That is the honest headline.

---

## 2a. "All twenty roadmap items are done" — and why that is not the answer

It is true, and it is checkable. Every item **R1 to R20** in
`RBI_REQUIREMENTS_COVERAGE.md` §2 is built, each with named code and an
acceptance test, and the adversarial rows are reproduced by one command. Four
carry an explicit qualifier that must travel with them: **R5** is done on the
binding side, **R11** and **R16** are done as mechanisms whose *placement*
(where the witness runs, which hardware module, whose PIN) is the
institution's decision, and **R13** is done as controls whose *operation*
(RPO/RTO, off-site custody, drill cadence) is likewise the institution's.

**The roadmap is complete. The matrix is not, and the ecosystem is not.**
Those are three different statements and only the first is finished.

**2a.1 Completing a list you wrote yourself is a closed loop.** The twenty
items were derived from our reading of the RBI instruments in
`RBI_AGENT_RISK_MAP.md` §1. Finishing them establishes that we built what we
said was needed. It does not establish that what we said was needed is
sufficient, or that we read the instruments correctly. Only three things break
that loop, and none has happened: a run on a regulated entity's hardware, an
independent CERT-In empanelled assessment, and the institution's own auditor
reproducing verification with their own keys.

**2a.2 One matrix row is still open, and it is the load-bearing one.** Of
every requirement in sections A to F, exactly one remains **BUILD**: **C6**,
`PHANTOM_CLAIM` demonstrated on real hardware with the two-daemon pair. It is
narrowed — the live foreign-eBPF attack against both real daemons has been
executed and the collector signed `IntegrityUnknown` — but the verdict itself
still needs the decision point issuing signed expectations into the same
pipeline, and all of it on an institution's hosts. No roadmap item closes C6;
pilot Phases 2–3 do. A reader who sees twenty green roadmap rows and concludes
the matrix is green has drawn the wrong inference, which is why this section
exists.

Four further rows are `INTEGRATE` — the mechanism is built and the
institution supplies the other half: where the anchoring witness runs (D3),
what a kill-switch trigger is wired to (E3), and two governance artefacts the
regulated entity must hold and maintain itself (F1, F3). Those are not
defects and they are not ours to close.

**2a.3 Twenty items cover the accountability domain, not the ecosystem.**
Section **G** of the matrix is out of scope by design and lists the owner for
each: model bias and drift, explainability of a model's decision, customer
disclosure and grievance redress, transaction-content fraud scoring,
concentration risk. Those are among the *critical* problems AI agents create
in Indian financial services, and nothing in R1–R20 touches them. The
accountability and evidence domain is covered completely; the ecosystem is
covered partially and deliberately.

**2a.4 Every one of the twenty is at rung R1, R2 or R3.** See §2. The roadmap
was never capable of producing an R4 row, because an R4 row is produced by an
institution, not by us.

---

## 3. The ten failure classes, scored

Classes are those in `RBI_AGENT_RISK_MAP.md` §2. "Verdict" is the highest rung
reached, not the aspiration.

| # | Failure class | Highest rung | What the tests actually establish | What is missing before this is solved |
|---|---|---|---|---|
| **F1** | The agent acts outside its mandate | **R3** | An action with no signed authorization behind it reconciles to `UNATTRIBUTED_EFFECT` at `Attested` strength, from kernel-observed execution against the decision point's signed statement that no authorization existed in that window. The decision point is a separate signing authority; a manipulated agent cannot mint its own expectation. Live in `ghost-demo/tests/live.rs`, `live_coverage.rs`. | The observed fact is "unauthorised connection to host H at time T by process P", not "unauthorised ₹5,00,000 transfer to beneficiary B". Payload-level attribution needs the agent framework or the institution's gateway to sign its tool calls — built as a format and a verifier, **not** wired at any gateway (blocker B10). |
| **F2** | The agent claims work it never did | **R2** | `PHANTOM_CLAIM` is reachable: authorization existed, and an observer with **gate-independent kernel-pushed coverage** of the window saw no execution. The netlink connector is the only coverage the reconciler accepts for a non-occurrence claim; without it the answer is `CANNOT_PROVE`, and the live suite asserts the system does *not* manufacture a phantom claim without coverage. | **The commercially central verdict has never been produced end to end on live hardware.** It is reachable by construction and on synthetic inputs only. Closing it needs the decision point issuing signed expectations into the two-daemon pipeline (pilot Phases 2–3) on an institution's host. This is matrix row **C6**, open. |
| **F3** | Something other than the authorised agent does the work | **R3** | Process identity is the executable's content hash plus the process instance (pid, start ticks, boot id), never the PID or the path; a reused PID and a renamed binary are both handled. Container placement is read independently by the observer, and "one side did not record it" answers `ContainerNotComparable` rather than manufacturing a difference. | Identity of the *process*, not of the *model or prompt* inside it. Two agents running the same binary with different system prompts are one identity to this system. |
| **F4** | The observer is blinded and nobody notices | **R3** | The load-bearing result. A foreign eBPF program returning 0 on a sampled tracepoint suppresses events host-wide with no dropped-record accounting. Against the two real daemons, the off-host collector — different process, only key — signed `IntegrityUnknown` and **withdrew attested coverage**, while the chain sequence advanced throughout, so it was neither loss nor a continuity break but a live observer stating it could not vouch for its own capability. Rows OI-13..OI-15, raw output sealed. | The attack is **detected, not prevented**: a `CAP_BPF` adversary can blind the sensor and this is not claimed otherwise. A full-root attacker can additionally hide the program from the detection query (OI-08, deferred). And it ran on a development VM. |
| **F5** | Evidence is altered after the fact | **R3** | Editing, deleting, reordering or duplicating an attested record all fail verification; heads are **recomputed** from each record's bytes, so a forged `prev_head` cannot be made to agree with a doctored predecessor. Deletion and reordering leave every surviving signature genuine — only the chain check catches them, which is why it exists. Rows EA-01..EA-10, and run live against the archive a running collector produced. | Detection, not prevention, and it bounds tampering **after** collection. A host with root can lie to its own probe before anything is signed; the collector attests what it received, not what happened. |
| **F6** | The clock under the evidence is wrong | **R3** | The kernel's `ntp_adjtime` view — whether a daemon was steering the clock, and the kernel's error bound — is inside the bytes the key signs (protocol 12). Editing, dropping or inserting the reading after signing each fails verification, and a record carrying no reading is encoded distinctly from one carrying a good reading, so silence never reads as "fine". Rows CL-01..CL-09. | Root on the collector host can clear the synchronisation flag on a clock it has just moved. Signing raises the bar from "trust the operator's log" to "the key signed this claim", and no further. Choosing and running the NTP sources is the institution's. |
| **F7** | The evidence store is the weak link | **R2** | Row-level security, revoked `DELETE`, append-only triggers, legal hold and a 180-day retention floor are enforced by PostgreSQL under a role the service does not hold — and an exercised restore drill proves those controls **survive** a backup and restore, which is the half a naive drill skips. | Run against a throwaway cluster this harness creates, not an institution's database. RPO/RTO, off-site custody, backup encryption and drill cadence are the entity's to set and are not tested here. |
| **F8** | Authority is delegated too widely | **R2** | Delegation attenuates only; an issuer must hold the parent grant; a hop that tries to widen a resource grant is refused; self-issued authority is refused when the verifier demands independence; destinations resolve against a signed registry and an unregistered one is refused **before** the act. | The refusal is at this system's decision point. An institution whose agents reach the network by another path is not covered by it, and this system is advisory: it does not block. |
| **F9** | Nobody can verify without the vendor | **R3** | Three offline verifiers, one per evidence family: evidence packets, log heads and proofs, and — new — the observer's own chain of attested batches and signed health. The last is run in the live harness given two files and one public key, opening no socket and reading nothing from us, and then made to refuse the same archive with one record deleted. | **No third party has done this yet.** Verification performed by the party that produced the evidence is a consistency check. Pilot Phase 5 is where this becomes worth something. |
| **F10** | Concentration on one vendor's account of events | **R1** | External anchoring: a witness on a system the log operator does not control, holding a key the operator does not have, countersigns log heads, so a rewritten log cannot produce a receipt for the head it discarded. An independent cross-check against auditd is built. | Where the witness runs and who holds its key is a deployment decision nobody has made. The cross-check has not been run against an institution's own Tetragon or auditd deployment. |

---

## 3a. The failure class §3 was missing

The ten classes above come from `RBI_AGENT_RISK_MAP.md`, which was written
about agents that *use* the accountability channel. There is an eleventh, and
its absence from that list was a real gap in a document whose purpose is to
be honest about gaps.

| # | Failure class | Highest rung | What exists | What is missing |
|---|---|---|---|---|
| **F11** | **The agent declines to use the channel at all** | **R2** | Everything else in this repository is *inline*: it proves what went through the funnel. An agent that calls a tool server directly, keeps running after its credentials were revoked, spawns a copy of itself, or has its identity borrowed never touches the funnel, so none of it appears in the ledger. **Inline enforcement cannot see its own bypass**, and a stricter gateway does not help, because a stricter gateway is still one an agent can decline to use. `ot-sentinel` (merged 2026-09-20, 82 tests passing) closes it by *reconciliation*: independent sensors report what happened, the sentinel compares that against what the ledger sealed, and the difference is the finding. Matching is one-to-one on the digest of the canonical call parameters, so a ghost cannot hide behind a concurrent legitimate call of the same tool, and a replayed call has no second packet to account for it. **Since 2026-09-20 its effect sensor is fed from the kernel.** Its detector previously read a JSONL log of process launches and egress written, in the deployment it was designed for, *by the components being watched* — its own source says the detector "had nothing feeding it". `aip-sentinel-feed` (34 tests) now renders AIP's collector-signed, pidfd-bound kernel evidence into that sensor's schema, verifying the archive under its anchor first and emitting nothing if that fails. `aip-feed-conformance` (4 tests) proves the join against the real Phase-1 archive: **0 malformed lines** through the consumer's own tailer, an unapproved destination becoming a finding that cites the feed's record id, and an approved one producing none. | Its 31 integration tests (`ghost_hunt.rs`) **still cannot run here**: they need `ot-mcp-gateway` and `ot-pqc`, and `ot-pqc` was not part of the import, so the full ghost hunt remains unexercised in this workspace. It has also never been run against a real deployment's sensors — the same limit as every other row. |

**Why this belongs in this document rather than only in a changelog.** §1.1
says the tests were written by the party being tested, and the worked example
of that problem is this class: it went unlisted not because anyone decided to
omit it, but because the risk map and the test suite were written from the
same vantage point — inside the funnel. An outside assessment is what finds
the class you did not think to name, which is why blocker B2 is on the list.

**Now carried into the submission — as an architecture item, not a validation
result.** `ot-sentinel` arrives with an evidence-chain format that is **not
byte-compatible** with this system's. That decision is now made:
`docs/adr/ADR-EVIDENCE-CHAIN-FORMAT.md` is **closed** under bounded
coexistence — `aip-core` is the evidence format everywhere outside the import,
the second stays internal to the sentinel's reconciliation path, and the
dependency guard test is permanent and was re-verified against a deliberate
violation. The feed did not require resolving the conflict, because the
conflict is on the *evidence* side and the feed touches only the *observation*
side, which carries no chain: the coupling is a file, not a link.

**And it is explicitly not corroboration.** `ot-sentinel` is ours. §10a and
§10b of the technical brief are corroboration because bpftrace, auditd and
SPIRE were built by other people. This is §10c, filed as an architectural gap
closed with our own components, and the brief says so in those words. Anyone
quoting it as a third corroboration axis is misreading it.

---

## 4. What is not in scope at all, and who owns it

Claiming these would be false, and RBI would find it. They are listed so the
absence is deliberate rather than an oversight.

| RBI concern | Owner |
|---|---|
| Model bias, fairness, drift, data quality (MRM; FREE-AI fairness) | The institution's model risk function and its model vendors |
| Explainability of a model's decision (MRM) | Model vendors; RE model validation |
| Customer disclosure, consent, grievance redress (DPDP; Digital Lending) | RE compliance; consent managers |
| Transaction-content fraud scoring, mule detection (MuleHunter / IDPIC) | RBIH, IDPIC, RE fraud teams |
| What was said inside a TLS session or a chat | The agent framework (signed tool calls) and the gateway (signed receipts) |
| Root or kernel compromise of the observed host | Host hardening; hardware attestation; off-host observation research |
| Concentration risk across vendors (the Governor's seven risks) | The RE board; RBI supervision |

This system covers **the accountability and evidence domain, and only that.** A
vendor claiming all seven rows above is the vendor FREE-AI warns regulated
entities about.

---

## 5. The four claims that are supported, stated as they should be said

Everything above reduces to four sentences that can be defended under
questioning. Nothing broader should be said.

1. **"An action this system observed can be attributed to a process, and that
   attribution cannot be altered afterwards without detection."** — R3.
2. **"When this system could not see, it says so in a signed record, and the
   silence in that window is never presented as evidence that nothing
   happened."** — R3, and the one demonstrated against a live attack.
3. **"The account is verifiable by your side, offline, with keys you hold and
   no call to us."** — R3 mechanically; **R2 in the sense that matters**, because
   your auditor has not yet done it.
4. **"Everything this system cannot establish, it names."** — this document is
   that claim being exercised.

And the sentence that must **not** be said: *"our tests prove we solve the
agent accountability problem for Indian regulated entities."* The tests prove
properties of an evidence layer on a development host against attacks we chose.

---

## 6. What would move the answer toward "yes"

Falsifiable, ordered by how much each changes the answer. Each is a gate, not a
milestone: it either happened or it did not.

1. **Run Phase 1 on a regulated entity's hardware** with the collector on a
   genuinely separate host (blocker **B8**). This is the only item that creates
   an R4 row, and until it happens every rung above is capped at R3.
2. **Produce `PHANTOM_CLAIM` end to end live** — decision point issuing signed
   expectations into the two-daemon pipeline, reconciler concluding an
   authorised action never executed (matrix row **C6**, pilot Phases 2–3). This
   is the class REs are actually buying against (F2), and it is the weakest row
   in §3.
3. **An independent CERT-In empanelled assessment**, with remediation
   (blocker **B2**). It is the only thing that addresses §1.1.
4. **The institution's own auditor reproduces offline verification** with their
   own keys (pilot Phase 5), which is the only thing that addresses F9's gap.
5. **Gateway receipt issuance at the institution's API or MCP gateway**
   (blocker **B10**), which is what moves F1 from "unauthorised connection" to
   "unauthorised transaction".

Until at least 1 and 2 are done, the correct description of this system to a
supervisor is: *built, adversarially tested, demonstrated live on a
development host, and not yet run in an institution.*

---

## 7. How to check any of this yourself

```bash
# Every adversarial row in the ledger, run against the code.
validation/red_suite/run.sh

# The live two-daemon attack and the offline verification of what it produced.
# Needs root (or CAP_BPF + CAP_PERFMON + CAP_NET_ADMIN) and tracefs.
validation/pilot_e2e/run.sh

# The storage controls, against a real PostgreSQL, including that they
# survive a backup and restore.
deploy/sql/restore_drill.sh

# F11: AIP's kernel evidence rendered as the out-of-band reconciler's input,
# and the reconciler actually parsing and acting on it.
cargo test -p aip-sentinel-feed
cargo test -p aip-feed-conformance

# The closed ADR's boundary, still enforced.
cargo test -p aip-test --test evidence_chain_boundary

# The whole suite.
cargo test --workspace
```

A row in `docs/security/ADVERSARIAL_RESULTS.md` that the RED suite cannot
reproduce is a row that should not be believed, and the runner reports those
separately rather than counting them as passes.
