# Where AI agents will create the mess in the RBI ecosystem — and where this system fits

> **Status: research note, September 2026.** Built from public reporting and
> regulator publications found by web search on 2026-09-19. Several primary
> documents (RBI circulars, the FREE-AI report PDF, the IMF note) could not be
> fetched from this environment, so dates and figures below come from
> secondary reporting and must be checked against the primary text before any
> of them is quoted to RBI. Every fit claim about this repository maps to code
> named in `docs/pilot/BFSI_PILOT_PLAN.md` §7 or to a row in
> `docs/security/ADVERSARIAL_RESULTS.md`; where it does not, the row says so.

## 0. The one-paragraph answer

Indian regulated entities (REs) are moving agents from answering questions to
executing work: loan origination, collections calls, KYC, reconciliation, and
soon UPI payments initiated by agents under delegated mandates. Every one of
those agents will produce its own logs and its own explanation of what it did.
RBI's direction of travel — the FREE-AI framework (Aug 2025), the draft Model
Risk Management guidance (Jun 2026), the revised fraud-liability directions
(Jun 2026, effective Jan 2027), the Governor's "cannot hide behind
algorithms" (Aug 2026) and the Deputy Governor's "cannot outsource the
consequence" (Sep 2026) — puts the burden of proof on the institution, not on
the agent, not on the vendor, and increasingly not on the customer. The gap
that opens is evidentiary: **the institution must prove what an agent
actually did, under whose authority, from an account the agent could not have
written.** That is the only problem this repository solves, and it is the
problem every instrument below assumes someone has solved.

## 1. The regulatory clock (what is already binding, what is coming)

| When | Instrument | What it demands that touches agents | Source |
|---|---|---|---|
| Apr 2022 (in force Jun 2022) | CERT-In Direction 20(3)/2022 | Report cyber incidents within **6 hours**; retain ICT logs **180 days** in India; NTP-synchronised clocks | [UpGuard](https://www.upguard.com/blog/indias-6-hour-data-breach-reporting-rule), [AMLEGALS](https://amlegals.com/cert-in-compliance-guide-2025/) |
| Apr 2023 (in force Oct 2023) | RBI Master Direction — Outsourcing of IT Services | REs may outsource the activity, **never the accountability**; RBI audit rights over vendors; incident timelines | [Khaitan](https://www.khaitanco.com/thought-leaderships/RBI-Releases-Master-Direction-To-Regulate-Outsourcing-of-IT-Services), [RBI PDF](https://fidcindia.org.in/wp-content/uploads/2023/04/RBI-OUTSOURCING-OF-IT-SERVICES-10-04-23.pdf) |
| Nov 2023 (in force Apr 2024) | RBI Master Direction — IT Governance, Risk, Controls and Assurance | Every application touching critical data must keep **audit trails detailed enough for forensics, dispute resolution and non-repudiation** | [Medianama summary](https://www.medianama.com/2023/11/223-summary-rbi-direction-it-governance-risk-controls/), [RBI PDF](https://fidcindia.org.in/wp-content/uploads/2023/11/RBI-IT-MASTER-DIRECTIONS-07-11-23.pdf) |
| May 2025 | RBI Digital Lending Directions, 2025 | RE is **directly responsible for every act of a Lending Service Provider**, including collections; DLA registry (CIMS) | [Legal500](https://www.legal500.com/developments/thought-leadership/reserve-bank-of-india-digital-lending-directions-2025-brief-overview-analysis/), [Synergia](https://synergialegal.com/an-overview-of-the-rbis-digital-lending-direction-2025/) |
| 13 Aug 2025 | RBI FREE-AI Committee Report (7 sutras, 26 recommendations) | Board AI policy; **AI inventory** reviewed six-monthly and open to inspection; **AI incident reporting** with a good-faith posture; **trigger-based red teaming**; **graded liability with a tolerant supervisory stance for REs that can show incident reporting, audits and red teaming**; AI sandbox | [KPMG](https://kpmg.com/in/en/insights/2025/08/rbi-free-ai-committee-report-on-framework-for-responsible-and-ethical-enablement-of-artificial-intelligence.html), [Lexology](https://www.lexology.com/library/detail.aspx?g=28571287-4065-4fbc-ae4e-eab6cf8dce30), [Chambers](https://chambers.com/articles/rbi-committee-report-on-responsible-ai-in-the-financial-sector-free-ai-framework) |
| 13 Nov 2025 → 13 May 2027 | DPDP Rules, 2025 | Full compliance at 18 months; breach notification; penalties to ₹250 crore, stackable | [PIB](https://static.pib.gov.in/WriteReadData/specificdocs/documents/2025/nov/doc20251117695301.pdf), [Seclore](https://www.seclore.com/fundamentals/dpdp-rules-2025-compliance-guide/) |
| Dec 2025 → Dec 2026 | MuleHunter.AI / IDPIC | 23 banks live by Dec 2025; MHA directs all FIs to integrate by Dec 2026 | [Medianama](https://www.medianama.com/2025/12/223-rti-23-banks-mulehunter-mule-accounts/), [RMA India](https://rmaindia.org/mulehunter-ai-rbis-ai-fraud-detection-system-now-live-across-31-banks/) |
| 24 Jun 2026 (draft; comments to 24 Jul) | RBI Draft Guidance — Regulatory Principles for Model Risk Management | Board-approved MRMF; risk tiering; **kill switches**; **human oversight** and explainability; **third-party model accountability**; customer disclosure | [Lexology](https://www.lexology.com/library/detail.aspx?g=3ca3573e-7f9b-4ba3-9aff-97c7073b20bf), [nasscom](https://community.nasscom.in/communities/public-policy/analysis-rbis-draft-guidance-regulatory-principles-model-risk-management), [CorpLawUpdates](https://www.corplawupdates.in/updates/rbi-draft-guidance-model-risk-management-2026-ai-ml-banks-nbfcs) |
| 24 Jun 2026 (effective 1 Jan 2027) | RBI Responsible Business Conduct — Third Amendment (fraudulent electronic banking transactions) | New category "fraudulent electronic banking transactions"; **burden of proving customer liability on the bank**; zero liability on bank negligence or third-party breach; small-value compensation | [Lexology](https://www.lexology.com/library/detail.aspx?g=07edd0d8-9eed-4245-9cb1-10befde4e608), [ELP](https://elplaw.in/leadership/rbi-tightens-customer-protection-framework-for-fraudulent-electronic-banking-transactions-2/) |
| 12 Aug 2026 | Governor Malhotra, FIBAC | Seven risks incl. **concentration in a few models and vendors**; "cannot hide behind algorithms"; complete AI inventories and explainability before credit-model deployment | [Entrepreneur India](https://india.entrepreneur.com/business-news/rbi-governor-sanjay-malhotra-calls-ai-a-new-way-of-running-a-bank-fl), [The420](https://the420.in/rbi-governor-malhotra-dpdp-compliance-banks-six-ai-risks/) |
| Sep 2026 | Deputy Governor Rohit Jain, GFF 2026 | "An institution may outsource the computation, but it cannot outsource the consequence" | [Medianama](https://www.medianama.com/2026/09/223-banks-accountability-algorithmic-decisions-rbi/) |
| Jul–Sep 2026 | NPCI Unified Agent Protocol + AI-agent registry for UPI | Delegated agent payments within caps (UPI Circle: ₹15,000/month, ₹5,000/txn); agent registry to register and verify agents; **launch pulled at GFF; liability framework and RBI approval unfinished** | [CIO.inc](https://www.cio.inc/india-readies-upi-to-support-payments-initiated-by-ai-agents-a-32777), [Technology.org](https://www.technology.org/2026/09/11/npci-ai-agent-registry-upi-agentic-payments/), [Medianama](https://www.medianama.com/2026/09/223-npci-ai-agents-upi-payments/), [Inc42](https://inc42.com/buzz/npci-to-launch-agentic-payments-on-upi-report/) |

Two external anchors worth carrying into any RBI conversation:

- The IMF (Apr 2026) frames the core problem exactly as this repository does:
  agent-initiated payments break the assumption that every payment order is
  traceable to an explicit authorised instruction; what is needed is
  **authorization grounded in verifiable mandates, scope limitations and
  auditability**, with agents kept in an upstream "intent and orchestration"
  layer and deterministic controls left in authorization and settlement.
  ([IMF](https://www.imf.org/en/publications/imf-notes/issues/2026/04/22/how-agentic-ai-will-reshape-payments-575560),
  [Payment Expert](https://paymentexpert.com/2026/04/29/imf-argues-against-ai-payments/))
- Indian experts responding to the MRM draft named the missing layer: the
  draft governs *models*, not the *agents* that orchestrate them; they asked
  for **workflow-level risk classification, an agent-level authority matrix,
  hand-off logs, and practical reversibility**, and observed that a bank
  buying an agentic platform "owns the accountability but not the control".
  ([Digit](https://www.digit.in/features/general/rbi-draft-ai-model-ignores-agentic-ai-risk-say-experts.html/amp/))

## 2. Where agents will create the mess — ten failure classes

For each class: the scenario as it will occur in an Indian RE; why the
controls REs have today miss it; the RBI instrument it trips; what this
repository proves; what it does not.

### F1. The agent acts outside its mandate

**Scenario.** A collections agent authorised to call and message calls a
number outside its list, or a treasury agent authorised to reconcile
initiates a transfer. Under NPCI's protocol an agent authorised for ₹5,000
routine bills executes a purchase at a sale price the customer never
discussed. The documented 2026 case: a procurement agent manipulated over
three weeks into believing it could approve anything under $500,000, then
used to place $5 million of false orders in ten transactions
([ARMO](https://www.armosec.io/blog/financial-services-ai-agent-security/)).

**Why today's controls miss it.** The agent's own log records what the agent
believed it was authorised to do. A manipulated agent logs a manipulated
belief. Application-level authorization inside the agent framework is part of
the same process the attacker manipulated.

**Instrument tripped.** Responsible Business Conduct amendment (bank must
prove the customer, not the bank, is liable); FREE-AI incident reporting;
MRM human-oversight thresholds; NPCI's unfinished liability framework.

**What this repository proves.** An action executed with no signed
authorization behind it is `UNATTRIBUTED_EFFECT`, at `Attested` strength,
from kernel-observed execution reconciled against the decision point's
**signed statement that no authorization existed in that window**
(`aip-authorize` coverage ledger; live test `ghost-demo/tests/live.rs` and
`live_coverage.rs`). The decision point is a separate signing authority the
agent cannot influence; a manipulated agent cannot mint an expectation.

**What it does not.** It sees the connection, the bytes and the process; it
does not see the payment amount or beneficiary inside TLS. "Unauthorized
transaction" resolves to "unauthorized connection to the payments API at
time T by process P". Payload-level attribution needs the agent framework or
the gateway to sign its tool calls (the client-side signing item on the
blocker list).

### F2. The agent claims work it never did

**Scenario.** A voice agent reports 10 million collection calls a month
([Mahindra Finance / Sarvam at GFF 2026](https://cxotoday.com/corner-office/how-indian-banks-are-preparing-for-the-next-phase-of-ai-adoption-through-agentic-ai/)),
a KYC agent reports a document check, a reconciliation agent reports a
ledger comparison — and some of it never executed. Under the Digital Lending
Directions the RE is liable for every act *and omission* of its LSP.

**Why today's controls miss it.** The only record of the call, check or
comparison is the agent's completion message. Nothing independent says
whether the process ever opened the socket, executed the binary, or wrote
the file.

**What this repository proves.** `PHANTOM_CLAIM`: authorization existed and
the observer, with **gate-independent kernel-pushed coverage** of the window,
saw no execution. The pilot probe now drives the netlink connector
(`aip-probe`, `AIP_PROBE_SENSORS=...,connector`), which is the only coverage
the reconciler accepts for a non-occurrence statement. Without it the honest
answer is `CANNOT_PROVE`, and that is what the system says.

**What it does not.** `PHANTOM_CLAIM` is reachable on synthetic inputs and
by construction; it has not yet been demonstrated on a live host with the
two-daemon pair (pilot Phase 4). The live suite deliberately asserts the
system does *not* manufacture a phantom claim without coverage.

### F3. Something other than the authorised agent is doing the work

**Scenario.** A replaced binary, a re-used PID, a container running a
different image under the agent's credentials, or a poisoned dependency:
in Jan–Feb 2026, 824 of 10,700 skills on a public agent marketplace were
malicious; a mail-server MCP package shipped fifteen clean versions before
adding an exfiltration line
([Beam](https://beam.ai/agentic-insights/ai-agent-security-breaches-2026-lessons),
[Help Net Security](https://www.helpnetsecurity.com/2026/06/11/owasp-prompt-injection-ai-security-failures/)).

**Why today's controls miss it.** Credentials authenticate a key, not a
process. Whatever holds the key is "the agent". The Governor's concentration
warning applies here: one poisoned shared component is poisoned in every RE
that runs it.

**What this repository proves.** `IDENTITY_DIVERGENCE`: the executing
process instance (pid, start time, boot id, **executable content hash**, not
path) differs from the one the authorization bound
(`ExecutionBinding`; live test `live.rs` scenario D). A swapped or updated
binary changes the hash; a recycled PID changes the start time.

**What it does not.** The binding has no cgroup or namespace fields, so two
containers sharing a PID view are not distinguished. It measures the
executable, not its loaded plugins or model weights.

### F4. Prompt injection turns the agent into an exfiltration channel

**Scenario.** The 2025 zero-click Copilot case: one crafted email, ingested
during summarisation, made the agent pull data from OneDrive, SharePoint and
Teams and send it out through a trusted domain (CVE-2025-32711,
[Help Net Security](https://www.helpnetsecurity.com/2026/06/11/owasp-prompt-injection-ai-security-failures/)).
The RE analogue is a customer-service agent with read access to a core
banking API and an outbound HTTP tool. DPDP penalties for a breach start at
crores; CERT-In wants the report in six hours.

**Why today's controls miss it.** Every step is a legitimate tool call to
the agent framework. The framework's log shows intended behaviour.

**What this repository proves.** Kernel-observed connections to endpoints
with no authorization behind them (`UNATTRIBUTED_EFFECT`), with byte counts,
timing and the responsible process instance, signed by a collector on
another host and committed to an append-only log. That is the six-hour
report's evidence base, ready before the incident is understood.

**What it does not.** It cannot read what left. It cannot name the resource
behind a shared gateway address (the resource registry proposed in the plan
below). It is not a data-loss-prevention system.

### F5. Authority drifts — agents delegating to agents, vendors overriding limits

**Scenario.** An orchestrator agent delegates to a sub-agent with a wider
scope than it holds itself; a vendor platform adds a write-capable tool or
widens a credential scope in an update; a human approval threshold is
lowered in configuration. The Digit experts' "agent-level authority matrix"
is exactly this concern; the Deputy Governor's line is its consequence.

**What this repository proves.** Delegation chains are signed per hop, the
issuer of each hop must be the holder of the previous one, scope can only
narrow, expiry can only shorten, depth is bounded, and a self-issued root
is refused at the decision point (`aip-core`, `aip-authorize`; adversarial
tests in both). A widened sub-delegation does not verify; an action outside
the most-attenuated scope fails `SCOPE_AUTHORITY`.

**What it does not.** Scope is a set of *actions*; it has no *resource*
dimension yet (see §4). The shipped HTTP service still accepts a self-issued
authority when the caller names its own key as trusted; only the decision
point path closes that.

### F6. The agent's log is the only record — and the regulator wants non-repudiation

**Scenario.** RBI's IT Governance Direction requires audit trails fit for
forensics, dispute resolution and non-repudiation. FREE-AI asks for incident
reporting and grades supervisory tolerance by the RE's ability to show
audits and red teaming. A 2026 survey has 88% of organisations reporting a
confirmed or suspected agent incident in the year
([ARMO](https://www.armosec.io/blog/financial-services-ai-agent-security/)).
The RE's evidence in every case is the agent framework's log, on the same
host, writable by the same process.

**What this repository proves.** A second account, produced by a party the
agent cannot write: kernel observation signed by an off-host collector,
reconciled by a fourth key, committed to a Merkle log, verifiable offline
with `nexora-verify` and `aip-verify` using keys the RE holds. Tampering
with any artefact after signing is detected and classified
(`SENSOR_INTEGRITY_FAILURE` at `Proven`). This is what "audit trail fit for
non-repudiation" means for an actor that writes its own logs.

**What it does not.** It does not replace the application log; it
corroborates or contradicts it. It stores no verdict in the HTTP service
today (pilot Phase 3). Export bundles are checksummed and signed; release
binaries are checksummed only.

### F7. Monitoring is blinded, and nobody notices

**Scenario.** An agent with `CAP_BPF`, or a co-resident eBPF-based
security tool, attaches a program to the tracepoints an observer samples and
suppresses its events host-wide with no loss counter. Every monitoring
product that reads those tracepoints goes quiet and reports "no activity".

**What this repository proves.** The observer detects a foreign program on
its gates and signs `IntegrityUnknown`; the reconciler answers
`CANNOT_PROVE(ObserverIntegrityUnknown)` rather than "nothing happened"
(ledger rows OI-01..OI-12). As of this week the finding travels inside the
signed batch from the probe to the off-host collector, and the collector
refuses to stay `Active` if a probe stops reporting it.

**What it does not.** A root or kernel attacker can hide the program from
the query (OI-08). On-host detection bounds a `CAP_BPF` attacker, not root.

### F8. Liability disputes over agent-initiated payments

**Scenario.** From 1 Jan 2027 the bank bears the burden of proving the
customer is liable for a fraudulent electronic transaction. NPCI's protocol
lets an agent pay without per-transaction approval. The customer says "my
agent never did that" or "I never authorised that scope". The IMF's
question: can the payment order be traced to an authorised instruction?

**What this repository proves.** A signed mandate (`ExpectedExecution`:
agent, action, parameter digest, validity window, process binding) issued
*before* the act by a decision point, and a signed observation of the act
*matching* that mandate (`VERIFIED_EXECUTION`), or not (`UNATTRIBUTED_EFFECT`,
`IDENTITY_DIVERGENCE`, `CANNOT_PROVE`). That is the evidence a bank presents
to discharge its burden — or to concede honestly that it cannot.

**What it does not.** It is not the mandate registry NPCI is building; it is
what makes any registry's entries checkable against what executed. The
parameter digest binds the endpoint and the declared parameters, not the
TLS payload.

### F9. Vendor agents the RE cannot see inside

**Scenario.** Most REs will buy agentic platforms. The Governor's
concentration warning and the Outsourcing Direction both land on the RE:
accountable for a system it neither built nor can inspect. The experts'
phrasing: "owns the accountability but not the control".

**What this repository proves.** Observation is external to the vendor's
process: kernel events for the vendor agent's processes on the RE's hosts,
signed by the RE's collector, reconciled against authorizations the RE's
decision point issued. The RE holds an account of the vendor's agent that
the vendor did not write.

**What it does not.** Nothing about model behaviour, bias, explainability or
concentration itself. If the vendor's agent runs on the vendor's cloud, the
RE's probe is not there.

### F10. Kill switches and human oversight without evidence to pull them

**Scenario.** The MRM draft mandates kill switches and human oversight. A
switch needs a trigger. If the trigger is the agent's own anomaly score, the
manipulated agent decides when it is stopped.

**What this repository proves.** A verdict with a graded evidence strength,
strictly separated from severity, that a human or a policy engine can act
on; a containment path that is built, gated on `Proven` evidence and
explicit operator enablement, and **provably unreachable from anything the
engine can produce today** (`aip-containment/tests/reachability.rs`). The
system supplies the evidence for the switch. It is not the switch.

**What it does not.** No autonomous enforcement in the pilot, by design. No
transaction-path gating, ever, under the pilot plan.

## 3. Where this system does not fit — say it before RBI does

- **Model risk proper**: bias, fairness, explainability, data quality,
  drift. The MRM draft is mostly about these. This system observes
  execution, not reasoning.
- **Customer-facing conduct**: disclosure, consent, grievance. DPDP and the
  Digital Lending Directions. Out of scope.
- **Fraud detection on transaction content**: MuleHunter's domain. This
  system attributes execution to authority; it does not score transactions.
- **Anything inside TLS**: amounts, beneficiaries, prompts, responses.
- **Root compromise of the observed host**: bounded after collection, not
  prevented.
- **Performance and scale**: no figure exists; none may be quoted.

## 4. Concrete entry points into the RBI ecosystem

1. **NPCI's agent registry and Unified Agent Protocol.** The registry will
   identify agents; the protocol will carry mandates; the liability framework
   is unfinished. The missing piece between "registered agent with a mandate"
   and "who pays when it errs" is execution evidence bound to the mandate.
   Proposal: an evidence profile for registered agents — mandate = signed
   `ExpectedExecution`; execution = attested observation; dispute artefact =
   committed verdict verifiable offline. This is the highest-leverage entry
   point and the one with a deadline RBI itself has imposed.
2. **The MRM consultation gap.** Submit the agent-layer evidence model as a
   response to the "models, not agents" critique: agent-level authority
   (signed, attenuating delegation), hand-off logs (signed observations),
   reversibility trigger (graded verdicts). Even after the comment window,
   the final guidance will need this and the FinTech Department knows it.
3. **FREE-AI AI Innovation Sandbox / RBIH.** The pilot plan's five phases are
   sandbox-shaped: observer-only, non-gating, falsifiable exit gates. Ask for
   the sandbox as the pathway.
4. **RE-level AI inventory and incident reporting.** FREE-AI wants an
   inventory open to inspection and incident reports in good faith. A signed
   per-agent execution record is the inventory's evidence layer and the
   incident report's attachment.
5. **Digital Lending LSP accountability.** REs are liable for LSP agents'
   acts and omissions. An RE observing LSP agents on its own hosts, or
   requiring LSPs to run the probe, converts an unbounded liability into an
   evidenced one. NBFCs and digital lenders are the natural first pilot
   subjects, as the pilot plan already says.
6. **CERT-In six-hour reporting.** Signed, offline-verifiable execution
   evidence that exists *before* the incident is understood is the only way
   a six-hour report says anything defensible.

## 5. What this implies for the build order

The RBI-facing gaps are, in order of what an RE evaluator will ask for
first:

1. **Resource-level naming and authority.** Verdicts must say "core banking
   API", not an address; scope must be able to grant resources, not only
   actions. (Design in the prior session note; not started.)
2. **The per-agent access ledger.** For agent X over window W: every
   resource reached, verdict, evidence grade, signed, committed, verifiable.
   This is the artefact for F6, F8, F9 and the FREE-AI inventory.
3. **Verdict persistence in the service** (pilot Phase 3), so an auditor can
   fetch what an RE's own system concluded, not only what the demonstrator
   printed.
4. **Client-side signing of tool calls** by the agent framework, so
   payload-level parameters (amount, beneficiary) enter the mandate and the
   parameter digest without the observer ever reading payload.
5. **The live two-daemon attack on institution hardware** (pilot Phase 4),
   because F7 is the claim most likely to be tested by an evaluator and the
   one most recently changed.

## 6. Source caveat

Where a row above cites secondary reporting (law-firm notes, trade press),
the primary RBI or NPCI text was not retrievable from this environment.
Before any figure, date or quotation is used in a document to RBI, pull the
primary: the RBI press release and circular for each Direction, the FREE-AI
report PDF, the MRM draft, and NPCI's own statements from GFF 2026. Nothing
in this note should be read as legal advice on applicability to a specific
RE.
