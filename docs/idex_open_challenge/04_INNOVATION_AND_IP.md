# 04 — Innovation, Differentiation & IP

## 1. What is genuinely novel

The novel contribution is **not** "use Ed25519" or "keep an audit log" —
those are commodities. It is the **integrated EvidencePacket**: a single,
portable, offline-verifiable artifact that binds, in one tamper-evident
object,

1. the acting agent's identity and provenance commitment,
2. the **complete chain of delegated authority** with mathematically
   enforced **scope attenuation** (a child can never exceed its parent),
3. the decision and each performed action, individually signed and bound to
   that decision,
4. external receipts that the counterparty can countersign, and
5. a **trust floor the verifier derives from the evidence** rather than one
   the producer asserts —

such that **any modification anywhere is detectable and verification is a
pure offline function of the packet plus the verifier's own trusted keys.**

## 2. Differentiation from existing approaches

| Approach | What it does | What it does NOT do (that AIP does) |
|---|---|---|
| Application / SIEM logs | Record events centrally | Not tamper-proof against privileged insiders; record actions, not delegated authority; need central trust |
| Identity / IAM, workload identity (e.g. SPIFFE-style) | Decide *who may act* | Do not emit a portable, offline-verifiable record binding an action to the delegated authority behind it |
| Observability / tracing | Show *what happened* operationally | No cryptographic non-repudiation; mutable; not authority-aware |
| Capability tokens / macaroons | Attenuable bearer authority | No bound action-evidence artifact, no derived trust floor, no countersigned bilateral receipts as one verifiable packet |
| Transparency logs | Append-only public logs | Complementary — AIP can anchor packet hashes to such a log (roadmap), but solves the per-action authority-binding problem they do not |

**Summary:** identity systems answer "who," observability answers "what,"
AIP answers **"under whose authority, within what limits, and can you prove
it offline" — the accountability question none of the above answers as a
single verifiable artifact.**

## 3. Indigenous content & sovereignty

- Designed and implemented in India by Vanian Technologies Private Limited.
- Core depends only on standard, open cryptography (Ed25519, SHA-256) via
  permissively licensed libraries; **no foreign cloud, no foreign licensing
  in the trust path**, no call-home.
- Verification is fully **offline** and **open-specified**, so the MoD
  retains sovereign ability to verify evidence independently and in
  perpetuity, regardless of vendor.
- Indicative indigenous content: `[FILL IN per the scheme's IC computation;
  the software core is India-origin IP]`.

## 4. Intellectual property status

- **Copyright:** original source in this repository, owned by Vanian
  Technologies Private Limited.
- **Patents:** provisional filings exist relating to delegation-bound,
  scope-constrained audit binding. **Honest note:** several broader
  mechanism claims face meaningful prior art (capability tokens/macaroons,
  workload identity). The applicant's IP position is strongest on the
  **integrated EvidencePacket + derived-trust-floor verification**, and that
  is where focused prosecution is advised. See `../../reports_and_patents/`
  (attorney working documents) and `../../AUDIT_CORRECTIONS.md`.
- **Open specification, proprietary product:** the EvidencePacket
  **format + verification rules** (`AIP_SPEC.md`) are intended to be open so
  that verification is never single-vendor; the productised service,
  console, and management plane remain proprietary. This is the standard
  "open format / commercial implementation" model and is favourable to the
  MoD's interest in avoiding lock-in for *verification*.
- **Licensing to MoD:** `[FILL IN: proposed Government Purpose Rights /
  licence terms per iDEX/DRDO IP guidelines]`.

## 5. Competitive / strategic note (honest)

Large identity and observability vendors could build an adjacent capability;
AIP's defensible position comes from (a) being first to package agent
**accountability** as an open, offline-verifiable evidence standard, (b)
sovereign Indian IP suited to defence procurement, and (c) the network effect
of an adopted verification format. The applicant does not claim an
insurmountable technical moat; it claims a real, tested head-start on a
problem that is about to become acute as autonomous systems are fielded.
