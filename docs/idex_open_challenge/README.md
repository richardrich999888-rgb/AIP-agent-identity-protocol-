# AIP — iDEX Open Challenge Submission Package

**Applicant / Owner:** K. NAGA SRI GANESH  `[FILL IN: entity (if any), CIN, registered address, DPIIT recognition no.]`
**Product:** AIP — Accountability Infrastructure for Autonomous AI
**One line:** *Prove what an autonomous AI agent did, and who authorized it — verifiable offline, even on air-gapped networks.*

> **Note on this package.** Every capability claim in these documents is
> backed by source code in this repository and an automated test suite that
> reproduces it. Where something is not yet built, it is labelled **roadmap**.
> This discipline is deliberate: in a defence accountability product, an
> overstated claim is itself a vulnerability. See `../../AUDIT_CORRECTIONS.md`.

---

## Reading order

| # | Document | Purpose |
|---|---|---|
| 00 | [Submission Overview](00_SUBMISSION_OVERVIEW.md) | Executive summary, fit with iDEX, the ask |
| 01 | [Problem & Solution](01_PROBLEM_AND_SOLUTION.md) | The defence problem and how AIP solves it |
| 02 | [Technology & TRL](02_TECHNOLOGY_AND_TRL.md) | Architecture, what exists, honest TRL with evidence |
| 03 | [Defence Use Cases](03_DEFENCE_USE_CASES.md) | Concrete tri-services / C2 / autonomous-systems scenarios |
| 04 | [Innovation & IP](04_INNOVATION_AND_IP.md) | What is novel, prior-art delta, IP and indigenous-content status |
| 05 | [Prototype Plan & Milestones](05_PROTOTYPE_PLAN_AND_MILESTONES.md) | Phased build to a deployable field prototype |
| 06 | [Team & Budget](06_TEAM_AND_BUDGET.md) | Team, indicative budget, fund utilisation (founder to complete) |
| 07 | [Compliance & Security](07_COMPLIANCE_AND_SECURITY.md) | Security posture, certifications status, data/sovereignty |

## How to reproduce the claims (for evaluators)

```bash
cd aip-standalone
cargo build --workspace      # builds clean
cargo test  --workspace      # 214 tests pass, 2 ignored (release-only perf gates)
cargo run   -p banking-demo  # end-to-end evidence + tamper-detection demo
```

The same flow that the demo shows for a financial approval maps directly to a
defence authorisation (commander → delegated authority → autonomous agent →
action → tamper-evident evidence). See document 03.

---

## Fields requiring applicant input before submission

These are organisation- and programme-specific and are intentionally left as
placeholders rather than fabricated:

- Legal entity details (CIN, GSTIN, DPIIT/Startup India recognition).
- The specific iDEX **Problem Statement / Challenge code** being applied to,
  and the sponsoring Service/DPSU, once selected.
- Funding ask and milestone-linked disbursement schedule (document 06).
- Team CVs and prior defence/security experience (document 06).
- Any existing trial, LoI, or sponsor engagement (none claimed here).
