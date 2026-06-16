# AIP — Design Partner Evaluation Pack

**Purpose:** let a regulated enterprise (bank / insurer / auditor / regulator)
review AIP and decide on a pilot — in about 30 minutes.

**One line:** AIP produces an **EvidencePacket** for every consequential AI
agent action — a tamper-evident, offline-verifiable record binding the action
to the chain of human authority behind it.

> **Honesty policy.** Every capability statement here is backed by code in
> this repository and reproducible commands. Maturity is stated plainly
> (production / pilot / prototype). What is missing is listed, not hidden.
> See `04_PILOT_READINESS.md` and the gaps columns throughout.

## 30-minute review path

| Min | Read | You will learn |
|----|------|----------------|
| 0–5 | `01_EVALUATION_PACKAGE.md` §1–2 | What AIP is; the architecture |
| 5–12 | `03_LOAN_DEMO.md` | A real ₹5 crore loan EvidencePacket, its verification, and why a log can't do this |
| 12–18 | `02_AUDITOR_CHECKLIST.md` | Whether AIP answers the auditor's five questions |
| 18–24 | `04_PILOT_READINESS.md` | What is production / pilot / prototype today |
| 24–30 | `05_TOP_50_QUESTIONS.md` (skim) + `01` §7 pilot guide | Likely Q&A; how a pilot deploys |

## Reproduce the demo yourself

```bash
cd aip-standalone
cargo run -p aip-protocol --example loan_approval   # prints the real artifacts
cargo test --workspace                               # core: 214 pass, 2 release-only ignored
cd ../aip-service && cargo test                       # service: 37 pass
```

## Contents

| File | Task it answers |
|---|---|
| `01_EVALUATION_PACKAGE.md` | Overview, architecture, examples, threat & security model, pilot guide |
| `02_AUDITOR_CHECKLIST.md` | Auditor acceptance checklist + role-by-role trust/blockers |
| `03_LOAN_DEMO.md` | Live demo scenario with real generated artifacts |
| `04_PILOT_READINESS.md` | Code-backed production / pilot / prototype classification |
| `05_TOP_50_QUESTIONS.md` | The 50 questions a bank/auditor/regulator will ask |
| `06_DATA_ROOM.md` | Due-diligence data room: READY / PARTIAL / MISSING |
| `07_CUSTOMER_DISCOVERY.md` | Discovery questions, objections, buy/reject triggers |
