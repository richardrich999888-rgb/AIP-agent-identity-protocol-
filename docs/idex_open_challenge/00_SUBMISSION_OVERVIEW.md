# 00 — Submission Overview

## Executive summary

Armed forces are beginning to field **autonomous and AI-assisted systems** —
ISR analysis agents, decision-support tools, logistics and EW automation,
unmanned platforms. Each one raises the same unanswered question the moment
it acts: **on whose authority, within what limits, and can we prove it after
the fact to a board of inquiry, an adversary, or a coalition partner?**

Today that question is answered with mutable application logs and trust.
Logs can be altered by an administrator or an intruder; they record *what a
system did* but not *which delegated authority permitted it*. For a defence
force, that is a non-repudiation and command-accountability gap.

**AIP (Accountability Infrastructure for Autonomous AI)** closes the gap. For
every consequential action an AI agent takes, AIP produces an
**EvidencePacket**: a compact, cryptographically signed, tamper-evident
record that binds the action to the chain of delegated authority behind it —
from the human commander, through every intermediate system, down to the
acting agent — and is **verifiable offline**, with no call back to any
server. Alter one field of a sealed packet and verification fails on a named
cryptographic rule.

We are submitting AIP to the iDEX Open Challenge because the requirement —
provable authority, tamper-evident audit, offline/air-gapped verification,
indigenous IP — is squarely a defence requirement, and the cryptographic
core already exists and is tested.

## Why this matters to the Services

| Defence need | How AIP meets it |
|---|---|
| **Command accountability for autonomous action** | Every agent action carries a verifiable chain back to the authorising commander and the limits they set. |
| **Non-repudiation** | Ed25519 signatures over a canonical encoding; neither the agent, an operator, nor an intruder can deny or silently alter a recorded action. |
| **Tamper evidence** | Any post-sealing modification — including to embedded delegation signatures — breaks the hash/signature chain and is detected. |
| **Air-gapped / DDN operation** | EvidencePackets verify **offline** against trusted public keys; no connectivity to the issuer is required at verification time. |
| **Coalition / inter-agency evidence** | Counterparties countersign receipts; the evidence is bilateral and independently verifiable by either side. |
| **Indigenous, sovereign IP** | Designed and built in India by an Indian company; no foreign cloud or licensing dependency in the core. |

## Current status (honest)

- **Working, tested core:** identity, delegated authority with mathematical
  attenuation, tamper-evident EvidencePackets, and a 14-rule verification
  engine — `cargo test --workspace` runs **214 tests green**.
- **Working end-to-end demonstrator:** an authority→delegation→action→
  evidence→tamper-detection flow (`cargo run -p banking-demo`), structurally
  identical to a defence authorisation chain.
- **System Technology Readiness Level: TRL 4** (validated in a laboratory
  environment). Cryptographic primitives are mature; the integrated
  accountability system has been validated in test, not yet in the field.
- **Not yet built (roadmap):** hardened multi-tenant service, operator
  console, SDKs, integration with a Service system of record, and field
  trial. These form the proposed iDEX work programme (document 05).

## The ask

`[FILL IN once a Problem Statement / sponsor is selected]`

Indicative: grant support under the relevant iDEX scheme to take AIP from
TRL 4 to a **field-trialable prototype (target TRL 6–7)** integrated with one
sponsoring Service use case, over `[FILL IN]` months. Detailed milestones,
budget, and fund-utilisation in documents 05 and 06.

## What we are asking iDEX / the sponsor to provide

1. A concrete **sponsoring use case** and a system to integrate with.
2. Access to a representative (unclassified or suitably controlled) test
   environment for the field prototype.
3. Milestone-linked grant support per the selected scheme.

## What we commit to deliver

1. A deployable AIP accountability service + verifier hardened for a defence
   network, integrated with the sponsor's chosen use case.
2. An operator/auditor console for issuing, inspecting, and verifying
   EvidencePackets, including offline verification.
3. The open EvidencePacket specification and conformance tests, so the MoD is
   never locked to a single vendor for *verification*.
4. Documentation, security review artifacts, and a field-trial report.
