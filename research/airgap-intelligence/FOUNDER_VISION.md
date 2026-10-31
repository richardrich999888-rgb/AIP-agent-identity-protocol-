# SYNTRIASS Air-Gap Native Intelligence — the proposal in plain English

Status labels used throughout: **Built** (code + reproducible evidence in this
repository), **Research** (experiment exists, not productised), **Proposed**
(untested idea), **Commercial** (substantiated customer engagement — none is
recorded in this repository).

## What is proposed

Organisations that cannot send data to external AI services — because policy
forbids it, or because their networks are physically disconnected — still want
AI that reads their documents, answers technical questions, and carries out
approved tasks. SYNTRIASS proposes software they install on hardware they
already own, which:

1. answers from the organisation's own documents, and only from documents the
   asking person may see;
2. uses the **cheapest sufficient computation** for each request — exact code
   where the answer is a rule or arithmetic, a small model where language must
   be interpreted, a larger local model only when needed;
3. never lets a model's output authorise an action — a separate deterministic
   authority does, and leaves evidence an auditor can check offline;
4. optionally spreads work and software updates across the organisation's own
   approved machines.

## Why it matters

"Install an open-weight model" is not a deployment: someone must size
hardware, keep it updated without internet, control who sees what, and explain
afterwards what the AI did. Each of those is a cost the customer bears today.

## Who buys it (hypothesis — no customer evidence in this repository)

Organisations with confidential engineering, financial or research data and a
policy against external AI: engineering and aerospace firms, banks,
pharmaceutical R&D, critical-infrastructure operators, government. The buyer
is whoever owns both the AI budget and the data-handling risk (CIO/CISO).

## How it differs from local LLM hosting

| Local LLM hosting | This proposal |
|---|---|
| One model answers everything | Exact code first; model size chosen per request (**Research**: iteration 1 cascade) |
| Model decides | Model interprets; code decides where the rule is known (**Research**: iteration 1) |
| Access control around the app | Access enforced inside retrieval (**Built**: Sovereign slice 1/Phase A) |
| Logs | Signed authorisation + runner record verifiable offline (**Built**: slice 1); independent kernel observation (**Built in AIP repo, not yet integrated here**) |
| Cloud-first, offline mode optional | Designed to run with no external route (**Built** for the demo path; tested in a network namespace) |
| One server | Optional coordination of approved machines (**Proposed**; no code) |

## What it is not

Not a chatbot wrapper, not a public P2P network, not a blockchain or token,
not a claim that a 1–2B model matches a frontier model.

## Naming and ownership (for founder review — not resolved here)

Code, crates, patents and prior documents in this repository are named and
attributed to VANIAN Technologies. The new product names (SYNTRIASS Air-Gap
Native Intelligence, SYNTRIASS Sovereign Intelligence Mesh) are used only in
new documents. **No IP assignment between VANIAN Technologies and SYNTRIASS
Labs is recorded in this repository**; which entity owns which code and patent
families must be settled with documentation before any external claim.
