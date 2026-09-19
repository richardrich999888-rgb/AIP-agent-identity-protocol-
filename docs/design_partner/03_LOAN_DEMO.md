# 03 — Live Demo: ₹5 Crore Loan Approval

**Reproduce:** `cd aip-standalone && cargo run -p aip-protocol --example loan_approval`
All output below is **verbatim from that program** — nothing here is mocked.

## Scenario

```
Human Branch Manager  ──issues scoped authority──▶  Loan Agent (AI)
                                                         │ delegates a NARROWER authority
                                                         ▼
                                                   Sub-Agent (AI underwriter)
                                                         │ approves
                                                         ▼
                                          ₹5,00,00,000 term loan → core-banking ledger
```

- Manager grants the Loan Agent **orchestrator** scope (read/write/execute/delegate; **admin denied**), valid 1 hour.
- Loan Agent delegates to the Sub-Agent a **submitter** scope (**write only** — cannot re-delegate, admin, or delete).
- Sub-Agent approves loan `LN-2026-5512` and posts a ledger entry; the core-banking system **countersigns** the receipt.

## Verification output (real, abridged to the rule list)

```json
{
  "valid": true,
  "trust_floor": "COUNTERPARTY_SIGNED",
  "tampered": false,
  "authority_chain_verified": true,
  "delegation_chain_verified": true,
  "scope_verified": true,
  "receipt_verified": true,
  "revocation_clear": true,
  "packet_id": "9943642cf27540a09822eb9fbc9c6eeb",
  "agent_id": "aip14PkYiP72rmqY2nCf1BWzkRaxBZQdJPAcySkb6nLGcn"
}
```

The evaluated rules all pass (the engine has 18; `VERIFICATION_TIME_BOUND` and
`REPLAY_SCOPE` are NOT EVALUATED unless the verifier supplies a time and a
history — see `AIP_SPEC.md` §5), including (verbatim `detail` strings):

- `ROOT_TOKEN_SIGNATURE` — "root token signed by trusted issuer aip17V6PKzBzpMw9JH4pLQJGsPPgd2bKWCYogSa47JBwMU"
- `DELEGATION_CHAIN` — "1-hop delegation chain verified (per-hop signatures, JTI linkage, depth, scope attenuation)"
- `AUTHORITY_CHAIN` — "authority chain connects principal aip17V6PK… to acting agent aip14PkY…"
- `SCOPE_AUTHORITY` — "decision and all actions fall within the effective (most-attenuated) scope"
- `RECEIPT_BINDING` — "receipt LEDGER-LN-2026-5512 @ core-banking.examplebank.in countersigned by core-banking.examplebank.in"

## Authority graph (real DOT output)

```dot
digraph accountability {
  rankdir=LR;
  "principal"       [shape=house,     label="Branch Manager (aip17V6PK…)"];
  "authority_grant" [shape=note,      label="root token 94d5f7d4… → aip13Z1Rqh… (Loan Agent)"];
  "delegation:0"    [shape=cds,       label="hop 0 (depth 1): Loan Agent → Sub-Agent"];
  "agent"           [shape=component, label="aip14PkY… (Sub-Agent)"];
  "decision"        [shape=diamond,   label="Approve term loan LN-2026-5512 for INR 5,00,00,000…"];
  "action:0"        [shape=box,       label="POST /v1/core-banking/loans/approve {loan_id:LN-2026-5512, amount_paise:50000000000}"];
  "receipt"         [shape=tab,       label="LEDGER-LN-2026-5512 @ core-banking.examplebank.in"];
  "principal"       -> "authority_grant" [label="Issues"];
  "authority_grant" -> "delegation:0"    [label="Delegates"];
  "delegation:0"    -> "agent"           [label="ActsUnder"];
  "agent"           -> "decision"        [label="Decides"];
  "decision"        -> "action:0"        [label="Performs"];
  "action:0"        -> "receipt"         [label="Produces"];
}
```

## The point: why a log is insufficient

The demo then **tampers with one field** — changing the approved amount from
₹5 crore to ₹50 crore — and (as a sophisticated attacker would) **recomputes
the packet hash** to cover its tracks. Real output:

```
valid:        false
tampered:     true
trust_floor:  UNVERIFIED
FAILED RULES:
 - AGENT_SIGNATURE : signature payload hash does not cover current packet contents
 - TRUST_FLOOR     : claimed floor CounterpartySigned exceeds what the evidence supports (Unverified)
```

| | A normal application log | An AIP EvidencePacket |
|---|---|---|
| Records the action | yes | yes |
| Records **who authorized** it (human-rooted chain) | no | yes |
| Enforces that the agent **stayed within delegated authority** | no | yes (`SCOPE_AUTHORITY`) |
| Detects an **admin/insider editing the record** | no (admins can edit logs) | yes — the ₹50 crore edit fails verification |
| Detects an attacker who **also fixes the hash/checksum** | no | yes — the agent **signature** still fails |
| Verifiable by a **third party with no access to our systems** | no | yes — offline, against trusted public keys |

A log answers "what the system recorded." An EvidencePacket answers "what
provably happened, under whose authority, and whether anyone touched it" —
which is the question a board of inquiry, an auditor, or a regulator asks.
