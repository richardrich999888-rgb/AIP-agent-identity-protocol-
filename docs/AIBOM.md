# AIBOM — the evidence-gap assessment for AI agents

`aip-aibom` reads an agent's declared bill of materials, the evidence the
deployment can produce, and the assessor's own trust context, and reports for
**every field, who vouches for it**.

It is not an inventory dashboard. It answers the question an inventory cannot:
*of everything this agent's owner says about it, what can anybody other than
the owner actually establish?*

> **What it does not do.** It does not establish what an agent did. A manifest
> describes what an agent is and is authorised to do; runtime evidence is
> NEXORA's to verify, and this tool reads NEXORA's verdict rather than
> computing one (ADR-017).

---

## Quick start

```sh
cargo run -p aip-aibom --example treasury target/aibom-treasury
cargo run -p aip-aibom --bin aibom -- assess \
  --manifest   target/aibom-treasury/manifest.json \
  --seal       target/aibom-treasury/seal.json \
  --evidence   target/aibom-treasury/evidence.json \
  --context    target/aibom-treasury/context.json \
  --mcp-config target/aibom-treasury/mcp.json \
  --now-ms     <the time the example printed>
```

| command | does |
|---|---|
| `aibom assess` | the assessment — `--format text\|json\|fields-csv\|findings-csv` |
| `aibom diff --old a.json --new b.json` | what changed, each change marked widening, narrowing or neutral |
| `aibom discover --mcp-config f.json` | the tools an MCP client config exposes, and where inline credentials sit |
| `aibom digest --manifest m.json` | the manifest's canonical SHA-256 |

**Exit status:** `0` success · `1` an input was unreadable or refused, *including
a mistyped flag* · `2` a `Critical` finding, or a diff that widens what the
agent may do. Usage errors are deliberately not `2`: a typo must never read as
a security result.

`--now-ms` is required. The assessment reads no clock.

## The three inputs, and who they belong to

| input | supplied by | trusted? |
|---|---|---|
| **manifest** — what the agent is and may do | the agent's owner | no — it is the claim being tested |
| **evidence bundle** — identity document, delegation chains, decision-point expectations, NEXORA proofs, gateway tool receipts, approval artifacts, signed access ledgers | the assessed party | no — every artifact is re-verified by the verifier that owns it |
| **context** — issuer keys; decision-point, observer, gateway, approval-surface, ledger-signer and publisher anchors; revocations; the agent's own public key | the assessor | yes, and only this |

The bundle has no field for a key, an anchor, a revocation or a time. A party
cannot supply the terms it is judged by, and cannot un-revoke a token by
leaving the revocation out.

## Standings

| standing | means | from |
|---|---|---|
| `VERIFIED` | a core verifier accepted an artifact that supports the field | `validate_aid`, `verify_delegation_chain`, `verify_expected_execution`, `verify_tool_receipt`, `AccessLedger::verify` |
| `OBSERVED` | NEXORA accepted a proof whose re-derived identity matched — at NEXORA's verdict and strength, never raised | `verify_nexora_proof` |
| `DISCOVERED` | found by a discovery the assessor itself ran | MCP config adapter |
| `SELF-REPORTED` | the owner's word, and nothing else | default |
| `UNKNOWABLE` | no mechanism can establish it, citing which limit | `AIRI_LIMITATIONS.md` |
| `LAPSED` | verified, but expired, revoked or not yet valid at the assessor's present | signed windows, assessor's revocations |
| `CONTRADICTED` | verified evidence that **positively** disagrees | e.g. a scope that explicitly denies a declared action |
| `EVIDENCE-REJECTED` | evidence offered for the field failed its verifier | any |

**Absence is never contradiction.** A declared permission no offered chain
grants is `SELF-REPORTED`, with a finding — the bundle may simply not hold the
grant. `CONTRADICTED` is reserved for evidence that says the declaration is
false.

**A verified identity is self-certifying.** An AIP-ID derives from its key, so
`VERIFIED` identity needs no anchor from the assessor — and establishes only
that the id is bound to that key. Not who holds the key.

There is no `TRUSTED`, `COMPLIANT`, `ASSUMED` or `MITIGATED`. The vocabulary
has no word for an overclaim, and a structural test keeps it that way.

## What can and cannot be raised above `SELF-REPORTED`

| # | component | can be raised by |
|---|---|---|
| C1 | identity | identity document (`validate_aid`) |
| C2 | models | **never** — hosted: N-3; local weights loaded: N-4 |
| C3 | frameworks | nothing yet |
| C4 | tools | the assessor's own MCP-config discovery; a gateway-countersigned receipt for a forwarded call. A tool's *effect*: **never** (N-2) |
| C5 | permissions | delegation chain, live at the assessor's present. Per-action limits and approval thresholds: the institution-signed spend policy (ADR-018); the decision point's signed attestations and refusals show it enforced. Per-day / per-month limits and the approver: **never**. A shown-versus-authorised divergence is critical |
| C6 | data access | a signed access ledger showing the agent reached the resource, as the institution's registry names it. Access mode: **never** |
| C7 | environment | decision-point expectation (authorised binary); NEXORA proof (observed binary) |
| C8 | relationships | delegation chains; identity lineage |
| C9 | security controls | **never** — each one is reported as claimed and unevidenced |
| C10 | cryptography | identity-key algorithm from the validated document; post-quantum: **never** (N-10) |
| C11 | supply chain | nothing beyond C7 |
| C12 | governance | nothing — metadata, not a control |
| C13 | validity | the manifest's own window |

## The worked example

The treasury agent from the AIBOM brief: authorised by a CFO to read balances
and create payments, declared with a $1,000 per-payment limit and a $500
approval gate, sealed by the platform team. The institution signs a spend
policy with the same terms, and its decision point enforces it. The agent asks
to pay $400 (authorised, attested) and $5,000 (refused, refusal signed). Its
MCP configuration carries an inline API key and a CRM export the manifest
forgot.

```
7 of 27 fields are backed by an independent verifier; 15 rest on the author's
word; 3 cannot be established by any mechanism here.

CRITICAL
  [C04] credential inline in MCP server 'ledger' at Env { name: "LEDGER_API_KEY" } (KnownTokenPrefix); value withheld
  [C05] $.permissions.allowed[2]  verified evidence contradicts the manifest: a verified chain
        held by this agent explicitly denies custom:refund_payment
HIGH
  [C04] MCP server 'crm-export' is configured for the agent and absent from the manifest
  [C05] bundle.spend_refusals[0]  the decision point refused custom:create_payment for 500000
        minor units (USD, exponent 2) against a per-action limit of 100000 (LimitExceeded)
  [C09] $.security_controls[0]  security control claimed; nothing here can establish it exists
MEDIUM
  [C07] $.environment  an executable was authorised or observed and the manifest declares none
INFO
  [C02] $.models[0]        N-3: That a provider served the model requested
  [C04] $.tools[0].effects N-2: That a claimed external effect landed

FIELDS (excerpt)
  [C05] $.permissions.approval_gates[0].above     VERIFIED       accepted by SpendPolicy
  [C05] $.permissions.approval_gates[0].approver  SELF-REPORTED  the manifest author's word only
  [C05] $.permissions.limits[0]                   VERIFIED       accepted by SpendPolicy
```

That is the "$1,000 authorised, $5,000 attempted" story, told from signed
bytes. The $1,000 limit is the institution's signature, not the owner's word;
the decision point refused $5,000 and signed what it was asked; the $400
payment's attestation cites the same policy by digest, so the limit is shown
*enforced*, not merely declared. Had the manifest said $5,000, the limit would
be `CONTRADICTED` and critical.

What it still does not establish: that every payment went through this
decision point (that is its coverage statement), a daily or monthly limit
(no artifact carries one), who the approver is, or that the payment system
applied the amount (N-2). And the grant denies refunds the manifest claims,
and the agent can reach a tool nobody declared — as before.

The seal changed none of it. It says the platform team published this
inventory, unaltered. It does not say the inventory is true.

## Manifest schema

JSON, `schema_version: 1`, `deny_unknown_fields` everywhere — a manifest that
tries to add `"verified": true` is refused, not ignored.

```json
{
  "schema_version": 1,
  "validity": { "issued_at_ms": 1792936459739, "valid_until_ms": 1800712459739 },
  "agent": { "id": "aip1…", "name": "Treasury Automation Agent",
             "owner": "finance-team", "version": "1.2.0", "deployment": "production" },
  "models": [{ "provider": "example-provider", "model": "example-model",
               "version": "2026-10", "hosting": "hosted" }],
  "tools": [{ "id": "ledger", "kind": "mcp", "actions": ["post_entry"] }],
  "permissions": {
    "allowed": [{ "Custom": "create_payment" }],
    "limits": [{ "action": { "Custom": "create_payment" }, "per": "per_action",
                 "max": { "minor_units": 100000, "currency": "USD", "exponent": 2 } }],
    "approval_gates": [{ "action": { "Custom": "create_payment" },
                         "above": { "minor_units": 50000, "currency": "USD", "exponent": 2 },
                         "approver": "cfo" }]
  },
  "environment": { "runtime": "container", "network": "restricted",
                   "binary": { "exe_sha256": "<64 lowercase hex>" } },
  "relationships": { "delegated_from": ["aip1…cfo"] },
  "security_controls": [{ "kind": "sandbox", "description": "gVisor" }],
  "crypto": { "identity_key_algorithm": "Ed25519", "post_quantum": false },
  "governance": { "risk_class": "high" }
}
```

- **Amounts** are integer minor units with an explicit ISO 4217 currency and
  exponent. A float does not parse.
- **Actions** use the core's own vocabulary (`ScopeAction`), so a declaration
  is compared with a verified scope without translation.
- **Collections are sets.** Duplicates are refused; order does not affect the
  digest.
- **No string may contain a control character** — every string reaches a
  terminal or a spreadsheet.

The manifest does not contain its own digest. A seal is a separate object
(`seal.json`) over the canonical digest.

## Context file

```json
{
  "issuers":           { "aip1…cfo": "<hex public key>" },
  "decision_points":   { "aip1…dp":  "<hex public key>" },
  "publishers":        { "platform-team": "<hex public key>" },
  "revoked_jtis":      ["<32 hex>"],
  "gateways":          [{ "id": "mcp-gateway-1", "key_version": 1, "public_key": "<hex>" }],
  "ledger_signers":    [{ "id": "ledger-1",      "key_version": 1, "public_key": "<hex>" }],
  "approval_surfaces": { "approvals-ui": "<hex public key>" },
  "spend_policy_issuers": { "bank.example/treasury-policy": "<hex public key>" },
  "evaluate_proofs":   true,
  "observers":         [{ "id": "collector-a", "key_version": 1, "public_key": "<hex>" }],
  "agent_public_key":  "<hex>"
}
```

`spend_policy_issuers` anchors the institution's spend-policy authority. The
evidence bundle carries `spend_policies` (signed by it), and
`spend_attestations` / `spend_refusals` (signed by a decision point in
`decision_points`); none of them is trusted for its own key.

Without `evaluate_proofs`, NEXORA proofs in the bundle are reported as not
evaluated and never credited.

`agent_public_key` is passed to every verifier that checks independence. A
gateway, an approval surface or an observer anchored under the agent's own
key is refused: a receipt the agent can sign is its self-report under another
name.

**Naming must match.** A declared tool's `id` must be the tool identifier the
gateway resolves calls to; a declared data-access `resource` must be the
resource id in the institution's signed registry. A mismatch is reported as
an undeclared tool or resource, which is the honest result: the manifest and
the institution are not describing the same thing.

## MCP discovery

Reads `mcpServers` (Claude Desktop and most clients) or `servers` (VS Code).
Records the server name, the program launched or the endpoint reached —
userinfo, query and fragment removed — and environment variable **names**.

It never records arguments, environment values, header values or URL
credentials; the output type has no field for one. Where a value looks like a
credential it reports the location and why: a credential-like name, a known
provider token prefix (`sk-`, `ghp_`, `xoxb-`, `AKIA`, …), or URL userinfo.
This is a heuristic and is labelled as one: a secret under an innocuous name
with no recognisable prefix is missed. `${VAR}` and `$VAR` are references and
are not flagged.

A file that parses but is not an MCP config is refused, rather than read as
"this agent has no tools".

## Limits, stated

- **It assesses claims, not behaviour.** Nothing here observes an agent act.
- **Only per-action limits are verifiable, and only under a signed spend
  policy** (ADR-018). Without one, a limit is the author's word.
  Per-day and per-month limits are carried by no artifact. An approval
  threshold is verified against the policy and each approval-required
  decision offered is checked for an agreeing approval; the approver's
  identity is not established, and decisions not offered are not seen.
- **A ledger shows what was reached inside its window, not what may be
  reached.** A declared resource the ledger does not show is the author's
  word, never a contradiction.
- **Discovery covers MCP client configs only.** Lockfiles, framework code
  scanning and cloud-provider inventories are not implemented.
- **No CycloneDX export yet.** Deferred until the schema is stable.
- **The CLI does not handle private keys.** Sealing is a library API.
- **An identity's `expires_at` is not relied on.** It sits outside the bytes
  the identity's self-signature covers, so anyone holding the document can
  change it. Its presence is reported; its value is not used.
