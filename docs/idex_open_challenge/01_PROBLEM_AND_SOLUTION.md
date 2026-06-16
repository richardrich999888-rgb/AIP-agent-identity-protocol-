# 01 — Problem & Solution

## 1. The problem

Defence organisations are introducing AI agents and autonomous systems into
workflows that were previously performed by accountable human officers:
target nomination support, ISR triage, mission planning aids, logistics
allocation, electronic-warfare responses, and unmanned platform tasking.

When such a system performs or recommends a consequential action, three
governance questions must be answerable **with proof, after the fact**:

1. **Authority** — which human commander/authority permitted this class of
   action, and what limits did they place on it?
2. **Attenuation** — did the action stay within those limits as authority
   was delegated down through intermediate systems and sub-agents?
3. **Integrity** — is the record of what happened genuine, complete, and
   unaltered — even if an administrator, an insider, or an intruder later
   had access to the logs?

### Why current practice fails

- **Application logs are mutable.** Anyone with privileged access — or an
  adversary who gains it — can edit or delete them. They are not evidence in
  any adversarial sense.
- **Logs record actions, not authority.** They show that "Agent X called
  API Y," not "Agent X acted under authority delegated from Commander Z,
  who restricted it to scope S."
- **Identity ≠ accountability.** Workload-identity and IAM systems control
  *who may act*; they do not produce a portable, verifiable record binding a
  specific action to the delegated authority behind it.
- **Connectivity assumptions.** Many audit/observability tools assume a
  live link to a central service. Defence networks are frequently
  air-gapped, intermittently connected, or operate across security domains
  where call-home verification is unacceptable.
- **Single-vendor trust.** If only the vendor's server can validate the
  records, the MoD cannot independently prove anything in a board of inquiry
  or to a coalition partner.

The consequence is a **command-accountability and non-repudiation gap** that
widens with every autonomous capability fielded.

## 2. The solution: AIP

AIP makes **accountability a property of the action itself**, not of a log
file that happens to sit next to it.

### The EvidencePacket

For each consequential action, the acting agent seals an **EvidencePacket**
containing:

- **Who acted** — the agent's cryptographic identity (public key + a
  provenance commitment to its model/build/environment).
- **Under whose authority** — the root authority token issued and signed by
  the human principal (commander/authority), plus the full **delegation
  chain** down to the acting agent, each hop independently signed.
- **What was decided** — a decision record with inputs and rationale bound
  by hash.
- **What was done** — each performed action, individually signed and bound
  to the decision it served.
- **What it touched** — bindings to external traces and receipts; the
  receiving system can **countersign** the receipt, producing bilateral
  evidence.
- **How much to trust it** — a trust floor the verifier *derives* from the
  evidence (it cannot be asserted by the producer).

### The guarantees (implemented and tested)

1. **Tamper evidence.** The packet hash is `SHA-256` of a canonical,
   length-prefixed encoding; the agent signs that hash with `Ed25519`. Any
   later modification — to the decision, an amount, a target, a scope, or
   even an embedded delegation signature — changes the bytes and breaks
   verification. An attacker who recomputes the hash still fails the agent
   signature check.
2. **Authority binding & attenuation.** Each delegation hop is verified for
   signature, parent linkage, depth, and **scope subset**: a child's
   authority can never exceed its parent's (enforced by a lattice
   intersection / "MEET" operation). The decision and every action must fall
   within the most-attenuated effective scope, or verification fails.
3. **Offline verification.** A verifier needs only the trusted public keys of
   the principal and intermediate authorities and its revocation list — no
   network call to the issuer. This is what makes AIP usable on air-gapped
   and cross-domain defence networks.
4. **Independent, multi-party verification.** Because verification is a pure
   function of the packet + trusted keys, the MoD, an inquiry, or a coalition
   partner can each verify the same packet independently. The open
   specification (document 04) means verification is never locked to one
   vendor.

### Where the trust comes from

AIP deliberately keeps the **trust registry out of band**: the verifier — an
auditor, a security cell, a partner force — decides which keys it trusts for
which principals and which tokens are revoked. The packet carries
**evidence**, not trust. This matches how defence accountability actually
works: authority and trust roots are established by the chain of command, not
asserted by the tool.

## 3. The defence analogy in one line

A military order carries the issuing authority, the limits of the order, and
a signature; subordinate orders may narrow but never widen it; and the record
must survive scrutiny. **The EvidencePacket is that, made cryptographic and
machine-verifiable for autonomous systems.**
