# External anchoring of the NEXORA commitment log (R11)

## The problem this addresses

`aip-nexora` gives an append-only Merkle tree with inclusion and consistency
proofs. Those establish that a record sits under a root, and that one root
extends another. Neither establishes **that the root you are shown today is
the root that existed yesterday**.

Whoever holds the NEXORA signing key can build a shorter log, sign a head
over it, and hand out proofs that check out. Every cryptographic test
passes. The removed records are gone and no artefact says so. This is not a
weakness in the Merkle construction; it is what a Merkle log does not claim
to do.

`aip-nexora`'s own `MemoryAnchor` documents the limit plainly: it is "the
shape of an anchor, not its independence."

## The mechanism

A **witness** runs on a second system. It holds:

- its own Ed25519 signing key, which the log operator does not have;
- the NEXORA public keys it will accept heads from;
- an append-only file of the receipts it has issued.

It receives signed heads (and, after the first, consistency proofs). It
verifies each head under its own anchors, checks that the log has grown and
that the growth is proven, and countersigns into a `WitnessReceipt`.

The property is negative and that is what makes it useful:

> An operator who rewrites the log can still sign the new head. They cannot
> produce a witness receipt for it.

Receipts already distributed are therefore evidence the operator cannot
revise. `aip_anchor::audit` checks a log against held receipts and returns
`Consistent`, `Diverged` (with which of truncation, in-place rewrite, or a
divergent history), or `NotEvaluated`.

`NotEvaluated` is never a pass. A log with no receipts is **unanchored**,
and the whole point of this mechanism is that an unanchored log and an
anchored one must not read alike.

## What the code cannot do for you

Everything above is worthless if the witness is not independent. The code
cannot check this and does not pretend to. A witness on the same host, run
by the same administrator, with its key in a file that administrator can
read, is a second signature by one party.

Four conditions have to hold in the deployment, and each is an operational
control, not a software one:

1. **Different host, different administrator.** The witness runs on a system
   whose root does not overlap with the NEXORA host's. In a regulated entity
   the natural placement is inside the entity, under a team that does not
   operate the AI platform — the audit function, the CISO's group, or the
   infrastructure team — and explicitly not under whoever runs the agents.

2. **The witness key is never on the NEXORA host.** Generate it on the
   witness host. It does not leave. `Witness::new` refuses to construct a
   witness whose public key matches any NEXORA anchor it holds, which
   catches the crude version of this mistake and not the subtle one.

3. **The receipt file is append-only in the filesystem, not only in
   intention.** Put it on storage where the witness process can append and
   nothing can rewrite. The same `deploy/sql/hardening.sql` posture applies
   if the receipts go into a database instead: no UPDATE, no DELETE for the
   writing role.

4. **Receipts leave the building.** A receipt held only on the witness host
   protects against a compromised log host, not a compromised site. Copy
   each receipt to at least one destination outside the entity's own
   control — the supervisor, an external auditor, a notary service, or a
   public transparency log. What matters is that a copy exists somewhere
   the entity cannot reach.

Condition 4 is what turns this from an internal control into evidence a
third party can rely on. Conditions 1–3 without it protect against an
insider; only 4 protects against the institution.

## Running it

Generate the witness key on the witness host and keep the private half
there:

```
# on the witness host
openssl genpkey -algorithm ed25519 -out witness.pem
# extract the 32-byte seed and public key by your own key-management
# procedure; the private key is never copied to the NEXORA host
```

Countersign a head:

```
aip-anchor witness \
  --head head.json \
  --consistency proof.json \
  --witness re-witness-1:1 \
  --key "$WITNESS_KEY_HEX" \
  --trust-log nexora-1:1=<nexora_pubkey_hex> \
  --receipts /var/lib/aip-anchor/receipts.jsonl
```

`--trust-log` is mandatory. A witness with no anchors would countersign any
head presented to it, which is the opposite of what a witness is for.

Check a receipt set, offline, anywhere:

```
aip-anchor verify \
  --receipts receipts.jsonl \
  --trust-witness re-witness-1:1=<witness_pubkey_hex>
```

## Cadence

Anchoring cadence sets the blast radius. Records committed between the last
receipt and a rewrite are the records a rewrite can still remove undetected.

Choose the interval from what an undetected gap is worth, not from load:
the witness does constant work per head regardless of how many records the
head covers. Anchoring after every reconciliation verdict is defensible;
anchoring hourly leaves an hour.

State the chosen cadence in the pilot's operating procedure, and make a
missed anchoring window an alert. A witness that stops being fed is
indistinguishable, from the receipts alone, from a log that stopped growing.

## What a reviewer should ask for

1. The witness host's ownership, and evidence that it is not the NEXORA
   host's administrator.
2. The receipt file, or the external copies — and the chain check over them
   (`aip-anchor verify`), which fails if any receipt was removed.
3. The audit output (`aip_anchor::audit`) run against the live log.
4. The anchoring cadence, and the alerting on a missed window.

An answer of "we use a Merkle log" to question 3 is not an answer to
question 3.
