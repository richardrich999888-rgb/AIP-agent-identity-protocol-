# IP / Patent Engineering Report

Written for a technically competent, skeptical reader. Nothing here is a
legal opinion. The question addressed is narrower and answerable from
source: **which structures in this repository are concrete, non-obvious
implementations rather than restatements of known practice, and are they
described in the code with enough specificity to support a claim?**

Novelty is assessed against what the code *does*, not what the documents
say. Where a mechanism is a competent application of known art, that is
stated plainly — an audit that calls everything novel is worthless.

## 1. Candidate structures, ranked

### 1.1 The single-choke-point verdict precondition — **strongest candidate**

**Location:** `prod/aip-standalone/aip-reconcile/src/reconcile.rs:89-183`.

**What it is.** Every result class the engine can emit passes through one
predicate, `precondition_holds(result, strength)`, which asks whether the
evidence *visible in the record being emitted* permits the class being
proposed. Per-branch logic decides which class to propose; this decides
whether it is allowed. A proposal that fails is not an error — it is
rewritten to `(CannotProve, Heuristic, InvariantNotSatisfied)`.

**Why it is structurally interesting.** The separation of *proposal* from
*permission*, with a fail-closed rewrite rather than a rejection, means that
a future edit which forgets to establish a precondition degrades the verdict
instead of asserting one. The code says this explicitly of
`coverage_recomputed`:

> `PhantomClaim` cannot leave `finish` without it, so a future edit that
> forgets the recomputation downgrades to `CannotProve` instead of asserting
> non-execution.

That is a maintenance property expressed in the type and control flow rather
than in a comment or a review checklist.

**Prior art it must be distinguished from.** Policy decision points with
obligation checks (XACML and descendants) separate decision from
enforcement. Static analysers use lattice joins to keep uncertainty
absorbing. What is not standard here is the combination of (a) an epistemic
strength ladder in which the top class is reserved for facts a third party
can recompute from held bytes, (b) per-class *structural witnesses* rather
than scores, and (c) equality rather than threshold comparison on strength,
so over-claiming is downgraded as readily as under-claiming.

**Specification quality:** high. The preconditions are exhaustively matched,
the rationale for each is in the doc comments, and the fail-closed direction
is stated.

### 1.2 The two-axis warrant ceiling with no arithmetic — **strong candidate**

**Location:** `prod/aip-standalone/aip-warrant/src/warrant.rs:172-280`.

**What it is.** The permitted response is
`min3(result_cap, strength_cap, severity_cap)`, where each cap is an
explicit `match`, followed by monotone lowering only:

```
if unavailable || !cited || protected  → response = min(response, Alert)
if response == Contain && !policy.autonomous_containment → Alert
```

**Why it is structurally interesting.** The module doc states the design
constraint directly: "Nothing here computes a product of the two axes." The
usual approach — multiply severity by confidence, threshold the product — is
precisely what this refuses. A high-severity, low-evidence finding cannot
borrow authority from its severity. Each axis independently *caps*; none
can raise.

**Prior art it must be distinguished from.** CVSS-style scoring, risk
matrices, and alert-scoring in SIEM products all compose severity and
confidence into a scalar. The distinguishing feature is the refusal to
compose, plus the enumerated set of monotone lowering conditions
(unavailability, absence of citation, protected identity, operator policy),
each of which names an epistemic or governance condition rather than a
numeric weight.

**Specification quality:** high, and the ordering of `ResponseClass` is
declared with the invariant that every cap is a `min` against it.

### 1.3 Host-authored coverage re-derivation — **strong candidate**

**Location:** `prod/aip-standalone/aip-reconcile/src/reconcile.rs:1043-1120`
(`recompute_coverage`).

**What it is.** The collector signs a batch that includes coverage fields —
`claimed_from_ms`, `claimed_to_ms`, `active_mechanisms`, `probe_run_id` —
every one of which is authored by the *host-side probe*. The reconciler does
not read them. It re-derives, from the attested batches alone, whether the
window was continuously sampled by one probe run using a kernel-pushed
mechanism, anchoring the end of the window to `health_emitted_at_ms`, a time
the collector itself signed.

The reasoning in the doc comment is the substance of the invention:

> a compromised host [could] manufacture coverage over an interval nothing
> sampled — and a `PHANTOM_CLAIM` is precisely a statement about such an
> interval.

**Why it is structurally interesting.** A signature over host-authored
claims authenticates the *collector's relay*, not the *claim's truth*. The
distinction is routinely missed. The mechanism — signed relay of an
untrusted claim, plus independent re-derivation by the consumer, plus a
verdict class that exists only to state a negative about an interval — is a
specific and describable arrangement.

**Prior art it must be distinguished from.** Remote attestation quotes,
transparency-log consistency proofs, and audit-log gap detection all touch
this. The specific arrangement of *probe (untrusted, keyless) → collector
(trusted, signing, off-host, assigns sequence and clock) → reconciler
(re-derives coverage rather than reading it)* is what would need to be
claimed.

### 1.4 Keyless probe / off-host attestation boundary — **moderate candidate**

**Location:** `prod/aip-standalone/aip-observe/src/attest.rs:1-95`.

**What it is.** The observed host holds no signing key by construction:
`probe` has no key field and no signing method; `ObservationBatch` has no
signature field; `sequence` is assigned by the collector; `attested_at_ms`
is the collector's clock. The signed head is computed from a
domain-separated preimage and never carried, so no supplied hash is trusted.
`key_version` is inside the preimage, so rotation is anchored rather than
retrofitted.

**Assessment.** The individual elements are known practice (remote logging
with signing at the collector; computed-not-carried digests; key versioning
in the preimage). What is well done rather than novel is the *completeness*
— the module doc enumerates exactly what an attacker with root on the
observed host can and cannot forge, and the type definitions match the
claim. This is strong engineering and weaker patent material than 1.1–1.3.

### 1.5 Temporal attenuation enforced against a valid signature — **moderate candidate**

**Location:** `prod/aip-standalone/aip-core/src/delegation.rs:220-231`.

**What it is.** After authenticity is established, the chain separately
rejects a hop whose `expires_at` outlives its parent's — including the
`None` case, where an unbounded child of a bounded parent is refused. The
ordering is deliberate and documented: a *forged* expiry reports
`SignatureInvalid`, a *genuinely over-delegated* one reports
`AttenuationViolation`. The two are different accusations and the code keeps
them distinct.

**Assessment.** Capability attenuation and monotone expiry narrowing are
established art (macaroons, biscuits, SPKI/SDSI). The refinement worth
noting is the error-class separation — distinguishing "this was tampered
with" from "your issuer exceeded their authority" is diagnostically and
forensically meaningful and is rarely implemented.

## 2. Structures that are competent but not novel

Stated plainly so the portfolio is not padded:

- **Prefix-free canonical encoding with domain tags.** Correct and necessary
  (Report 05 §2), but this is textbook — length-prefix everything, lead with
  a domain separator. Its value here is remedial, not inventive.
- **RFC 6962 Merkle with `0x00`/`0x01` leaf-node separation.** Explicitly
  implementing a published standard.
- **Ed25519 / SHA-256 usage.** Library calls.
- **The 17-gate containment chain.** Thorough and well-ordered, but a gate
  sequence is a checklist; the novelty in this area sits in 1.1 and 1.2,
  which decide what reaches the gates.
- **X25519+Kyber hybrid combiner.** The construction is correct
  (domain-separated, length-prefixed) and is the recommended pattern; it is
  not new, and here it is not exercised across a trust boundary at all
  (Report 03, I-20).

## 3. Material risks to any filing

These are engineering facts with IP consequences, stated because a patent
examiner or an acquirer's technical diligence will find them.

**IP-1 (high).** The containment path — a plausible subject of any
"autonomous accountability enforcement" claim — is **unreachable from the
engine** (Report 04 §3, EXECUTION-PROVEN). A claim describing an end-to-end
system that observes, reconciles, warrants and contains would not be
supported by a reduction to practice, because the fourth stage cannot be
entered from the third. The demonstrated system stops at `Constrain`.

**IP-2 (high).** The three strongest candidates (1.1, 1.2, 1.3) exist
**only on `claude/codebase-production-readiness-wm6idp`**, a branch that is
not merged to `main`. Whatever is filed must be anchored to that branch's
tree; `main` does not contain the described mechanisms.

**IP-3 (medium).** All 103 commits carrying this work have a single machine
author identity (Report 02 §2). Inventorship for machine-generated
contributions is unsettled and jurisdiction-dependent. This needs a
documented human conception and reduction-to-practice record independent of
the commit log. That record does not exist in the repository.

**IP-4 (medium).** `SYNTRIASS`, `NEXORA`, `GHOST` and `AIRON` appear as
domain-tag namespaces across the code
(`SYNTRIASS/GHOST/…`, `SYNTRIASS/NEXORA/…`, `AIRON-AEGIS-HYBRID-v1`). These
are wire-format constants; changing them later is a breaking protocol change.
Name clearance should precede, not follow, any public deployment.

**IP-5 (low).** `aegis-quantum` carries `license = "UNLICENSED"` in its
workspace package metadata while depending on third-party crates. This is a
licensing hygiene item, not an infringement finding.

## 4. Drafting guidance implied by the code

If claims are drafted, the following are the load-bearing specifics that
distinguish this implementation from the general idea, and they should
appear in the specification because they are what makes it non-obvious:

1. Strength comparison is **equality**, not a threshold, for content-derived
   verdicts — over-claiming is downgraded, not accepted.
2. The top evidence class is defined by **recomputability by a third party
   from held bytes**, not by source or by confidence.
3. Positive action evidence is **unconstructible outside the engine** (a
   private field with `pub(crate)` constructors), so a caller cannot supply
   a match.
4. Coverage is **re-derived from batches**, with the window's end anchored
   to a time the collector signed.
5. The response ceiling is a **`min` of independent caps**, with an
   explicit prohibition on composing the axes arithmetically.
6. Observer-directed and workload-directed findings have **different
   targets** (`ResponseTarget::Observer` vs `Workload`), so a sensor fault
   can never authorize action against the workload.

Item 6 is worth emphasising: it is a small piece of code and it forecloses a
whole class of attack in which compromising the sensor becomes a route to
acting on the workload.
