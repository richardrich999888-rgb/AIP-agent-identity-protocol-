# ADR-009 — The approval tier: shown versus authorized

**Status** PROPOSED (crate implemented; no reconciler entry point)
**Date** 2026-09-13
**Related** ADR-008 (enforcement boundary), `APPLICATION_LOG_SENSOR_DECISION.md`,
`docs/IP/CLAIM_SUPPORT_MATRIX.md`, audit blocker B-3, AIRI_MIGRATION §4

---

## 1. The gap

Every artifact this system holds describes the *system's* side of an action:
the decision point's `ExpectedExecution`, the collector's `AttestedBatch`,
the agent's own AIRI claims. **What a human approver was shown is not among
them.**

That is the gap behind the failure mode the industry calls human-approval
exploitation: the approval was genuine, and it was an approval of something
other than what was sealed. No amount of observation catches it, because the
execution may match the authorization perfectly — the divergence is upstream
of both.

## 2. Decision

**Add a tier that seals what was shown and compares it, arithmetically,
against the sealed intent. It produces a comparison, never a verdict.**

`aip-approval`:
- `ApprovalArtifact` — signed by the **approval surface**, domain-separated
  under `SYNTRIASS/GHOST/APPROVAL_ARTIFACT/v1`, committing to the decision
  id, the expectation digest, the digest of the bytes shown, the rendered
  form, the action kind shown and the parameter digest shown.
- `verify_artifact` — the only constructor of `VerifiedApprovalArtifact`,
  against anchors the verifier chose. Refuses an artifact whose surface
  anchor is the agent's own key, mirroring
  `verify_expected_execution_for_agent`.
- `compare_shown_to_authorized` — pure, clock-free, network-free, over a
  *verified* `ExpectedExecution`.

Following ADR-008 §2, the tier is a separate component that cannot name
`aip-observe`, `aip-observation`, `aip-reconcile`, `aip-warrant` or
`aip-containment`; a test reads its own manifest to keep it that way.

## 3. Why this class is different — and why it matters beyond the feature

Every workload-directed divergence class the engine has today is pinned at
`strength == EvidenceStrength::Attested` **exactly**, and the code gives the
reason: *"the content is procfs-read and can never be `Proven`."* `Proven` is
reserved for facts a third party recomputes from held bytes, which is why
`classify_observer_error` grants it for signature arithmetic and refuses it
for a bad local trust anchor.

A shown-versus-authorized divergence is **not content-derived**. Both inputs
are signed artifacts; the comparison is digest equality; a third party with
the two artifacts and the two anchors recomputes the same answer offline.
Nothing is read from the observed host.

It is therefore the **first workload-directed divergence class in this system
whose basis could legitimately carry `Proven` without weakening the rule that
keeps everything else at `Attested`.** `Basis::Recomputable` is the marker.

The consequence reaches past this ADR. Blocker **B-3** — containment
unreachable because the gate needs `Proven` and no workload verdict can carry
it — is not a gate that is too strict. It is a gate with no eligible input.
This tier is the first candidate input. Making it one is §4, and it is
deliberately not done here.

## 4. The gate — not crossed by this ADR

A `reconcile_approval_divergence` entry point is **a new way to accuse**, and
the project's own rule (AIRI_MIGRATION §4) is that such a path needs the
depth the existing `PhantomClaim` path has before it is trusted. Required
first:

1. **The same choke point** — `Draft`, `prologue`, `precondition_holds`. No
   second authority.
2. **A structural precondition at least as strict as `PhantomClaim`'s**: both
   artifacts verified under **verifier-chosen** anchors, matched
   `decision_id`, and `Basis::Recomputable`. The type already refuses to
   report `Recomputable` when the expectation did not verify — pinned by
   `a07`.
3. **An adversarial suite of comparable depth** to
   `aip-reconcile/tests/adversarial.rs`, specifically covering: a surface
   that signs a false artifact (the surface is a new trust anchor and a new
   thing to compromise); a replayed artifact from an earlier expectation
   under a reissued decision id (covered today by `a04`); and **a rendering
   whose digest is honest but whose meaning differs** — which this comparison
   cannot see and must never claim to.
4. **A false-positive budget** agreed with whoever operates it.

## 5. Stated limitations

- **The comparison is over digests, not meaning.** A surface that renders
  "1206" in 4-point grey has produced an honest digest of a dishonest
  screen. `RenderedForm` records which form was digested so the limit is
  visible rather than assumed away; it does not close it.
- **The surface is a new trust anchor.** Its key can be compromised, and then
  it can sign whatever it likes. The tier narrows the trusted set; it does
  not eliminate it. This is the same shape as the collector's key-custody
  boundary and is stated the same way.
- **`Agrees` says nothing about execution.** It means the human approved what
  was sealed. What then ran is the observer's question, and this crate never
  asks it — pinned by `a11`, which asserts the serialised result contains no
  execution or verdict vocabulary at all.
- **Absence is the ordinary case.** Most decisions are never shown to a
  human. `NotEvaluated { NoApprovalArtifact }` is not a gap in coverage and
  must not be surfaced as one.

## 6. Relationship to the application-log decision

`APPLICATION_LOG_SENSOR_DECISION.md` (Gate 5, DECIDED) fenced application,
database and proxy records out of *observation*: a record a host-side process
writes about itself is a witness's claim with no loss signal the observer can
trust.

An approval artifact is also a statement written by a non-kernel party — so
why is it admissible here when a log line is not?

Because it is not being admitted as **observation**. It is one half of a
**comparison between two authorization-side documents**, and it makes no
claim about what happened on the host. The log-sensor decision bars such
records from producing, upgrading or lowering a reconciliation result and
from counting as coverage. This tier does none of those things: it produces
no result, and coverage is untouched. The fence stands.
