# Experience-to-capability engine

Code: `sovereign/syntriass-runtime/src/capability/` (pure) and
`src/learning.rs` (lifecycle IO). Harness:
`research/capability-learning/harness/`. Results: LEARNING_BENCHMARK.md.

## 1. What a capability is

A **typed, versioned, content-addressed artifact** (`artifact::Capability`),
never a prompt and never code:

| Field | Meaning |
|---|---|
| `id`, `version`, `intended_task`, `outcomes` | identity and output vocabulary |
| `applicability` | terms that must appear + minimum inputs found |
| `procedure` | inputs (kind + cue words) → text guards → numeric guards → missing-input outcome → derived values → ordered rules → default |
| `required` | caller requirements (tenant, minimum clearance, security domain) — a requirement, never a grant |
| `dependencies` | evidence document digests, policy version, optional execution-model hash |
| `evidence_refs`, `failure_conditions`, `tests` | provenance; artifact tests run as *generated* only |
| `proposed_by` | principal id or `model:<sha256>` |

Its identity is the SHA-256 of its canonical JSON. The procedure language
(`expr`) has arithmetic, comparisons and and/or — no calls, IO, loops,
strings or indexing; bounded tokens, depth and exponent; division by zero
and non-finite values refuse. Unit handling lives in reviewed runtime code
(`quantity`); a capability selects kinds and cue words but cannot add a unit.

## 2. Separation for model-independent retention

| Part | Where | Model-specific? |
|---|---|---|
| Proposal prompt and transcript | `results/propose_*/transcript.jsonl` | yes (only used to draft) |
| Procedure | artifact `procedure` | no |
| Executable rules | compiled `Compiled` from the procedure | no |
| Test cases | signed `ExpertSuite` (separate object) | no |
| Evidence | digests bound from the corpus | no |
| Approval | Ed25519 signature over capability hash + validation report hash | no |
| Execution model | `dependencies.execution_model_sha256` — `None` for this capability | when set, a model change makes it stale until re-validated |

## 3. Lifecycle

`PROPOSED → TESTING → VALIDATED → APPROVED → ACTIVE`, plus `REJECTED`,
`SUSPENDED`, `REVOKED`, `SUPERSEDED`. The edge table (`lifecycle::allowed`) is
the whole policy: the validator moves to TESTING/VALIDATED/REJECTED; only an
approver approves or revokes; only an operator activates or supersedes.
Execution requires `ACTIVE ∧ approval present ∧ passing validation ∧ content
hash unchanged`, and at request time the runtime re-checks the approval
signature against its configured approvers, the caller's tenant, domain and
clearance, and every dependency (evidence digest read through the SQL ACL,
policy version, execution model).

## 4. Independent validation (and the defect fixed on the way)

Validation counts **only** cases from an `ExpertSuite` signed with a trusted
expert's key (operator-configured), whose expert is not the proposer and
whose tenant is the capability's. Requirements: ≥ 8 expert cases, ≥ 1
counterexample, all passing; artifact-carried cases all passing (they can
only fail it); every evidence document readable by the capability's own
tenant. The report binds capability hash, suite hash and expert id; the
approval signs the report hash.

The version found at the start of this session let artifacts carry their own
"expert" cases with an unauthenticated author string — a capability could
certify itself (commit c15c3f2 fixes it; regression tests cover forged
authorship, proposer-signed, other-tenant and tampered suites).

## 5. Experience ingestion

`capability::experience`: an experience is admitted only into the recording
principal's tenant and security domain; agent-reported success is stored as
`SelfReported` and never counts; a `Verified` experience becomes a suite case
only when the named verifier (≠ actor) signs it into a suite.

## 6. Evidence binding

A proposal names documents; `learning::bind_evidence` fills their digests
from the corpus, read as the capability's tenant at its required clearance.
Unknown, other-tenant or unreadable documents abort the proposal. A later
change to a document makes the capability stale (refused, not re-used).

## 7. Proposal: what happened

The local model (Qwen2.5-1.5B Q8_0) produced the right *shape* (four inputs,
validity rule, temperature correction, minimum, PI bands) but every draft
had defects: operator precedence in the correction, an undefined `minimum`,
a misnamed variable, the wrong outcome for out-of-range temperature, shifted
PI bands. Repair feedback (compiler diagnostics, demo mismatches) produced
byte-identical output. The usable capability is the model draft plus 7
engineer corrections, each citing the procedure text. Larger models (not
runnable on this host) are the obvious next test of autonomous proposal.

## 8. Reuse path

At request time the controller sees only ACTIVE, authorized, applicable
capabilities: exactly one fresh → run it; more than one → refuse as
ambiguous; one stale → refuse and flag for re-validation (never fall back to
an unvalidated answer). Explicit invocation by id is refused unless every
check passes.
