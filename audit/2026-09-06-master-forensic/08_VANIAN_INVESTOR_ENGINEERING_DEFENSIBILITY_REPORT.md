# Investor Engineering Defensibility Report

Written on the assumption that it will be read adversarially by someone
whose job is to find the gap between the claim and the code. Every figure is
reproducible from `00_EVIDENCE_BASE.md`.

## 1. What actually exists

| | Figure |
|---|---:|
| Rust LOC on the strongest branch (`prod`) | 58,268 |
| Tests passing on `prod` | 787 (0 failing, 3 ignored, 78 binaries, 0 warnings) |
| Tests passing on `main` | 143 |
| Crates on `prod` absent from `main` | 8 |
| Adversarial-test files on `prod` | 4, totalling 3,320 lines |
| Domain-separated wire tags | 15 |
| Branches carrying materially different architectures | 4 |

The engineering is real. 66,074 lines were added to `prod` in fourteen days
and the result compiles clean and tests clean. That is not a prototype's
test posture.

## 2. The five things a technical diligence will find

Stated first, without cushioning, because they will surface anyway.

**D-1 — The strongest work is not on `main`.**
`main` is 103 commits behind `claude/codebase-production-readiness-wm6idp`.
Every architectural asset described in §3 — the reconciliation engine, the
observation layer, the warrant ceiling, the corrected signing payloads —
exists only on that unmerged branch. A reviewer cloning the default branch
sees 16,653 Rust LOC and 143 tests, not 58,268 and 787.

**D-2 — Containment cannot fire.**
EXECUTION-PROVEN (Report 04 §3). The gate chain requires an evidence
strength of `Proven` for a workload violation; the reconciliation engine
caps every workload violation at `Attested` exactly. An exhaustive 32-cell
sweep under a maximally permissive policy returns `Contain` in four cells,
all four requiring a hand-forged record. Neither the warrant crate nor the
containment crate has ever called the reconciler.

If the product story is "it observes, proves, and then acts", the fourth
verb is currently not reachable from the third. The demonstrated ceiling is
`Constrain`.

**D-3 — Two P0 defects remain open on every branch.**
The verifier has no clock (a packet dated fifty years out passes all rules
at `AuthorityBound` with `tampered = false`), and a delegation hop's issuer
is never bound to the previous hop's grantee (any trusted key can substitute
itself into a chain). Both are in the code that carries the protocol's
central claim about who authorized what, and when.

Both are small fixes. That is the point: they are small, they are known, and
they are open.

**D-4 — The HTTP service was not touched.**
`aip-service/src/handlers.rs` is byte-identical (`b5341baf3c4e0b03`) across
main, prod, audit and importot. `keys.rs` likewise. Every service-tier
finding — verbatim scope handling, admin fail-open, cross-tenant revoke,
private seeds accepted in request bodies, silent key regeneration on a
missing key file — is unremediated. The service is also a member of no
workspace, so the repository's primary test command never compiles it.

`prod` did add one thing here: a characterization test named
`weakness_generate_then_verify_accepts_self_issued_authority`, which asserts
that a caller can self-issue an admin token and have the service seal and
then validate it. The weakness is documented and pinned. It is not fixed.

**D-5 — The quantum-resistance claim is not supported by code.**
No post-quantum cryptography exists on `main` or `prod`. It exists on
`valladder` and `aipv4` — the repository's *oldest* branches, from
May–June 2026, forked from the initial commit — and there
`process_packet_event` discards the packet event and runs a key exchange
between two parties simulated in the same process. `secrets_match` is
arithmetically always true. There is no peer, no network, and no write to
the session map the documentation describes. The hybrid combiner itself is
correctly constructed; it is exercised only against itself.

## 3. What is genuinely defensible

Also stated without cushioning, because a report that only lists problems is
as useless as one that only lists strengths.

**The epistemic discipline is real and it is unusual.** Three properties,
all CODE-PROVEN and TEST-PROVEN on `prod`:

- The default verdict is "cannot prove". Absence of evidence yields no
  verdict, enforced through one choke point, with a fail-closed rewrite.
- The highest evidence class is defined as *recomputable by a third party
  from held bytes*, and content read from the observed host is structurally
  barred from it because that content is root-forgeable.
- Coverage claims authored by the observed host are re-derived from the
  attested batches rather than read, because a signature over a host's claim
  authenticates the relay, not the claim.

Most systems in this space compose a severity and a confidence into a score
and threshold it. This one explicitly refuses to: "Nothing here computes a
product of the two axes." Each axis independently caps the response; none
can raise it. That is a defensible architectural position and it is
implemented as stated.

**The observer boundary is designed rather than asserted.** The probe on the
observed host holds no key, has no signing method, and its batch type has no
signature field. The collector, off-host, assigns the sequence number and
the timestamp. The module documentation states precisely what an attacker
with root on the observed host can forge (the content of observations
*offered*) and cannot (an attestation of them), and names the remaining
transport assumption as a deployment obligation rather than glossing it.

**The test posture on `prod` is serious.** 787 tests including 3,320 lines
of dedicated adversarial tests. The delegation test that constructs a hop
*validly signed by the genuine key* which nonetheless outlives its parent,
and requires rejection, is the kind of test that only gets written when
someone has thought about the actual threat rather than the feature list.

## 4. Where the tests do not cover what they appear to

Three cases, because diligence will find them and it is better that they
appear here first (Report 06 §4 has the detail):

1. **Containment tests** verify seventeen gates against hand-built records
   that the engine cannot produce.
2. **The circuit-breaker exhaustion test** verifies a mock LRU defined in
   the test crate; the real `CircuitBreaker` has an unbounded `HashMap` with
   no eviction path — a remote memory-exhaustion vector in the component
   whose stated purpose is defending against runaway agents.
3. **The PQC tests** verify a loopback round-trip; none supplies a wrong
   ciphertext, a tampered key, or a counterparty.

None of these tests is defective. The gap is between what they assert and
what their names imply.

## 5. Governance

All 103 commits on `prod` — 66,074 lines — carry a single machine author
identity, over fourteen days. Commit metadata records no independent human
review of any commit.

For an engineering-velocity narrative this is a strength. For diligence it
raises two specific questions that the repository cannot currently answer:
who reviewed the cryptographic changes, and what record establishes human
conception for any intellectual property claim (Report 07, IP-3). Neither is
a code defect. Both are answerable with process, and the answer should exist
before it is asked.

## 6. Position

**The asset is the reconciliation engine and the observation boundary, on
one unmerged branch.** They encode a defensible and unusually disciplined
position on what a system may claim to know and on what evidence.

**The liabilities are specific, enumerable, and mostly small.** Two P0
defects that are each a few lines. A containment path that needs a decision
before it needs code. A service tier that was never in scope for the work
that was done. A post-quantum component that measures latency rather than
establishing a secret with anyone.

**What would change the position most, in order:**

1. Merge `prod` to `main`, or state clearly that `main` is not the product.
   The current arrangement means the repository's default branch
   understates the work by 42,000 lines and 644 tests.
2. Close the two P0s. They are small and they sit under the central claim.
3. Answer whether autonomous containment is meant to be reachable, then
   write the end-to-end test either way. The test documents the answer.
4. Either bring the service tier into scope or scope it out explicitly.
   Byte-identical handlers across four branches is a decision by default.
5. Stop describing the system as quantum-resistant until a PQC exchange has
   a counterparty.

None of the five is research. All five are engineering with known shapes.
