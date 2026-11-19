# P0-049 open gaps

**Release NOT READY.** Detailed source/test/evidence mapping is in
`P0-049-COMPLETION-MATRIX.md`.

1. **W3 is incomplete.** Live model drafting, the newly retained B3 applicability failure,
   C1 answered-session/question linkage, teaching approval composition, knowledge packs, signed answer records, local
   REST/MCP, examples, role-aware teaching UI and complete two-domain workflow
   remain. Iteration 3 fixes explicit exclusion word forms and explains the term
   length limit. The broader suite still rejects `fa-3`: a battery-cell request
   enters the transformer path and returns INSUFFICIENT_INPUT rather than
   NOT_APPLICABLE. The same failure occurs before/after this fix and on CI.
   Keep its original label and repair applicability before approval. The C1
   command is a bounded read-only diagnostic, not a full demo.
2. **No complete offline kit.** W's builder omits the AIRON binary, weights,
   inference runtime, teaching files and complete local dependencies. Python setup
   can use PyPI when wheels are absent. No complete authenticated manifest and
   offline clean-machine install have been accepted.
3. **Original OVERLAY demo source unavailable.** Six recorded local revisions are
   not accessible remotely or locally here. Rebuild W4/W5 from verified requirements
   on accessible source, with fresh tests/captures, unchanged app hashes and identity
   refusals. Keep PQ labelled PROOF OF CONCEPT.
4. **Network/sensor acceptance open.** The process-connector sensor requires the
   initial netns. No independent isolation boundary or full-run packet captures
   were established for that sensor here. C1-only namespace counters are retained;
   they do not establish the sensor's network isolation. Historical signatures do not
   establish sensor continuity or event completeness.
5. **Benchmarks incomplete.** W6.1 already has a wrapper and comparison script;
   their full offline run has not been retained/accepted. W6.3 and two-machine
   sizing need a genuinely separate host, with no mixing of hardware results.
6. **Wrong investor sequence.** W currently omits teaching in favour of Quantum
   X-ray. The required plug → teach → liar sequence and its actual duration are
   unmeasured. Manufacturing and healthcare modes are missing; banking/defence
   need current end-to-end acceptance.
7. **Rehearsal threshold unmet.** Historical subset results do not cover all
   required modes or W3's twenty-run requirement, final integrated code, fresh
   offline installs and complete signed/capture archives.
8. **Integration and CI open.** T/W diverge; three overlapping dependency/setup
   paths differ. PR #16/#17/#19 require content-aware integration review. Four
   HIGH Trivy findings on the retained Helm render remain. Iteration 2 at `9e3909e`
   updates the affected SQLite/rustix pins and fixes audit exit propagation; local
   audit/deny and storage/runtime regressions pass. Iteration 3 source audit/deny
   also passes; a complete-CI claim remains unavailable. No finding was suppressed,
   no advisory exemption added and no branch auto-merged.
   Iteration 3 teaching CI `43164083237` fails on the newly enforced fa-3 attack
   after its regression tests pass. That failure is retained, with no
   `continue-on-error` or expected-label substitution.
9. **External acceptance absent.** No external evaluator has installed the final
   package, verified all signed evidence and reproduced required results. The
   connected CI reproduction of C1 is useful evidence, not this acceptance.

Iteration boundary: implementation, local verification, evidence, branch update,
draft PR and CI inspection are the authorized work for one iteration. Continue with
the next dependency-ordered item; do not turn incomplete rows green by relabelling.
