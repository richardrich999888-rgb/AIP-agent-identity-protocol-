# Skill 27 — Enterprise Autonomous Systems Profile

## Purpose
Map enterprise agents and cloud workloads into the same accountability model after the physical-edge abstraction is stable.

## Source of truth
AIRI framework/model/tool abstractions and the universal autonomous-system model.

## Non-negotiable rules
- Enterprise agents are one deployment class, not the definition of Vanian.
- Reuse existing AIP/AIRI/observation/reconciliation semantics.
- Do not create separate enterprise-only trust scores or verdict systems.

## Required work
- Define enterprise mappings for agent, model, tool, API, database, filesystem, container and cloud execution.
- Support framework adapters through the existing thin-adapter pattern.
- Define tenant/workload binding separately from global identity.
- Add end-to-end worker/subprocess/container context propagation.
- Add adversarial tests for cross-tenant, cross-agent and cross-framework transplantation.

## Acceptance gate
- Enterprise workloads map cleanly into the same accountability core used by edge systems.
- No enterprise-specific branch of reconciliation exists.

# Claude Code Skill

## Governing discipline
- Treat repository code and executed evidence as higher authority than prose claims.
- Preserve the existing conservative epistemic model: uncertainty is not success.
- Never introduce a second reconciliation/verdict engine.
- Every security-sensitive object must be versioned, domain-separated, and encoded injectively.
- Every new claim must identify its evidence class and its observation boundary.
- Do not claim post-quantum security unless a real counterparty exchange and trust boundary are implemented and tested.

## Required workflow
1. Read the relevant existing architecture, tests, and audit findings before editing code.
2. Produce an implementation plan and invariant matrix before implementation.
3. Implement the smallest compatible change.
4. Add adversarial tests for substitution, replay, transplant, malformed input, and loss/absence as applicable.
5. Run targeted tests, then the complete required test matrix including service if in scope.
6. Produce an evidence report stating what is CODE-PROVEN, TEST-PROVEN, EXECUTION-PROVEN, DOCUMENTED, INFERRED, and UNKNOWN.
7. Do not promote or merge unless the skill acceptance gate is satisfied.

## Deliverables
- Architecture/specification changes
- Invariant matrix
- Implementation changes
- Adversarial/conformance tests
- Migration/versioning notes
- Evidence report and known limitations
