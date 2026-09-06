# Skill 11 — AI Runtime Integration Boundary

## Objective
Extend Vanian from host/process accountability into the AI-agent execution stack without weakening the existing epistemic model.

## Scope
Cover:
- Python application/runtime boundary
- agent orchestration frameworks
- model invocation
- structured tool/function calls
- async/event-driven execution
- subprocess and worker execution
- containers
- GPU/accelerator hand-off where observable

Candidate frameworks/adapters:
- LangChain / LangGraph
- LlamaIndex
- AutoGen
- CrewAI
- OpenAI-style Agents/Responses tool calling
- custom Python agent runtimes

Do not make any third-party framework a trust anchor.

## Core rule
Framework instrumentation is declarative evidence about what the application says it is doing.
Independent runtime observation remains the authoritative observation boundary wherever technically possible.

## Required model
Preserve this chain:

Identity
→ Authority
→ Authorization
→ ExpectedExecution
→ AI Intent / Tool Request
→ Runtime Execution
→ Independent Observation
→ Action Evidence
→ Reconciliation
→ Warrant
→ Containment
→ NEXORA Proof

## Design requirements
1. Define a stable Vanian AI Runtime Interface (AIRI) independent of vendor/framework APIs.
2. Make framework adapters thin translators into AIRI.
3. Bind every adapter event to:
   - AIP agent identity
   - execution instance
   - ExpectedExecution where applicable
   - correlation/execution ID
   - parent/child execution lineage
   - model/runtime metadata
4. Do not allow adapter self-report to manufacture Proven evidence.
5. Do not infer authorization from framework configuration.
6. Keep identity lineage, authority lineage, process lineage, and application execution lineage distinct.
7. Treat missing adapter evidence as incomplete observation, not proof of absence.
8. Define explicit versioning and canonical serialization for AIRI events.
9. Domain-separate AI runtime event signatures from existing packet/token/expected/observed domains.
10. Preserve offline-verifier re-derivation semantics: the verifier must recompute facts from supplied evidence, never trust claimed verdict fields.

## Acceptance criteria
- One framework adapter can emit an AIRI execution trace.
- The same AIRI schema can represent multiple frameworks.
- Cross-framework event substitution fails cryptographically or structurally.
- Adapter-only evidence cannot escalate CANNOT_PROVE to Proven.
- Execution instance binding survives process/worker transitions where supported.
- Every limitation is documented as NOT_DETERMINABLE or CANNOT_PROVE rather than silently inferred.
