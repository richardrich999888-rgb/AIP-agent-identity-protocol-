# Skill 14 — Tool Invocation, External Effect & Consequence Boundary

## Objective
Extend accountability from an AI agent's internal decision to the concrete tool/API/device consequence.

## Required distinction
A tool call has at least three layers:

1. Requested invocation
2. Runtime execution
3. External effect

These must not be collapsed.

## Examples
- HTTP request
- database mutation
- filesystem mutation
- shell command
- cloud API
- MCP tool
- browser action
- robotics command
- industrial control
- drone/vehicle command

## AIRI event model
Every tool invocation should carry, where available:
- tool identity
- action kind
- parameter commitment
- caller/agent identity
- execution identity
- ExpectedExecution reference
- timestamp/monotonic sequence
- framework correlation ID
- result classification
- parent execution ID

Sensitive values should normally be represented by policy-controlled commitments rather than raw data.

## Binding and reconciliation
The system must be able to distinguish:
- agent claimed it called tool
- tool request was emitted
- runtime executed request
- independent observer saw matching execution
- external effect was independently observed
- observed action matched ExpectedExecution

Do not mark the chain as Proven until the repository's explicit evidence preconditions are satisfied.

## MCP and API gateways
Adapters/gateways are integration surfaces, not automatic trust anchors.
Authenticated gateways may become authoritative only when their trust model, key lifecycle, transport, and independent verification are explicitly defined and tested.

## Acceptance criteria
- Parameter substitution is detectable.
- Tool-call transplantation across agent/execution identities fails.
- Replayed events are detectable.
- A tool response cannot by itself prove that the requested side effect occurred.
- A denied invocation produces a verifiable non-execution path where independent evidence supports it.
