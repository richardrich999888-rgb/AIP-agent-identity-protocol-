# Skill 12 — Python Runtime & Agent Boundary

## Objective
Establish a trustworthy boundary between Python agent code and Vanian's independent execution-accountability pipeline.

## Threat model
Assume the agent process can be compromised or can lie.
Python logs, callbacks, decorators, framework hooks, and application telemetry are therefore self-authored unless independently corroborated.

## Required concepts
Distinguish:
- declared intent
- requested tool call
- framework event
- Python execution
- subprocess execution
- external effect
- independently observed execution

## Implementation direction
Create a reusable Python-side SDK/interface that can:
- bind a Python agent to an AIP identity
- create/propagate execution IDs
- attach ExpectedExecution references
- emit AIRI events
- propagate identity/correlation context across async tasks
- propagate context to child processes/workers where feasible
- explicitly mark framework/self-report evidence

The SDK must not:
- hold authoritative observer private keys
- self-assert Proven
- create a warrant
- directly authorize itself
- silently mint identity after key loss
- convert a framework callback into independent observation

## Context propagation
Cover:
- synchronous calls
- asyncio tasks
- threads
- multiprocessing
- subprocesses
- worker queues/message buses when supported

Use explicit context objects rather than ambient mutable global state where possible.

## Security
- No private seed material in ordinary HTTP request bodies.
- No world-readable private key files.
- No self-supplied trust anchors for authoritative verification.
- Use explicit key/version identifiers.
- Use domain separation and canonical encoding.
- Fail closed on malformed or ambiguous execution context.

## Acceptance criteria
A sample Python agent can:
1. obtain/use an existing AIP identity;
2. receive an ExpectedExecution;
3. execute a tool request through AIRI;
4. propagate execution identity into the tool boundary;
5. produce a self-report event that is clearly classified as self-report;
6. be reconciled with independent evidence;
7. never gain Proven status merely because the SDK says the action succeeded.
