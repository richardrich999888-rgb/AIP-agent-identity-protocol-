# A2A integration

Status: PARTIALLY_VERIFIED. Python SDK 1.3.0 is used through its native protobuf messages, AgentCard resolver and ClientFactory. ADK 2.13.0's A2A extension remains explicitly experimental.

`A2AConnection` requires an operator-approved HTTPS origin, CA and client certificate. It disables ambient proxy credentials and redirects, bounds responses, checks every advertised interface origin, and obtains an audience-scoped credential only after checking the outgoing origin. An Agent Card retains retrieval provenance, serving-endpoint authentication, content commitment, unverified card signature status and DECLARED capabilities. TLS authenticity does not validate capability claims or a card's optional signature.

The exercised profile is nonstreaming request/response with task and artifact handling delegated to the official SDK. Streaming, cancellation, push notifications, authenticated extended cards, all SDK transports and full official conformance certification are NOT_EXECUTED. A working SDK interaction is not conformance certification.

## Cross-organization profile

The lab models a bank delegator and provider research agent. They communicate over mTLS with a signed, audience-bound JWT. A separate task credential binds delegator, tenant, parent task, resource, action, exact message commitment, expiry and unique delegation ID. Durable SQLite reservation precedes dispatch and refuses replay after restart. Failures consume the reservation. The replay database and its parent directory must be institution-controlled; clustered replay storage and garbage collection are not implemented.

This task credential is a **VANIAN deployment profile**, not the standardized A2A delegation format, not VANIAN AIP identity and not `ExpectedExecution`. In production the issuer must be outside the agent. The lab issuer is in the harness, so institutional delegated authority is NOT_ESTABLISHED.

The server example authenticates before ADK and strips credentials from metadata because ADK can echo metadata into task history. Only the delegation reference and parent task are forwarded. No local gateway credential is sent to the remote endpoint.

Live negatives cover absent client certificate, absent bearer, wrong audience and changed delegated content. Unit tests cover forged issuers/keys, unsupported token profiles, durable replay, revocation and cross-origin forwarding. Records explicitly report remote kernel UNOBSERVED. A successful provider response proves neither its hidden computation nor its business outcome.

## Reproduction

Follow [the package README](../../integrations/interoperability/README.md). The final combined workload and public gateway receipts are under `validation/interoperability/results/20261028/combined/`. It runs two real model-driven ADK agents. It does not establish two independent organizations or remote sensor access.

The official [A2A TCK](https://github.com/a2aproject/a2a-tck) was identified separately. Its pinned compatibility/coverage assessment is recorded in the upstream lock. It was not substituted with this adapter's unit tests.
