# Google ADK integration

Status: PARTIALLY_VERIFIED. The live run uses actual `LlmAgent`, `Runner`, `InMemorySessionService`, `BasePlugin`, `to_a2a`, and the official A2A SDK. No upstream source modification is required.

A bank agent uses model-generated arguments to call a delegation tool. Its request reaches a provider ADK agent over authenticated A2A. The provider makes a genuine second model decision to call a tool. The existing ContextForge gateway dispatches that request to a real MCP upstream and signs what it received. The final combined run also applies Microsoft's native pre/post-tool governance to that provider tool.

The local Qwen model performs four genuine inference calls. No fixed response, synthetic model trace or fabricated kernel event stands in for inference. The small model's prose is untrusted and may be inaccurate; only the actual tool result and verified receipt support tool-boundary conclusions. Financial records are synthetic.

`VanianAdkPlugin` records invocation, declared agent, tool-call identifier, argument commitment and tool errors through supported callbacks. It does not sign runtime observations or handle observer keys. Sink/serialization failures increment `dropped_events` and log a coverage gap without gating the tool. Operators must monitor this counter and logs; dropped records must not be interpreted as no activity.

Both logical agents run within one process. No trustworthy kernel boundary distinguishes their individual execution. A callback correlation is FRAMEWORK_REPORTED and not a verified `ExecutionBinding`. Local mTLS verifies the test endpoints and credentials, not institutional ownership.

Multi-agent session/task metadata is demonstrated. ADK confirmation/approval flows, arbitrary workflow types, provider-specific cloud models and all MCP/A2A transport combinations are not validated. The supported extension points do not make the full end-to-end acceptance gate green. Reproduction and evidence links are in [VALIDATION_REPORT.md](VALIDATION_REPORT.md).

