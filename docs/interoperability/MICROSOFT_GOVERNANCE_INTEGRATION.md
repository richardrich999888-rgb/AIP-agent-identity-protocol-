# Microsoft governance evidence bridge

Status: PARTIALLY_VERIFIED for a real governed ADK tool invocation. Broader toolkit/Agent Mesh/MCP gateway claims remain NOT_EXECUTED.

The inspected Microsoft repository is `4eca1f5b44d30ebe5e9745ac36ca394f887e617b`. Its native Python compatibility SDK builds as `agent-control-specification==0.4.0b0` and depends on `agent-control-spec==0.4.0-alpha.4`. The latter core has moved to responsibleai/agent-control-spec. These preview/alpha components are not described here as a finalized universal governance standard.

The live test builds the real Rust binding, loads an ACS manifest and Rego policy, then invokes `AgentControl.run_tool` around the provider's actual ContextForge call. An out-of-scope record is denied before dispatch. Valid input receives native pre/post decisions. The existing engine computes `input_identity` and `enforced_identity`; the bridge preserves them, the full verdict and any transformed target. It neither re-evaluates Rego nor converts transforms/warnings/approvals to a boolean.

`microsoft_result` consumes the actual `InterventionPointResult` dataclass or its serialized form. Tuple normalization changes JSON representation only. `correlate_decision_request` compares supplied native identity strings within one tenant and returns agreement/divergence/insufficient evidence. That comparison is not signature verification or a kernel verdict. A caller must separately derive the gateway-received identity under ACS's exact encoding; this increment does not claim that join is verified.

In the test the ACS hook runs in the workload process and OPA is a local child evaluator. The upstream security guidance also supports stronger isolated deployments; it would be inaccurate to claim every Microsoft control necessarily shares the workload process. Native audit references and evidence pointers are not fetched or cryptographically endorsed by VANIAN. Source signatures, if introduced by a deployment, require an explicit verifier and trust policy; none are claimed here.

Microsoft supplies the implemented governance controls. VANIAN reuses gateway signatures and adds separately qualified evidence references; independent kernel observation remains absent. Agent Mesh identities, all framework integrations, gateway enforcement and the toolkit's entire audit subsystem were not executed.

Failure history is retained: an incorrect OPA executable environment setting produced a native blocked verdict; native tuple-valued warnings initially required JSON-container normalization. Neither failure was converted into successful governance.
