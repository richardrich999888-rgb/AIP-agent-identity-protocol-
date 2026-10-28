# Policy interoperability

OPA is the reference evaluator. `OpaAdapter` sends a native input to an institution-configured HTTPS endpoint and records engine/version, expected policy version, issuer-qualified principal, tenant, resource, action, request, execution-context reference, input commitment, timestamp, native response, source authenticity and conditions. The v1 adapter profile requires a native object containing boolean `allow` and matching `policy_version`. Undefined, string-valued or differently versioned results remain INDETERMINATE. Transport failures propagate; they never become allow.

The JSON commitment is domain-separated local reference encoding, **not** AIP ActionParameters, JCS or an upstream engine's hash. Native ACS input/enforced identities retain their own meaning. Do not compare these unlike digests as if they represented the same encoding.

A successful TLS exchange authenticates the configured policy service at evaluation time. It is not a signed, replay-verifiable decision archive. The CA file digest is retained; the live harness destroys ephemeral private keys. Decisions remain REFERENCE_ONLY. Policy provenance, ownership, freshness, revocation and source signature validation must be established before an institutional authority issues the existing signed `ExpectedExecution` bound to action and execution context.

The real OPA 1.21.4 mTLS test executed allow, deny and missing-client-certificate rejection. Its official release binary reports a `-dirty` build identifier; the exact downloaded binary digest is pinned. We do not mislabel that binary as the inspected main commit.

Microsoft ACS invokes its existing Rego evaluator; the bridge records its result, transformations, warnings, approvals and original/enforced input identities. It does not implement a second evaluator. The initial unavailable-executable failure blocked execution and was not recorded as approval.

Cedar's typed principal/action/resource/context model and OpenFGA's relationship tuples require separate adapters preserving native diagnostics, conditions, authorization model IDs and consistency semantics. They are evaluated, NOT_EXECUTED, and deliberately deferred until the reference same-run chain is complete. Relationship checks such as organization→agent, owner→agent, agent→tool/resource and parent→child do not by themselves authenticate a delegated execution. Removing a relationship is not proof that an already-issued bearer credential was revoked.

