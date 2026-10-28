# Evidence and trust boundaries

| Source | Permitted conclusion | Not established |
|---|---|---|
| Authenticated issuer JWT / JWT-SVID | Subject under configured key, profile, audience and time | Logical-agent ownership, revocation freshness, execution |
| TLS-served Agent Card | Card served by configured endpoint | Capability truth, card signature, organization authority |
| OPA / ACS result | What that evaluator reported, with exact native semantics | Independently signed execution authority or observed compliance |
| Signed task-delegation profile | Authenticated request scope under the configured delegator key | AIP authorization chain or remote internal execution |
| ContextForge signed receipt | Gateway-received parameter commitment and disposition | Downstream business outcome or kernel execution |
| ADK callback / OpenTelemetry | Application-reported correlation | Independent process or logical-agent attribution |
| OpenShell OCSF | Reported native enforcement/audit event | Authenticated export or separate sensor coverage without further evidence |
| Attested observation plus sensor health | Existing core's supported OS events and qualified coverage | Truth of a compromised kernel or unobserved operations |
| Authoritative business system record | Its authenticated outcome within stated authority | Every causal step leading to it |

Keys for agent, institution decision point, gateway and observer must remain independently provisioned. Distinct byte strings are necessary but do not prove administrative independence. Off-host custody cannot repair a compromised source kernel.

`interop_verify` composes the existing Rust ExpectedExecution, gateway and observation verifiers without changing signing formats. It refuses reused role keys and malformed native envelopes. It returns native tool-boundary and runtime results separately. Expected-side coverage is Unknown. Its optional native authority bundle now passes through `aip-authorize::verify_authority_reference`, which checks the exact signed root/hop references, signatures, leaf agent, effective action scope and inclusive validity at issuance. Trusted roots are distinct from known delegator keys. Missing authority remains NOT_ASSESSED; supplied invalid authority is refused. Revocation, external identity mapping, institutional custody and resource/spend policy remain NOT_ASSESSED. It is not an institutional admission service.

Absence of an authorization does not imply adverse observed execution. Absence of a sensor does not imply compliance. A missing/mismatched receipt does not become a valid observation. Framework or governance references cannot deserialize as signed native observations. No aggregate trust score grants authority.

The final lab contains genuine model/tool traffic and gateway signatures but test-controlled identities and fixture ExpectedExecution records for separate comparator cases. The model's own tool receipt is **not** joined to those fixture authorizations. No same-run collector archive exists. Existing historical RBI archives are preserved and can be reverified separately; combining dates or operations would be invalid.

Evidence hashes in the archive manifest detect changed bytes only when the manifest is independently retained. They are not new observer signatures. Offline receipt verification trusts an externally supplied public anchor; the co-located lab anchor demonstrates reproducibility, not third-party identity validation.

Tetragon, Falco and auditd remain comparison candidates. Shared Linux kernel/capability failures must be recorded. Never feed a reconciliation output back into either source and call the resulting agreement independent corroboration.
