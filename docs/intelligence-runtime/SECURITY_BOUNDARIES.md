# Security boundaries — intelligence runtime v0.1

"Demonstrated" = an executable test or recorded run in this branch exercises
the property against the integrated code. None of this is an independent
audit or a certification.

## Demonstrated

| Property | Mechanism | Evidence |
|---|---|---|
| Model output cannot grant authority or change policy | controller sees features only; authority comes from the principal and signed approvals; exact policy decides priorities | `tests/runtime_app.rs::model_output_cannot_escalate_authority_or_change_policy` |
| Retrieval respects tenant and clearance | ACL inside the SQL query (Sovereign) | Sovereign tests; `grounded_qa_sees_only_the_callers_documents`; demo Scene 1 |
| Capabilities cannot self-certify | signed expert suites from trusted, independent experts; artifact cases count as generated | `capability_engine.rs` (6 suite-attack tests), c15c3f2 |
| Capabilities cannot self-authorize | `required` is checked against the caller; no field grants; approval by a configured approver ≠ proposer, Ed25519-verified per request | `learning_flow.rs`, `capability_engine.rs`, demo Scene 5 |
| Unauthorized principals cannot use a capability | invisible to other tenants/lower clearance; explicit invoke refused | Phase D: 18 probes, capability used 0 times |
| Tampering disables a capability | content hash re-checked at every use; approval bound to the hash | `tampering_after_approval_disables_execution`; demo Scene 5 |
| Stale knowledge, policy or model forces re-validation | dependency check per request | `changed_evidence_or_policy_makes_it_stale_and_refused`; Phase E (8/8 refused after a model swap) |
| Evidence cannot be chosen by the proposer | digests bound from the corpus | `evidence_digests_are_bound_by_the_system_not_the_proposer` |
| No cross-scope prefix-cache reuse | `CacheScope` (model, tokenizer, policy, knowledge snapshot, principal scope, domain); erase before a slot changes scope; never save/restore | integrated attack: 3 scopes, 2 slots, 0 violations; research harness: timing AUC 1.00 → 0.43 |
| No KV checkpoints on disk | slot directory 0700, must stay empty; supervisor errors if a file appears | `ModelServer::stop` |
| Offline | `offline.sh`: user+net namespace with loopback only, refuses to run if a route exists; inference client accepts loopback IP literals only | every model run in this branch; demo Scene 6 |
| Model integrity | streamed SHA-256 before every model start | `supervisor.rs` tests |
| Audit integrity | hash chain; request stored as a hash only | `audit_chain_verifies_and_detects_tampering`; `audit-verify` on every run |

## Not provided (must not be claimed)

1. **Authentication** beyond the OS uid → principal map (`ask`). `serve
   --eval` takes principals from its input and is an evaluation harness only.
2. **Key custody separation.** Approver, expert and runtime keys share one
   host and uid in the research setup; private keys are 0600 files.
3. **Independent observation.** No Sniffer Dog observer is attached; every
   audit record says `CannotProve`; nothing here is verified execution.
4. **AIP action authorization in the runtime path.** The AIP-authorized tool
   runner exists in `vanian-sovereign` but the runtime does not route to
   actions; the `consequential` approval flag is recorded, not enforced.
5. **Timing within a scope.** A principal can observe its own scope's cache
   state (repeat requests are faster) — by design; scope granularity
   (principal vs role) is a policy decision not made here.
6. **Sidecar isolation.** The Python sidecar runs as the runtime's uid with
   pipes only; it is not sandboxed beyond the network namespace.
7. **Denial of service** (long inputs are bounded by `MAX_TEXT_CHARS`, model
   time is not).
8. **Revocation distribution** across installations.
