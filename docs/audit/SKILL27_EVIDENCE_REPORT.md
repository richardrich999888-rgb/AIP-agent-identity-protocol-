# Skill 27 — Evidence Report

**Specification** `.claude/skills/27-enterprise-autonomy-profile/SKILL.md` — one
authoritative document, byte-identical on both branches carrying it.
**Baseline** `742517c` · **Branch** `claude/skill-25-implementation-xbz0t3`
**Related** ADR-011, ADR-013, `SKILL26_27_PLAN_AND_INVARIANTS.md`

---

## 1. Acceptance criteria

| # | criterion (from the specification) | status | where |
|---|---|---|---|
| R1 | Enterprise mappings for agent, model, tool, API, database, filesystem, container, cloud execution | met | `resource.rs` — eight members, each with its mechanisms and effect locality |
| R2 | Framework adapters through the existing thin-adapter pattern | met | `adapter.rs` over `aip-airi::FrameworkIdentity`; two shipped adapters |
| R3 | Tenant/workload binding defined separately from global identity | met | `binding.rs` — `WorkloadBinding` and `IdentityKind` |
| R4 | End-to-end worker/subprocess/container context propagation | met | `context.rs` over `aip-airi::PropagationBoundary`; container as declared attribution |
| R5 | Adversarial tests for cross-tenant, cross-agent and cross-framework transplantation | met | `tests/adversarial.rs` e1–e14 |
| N1 | Enterprise agents are one deployment class, not the definition of Vanian | met | `ProfileKind::Environment` under a fifth ordinary id, beside four others |
| N2 | Reuse existing AIP/AIRI/observation/reconciliation semantics | met | framework, model, tool, subprocess, context all `aip-airi`'s; ceilings `aip-observation`'s |
| N3 | No enterprise-only trust scores or verdict systems | met | structural guard forbids the vocabulary; verdict comes from `aip-reconcile` unmodified |
| G1 | Enterprise workloads map into the same accountability core as edge systems | met | `tests/integration.rs`, real execution reaching `VERIFIED_EXECUTION` through the shared engine |
| G2 | No enterprise-specific branch of reconciliation exists | met | three legs: source guard, manifest guard, integration test |

**10 of 10.**

## 2. The ten required transplantation attacks

| # | attack | outcome | test |
|---|---|---|---|
| 1 | cross-tenant | different commitment; a signature over one is not over the other | e1 |
| 2 | cross-agent | `BindingDoesNotCoverExecution` | e2 |
| 3 | cross-framework | different commitment; adapter version too | e3 |
| 4 | copied workload identity | refused — the strings are not the execution | e4 |
| 5 | copied execution context | refused at the binding check | e5 |
| 6 | subprocess boundary substitution | `ContextChainBroken` (spliced on the wire) | e6 |
| 7 | container boundary substitution | chain digest changes; attribution was never measured | e7 |
| 8 | API/tool identity substitution | distinct resources; neither outcome establishable | e8 |
| 9 | database/filesystem op between workloads | binding does not transplant; a socket is not a row | e9 |
| 10 | stale context replay | `ContextStale` at both ends of the window | e10 |

Plus four standing negatives (e11–e14). **Every attack fails binding, fails the
chain, or resolves to `Unknown`. None creates a valid identity.**

## 3. Evidence classes

**CODE-PROVEN** — the crate names no trust-score vocabulary (`TrustScore`,
`RiskScore`, `TrustLevel`, `Reputation`, `confidence_score`), never branches on
a framework name (`if name ==`, `match name`, `TRUSTED_FRAMEWORKS`, `allowlist`
all absent), mints no identifier, holds no key, builds no observation record and
adds no leaf kind. Twelve guard tests assert this over its own source. There is
exactly one `WorkloadBinding` constructor and exactly one place the execution
identity digest is computed.

**TEST-PROVEN** — 93 tests over constructed values (56 unit, 14 adversarial, 12
structural, 11 cross-vertical). All 14 invariants in the plan document.

**EXECUTION-PROVEN** — 6 tests running the Skill 22 reference as an enterprise
agent host: real processes, real measurement, and **the same reconciliation
engine the edge verticals use**, reaching `VERIFIED_EXECUTION` with no
enterprise branch anywhere in the path. A context chain over that real execution
admits only that execution and refuses a different process on the same host.

**DOCUMENTED** — ADR-013 (six decisions, six rejected alternatives, three open
questions), ADR-011, the plan and invariant matrix.

**INFERRED** — that the eight resources are the right decomposition; that a
tool's conservative locality is `Remote`; that a service mesh record belongs
with the workload rather than outside it; that the ten evidence sources cover
what real deployments have.

**UNKNOWN** — everything about actual deployment. No cloud, no Kubernetes, no
managed database, no hosted model, no real multi-tenant system. Whether the
binding survives contact with real autoscaling, where process instances are
created and destroyed continuously, is untested. Whether real framework adapters
can supply an `ExecutionBinding` at the moment they need to build a
`WorkloadBinding` is an integration question nobody has answered.

**Not claimed:** this is **not production-ready** and has not been deployed. The
acceptance gate is a Linux process on one host reconciling through the shared
core, which is what the specification asks for and is not a deployment.

## 4. Mutation testing

14 mutations targeting Skill 27's security-sensitive rules, each with patch
application, file change and compilation confirmed before any result was read.

| mutation | outcome | killed by |
|---|---|---|
| E1 binding covers by tenant only | KILLED | `a_binding_covers_only_the_execution_it_was_made_for` |
| E2 digest omits tenant | KILLED | `a_commitment_matches_only_itself` |
| E3 digest omits framework | KILLED | `the_tenant_the_workload_and_the_framework_are_all_committed` |
| E4 context links always hold | KILLED | `a_hop_lifted_from_another_chain_breaks_the_links` |
| E5 stale context accepted | KILLED | `a_stale_context_is_refused_at_the_boundary` |
| E6 context skips the binding check | KILLED | `a_chain_cannot_be_presented_by_a_different_execution` |
| E7 container declared measured | KILLED | `a_container_attribution_is_carried_and_never_measured` |
| E8 identities may substitute | KILLED | `the_four_identities_never_substitute_for_one_another` |
| E9 remote outcome established | KILLED | `a_local_filesystem_effect_is_establishable` |
| E10 remote state assertable | KILLED | `a_local_effect_is_assertable_and_a_remote_one_never_is` |
| E11 remote effect declared reachable | KILLED | `every_tier_is_reachable_and_remote_effect_is_not` |
| E12 framework grants authority | KILLED | `no_adapter_grants_authority_or_raises_a_ceiling` |
| E13 every outcome establishable | KILLED | `no_remote_effect_is_establishable_however_well_observed_the_host_is` |
| E14 agreement raises ceiling | KILLED | `agreement_never_raises_the_ceiling` |

**REQUIRED 14 · APPLIED 14 · PATCH APPLIED 14/14 · KILLED 14 · SURVIVORS 0.**

## 5. Wire, version and dependency impact

| item | result |
|---|---|
| production files changed outside the new crate | **0** (workspace member list and `Cargo.lock` only) |
| wire/protocol version changes | **none** — `AIRI_EVENT_VERSION` untouched |
| signed field changes | **none** — no `PropagationBoundary` variant added |
| new `SourceMechanism` variants | **0** |
| new `LeafKind` variants | **0** |
| new reconcilers / verifiers / trust scores | **0** |
| new trust anchors / signers / keys | **0** |
| new identifiers | **0** — tenant and workload are validated strings inside a commitment |
| new domain tags | 1, with 5 structure discriminants |
| new parameter keys | 1, versioned in the key |
| new external dependencies | **0** — no cloud SDK, no Kubernetes client, no framework |

## 6. Known limitations

1. **Not deployed.** No cloud, no orchestrator, no real tenancy.
2. **A container is never measured.** Its attribution is committed and
   establishes nothing; the process behind it is what is measured.
3. **Remote effects are unreachable** and always will be without a mechanism
   that observes another host.
4. **A cloud audit log is capped at `Corroborative`** despite being genuinely
   independent, because no mechanism ingests it.
5. **Autoscaling is untested.** Every replica is a different execution and
   therefore needs its own binding; whether that is workable at scale is an
   open integration question.
6. **A partially-trusted collector is modelled generously** — one sharing an
   administrator with the workload is treated like any other host observer.
