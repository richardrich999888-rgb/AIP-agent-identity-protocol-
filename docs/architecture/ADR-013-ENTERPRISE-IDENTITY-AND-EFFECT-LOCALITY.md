# ADR-013 — Enterprise Identity Binding and Effect Locality

**Status** ACCEPTED (scope: the enterprise profile's semantics only)
**Date** 2026-09-07
**Branch** `claude/skill-25-implementation-xbz0t3`
**Baseline** `742517c`
**Related** ADR-011 (the five-vertical finding), ADR-003, ADR-012

---

## Context

Skill 27 maps enterprise agents and cloud workloads onto the same accountability
core the edge verticals use. Most of what it needs already exists: `aip-airi`
carries framework, model, tool, subprocess and context-propagation abstractions,
and its `FrameworkIdentity` already states that it is **not a trust input**.

Two things did not exist, and one thing about enterprise is genuinely different
from every vertical before it.

## Decision 1 — a workload binding commits to the execution identity

Tenant, workload and framework are **strings**. Anything that holds them can
send them, so a binding over strings alone is a binding an attacker can forge by
copying a config map.

`WorkloadBinding` therefore commits to the tenant, the workload, the system, the
framework commitment **and** `SHA-256(ExecutionBinding::identity_bytes)` — which
covers the agent AIP-ID, the process instance triple `(pid, start ticks, boot
id)` and the executable's *contents*.

The constructor takes the `ExecutionBinding` itself, not a digest. There is no
path that accepts the strings alone, because there is no function that does, and
`tests/no_second_architecture.rs` asserts there is exactly one constructor and
exactly one place the digest is computed.

Consequences, all pinned by tests and mutations: a binding does not transplant
across tenants (E1), agents (E2), frameworks (E3), or process instances (E4);
and equal pids are never sufficient, because `identity_bytes` includes the start
ticks and the boot id.

## Decision 2 — four identities, and none substitutes for another

| identity | measured? | who asserts it |
|---|---|---|
| tenant | no | the operator |
| autonomous actor (AIP-ID) | no | the identity layer |
| workload | no | the operator |
| process execution | **yes** | an observer |

`IdentityKind::may_substitute_for` is `false` for every pair including a kind
with itself-as-another-kind, and `is_measured()` is true for exactly one.

`IdentityKind` is a **vocabulary, not an identifier type**. `aip-system` owns
identifiers; this profile expresses a tenant as a validated string inside a
commitment rather than minting a parallel identity system, and the structural
guard forbids `struct TenantId`, `struct WorkloadId` and their relatives.

## Decision 3 — a container is a process, and no wire format changed

Skill 27 asks for container context propagation. This profile adds **no**
`PropagationBoundary::Container` variant.

`PropagationBoundary` is encoded into the `AiriEvent` signing preimage, so a new
variant is a wire change. It would also be dishonest: the core's settled position
is that a container is **not an established identity** — nothing measures a
namespace set or a cgroup, and a namespace inode is reused after it is freed
(`aip-robotics::RobotIdentityKind::Container`).

At the boundary the kernel sees, a container crossing **is** a process crossing,
and the existing `Process` boundary represents it faithfully. What a container
adds is an attribution, carried as `ContainerAttribution` with
`is_measured() == false`, committed into the chain so substituting one changes
the digest, and establishing nothing either way.

## Decision 4 — a context chain links, and roots in the binding

Each `ContextHop` commits to the previous hop's digest; hop 0 commits to the
root `WorkloadBinding`'s digest. `ContextChain::extend` computes the link rather
than accepting one, so a caller cannot build a hop claiming to follow something
it does not.

`admit` requires three things, each of which can only refuse: the links hold,
the window contains the moment, and the root binding covers the presenting
execution. The third is what makes a copied context useless — a chain lifted
from one workload names a process instance the replayer does not have.

`check_links` is named as a structural self-check rather than `verify_*`:
verification of evidence is the core's word, and the structural guard forbids
this crate from using it.

## Decision 5 — effects split by locality, and the top tier is reachable

**This is the finding ADR-011 records.** Enterprise is the first vertical whose
top evidence tier is reachable. A file write is `SourceMechanism::Fanotify`; a
socket is `ProcNetTable`. `EnterpriseEvidence::LocalEffectObserved` is a real
tier a deployment reaches, and `EnterpriseResource::Filesystem` has an
establishable outcome.

What stays unreachable is the **remote** effect. `EffectLocality::Remote` covers
model calls, tool calls, APIs, databases and cloud control-plane actions, and
`outcome_establishable()` is false for all of them: a socket to a database is
not a row, and a call to an API is not a consequence at the far end.

`WorkloadState::assertable` returns `Unknown` for `RemoteEffectApplied` and
`Completed` at **every** tier, because no tier covers another host.

## Decision 6 — an adapter cannot describe itself

`EnterpriseAdapter::source()` is fixed at `EnterpriseSource::FrameworkTrace` and
is not overridable. `ceiling()` delegates to that source and is not overridable.
`framework_grants_authority()` is `false` and is not overridable.

An adapter reads instrumentation running inside the workload. Letting it declare
itself a different source is exactly how a self-report becomes independent
evidence by assertion, and it is the one thing a thin adapter must not be able
to do.

The structural guard additionally forbids `TrustScore`, `RiskScore`,
`TrustLevel`, `Reputation`, `if name ==`, `match name`, `TRUSTED_FRAMEWORKS` and
`allowlist` anywhere in the library — an enterprise-only score being the exact
shape Skill 27's acceptance gate prohibits.

## Alternatives rejected

**Add `PropagationBoundary::Container`.** A signed wire change implying a
boundary the core cannot measure. Rejected under Decision 3.

**Mint `TenantId` and `WorkloadId` as identifier types.** A parallel identity
system for two strings that are declared, not measured.

**Let `WorkloadBinding::new` take an execution-identity digest.** Convenient for
adapters, and it reintroduces the whole attack: a caller holding copied strings
and a copied digest would hold everything.

**Name the top tier `PhysicallyObserved` for symmetry with the other four.**
Rejected under ADR-011 Decision 3 alternatives: it would make five ladders look
identical and make one of them lie.

**Treat a cloud audit log as independent evidence.** It is genuinely
independent — a different service, a different account, written by the provider
— and it has no implemented mechanism here, so it is capped at `Corroborative`
like a ground-station track and an external camera. This is the cleanest
instance of the rule in the system, because nobody is tempted to call a wheel
encoder independent and everybody is tempted to call CloudTrail independent.

**Treat a service mesh record as independent.** Same answer, plus the mesh is
deployed by the same platform team as the workload.

## What this decision does not settle

**Whether a cloud audit log could ever be anchored.** It would need a collector
holding its own key, ingesting the provider's signed feed, with a mechanism
whose forgeability is characterised. That is an `aip-observation` change under
ADR-003's constraints and is outside Skill 27.

**How a partially-trusted collector should be modelled** — one on a separate
host that shares an administrator with the workload. Today it is treated like
any other host observer, which is probably too generous and costs nothing while
the ceiling is what it is.

**Production deployment.** Nothing here has been deployed. The acceptance gate
is a Linux process on one host reconciling through the same engine as the edge
verticals; there is no cloud, no Kubernetes, no managed database and no hosted
model anywhere in it.
