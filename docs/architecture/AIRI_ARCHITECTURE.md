# AIRI — Architecture

## 1. The full accountability chain

```
 ┌──────────────────────────────────────────────────────────────────────────┐
 │                          AUTHORITY  (unchanged)                          │
 │                                                                          │
 │  AIP Identity ──▶ ScopedToken ──▶ DelegationChain ──▶ Decision Point      │
 │  aip-core        aip-core         aip-core            aip-authorize       │
 │                                                            │             │
 │                                              signed ExpectedExecution     │
 └────────────────────────────────────────────────────────────┼─────────────┘
                                                              │ decision_id
              ┌───────────────────────────────────────────────┴──────────┐
              │                                                          │
 ┌────────────▼────────────────────────┐        ┌────────────────────────▼──┐
 │  SELF-REPORT  (AIRI — new)          │        │  OBSERVATION  (unchanged) │
 │                                     │        │                           │
 │  Python agent                       │        │  probe   (no key, on host)│
 │    └ vanian_airi SDK                │        │    │  offers observations │
 │        └ adapters                   │        │    ▼                      │
 │            framework / model / tool │        │  collector (key OFF-host) │
 │                │                    │        │    · assigns sequence     │
 │                ▼                    │        │    · stamps its own clock │
 │        AiriEvent, agent-signed      │        │    · signs OBSERVER_HEAD  │
 │        SYNTRIASS/AIRI/EVENT/v1      │        │            │              │
 │        hash-chained per execution   │        │            ▼              │
 │                │                    │        │      AttestedBatch        │
 └────────────────┼────────────────────┘        └────────────┼──────────────┘
                  │                                          │
                  └──────────────┬───────────────────────────┘
                                 ▼
                    aip_airi::corroborate
                    ┌──────────────────────────────┐
                    │ NotEvaluated  (default)      │
                    │ Corroborated  (sealed)       │
                    │ Uncorroborated               │
                    │ Contradicted                 │
                    └──────────────┬───────────────┘
                                   │  annotation only — no verdict
                                   ▼
                    aip-reconcile  (SEMANTICS UNCHANGED)
                    precondition_holds → fail-closed to CANNOT_PROVE
                                   │
                                   ▼
                    aip-warrant → aip-containment → aip-nexora
                                                      LeafKind::AiriEvent 0x09
```

## 2. Why the two evidence paths are asymmetric

| | AIRI | aip-observe |
|---|---|---|
| Who signs | the agent | the collector |
| Where the key lives | in the agent process | **off the observed host** |
| Whose clock | the agent's | the collector's |
| Can root on the host forge it? | **yes** | no — it can forge what is *offered*, not the attestation |
| What it establishes | authorship and integrity | that a collector attested these bytes |

Reconciliation is where the asymmetry is spent. Neither half alone says much;
the pair does. An AIRI claim the observer covered and did not see is the
interesting case, and it is only interesting *because* the observer's
signature is out of the agent's reach.

## 3. The three boundaries the specification refuses to collapse

### 3.1 Tool: request ≠ execution ≠ effect

```
agent → Python → framework → client lib → kernel → network → far side
        └─ layer 1 ─┘        └─ layer 2 ─┘                   └ layer 3 ┘
        ToolInvocation       ToolReport                      no event
        Requested            (a 200 lives here)              asserts this
```

### 3.2 Model: declaration ≠ selection ≠ execution

```
model_id requested  ≠  model served  ≠  weights loaded  ≠  kernel ran  ≠  GPU executed
     AIRI records         unverifiable      digest only      not visible    not visible
                          from here         if measured      from here      from here
                                            externally
```

### 3.3 Lineage: identity ≠ authority ≠ application

```
identity lineage    aip-agent            which document descends from which
authority lineage   delegation chain     who granted what to whom
application lineage parent_execution_id  which run spawned which
```

Nothing reads `parent_execution_id` to widen scope. A subprocess an agent
spawned itself carries the same expectation or none — which is what stops
authority laundering through a child process.

## 4. Context propagation

```
                  ┌─────────────── ExecutionContext ───────────────┐
                  │ agent_id · execution_id · parent · decision_id │
                  └───────────────────────┬───────────────────────┘
                                          │
     ┌──────────────┬─────────────────────┼──────────────┬──────────────────┐
     ▼              ▼                     ▼              ▼                  ▼
  await/task     thread              process        subprocess       worker queue
  contextvars    explicit bind()     to_env()       to_env()         to_env()
  (automatic)    (deliberate)        + from_env()   + from_env()     + from_env()
```

Threads and processes require an explicit handoff. A wrapper that copied
context automatically would attribute a worker's actions to whoever spawned
it, and a handoff is a lineage event that should be written down.

The environment carries **identifiers only** — never a key. A child that
signs loads its own identity.

## 5. Crate dependency graph

```
aip-types ──▶ aip-crypto ──▶ aip-core ──▶ aip-protocol
    │                            │
    │                            ▼
    ├──────────────────────▶ aip-authorize ──┐
    │                                        │
    ├──────────────────────▶ aip-observe ────┤
    │                                        ▼
    │                                  aip-reconcile ──▶ aip-warrant ──▶ aip-containment
    │                                        │                   │
    └──────────────────────▶ aip-airi ◀──────┘                   ▼
                              (new)                         aip-nexora
                                │                                ▲
                                └────────────────────────────────┘
                                        LeafKind::AiriEvent
```

`aip-airi` depends on `aip-types`, `aip-crypto`, `aip-observe`,
`aip-authorize`, `aip-reconcile` and `aip-nexora`. Nothing depends on
`aip-airi`, so it cannot affect the existing chain except through values a
caller explicitly passes it.

## 6. What a verifier holds

```
NexoraProof ──┬── expectation      (decision-point signed)
              ├── observer bundle  (collector signed)
              ├── AIRI leaves      (agent signed, LeafKind 0x09)
              ├── claim            (Reconciliation)
              └── warrant          (warrant-authority signed)

VerifierAnchors ──┬── decision-point keys
                  ├── observer keys  (observer_id, key_version)
                  ├── issuer keys
                  ├── warrant keys
                  └── agent public key
```

The verifier re-runs the reconciler over the package's own inputs and
compares canonical digests. A package whose verdict is not derivable from its
own evidence is rejected. It does not believe a serialized `Proven` because
the package author signed it.
