# Cache security — permissions, tenant isolation, versioning, invalidation

## Threat

Prefix caching reuses attention state for an identical token prefix. In
llama.cpp (and, per Gu et al., ICML 2025, several commercial APIs) the cache
is shared across all requests on a slot. Anyone who can send requests and
time them can test whether *another principal's* confidential text is
resident — without ever receiving that text.

## Experiment E3b (1.5B Q4_K_M, native build, 1 slot, 20 trials per mode)

Victim (`finance:payroll`) sends an 800-token confidential prefix + question.
Attacker (`ops:plant-a`) then sends either the exact prefix (hit trials) or a
different prefix of identical token length (miss trials), and times the
response. AUC = probability that a hit is faster than a miss.

| Cache mode | Attacker AUC | Median hit s | Median miss s | Victim's own 2nd request: tokens recomputed |
|---|---|---|---|---|
| shared (llama.cpp default) | **1.00** | 0.16 | 8.40 | alternates 5 / 808 (itself a leak signal) |
| scoped (`cachescope`) | **0.43** (chance) | 8.29 | 8.26 | 808 |

With a shared cache the leak is total: one request distinguishes hit from
miss by 50×. With scoping it disappears at the measured resolution (20
trials; small-sample AUC noise ±~0.25, so "≈ chance", not "proven zero").

## Mechanism (`cachescope/`, 25 unit tests)

Cached state is reusable only under an **identical** `CacheScope`:

| Field | Invalidates on |
|---|---|
| model SHA-256 | model change |
| tokenizer SHA-256 | tokenizer change |
| policy version | authorisation / grounding policy change |
| source snapshot | corpus or index change (e.g. Merkle root) |
| principal scope | different authorisation scope (not user name) |
| security domain | different domain |

Fields are length-checked and separator-safe; the key is SHA-256 over a
fixed field order. A request whose scope differs from the slot owner's is
served only after the slot is **erased**; `invalidate()` erases slots when a
dependency (policy, snapshot) changes. Fail closed: unknown → miss → erase.

## Costs and caveats (measured or read from source)

1. **Reuse is lost when tenants interleave on one slot** (victim recomputed
   808 tokens every time). With N slots, up to N scopes keep their caches;
   KV memory scales with slots (28 KiB/token/slot for 1.5B). Not measured
   with N > 1.
2. **Erase requires `--slot-save-path`** in llama-server (every `/slots`
   action returns 501 otherwise; `server.cpp` `handle_slots_action`).
   Enabling it also enables **save/restore of KV state to disk**, a new place
   for confidential derived data. Deployment rule: point it at an
   access-controlled, encrypted, per-domain directory and deny save/restore
   at the gateway; the test asserts erase writes no files.
3. **KV checkpoints are confidential data.** E4: a 3,000-token slot saves to
   an 82 MB file that restores in 34 ms (vs 38 s recompute). It encodes the
   prompt; anyone holding the file can resume or probe it. Treat it with the
   classification of the source documents; bind its filename/key to the
   `CacheScope`; never share across scopes. `profile.py` deletes the files.
4. Scope granularity is a policy decision: per-principal scope is safest and
   reuses least; per-role scope reuses more and leaks within the role. Not
   decided here.
5. Not tested: GPU/vLLM/SGLang prefix caches (same threat class), concurrent
   batching, multi-slot routing, timing noise in a real network.
