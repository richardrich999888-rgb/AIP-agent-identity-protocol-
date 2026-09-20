# Phase 4 — third-party ATT&CK corpus (runbook, NOT executed here)

**Status: not executed. Needs an Atomic Red Team clone (network).** These
atomics run on a normal host (they are **not** rootkits — confirm each one's
blast radius before enabling it), so they do not need the Tier-2 VM. They are
kept out of this build environment only because the corpus must be fetched.

## Corpus

**Atomic Red Team** (`github.com/redcanaryco/atomic-red-team`, MIT), pinned.
Linux atomics for process creation (T1059 shells), defence evasion (T1070,
T1222), exfil over network (T1041/T1048), file access. Each atomic is
ATT&CK-mapped YAML — the point of using it is that the corpus is **not**
self-authored, which answers the "you only test yourselves" objection
(`WHAT_THE_TESTS_PROVE.md` §1.1).

## Deliverable

Run each atomic through the reconciler and emit an **ATT&CK Navigator layer
JSON** colouring each technique by the observer's verdict
(`VERIFIED_EXECUTION` / `UNATTRIBUTED_EFFECT` / `PHANTOM_CLAIM` /
`CANNOT_PROVE` / not-covered). That layer is the single most credible artefact
to hand a CERT-In assessor (blocker B2): coverage against an external corpus,
not a self-drawn one. Append the third-party-sourced rows, each with its
reproducing command, to `docs/security/ADVERSARIAL_RESULTS.md`.

## Exit gate

`adversarial/atomic/run.sh` (to be written at execution time) reproduces the
layer and appends the ledger rows.
