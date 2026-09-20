# Phase 4 — ATT&CK coverage against the Atomic Red Team corpus

**Status: the coverage map, the Navigator-layer generator and the generated
layer are built, tested and committed. No atomic is executed here.**

## What is here

| File | What it is |
|------|-----------|
| `coverage.tsv` | The auditable technique→coverage map: per ATT&CK technique, the AIP primitive that observes it and the coverage class. |
| `gen_layer.py` | Deterministic generator: map → MITRE ATT&CK Navigator layer JSON, coloured by coverage class. Stdlib only, byte-stable. |
| `gen_layer_test.py` | Unit tests (happy path, malformed rows, unknown class, sort stability, blind-spot presence). |
| `aip-attack-coverage.layer.json` | The generated layer, committed so it can be diffed. Reproduced by `run.sh`. |
| `run.sh` | Reproducer: runs the tests, regenerates the layer, asserts no drift. Runs no atomic. |

## What the layer claims — and what it does not

The corpus is **Atomic Red Team** (`github.com/redcanaryco/atomic-red-team`,
MIT). Its value is that it is **not self-authored**, which answers the "you
only test yourselves" objection (`WHAT_THE_TESTS_PROVE.md` §1.1, blocker B2).

The layer is a **capability map**, not a run log. Each technique is coloured by
the AIP observer's *coverage class*:

- **attributed** (green) — the observer records the primitive and binds it to a
  process instance (exec/fork via the scheduler tracepoint + pidfd anchor;
  lineage start-verified). Strongest.
- **effect-observed** (amber) — the effect is recorded (socket / file), but
  attribution to a bound instance may be partial.
- **not-covered** (grey) — no AIP sensor observes the primitive. These are
  shown, never hidden. A coverage map with no grey would be a lie: AIP is a
  runtime *execution* observer, so at-rest content (T1027, T1552.001),
  in-memory-only techniques (T1055, T1620) and syscalls it does not hook
  (T1070.004, T1222.002) are genuine blind spots.

**No "verdict" is emitted for a technique that was not executed.** A verdict is
the result of executing a technique and reconciling it against a signed
expectation. That has genuinely happened only for the primitives demonstrated
live in Phase 1 (`evidence=phase1-sealed`, see
`integrations/agents/results/sealed/`): process exec (T1059/.004/.006), an
outbound TCP connect (T1071), and a marked file write (T1074.001). Every other
row is cited to `atomics/<ID>/` in the pinned corpus for reproduction in a
controlled environment and is **not run on this host** — several in-scope
techniques (T1070 indicator removal, T1222 permission changes) are destructive
and fall under the adversarial safety rules.

## Reproduce

```
bash adversarial/atomic/run.sh          # tests + regenerate + drift check
python3 adversarial/atomic/gen_layer.py # print the layer to stdout
```

Load `aip-attack-coverage.layer.json` in the MITRE ATT&CK Navigator to view the
coverage heat-map.

## Exit gate

The generated layer is reproducible from `coverage.tsv` (byte-identical), the
generator's tests pass, and the map contains all three coverage classes
including honest blind spots. The third-party-sourced rows are recorded in
`docs/security/ADVERSARIAL_RESULTS.md` (Phase 4 section).
