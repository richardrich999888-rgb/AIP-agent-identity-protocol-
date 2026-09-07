# AIRI Canonical Schemas

## What is normative here

**The wire format is the byte encoding, not JSON.** What a signature covers
is the canonical preimage defined in `AIRI_SPECIFICATION.md` §6 and
implemented once in `aip-airi/src/event.rs`. These schemas describe the
*shape* of an AIRI object for tooling — code generation, editor completion,
API documentation, request validation at a gateway — and are **not** the
thing a verifier checks.

A verifier that validated JSON and skipped the preimage would be checking
that a document is well formed, not that a signature covers it. The two
questions are unrelated.

## Files

| File | Describes |
|---|---|
| `airi-event.schema.json` | An `AiriEvent` and all nine payload bodies |
| `airi-bundle.schema.json` | The `AiriBundle` carried in a NEXORA proof |
| `airi-encoding.md` | The normative byte layout, field by field |

## Byte-level conformance

The one test that establishes cross-implementation agreement is the parity
suite, not these schemas:

```
cargo test -p aip-airi --test parity_vectors -- --ignored --nocapture \
  > sdk/python/tests/parity_vectors.json
cd sdk/python && python3 -m unittest tests.test_canonical_parity
```

A new implementation in any language is conformant when it reproduces those
vectors byte for byte and its signatures verify under
`aip-airi/tests/python_interop.rs`. Passing schema validation establishes
neither.
