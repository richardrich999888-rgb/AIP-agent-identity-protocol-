# AIBOM — Evidence Report

**Crate** `aip-standalone/aip-aibom` · **Binary** `aibom`
**Baseline** `65eb9e6` (integration tip of `codex/accountability-test-gaps-2026-10-20`,
fast-forwarded onto `claude/skill-25-implementation-xbz0t3`)
**Decision record** ADR-017 · **Design** `docs/architecture/AIBOM_ARCHITECTURE.md`
**Product guide** `docs/AIBOM.md`

This report states what is CODE-PROVEN, TEST-PROVEN, EXECUTION-PROVEN,
DOCUMENTED, INFERRED and UNKNOWN about the product. Nothing is promoted to a
stronger class because a fixture was built to demonstrate it.

---

## 1. What was built

An evidence-gap assessor for AI agents. It takes:

- a declared inventory (the manifest, 13 components),
- the evidence the deployment can produce, and
- the assessor's own trust context,

and reports, **per field, who vouches for it**. Every standing above
`SELF-REPORTED` is the output of a verifier that already exists in the
workspace; the crate defines no verification of its own.

## 2. How it got here

The first build was made on `3e51fae`. Before committing it, the branch map
showed that base was **85 commits behind** the integration line, which had
added a signed resource registry and access ledger, gateway-countersigned
tool receipts and an approval tier. On that line the first build's claims
that tool use, approval gates and data access were "never verifiable" were
**false**. With the owner's agreement the branch was fast-forwarded to
`65eb9e6`, the crate was ported, and C4, C5 and C6 were rebuilt to consume
those verifiers. The first build survives only on the local branch
`wip/aibom-on-3e51fae`; it was never pushed.

## 3. Baseline before the product was added

At `65eb9e6`, before any of this work was added:

```
cargo fmt --all -- --check                                            exit 0
cargo clippy --workspace --all-targets --all-features -- -D warnings  exit 0
cargo test --workspace --no-fail-fast   300 suites · 2958 passed · 0 failed · 7 ignored
```

The first attempt reported 15 failures and stopped early. All 15 were
`aip-hsm`'s PKCS#11 custody tests, which need SoftHSM2 and **deliberately
refuse to skip** without it ("a custody test that passes without the module
has not run"). That is environmental, and correct behaviour; SoftHSM2 2.6.1
was installed and the run repeated.

That clean run was luck — see §7.2.

## 4. Validation with the product

At `65eb9e6` plus this work (the product, and the `aip-service` test fix in §7.2):

```
cargo fmt --all -- --check                                            exit 0
cargo clippy --workspace --all-targets --all-features -- -D warnings  exit 0
cargo test --workspace --no-fail-fast   316 suites · 3095 passed · 0 failed · 7 ignored
```

**+137 passed**, matching the 137 tests the crate adds, with no existing test
changed except the three serialised in §7.2. The only existing files touched
are the workspace member list, the lockfile, and `aip-service/src/ingress.rs`
(test module only).

## 5. Mutation assurance

`validation/mutation/mutate_aibom.py`, through the repository's shared
forensic runner (`mutate_core.run_matrix`): unique fragment, changed digest,
successful compile, byte-identical restore. Results in
`validation/mutation/AIBOM_MUTATION_RESULTS.json`.

| run | mutations | killed | survivors | harness defects | files restored |
|---|--:|--:|--:|--:|---|
| first build, `3e51fae` | 46 | 41 | 5 | 0 | byte-identical |
| port, `65eb9e6` | **63** | **63** | **0** | **0** | byte-identical |

The five first-run survivors were real gaps, each closed with a regression
test named for it and confirmed killed by exactly that test:

| id | invariant the suite had not tested |
|---|---|
| AB-08 | a chain's window ends at its *earliest* link expiry — no fixture had links expiring at different times |
| AB-16 | onward delegation is credited only for a hop this agent issued |
| AB-28 | an API tool sharing an MCP server's name is not that server |
| AB-36 | a `${…}` template under a credential-named key is a reference, not a secret |
| AB-39 | a prefix-less value after `--password` is located — the only fixture value began with `sk-`, so the prefix rule masked the flag rule |

The 17 mutations added for the port cover the access ledger (C6), gateway
receipts (C4) and the approval tier (C5), including every independence
check that refuses an anchor equal to the agent's own key.

**One kill attribution was corrected.** The port run recorded AB-16 and AB-39
as also killed by `authority_that_never_expires_is_a_finding`, a delegation
test neither mutation touches. The cause was a wall-clock race in that
test's fixture — it assessed at a moment before its own token's issuance
whenever two milliseconds passed between issuances. The fixture was fixed
(40/40 repeats pass) and both mutations re-run: each is now killed by its
own test alone. Both had been killed by their intended tests all along; the
total did not change.

## 6. Evidence classes

**CODE-PROVEN** — the manifest has no field for a standing
(`deny_unknown_fields`); the output types are `Serialize`-only; the
vocabulary has no `Assumed`, `Trusted`, `Compliant`, `Mitigated` or
`Certified`; the bundle has no field for a key, an anchor, a revocation or a
clock; the engine reads no clock, file, environment or network. Each is also
asserted by a structural test.

**TEST-PROVEN** — every standing rule, against real artifacts produced by
the producing crates' own constructors: identities, delegation chains,
decision-point expectations, NEXORA proofs over collector-signed batches,
gateway receipts, approval-surface artifacts, and access ledgers built from a
real probe, a real collector and a signed registry. 137 tests in 13 files;
63 of 63 mutations killed.

**EXECUTION-PROVEN** — the `aibom` binary run end to end on real files
(`tests/cli.rs`), and the worked example reproduced byte for byte by the CLI
from the files it wrote. Exit status gates on critical findings; a usage
error is never the gate status.

**DOCUMENTED** — the component and standing tables in `docs/AIBOM.md` and
`AIBOM_ARCHITECTURE.md`, each row of which cites the verifier or test that
backs it.

**INFERRED** — that the MCP secret heuristic catches the credentials real
deployments leak. It is tested against the shapes it was written for and is
labelled a heuristic in the code, the docs and every finding.

**UNKNOWN** — performance at fleet scale; behaviour against real customer
manifests and bundles, of which there are none yet; whether an institution's
tool and resource naming will match its gateway and registry without a
mapping layer.

## 7. Findings in the existing code, surfaced while building this

### 7.1 An identity document's expiry is not signed

`AgentIdentityDocument::expires_at` is outside the bytes the self-signature
covers (`canonical_encode_aid`), and `validate_aid` never checks it. Anyone
holding the document can extend or delete it. Confirmed on `65eb9e6` by
`tests/assess_identity.rs::an_unsigned_identity_expiry_is_reported_and_not_relied_on`.
The product relies only on the signed `status` and reports the unsigned
expiry. **Not fixed**: covering it changes the identity signature payload and
invalidates every existing identity — a versioned wire change for the owner
to decide.

A second suspicion — that `validate_aid` accepts an unsigned document — was
**withdrawn**. The test written to show it failed; the code has an `else`
branch returning `MissingRequiredField`.

### 7.2 A 50% flaky test in `aip-service`

`ingress::tests` — three tests set and read the same process-wide environment
variables on parallel threads with no lock. Measured on unmodified service
code: **31 failures in 60 runs**. It passed the baseline by luck and failed
the first validation with the product, which is how it surfaced. Fixed in a
separate commit with a module-local lock and a clean-slate helper; **0
failures in 60 runs** afterwards. Test-only; no production line changed.

### 7.3 Two limitation records are out of date

`docs/architecture/AIRI_LIMITATIONS.md` N-10 still says *"No PQC exists on
this branch"*; `aip-crypto` now has a hybrid Ed25519 + ML-DSA-65 signature
path. No agent property is post-quantum as a result — the path signs
evidence, and production has no hybrid verifier for identity documents — so
the product's `Unknowable(N-10)` is still right, but the record's stated
reason is wrong. N-9 likewise predates gateway-countersigned receipts. Both
are flagged, not edited: the limitations record is the owner's.

## 8. Known limitations

1. **It assesses declarations, not behaviour.** It never observes an agent
   act; runtime evidence is NEXORA's and the ledger's.
2. ~~**Limits and approval gates are never raised.**~~ *Superseded by
   ADR-018 — see `docs/audit/SPEND_EVIDENCE_REPORT.md`.* Per-action limits
   and approval thresholds are now verified against an institution-signed
   spend policy, and each approval-required decision offered is checked for
   an agreeing approval. Per-day / per-month limits and the approver's
   identity remain the author's word.
3. **A ledger shows what was reached in its window**, not what may be
   reached; a declared resource it does not show is the author's word.
4. **Naming must match** the gateway's tool ids and the registry's resource
   ids; there is no mapping layer.
5. **Discovery reads MCP client configs only.** No lockfile, framework-code
   or cloud-inventory discovery.
6. **No CycloneDX export.** Deferred until the schema is stable.
7. **The CLI handles no private keys.** Sealing is a library API.
8. **A verified identity is self-certifying.** It binds an id to a key; it
   does not say who holds the key.
