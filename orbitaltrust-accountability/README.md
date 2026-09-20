# OrbitalTrust Accountability Layer — imported from ASC-space

A complete, working implementation of the agent accountability stack, imported
from the `ASC-space` repository where it was built and hardened. **114 files,
35,440 lines**, with `MANIFEST.md` carrying a SHA-256 per file.

This is an **import, not a merge**. It sits alongside `aip-standalone/` rather
than replacing anything, because the two codebases overlap in part and
complement each other in part. Read the next section before integrating.

## Wiring status (audited and wired 2026-09-20)

The import said these crates "will not build here until added to a workspace
carrying that block or pinned directly". That was true and it was not the
whole obstacle. **Two of the four Rust crates cannot build here at all**, for
a reason the import did not state: they depend on `ot-pqc`, which the source
workspace lists as a sibling crate and which **was not brought across**.

| Crate | In the workspace? | Tests | State |
|---|---|---|---|
| `ot-accountability-core` | **yes** | **56 pass** | Wired. Versions pinned directly rather than inherited from the source workspace's `[workspace.dependencies]`, so resolution for the forty crates already here is unchanged. `crate-type` narrowed to `rlib`; the `wasm` feature is intact for whoever wires the browser build. |
| `ot-sentinel` | **yes** | **82 pass** | Wired. The library needs nothing absent — the one `ot_mcp_gateway` mention in `src/sensors.rs` is a rustdoc link in a comment, not code. |
| `ot-mcp-gateway` | **no** | — | Needs `ot-pqc`: 11 non-optional references across 6 files. Cannot compile. |
| `ot-verifier` | **no** | — | Needs `ot-pqc`: 2 non-optional references. Cannot compile. |

`ot-sentinel/tests/ghost_hunt.rs` — 31 integration tests — is **preserved
verbatim and excluded from compilation** by `autotests = false`, because it
needs both absent crates. It is a stated exclusion, not a deleted test: when
`ot-pqc` arrives, removing that line and restoring the two dev-dependencies
is the whole of the work. The import claimed 114 sentinel tests; 82 + 31 =
113 are accounted for here.

**What this costs.** `ot-mcp-gateway` is the funnel on the MCP wire that
seals every `tools/call` before it reaches the upstream server. That is
directly the capability blocker **B10** in the RBI technical brief describes
as outstanding, and it is one of the two that cannot be built. Obtaining
`ot-pqc` from the ASC-space source is what closes it.

**Security skim performed before merging.** No `build.rs` anywhere in the
import, so nothing executes at build time. Zero `unsafe` in the two wired
crates. No network calls and no process spawning; every `fs::write` is inside
a `#[cfg(test)]` body writing tamper fixtures for negative tests.

**New third-party dependency:** `tempfile` (dev-dependency only, so it
reaches no shipped binary). Nothing else here used it.

**The manifest still holds, and that is checked rather than claimed.**
Wiring required rewriting two `Cargo.toml` files, which necessarily breaks
their hashes. Nothing else moved: **112 of the 114 files are byte-identical
to `MANIFEST.md`**, and the two that are not are exactly those manifests,
each carrying a header saying why. A clippy lint on `runtime.rs` is exempted
in `ot-sentinel/Cargo.toml` rather than fixed in the source, for the same
reason — silently rewriting imported code to satisfy a style lint destroys
the one property the manifest exists to give. Verify with:

```bash
python3 orbitaltrust-accountability/verify_manifest.py
```

It exits non-zero if any file other than those two has changed.

---

## How this relates to `aip-standalone/`

The repository already has its own accountability implementation
(`aip-core`, `aip-crypto`, `aip-protocol`, `aip-types`, `aip-verify` —
roughly 9,700 lines of Rust). The honest breakdown:

| Concern | `aip-standalone/` | This import | Relationship |
|---|---|---|---|
| Evidence packets | `aip-core` | `ot-accountability-core` | **Overlapping** — two implementations, different byte formats |
| Hash-chained audit | `scoped_audit.rs`, `previous_hash: [u8; 32]` | `seal_hash(prev ‖ canonical_json)`, hex | **Overlapping, not wire-compatible** |
| Identity / delegation | `aip-core`, `aip-protocol` | `authority.rs`, `identity.rs`, `lifecycle.rs` | **Overlapping** |
| Verification CLI | `aip-verify` | `ot-verifier` | **Overlapping** |
| **Out-of-band reconciliation** | — | **`ot-sentinel`** | **Absent here. This is the piece AIP does not have.** |
| Governed MCP wire | — | `ot-mcp-gateway` | **Absent here** |
| Durable tamper-evident authority store | — | `authority_journal.rs` | **Absent here** |
| Browser/WASM verifier + TS console | — | `typescript/` | **Absent here** |

**The integration question this raises — STILL OPEN, and now load-bearing.**
Wiring two of these crates into the workspace does not answer it; it makes
answering it more urgent, because the incompatible construction is now
compiled rather than dormant. Two hash-chain constructions now
live in one repository and they are not byte-compatible — `aip-core` chains
raw 32-byte digests, this core chains `SHA-256(previous ‖ canonical JSON)` as
hex. Both are sound; they are simply different. A packet sealed by one will
not verify under the other. That is a decision for the maintainers, not
something this import should make silently, which is why nothing under
`aip-standalone/` was touched.

The clearly additive part is `ot-sentinel`. AIP proves what went *through*
the funnel; it has no answer for an agent that declines to use the funnel at
all. Inline enforcement cannot see its own bypass. The sentinel closes that by
reconciling what independent sensors observed against what the ledger sealed.

## Contents

```
rust/
  ot-accountability-core/   Identity, AGENT_GENESIS lifecycle chain, credential
                            binding, DelegationEdge, revocation, and a durable
                            tamper-evident authority journal. Compiles to
                            wasm32 for browser-side verification.
  ot-mcp-gateway/           The funnel on the MCP wire: every tools/call
                            adjudicated and sealed before it reaches upstream.
  ot-sentinel/              Reconciliation, 11 detectors, the two-axis warrant
                            standard, sensor attestation, restart continuity,
                            and a runnable `sentinel` binary.
  ot-verifier/              Offline verification — no network, no engine.
  ot-api-governance/        Fleet-scale governance ingestion hub.
  workspace-Cargo.toml      Dependency versions; these crates use workspace
                            inheritance and will not build standalone without it.

typescript/                 Console-side identity, accountability ledger,
                            NEXORA anchors, governedDispatchTool, operator UI,
                            and 11 test suites.
python-sdk/                 `otgovern` — cross-language, byte-proven against
                            the Rust core.
docs/                       Product-line traceability and the typestate
                            authorization invention disclosure.
```

## Test status at import

```
ot-accountability-core   56 tests
ot-mcp-gateway           80 tests   (driven by a live gateway, not fixtures)
ot-sentinel             114 tests
typescript              117 tests
```

These crates inherit dependency versions from the source workspace. To build
them here, either add them to a workspace carrying the
`[workspace.dependencies]` block from `workspace-Cargo.toml`, or pin the
versions directly.

## Design commitments worth preserving in any integration

**Containment requires proof, never suspicion.** Findings carry two
independent axes — severity (how bad if true) and strength (how certain). Only
`Proof`, meaning arithmetic on held data, can trigger containment. A watchdog
that quarantines on statistical suspicion is a denial-of-service weapon aimed
at its own fleet. The default policy is advisory and acts only when an
operator turns it on.

**Every durable record is hash-chained, including the watchdog's own.** That
is why the authority store here is an append-only journal rather than a
database: a store an adversary could silently `UPDATE` would be the one
durable security record in an accountability product that cannot account for
itself.

**Silence is never read as safety.** A sensor that stops attesting produces a
sealed coverage gap, not a clean patrol. A sentinel restarted without its
state reports amnesia rather than starting fresh.

## Not built

Named rather than glossed: kernel-level eBPF sensors (schema and detector are
ready, no loader ships), cross-agent swarm correlation, and reconciliation at
10⁴-node scale. See `docs/ACCOUNTABILITY_PRODUCT_LINE.md`.
