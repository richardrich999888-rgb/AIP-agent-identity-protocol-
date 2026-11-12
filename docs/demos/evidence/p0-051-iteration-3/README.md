# P0-051 iteration 3 — tenant/domain lifecycle isolation

**Release NOT READY.** Bounded repair: activating, superseding or rolling back
one capability must not change an active record in another tenant or security
domain merely because the capability IDs match.

Implementation `ee3850c0c67995ee53e2e82b4983f6e0b55460fd`; hosted merge
`5acfc0efdb9703fe43f29e9b4375d713d1bf1aa6`; identical source tree
`0adadc1fc3d6ebd48fc13cf7d6a0f87f664546fc`. `source-tree.json` pins the three
changed files and confirms unchanged frozen task/dataset bytes. The only
production change scopes active-version lookup by tenant, domain and ID.

## Acceptance and original failures

Seven new behavior tests use a real corpus, file store, signed expert validation
and separately signed approvals. Two invoke the actual CLI. The prior
`learning.rs` reproduces **six failures / one pass**. Original CLI outputs show
another tenant's version superseded and another domain's version suspended.
The same tests pass with the fix. Foreign record bytes, including original
approval/history, are unchanged; same-scope duplicate activation and unapproved
targets still refuse. Fixtures establish pre-existing active records through the
pure lifecycle state machine after real validation/approval; this deliberately
prevents the broken selector from blocking creation of the attack fixture.

| Fresh check | Result |
|---|---|
| Full local runtime | 194 pass, including 7 new isolation tests |
| Full local teaching Python | 445 pass, no skips |
| Scoped Clippy / formatting | Pass |
| Hosted teaching 43224795762 | 296 relevant Rust and 267 focused Python pass; overlapping counts |
| Frozen teaching replay from downloaded CI | Control 11/12 rejected; corrected 12/12 and 26/26; 6 nonactivation probes included in 26 |
| Explicit examples | 3/3 separately in each scenario, no added suite cases |
| Independent signature check | Existing v1 suites and approvals from baseline, local and CI verify with Python cryptography |
| Verifier attacks | Approval one-byte edit, changed source/suite/tenant, missing approval and wrong trust reject |
| Security 43224795526 | Four HIGH Helm-render findings remain; original SARIF retained |

The clean published local scoped command ran inside a user/network namespace:
exit 0, wall **0.560703042003297 seconds**, child CPU **1.194756 seconds**, peak
child RSS **53908 KiB**. Original hardware and interface counters are retained;
only loopback existed and byte counters remained zero. CPU time can exceed wall
time because tests run concurrently. This is one component observation, not an
investor show, performance range, model benchmark or clean-machine installation.

## Retained material

`local-original.tar.gz` contains the clean published run, all 11 successful
fixture worlds, source/hardware/binary metadata, original signed suites and
approval snapshots, public synthetic trust pins, six verifier mutations, and
current teaching replay outputs/commands. `development-original.tar.gz` preserves
the seven failing-baseline worlds (six failed behavior tests) and the 11 fixed
development worlds. These world counts are fixture instances, not extra tests
or rehearsals. Test snapshots repeat the same approvals across states.

The untouched CI ZIP is artifact **13947841623**, SHA-256
`d0b43c755fb23e2bb74f7669355b023959472cc64793cde98da6dca49e9cc5b9`.
It retains all workflow originals, including 11 lifecycle worlds and the other
teaching/runner components. Full decoded CI log, provider state, original
Security ZIP, baseline failures and verification outputs accompany it.
`retention-verification.json` records archive hashes and checks for private-key
fields. Private signing keys were generated only in test memory and are not
distributed. Raw logs retain their original whitespace.

`verify_lifecycle_records.py` uses a separate Ed25519 implementation and
operator-selected public pins. It verifies capability/report/suite hashes,
tenant binding and the existing signatures without the private keys or agent
runtime. Authenticate the archive and pins separately. It does not qualify a
human expert or authenticate lifecycle history: **history is unsigned**, and
authentic baseline approvals also verify despite the selector's bad behavior.
The actual behavior tests, snapshots and source are essential evidence.

Exact extraction/verification and rerun commands are in
[independent verification](../../INDEPENDENT-VERIFICATION.md). The recorded new
local binary hash is
`6624ef6ad82d529c5f311254c0ddd95a96583c1ba4fbf190e3a7143416e1617f`.
For a separately built binary, authenticate its hash independently. SHA-256
manifests are integrity inventories, not signed authority attestations.

## Remaining boundary

This fixes version selection, not actor authentication. CLI actor/role strings
are not proof of authority. Complete signed teaching approval, expiry/revocation,
source/suite/map authorization, clearance policy, version floors and transactional
handling of storage failures remain open. Existing owner-controlled local state
is assumed; this is not a remote multi-user teaching service.

No fresh native sensor, model inference, knowledge pack, final UI/API, offline
kit installation, separate clean host or independently administered evaluator
ran. No packet capture is claimed. Final full-mode consecutive counts remain
zero. Main CI status is tracked separately; pending is never passing. Release
**NOT READY**, next C2 authority/approval work remains necessary.
