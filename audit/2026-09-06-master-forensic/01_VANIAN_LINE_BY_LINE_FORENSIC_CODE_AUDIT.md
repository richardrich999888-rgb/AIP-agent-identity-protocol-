# Line-by-Line Forensic Code Audit

## 0. Scope statement and honesty boundary

This audit read 58,268 Rust LOC across six branch trees in one pass. It did
not read every line of every file, and this report does not pretend
otherwise. §1 lists the files subjected to line-level analysis. §7 lists
files enumerated and sized but **not** read, marked
`NOT DETERMINABLE FROM CURRENT CODEBASE` where a property would require
reading them.

Where a file was read in full, findings are stated with line citations.
Where a file was read in part, the range read is given.

## 1. Files subjected to line-level analysis

| File (branch) | Lines | Read |
|---|---:|---|
| `main` + `prod` `aip-core/src/capability.rs` | 507 / 583 | full diff, both trees |
| `main` + `prod` `aip-core/src/delegation.rs` | 636 / 813 | full diff, both trees |
| `main` + `prod` `aip-protocol/src/verification.rs` | 709 / 773 | full diff, both trees |
| `main` + `prod` `aip-protocol/src/bundle.rs` | 673 / 673 | `verify_bundle_signature` |
| `main`…`aipv4` `aip-core/src/store.rs` | — | `IdentityStore::save`, 4 trees |
| `main` + `prod` `aip-service/src/evidence.rs` | 604 / 651 | full diff |
| `prod` `aip-reconcile/src/reconcile.rs` | 2,008 | 1–200 full; structural map of 200–2008 |
| `prod` `aip-reconcile/src/result.rs` | 835 | verdict enums, `Reconciliation`, `EvidenceRef` |
| `prod` `aip-warrant/src/warrant.rs` | 437 | 1–100, `evaluate` 172–300, `is_protected` |
| `prod` `aip-warrant/src/policy.rs` | 161 | `WarrantPolicy`, `Severity` |
| `prod` `aip-containment/src/contain.rs` | 384 | header, `gates` 1–90, `contain` 279–365 |
| `prod` `aip-observe/src/attest.rs` | 894 | 1–95 |
| `prod` `aip-nexora/src/merkle.rs` | 359 | domain-separation section |
| `valladder` `aegis-quantum-userspace/src/pqc.rs` | 723 | 1–200 + test map |
| `valladder` `aegis-quantum-circuit-breaker/src/lib.rs` | 757 | 27–135 full |
| `valladder` `aegis-quantum/stress-tests/{src/lib.rs,tests/lru_exhaustion_test.rs}` | 156 / 47 | full |

## 2. `aip-core/src/capability.rs`

### 2.1 `canonical_token_payload` — main

`main/…/capability.rs:208-231`. Reconstructed from the read:

```rust
buf.extend_from_slice(jti);              // 16 bytes, fixed — fine
buf.extend_from_slice(issuer_id.as_bytes());   // UNBOUNDED, NO PREFIX
buf.extend_from_slice(agent_id.as_bytes());    // UNBOUNDED, NO PREFIX
for action in &scope.allowed { … }
buf.push(0xFF);                          // separator a payload can contain
for action in &scope.denied { … }
buf.extend_from_slice(&issued_at.to_le_bytes());
// expires_at: ABSENT
```

`encode_scope_action` (`main/…/capability.rs:232-242`) encodes `Custom(s)` as
`0x01 ‖ s ‖ 0x00`.

**Findings.**

- **L-1 (P0).** Adjacent unprefixed strings are not injective.
  `("ab","c")` and `("a","bc")` yield identical bytes.
- **L-2 (P0).** `expires_at` is not in the signed preimage but *is*
  enforced by `check_temporal_validity` downstream. The verifier enforces a
  field the issuer never signed.
- **L-3 (P1).** No domain tag. A `ScopedToken` signature and a
  `DelegationToken` signature over structurally similar content are
  interchangeable.
- **L-4 (P2).** `0xFF` is used as an allowed/denied separator and `0x00` as
  a custom-action terminator. Both are bytes a `Custom(String)` action can
  contain, so a custom action with an interior NUL is ambiguous with two
  adjacent actions, and the allowed/denied boundary is forgeable by a
  crafted action name.

All four are present on `main`, `audit`, `importot`, `valladder`, `aipv4`.

### 2.2 `canonical_token_payload` — prod

`prod/…/capability.rs:221-238`. All four findings closed:

```rust
put_domain(&mut buf, SCOPED_TOKEN_DOMAIN);   // L-3
buf.extend_from_slice(jti);                  // fixed 16
put_str(&mut buf, issuer_id);                // L-1
put_str(&mut buf, agent_id);                 // L-1
encode_scope(&mut buf, scope);               // L-4
put_u64(&mut buf, issued_at);
put_opt_u64(&mut buf, &expires_at);          // L-2
```

`expires_at` is computed once at `:144` and threaded to both the payload and
the struct, so the signed value and the carried value cannot diverge — a
small detail that matters, because the previous code computed
`expires_in_ms.map(|d| now_ms + d)` inline at the struct literal.

`verify_scoped_token` (`:170-176`) passes `token.expires_at` into the
recomputed payload, so the check is closed on both sides.

**Tests that genuinely exercise the property** (`:253-330`, `:424-490`):
`test_mutate_expires_at_extend_rejected`,
`test_mutate_expires_at_some_to_none_rejected`,
`test_mutate_expires_at_none_to_some_rejected`,
`test_token_payload_adjacent_ids_do_not_collide`,
`test_token_payload_custom_action_interior_nul_unambiguous`,
`test_token_payload_expiry_presence_is_distinct`,
`test_token_payload_starts_with_domain_tag`.

The interior-NUL test is the strongest of these: it distinguishes
`Custom("x\0y")` from `[Custom("x"), Custom("y")]` from
`allowed=[Custom("x")], denied=[Custom("y")]` — three arrangements that the
old encoder could confuse.

## 3. `aip-core/src/delegation.rs`

### 3.1 `verify_delegation_chain` — prod, read in full

`prod/…/delegation.rs:179-244`. Five checks per hop, in this order:

| # | Check | Line | Error |
|---|---|---|---|
| 1 | `hop.parent_jti == prev_jti` | :200 | `LineageInvalid` |
| 2 | `hop.depth == i+1` | :206 | `LineageInvalid` |
| 3 | `is_scope_subset(hop.scope, prev_scope)` | :211 | `AttenuationViolation` |
| 4 | issuer signature over recomputed payload | :219 | `SignatureInvalid` |
| 5 | `hop.expires_at` does not outlive parent's | :227-235 | `AttenuationViolation` |

**Finding L-5 (P0, all six branches).** There is no check that
`hop.issuer_id` equals the previous hop's `grantee_id`, or — for hop 0 —
the root token's `agent_id`. The chain is linked by JTI and by depth. The
*identities* are not linked. Any principal whose key is present in
`issuer_public_keys` can present itself as the issuer of a hop whose
`parent_jti` matches, and all five checks pass.

The consequence is precise: delegation is authenticated (someone with a
trusted key signed this hop) but not attributed (that someone need not be
the party the previous hop delegated to). A "chain of custody" that does not
check custody.

**Checked, not a finding — the depth bound is correct.** The limit is
`if chain.len() >= MAX_DELEGATION_DEPTH` (`:190`), and `create_sub_delegation`
rejects `new_depth >= MAX_DELEGATION_DEPTH` (`:120`). With
`MAX_DELEGATION_DEPTH = 8` and root delegations starting at depth 1 (`:77`),
the maximum accepted depth is 7. This initially reads as an off-by-one, and
it is not: the module's invariant list states the bound as
`depth < MAX_DELEGATION_DEPTH` (`:18`), a strict inequality, and both call
sites implement exactly that. Recorded here because an automated scan and a
first reading both flag it, and the next auditor should not have to re-derive
the answer.

### 3.2 Ordering of check 4 before check 5 — correct, and deliberately so

The comment at `:224-226` explains it:

> checked after authenticity so a forged expiry is reported as
> `SignatureInvalid`, and an issuer that genuinely over-delegated is
> reported as `AttenuationViolation`.

This is right. The two conditions are different accusations — tampering
versus exceeding authority — and collapsing them would destroy forensic
information. `test_legitimately_signed_hop_outliving_parent_rejected`
(`:520-575`) pins it by forging a hop with the *genuine* delegating key and
requiring `AttenuationViolation` specifically, with a control case at equal
expiry that must succeed.

## 4. `aip-protocol/src/verification.rs`

### 4.1 The complete main→prod delta

64 lines, three changes, nothing else:

1. `use aip_types::EXECUTION_BINDING_VERSION;` (`:24`)
2. `check_execution_binding` — new rule R15 (`:484-533`), called at `:266`
3. `check_structure` problem strings widened `&str` → `String` (`:333-355`)
   so the unsupported-version message can name the version

### 4.2 R15 — read in full

```rust
fn check_execution_binding(packet, e) -> bool {
    let Some(b) = &packet.execution_binding else {
        return e.record(EXECUTION_BINDING, true,
            "no execution binding present; process-instance attribution unavailable");
    };
    // version, agent match, pid != 0, pid_start_time_ticks != 0,
    // boot_id != [0;16], exe_content_sha256 != [0;32]
}
```

**Assessment: correct and correctly scoped.** Three things are right about
it:

- Absence is *reported as passing*, not failed. A packet without a binding
  is not attributable to a process instance; that is a statement about what
  the record can support, not a defect in the record.
- The success message says "**NOT independently observed**" in the record
  itself, so a consumer reading the report cannot mistake a self-report for
  an observation.
- The call site comment at `:266-268` states it "Does NOT affect the trust
  floor: a self-report cannot raise evidence strength". The trust-floor
  derivation at `:270-280` does not reference the R15 result. Verified by
  reading the derivation.

### 4.3 `check_temporal_validity` — unchanged, and the P0

`prod/…/verification.rs:535-585`. Byte-identical to main (both bodies
extracted and hashed: `dbafa0086c1b34af`). It performs three comparisons:

```rust
if decided < issued_at                     → "decision predates issuance"
if decided > exp                           → "decision after expiry"
if action.performed_at > exp               → "action after expiry"
if action.performed_at < decision.decided_at → "action before its decision"
```

Every comparison is between two values **carried inside the packet**.
`VerificationContext` (`:29-43`) carries issuer keys, counterparty keys,
revoked JTIs, trace data and receipt data — and no clock.

**Finding L-7 (P0, all branches with this file).** A packet whose internal
timestamps are mutually consistent passes regardless of how far they sit
from real time. Combined with the absence of any replay rule among R1–R15,
a captured packet remains verifiable indefinitely and a fabricated one can
be dated arbitrarily. The system's temporal claims are internal-consistency
claims only.

The fix is small — a `now_ms` field and a bound — and the fact that R15 was
added without adding it is the notable part.

## 5. `aip-reconcile` — the verdict engine

### 5.1 Verification order

`reconcile.rs:5-9` declares it, and the code follows it:

> structure → expected signature → expected window → observer signatures →
> observer trust → chain/continuity → identity → decision id → binding →
> action → parameters → time → strength → result. A failed prerequisite is
> never skipped and never upgraded.

`prologue` (`:1131-1213`) implements everything the two entry points share
and returns a finished record on early exit, so a failed prerequisite
*cannot* fall through — there is no path that continues past it.

### 5.2 `Draft` and the four proof-carrying flags

`reconcile.rs:37-62`. Four fields exist solely to carry evidence that a
precondition was actually established:

| Field | Set by | Gates |
|---|---|---|
| `coverage_recomputed` | `recompute_coverage` only | `PhantomClaim` |
| `action_continuity_verified` | `compare_action` only | `VerifiedExecution` |
| `lineage` | `reconcile_lineage` only | `LineageViolation` |
| `wire` | Gate 2 corroboration | nothing — informational |

The comments state the maintenance intent explicitly: a future edit that
forgets the recomputation "downgrades to `CannotProve` instead of asserting
non-execution". This is the right way to express a safety property.

`wire` is documented as unable to raise or lower the verdict, and
`precondition_holds` does not reference it. Verified.

### 5.3 `precondition_holds` — read in full, findings

`reconcile.rs:89-137`. See Report 04 §2.1 for the table.

**Finding L-8 (P3).** `SensorIntegrityFailure` and `ContinuityFailure` are
the only two classes with no structural precondition — their arm is
`strength >= EvidenceStrength::Attested` alone. Every workload-directed
verdict must present a witness in the record; neither observer-directed
verdict must. For a system whose threat model includes a host that benefits
from discrediting its observer, the asymmetry runs the wrong way.

Mitigating: `classify_observer_error` (`:209-228`) is careful about which
failures earn `Proven` — signature arithmetic does, a bad local trust anchor
does not — and the match is exhaustive so a new variant breaks the build.
The care is present at the classification site; it is the precondition that
is thin.

**Finding L-9 (P2).** `Reconciliation` (`result.rs:679-699`) has fourteen
`pub` fields. `ActionComparison`'s positive variants are protected by a
private-field seal with `pub(crate)` constructors; the record carrying the
verdict is not. Any consumer crate can construct a verdict directly,
bypassing `finish()` and `precondition_holds`. The crate's own consumers do
exactly this (`aip-containment/tests/containment.rs:104`).

The authors identified constructor control as the correct mechanism and
applied it one level too shallow.

### 5.4 `compare_action` and `place_transition` — structural read only

`reconcile.rs:385-689`. Read at the level of doc comments and control-flow
shape, not statement by statement. Two properties are stated and appear
consistent with the code read:

- A transition placed **before** the decision "is not the authorized action,
  whoever claims it — and it also disqualifies presence evidence of the same
  connection", i.e. the "existed, but was not made" case.
- "Host claims only ever *restrict* a verdict."

`NOT DETERMINABLE FROM CURRENT CODEBASE` at this audit depth: whether every
path through `compare_action` honours the second property. It requires a
statement-level read of 230 lines and is the highest-value remaining target
for a follow-up pass.

## 6. `aegis-quantum` (valladder / aipv4 only)

### 6.1 `circuit-breaker/src/lib.rs:27-135` — read in full

```rust
pub struct CircuitBreaker {
    window_ns: u64,
    threshold: usize,
    connections: HashMap<ConnectionKey, ConnectionState>,   // unbounded
}
```

`record_event` (`:65`) does `self.connections.entry(*key).or_insert_with(…)`.
No method removes an entry. `reset` (`:109`) clears one connection's
timestamps and leaves the entry. `reset_all` (`:117`) clears the map and is
called by nothing on a timer or a bound.

**Finding L-10 (P1).** Per-key memory is bounded (the deque cannot exceed
`threshold + 1` before `tripped` short-circuits further pushes), but the
*number of keys* is not. An adversary varying the connection tuple allocates
one entry per tuple without limit, in the component whose documented purpose
is to stop "one rogue agent hammering an endpoint in a tight loop."

**Finding L-11 (P3).** `new()` (`:52`) computes `window_ms * 1_000_000` with
unchecked `u64` multiplication and validates neither argument.
`threshold = 0` trips on the first event; `window_ms = 0` yields a
one-nanosecond window.

**Finding L-12 (P3).** Once `tripped`, the timestamp deque is retained
indefinitely — `record_event` returns at `:76` before any eviction runs.
Tripping the breaker is the cheapest route to permanent per-key retention.

**Finding L-13 (P3).** `timestamp_ns` is caller-supplied and assumed
monotonic. Nothing enforces it. The eviction cutoff is
`timestamp_ns.saturating_sub(self.window_ns)`, so a caller feeding
non-monotonic values shrinks the cutoff and stops eviction early.

**Finding L-14 (P1) — the test that does not test this.**
`stress-tests/tests/lru_exhaustion_test.rs` (read in full, 47 lines) calls
`simulate_lru_saturation` and `MockLruSessionMap`, both defined at
`stress-tests/src/lib.rs:19,84`. Neither test constructs a
`CircuitBreaker`. The crate depends on `aegis-quantum-circuit-breaker` but
the exhaustion tests do not use it. Two passing tests named for a bound the
product code does not have.

### 6.2 `userspace/src/pqc.rs` — read 1–200

**Finding L-15 (P1).** `process_packet_event` (`:157-165`) logs the event's
addresses and discards it, then calls
`hybrid_x25519_kyber768_key_exchange()`. That function (`:90-131`) creates
`client_secret`, `server_secret`, and the Kyber keypair in the same process,
encapsulates to a public key it just made, decapsulates with the private
half it still holds, and compares two secrets derived entirely from key
material it owns. `secrets_match` is arithmetically always true.

There is no peer, no socket, no session-map write. The doc comment is honest
(`:152` "For TRL-4, we simulate the full round-trip"); the crate description
and the type name `PqcValidationReport` are not.

**Finding L-16 (P3).** `algorithm` is reported as `"Kyber-768 (ML-KEM)"`.
The dependency is `pqcrypto-kyber 0.8.1`, which implements round-3 Kyber.
FIPS 203 ML-KEM is a different construction. The label conflates them.

**Finding L-17 (P2).** `pqcrypto-kyber = "0.8"` and
`pqcrypto-traits = "0.3"` are caret ranges on cryptographic dependencies.

**Not a finding — `hybrid_session_hash` (`:134-142`) is correct:**
domain-separated under `AIRON-AEGIS-HYBRID-v1`, both secrets
length-prefixed before hashing. The construction is the recommended hybrid
pattern. It is exercised only against itself.

## 7. Enumerated but not read

Sized and located; no line-level claim is made about them. Any property
depending on these is `NOT DETERMINABLE FROM CURRENT CODEBASE` at this audit
depth.

| File | Lines |
|---|---:|
| `prod` `aip-observe/src/observed.rs` | 1,289 |
| `prod` `aip-observe/src/probe.rs` | 915 |
| `prod` `aip-observe/src/attest.rs` (96–894) | 799 |
| `prod` `aip-observe/src/{linux,perf,wiretap,sockstate,runtime,continuity,health,fanotify,sched,store,socksend}.rs` | 4,101 |
| `prod` `aip-reconcile/src/reconcile.rs` (200–2008) | 1,808 |
| `prod` `aip-reconcile/src/{action,result,inputs,ids}.rs` | 2,004 |
| `prod` `aip-nexora/src/commitment.rs` | 650 |
| `prod` `aip-authorize/src/{expected,decision,actions}.rs` | 1,135 |
| `prod` `aip-agent/src/*.rs` | 1,612 |
| `prod` `aip-containment/src/{record,actuator,attribution,replay}.rs` | 1,100 |
| `importot` all four Rust roots + Python SDK + 12,166 TS LOC | ~35,000 |
| `valladder` `airon-verify` | 948 |
| `aegis-quantum-ebpf/src/main.rs` | 322 |
| `aegis-quantum-userspace/src/af_xdp.rs` | 497 |

The highest-value unread targets, in order: `reconcile.rs:200-2008`
(the verdict derivation paths themselves), `observed.rs` (the observation
type system the verdicts rest on), and `aip-observe/src/probe.rs` (the
untrusted boundary).

## 8. Finding index

| ID | Sev | Summary | Branches affected |
|---|---|---|---|
| L-1 | P0 | Signing payload not injective | main, audit, importot, valladder, aipv4 |
| L-2 | P0 | `expires_at` enforced but not signed | main, audit, importot, valladder, aipv4 |
| L-3 | P1 | No domain separation in token payloads | main, audit, importot, valladder, aipv4 |
| L-4 | P2 | `0xFF`/`0x00` separators collide with custom action names | main, audit, importot, valladder, aipv4 |
| **L-5** | **P0** | Delegation issuer not bound to previous grantee | **all six** |
| **L-7** | **P0** | Verifier has no clock | main, prod, audit, importot |
| L-8 | P3 | Observer-directed verdicts have no structural precondition | prod |
| L-9 | P2 | `Reconciliation` constructible outside the engine | prod |
| L-10 | P1 | Circuit-breaker connection map unbounded | valladder, aipv4 |
| L-11 | P3 | `CircuitBreaker::new` unchecked arithmetic, no validation | valladder, aipv4 |
| L-12 | P3 | Tripped connections retain state indefinitely | valladder, aipv4 |
| L-13 | P3 | Timestamp monotonicity assumed, not enforced | valladder, aipv4 |
| **L-14** | **P1** | Exhaustion test exercises a mock, not the product | valladder |
| **L-15** | **P1** | PQC "exchange" has no counterparty | valladder, aipv4 |
| L-16 | P3 | Kyber labelled as ML-KEM | valladder, aipv4 |
| L-17 | P2 | Cryptographic dependencies unpinned | valladder, aipv4 |
