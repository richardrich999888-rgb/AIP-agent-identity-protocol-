# Native gate (items 3.1b and 3.2; native, not P0-059)

`gate.py` is the enforcement point and `gate_http.py` is its loopback HTTP
front. A call reaches the tool server **only** after all of the following
pass, in order:

1. envelope shape;
2. the agent is registered and its **Ed25519 request signature** verifies
   (proof of possession; closes #30 at this entry point);
3. the request falls inside a 30 s freshness window;
4. the nonce has not been seen before (seen nonces are persisted, so a
   restart does not reopen replay);
5. OPA allows the call (`opa_gate.py`), given the **operator-signed**
   revocation list.

Any failure is DENY. OPA failure is DENY. Every decision is a
`gate.decision` event, tagged with the stage it reached (pre-auth, auth or
policy) and the bundle hash.

**Approval (3.2).** `payments.settle_batch` above the threshold (10,000), or
with no numeric amount, gets PENDING_APPROVAL and is held. The agent retries
the same signed request with an operator's Ed25519 approval. The approval
must:

- be bound to that request's sha256;
- say APPROVE;
- be signed by a registered operator;
- be inside its time window (TTL at most 15 min).

OPA is consulted again, so a revocation made since the hold still denies.
An approval is single use.

Neither a forged request reusing the nonce, nor a plain replay, nor a bad
approval can cancel a held call. The live run found a defect here: a plain
replay used to cancel the hold. It is fixed and covered by regression
tests.

| Check | Command | Result |
|---|---|---|
| Unit tests | `venv-gate/bin/python -m unittest test_gate` | 30 passed / 0 failed / 0 skipped (3.2); 37/0/0 after 2.4 |
| Mutations | `mutations-gate.txt`, `mutations-orphan.txt` | 13/13 caught; 2.4 lineage 4/4 caught |
| Live, offline, real OPA | `unshare -n … VANIAN_OPA_BIN=… venv-gate/bin/python command-center/lab/live_gate.py OUT` | 3.1b: **11/11 checks** (`evidence/3.1b-native-gate/`). With 3.2: **18/18 checks** (`evidence/3.2-approvals/result.json`) |

The live run sends six signed calls and one replay. The TEST DATA tool
server's hit list is the proof. It received **only** the allowed call. It
received none of these, each refused at the gate:

- an explicitly denied tool;
- a forged identity (#6);
- revoked authority;
- a held sensitive call;
- the replay;
- a call made while OPA was unreachable.

**Authority is derived, not presented (item 2.4, 21 Nov).** Until 2.4 the
gate passed the agent's own `authority_jtis` and `delegation_depth` to OPA.
An orphan that left a revoked ancestor's grant out of its chain was
forwarded. This was found live (`evidence/2.4-orphan/orphan-prefix-hole/`).
The gate now needs a validated grants map (`agent_registry.load_grants`).
It derives the chain and depth from the registry's parent links, and
denies a mismatch or a missing grant at the auth stage. The 3.1b and 3.2
evidence above predates this fix. `live_gate.py` now has 20 checks,
including a stripped chain and an understated depth. Grants are lab-issued,
not AIP delegation tokens.

Dependency: `cryptography==50.0.2`, pinned in `requirements-gate.lock.txt`.
The system package is a build for another Python and crashes under
python3.11 here.

Label: **PREVENTION for calls that go through this gate.** A tool server
that can be reached another way is not protected by it. Detecting that
bypass is the observer's job (Sniffer Dog; 4.3 case d).

Not covered:

- parity with P0-059's allowlist cases. P0-059 is
  BLOCKED_BY_EXTERNAL_APPROVAL, so there are none to compare with;
- network isolation of the tool server;
- the replay scan reads every decision made by that agent. That is fine
  at lab scale, but it is not an index.
