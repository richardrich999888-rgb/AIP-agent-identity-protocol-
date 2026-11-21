# Native gate (item 3.1b; native, not P0-059)

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

Any failure is DENY. PENDING_APPROVAL holds the call (3.2). OPA failure is
DENY. Every decision is a `gate.decision` event with the bundle hash.

| Check | Command | Result |
|---|---|---|
| Unit tests | `venv-gate/bin/python -m unittest test_gate` | 20 passed / 0 failed / 0 skipped |
| Mutations | `mutations-gate.txt` | 6/6 caught |
| Live, offline, real OPA | `unshare -n … VANIAN_OPA_BIN=… venv-gate/bin/python command-center/lab/live_gate.py OUT` | **11/11 checks** (`docs/enterprise-wow/evidence/3.1b-native-gate/result.json`) |

The live run sends six signed calls and one replay. The TEST DATA tool
server's hit list is the proof. It received **only** the allowed call. It
received none of these, each refused at the gate:

- an explicitly denied tool;
- a forged identity (#6);
- revoked authority;
- a held sensitive call;
- the replay;
- a call made while OPA was unreachable.

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
