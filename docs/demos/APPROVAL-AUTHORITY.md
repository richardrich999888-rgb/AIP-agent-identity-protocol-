# Native approval authority — partial C2

Release remains **NOT READY**. This is an offline, operator-provisioned authority
policy for native approval, CLI activation/rollback and runtime capability use.
It is not authenticated human login, an independent administration boundary, or
the complete teaching-session approval workflow.

## Configure explicitly

Add `approval_policy` to the existing runtime JSON configuration. The following
is a schema example, not a usable credential or pre-authorized expert:

```json
{
  "approval_policy": {
    "authorities": {
      "expert:maintenance": {
        "expert_id": "expert:maintenance",
        "public_key_sha256": "SHA256_OF_THE_32_RAW_ED25519_PUBLIC_KEY_BYTES",
        "tenant": "koravi-process",
        "security_domain": "koravi-ot",
        "capability_ids": ["koravi.ep114.ir-acceptance"],
        "min_version": 1,
        "max_version": 2,
        "max_clearance": "restricted",
        "valid_from_ms": 1,
        "expires_at_ms": 1800000000000,
        "revoked": false
      }
    }
  }
}
```

Provision the matching public key in the existing `approvers` map through the
local operator's trusted configuration channel. Generate a fresh demonstration
key; never distribute private keys. Times are Unix milliseconds: valid-from is
inclusive and expiry exclusive. Set a short expiry suitable for your rehearsal.
The host clock and policy file are trusted inputs, not a trusted-time service.
An empty authorities map denies approval. Absent/null policy preserves the
existing owner-controlled legacy mode, which is **not C2-qualified**. Enabling
policy rejects legacy approvals until they are freshly approved under the policy.

```sh
syntriass cap-approve --config CFG --hash CAP_HASH --key EXPERT_KEYFILE
syntriass cap-activate --config CFG --hash CAP_HASH --actor OPERATOR --reason DEMO
syntriass cap-list --config CFG
```

The v2 Ed25519 signature binds the capability hash, validation-report hash,
expert ID, consequential flag, approval time and authority-grant hash. Capability
content includes tenant, domain, ID/version, source-body dependencies and scope;
the validation report binds the signed-suite digest. The grant binds the expert
public-key digest, allowed capability IDs/versions, tenant/domain, clearance,
validity interval and revocation status. No new signature algorithm is used.

Set `revoked: true` to withdraw that expert grant. The next capability request,
activation, direct ACTIVE transition or rollback rejects it. `cap-list` reports
`executable: false`; stored historical state remains inspectable. Changing any
grant field requires fresh approval, even when the new grant would otherwise
permit use. Removing policy cannot downgrade an existing v2 approval to legacy.
Raising `min_version` rejects rollback below that floor. Strict CLI operations
also recheck current source-body dependencies before approval or activation.

## Verification and limits

Run `cargo test --locked --offline -p syntriass-runtime` with dependencies staged.
Tests exercise real Ed25519 signatures, SQLite source binding and file-store CLI
operations. Runtime orchestration tests use deterministic model/interpreter fakes;
they are not live-model or investor rehearsals. Policy refusals leave capability
files unchanged in tested cases. Multi-file storage-failure atomicity is open.

Actor strings and supplied role labels are not authenticated operator identities.
The low-level lifecycle functions are trusted in-process primitives; callers must
perform the same policy checks as the CLI/runtime. No untrusted API is qualified.
The stored validation report remains an owner-controlled input. Connecting the
independent C1 replay, full original-document hash and unsigned example-map
digest to a teaching approval envelope is still required. Per-approval revocation,
rollback-resistant policy storage, login/clearance administration, offline packs
and independently authenticated distribution of policy/trust material are open.
