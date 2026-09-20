# Backup and recovery of the Evidence Vault (E5)

Immutability is not durability. `deploy/sql/hardening.sql` makes a stored
packet impossible to delete or alter (R13, matrix D7). It does nothing
about the disk under it failing, the volume being lost, or the cluster
being destroyed. A table nobody can delete from is still lost with its
disk. This is the durability half.

The load-bearing claim of this document is not that backups exist — every
DBA runs `pg_dump`. It is that **a restore has been exercised, and the
restored vault is still hardened.** A backup nobody has restored is a hope,
and a restore that brings the data back but leaves it mutable has lost the
control that made it evidence.

## The drill

`deploy/sql/restore_drill.sh` is the exercised restore, runnable on any
host with PostgreSQL server binaries. It:

1. stands up a primary vault, applies `schema.sql` and `hardening.sql`,
   and loads evidence, a retention policy, and a legal hold;
2. backs it up with `pg_dump -Fc` (custom format carries the roles' grants,
   the triggers and row-level security, not just the rows);
3. restores into a **separate empty cluster**;
4. verifies the evidence is identical, byte for byte, including the
   verbatim signed `evidence_json` that must re-verify offline; and
5. verifies every control survived the restore — the append-only trigger
   still refuses an `UPDATE` (the owner included), the legal hold still
   refuses a `DELETE`, the retention floor still refuses a sub-180-day
   policy, the `aip_app` role still holds `SELECT`/`INSERT` only, and
   row-level security still isolates tenants.

It creates throwaway clusters under a temp dir, uses Unix-socket auth only,
changes no system state outside that dir, and exits non-zero if any
assertion fails. Step 5 is the half a naive drill skips, and it is the half
that matters: a restored vault without its controls is a mutable copy of
one.

```
# On a host with PostgreSQL installed (as root, it drops to the postgres user):
deploy/sql/restore_drill.sh
```

Run it on the pilot's own hardware, on the schedule below, and attach the
output to the DR record. A green drill is the evidence that the RPO and RTO
figures are real rather than aspirational.

## Production backup, restore, and continuity

The drill proves the mechanism. A production posture is the institution's,
and these are the decisions it must record — the code cannot make them:

| Decision | What it sets | Why it is the entity's |
|---|---|---|
| **RPO** (recovery point objective) | how much evidence may be lost | CERT-In requires 180-day retention; the RPO says how much of the most recent window a failure may cost. A continuous-archiving setup (WAL archiving / PITR) gives a near-zero RPO; nightly `pg_dump` gives a one-day RPO. |
| **RTO** (recovery time objective) | how long a restore may take | Drives whether a warm standby is needed or a cold restore suffices. The drill's wall-clock on real data is the input. |
| **Off-site and off-host** | where backups live | A backup on the same volume as the vault fails with it. Backups go to storage under different failure and administrative domains — the same separation the collector key (`deploy/pilot/HSM_CUSTODY.md`) and the anchor witness (`deploy/pilot/ANCHOR_WITNESS.md`) require. |
| **Backup encryption and key custody** | who can read a backup | A `pg_dump` is the evidence in the clear. It is encrypted at rest, and the key is held where the vault's own keys are not — a backup an attacker can read and restore elsewhere defeats tenant isolation and legal hold. |
| **Backup immutability** | whether a backup can be deleted | Object-lock / WORM on the backup store, so ransomware or a rogue admin cannot delete the backups as a path around the vault's own append-only controls. |
| **Restore-drill cadence** | how often the drill runs | Quarterly at least, and after any schema change. A drill that has not run since the last migration is testing a vault that no longer exists. |

## What survives a `pg_dump`, and what does not

`pg_dump -Fc` of the `aip` database carries the tables, the append-only and
legal-hold triggers, the retention `CHECK`, and the row-level-security
policies — the drill proves it. It does **not** carry the **roles**
themselves (`aip_owner`, `aip_app`) or their passwords: cluster roles are
global, and a restore into a fresh cluster recreates them from the
provisioning step (`deploy/sql/`), not from the dump. The drill recreates
the roles before `pg_restore` for exactly this reason. A production restore
runbook does the same, and sets the `aip_app` password from the secret
manager, never from the backup.
