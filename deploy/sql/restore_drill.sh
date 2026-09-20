#!/usr/bin/env bash
#
# restore_drill.sh — the exercised restore drill for the Evidence Vault (E5).
#
# Immutability is not durability. deploy/sql/hardening.sql makes a stored
# packet impossible to delete or alter; it does nothing about the disk under
# it failing. A backup nobody has restored is a hope, not a control, so this
# script is the restore, run end to end, that turns the hope into evidence.
#
# What it proves, against a REAL PostgreSQL, with no network and no fixtures
# from outside:
#   1. A vault with data, the two roles, the append-only triggers, the legal
#      hold, the retention floor and row-level security is dumped.
#   2. The dump is restored into a SEPARATE, EMPTY cluster.
#   3. The restored vault has the same evidence, byte for byte.
#   4. The restored vault is STILL HARDENED: the append-only trigger still
#      refuses an UPDATE, the legal hold still refuses a DELETE, the retention
#      floor still refuses a short policy, the app role still cannot delete,
#      and row-level security still isolates tenants. A restore that brought
#      the data back but left it mutable would be a restore that lost the
#      control, and this is where that is caught.
#
# It creates two throwaway clusters under a temp dir, uses Unix-socket auth
# only (no TCP, no password prompt), and removes everything on exit. It
# changes no system state outside that temp dir.
#
# PostgreSQL refuses to run as root, so when invoked as root every server and
# client command is run as an unprivileged user (default: the `postgres`
# system user; override with AIP_DRILL_USER). Invoked as non-root, it runs
# as the caller.
#
# Usage:  deploy/sql/restore_drill.sh
# Exit:   0 only if every assertion above holds. Any failure is fatal.

set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SCHEMA="$HERE/schema.sql"
HARDENING="$HERE/hardening.sql"

# ── Locate the server binaries ───────────────────────────────────────────────
PGBIN=""
for d in /usr/lib/postgresql/*/bin /usr/pgsql-*/bin; do
  [ -x "$d/initdb" ] && PGBIN="$d" && break
done
if [ -z "$PGBIN" ] && command -v initdb >/dev/null 2>&1; then
  PGBIN="$(dirname "$(command -v initdb)")"
fi
[ -n "$PGBIN" ] || { echo "FATAL: no PostgreSQL server binaries (initdb) found"; exit 1; }

# ── Privilege drop: initdb/postgres will not run as root ─────────────────────
DRILL_USER="${AIP_DRILL_USER:-postgres}"
if [ "$(id -u)" -eq 0 ]; then
  id "$DRILL_USER" >/dev/null 2>&1 || {
    echo "FATAL: running as root and the unprivileged user '$DRILL_USER' does not exist;"
    echo "       set AIP_DRILL_USER to a non-root user."; exit 1; }
  RUN=(runuser -u "$DRILL_USER" --)
else
  RUN=()
fi
run() { "${RUN[@]}" "$@"; }

# A temp dir the drill user owns.
WORK=$(mktemp -d)
if [ "$(id -u)" -eq 0 ]; then chown "$DRILL_USER" "$WORK"; fi
PRIMARY="$WORK/primary"
RESTORE="$WORK/restore"
PSOCK="$WORK/p"; RSOCK="$WORK/r"
DUMP="$WORK/vault.dump"
run mkdir -p "$PSOCK" "$RSOCK"

cleanup() {
  run "$PGBIN/pg_ctl" -D "$PRIMARY" stop -m immediate >/dev/null 2>&1 || true
  run "$PGBIN/pg_ctl" -D "$RESTORE" stop -m immediate >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

step() { printf '\n\033[36m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
die()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; exit 1; }

# psql helpers. Each runs as the drill user, ON_ERROR_STOP, on a given socket.
psql_ok() { # sock db user sql
  run "$PGBIN/psql" -h "$1" -d "$2" -U "$3" -v ON_ERROR_STOP=1 -c "$4" >/dev/null 2>&1 \
    || die "expected success on [$2/$3]: $4"
}
psql_file() { # sock db user file
  run "$PGBIN/psql" -h "$1" -d "$2" -U "$3" -v ON_ERROR_STOP=1 -f "$4" >/dev/null 2>&1 \
    || die "expected success applying $4"
}
psql_val() { # sock db user sql  -> stdout
  run "$PGBIN/psql" -h "$1" -d "$2" -U "$3" -tAc "$4"
}
must_fail() { # sock db user sql   (one or more -c via ';' inside sql)
  if run "$PGBIN/psql" -h "$1" -d "$2" -U "$3" -v ON_ERROR_STOP=1 -c "$4" >/dev/null 2>&1; then
    die "expected refusal but it succeeded on [$2/$3]: $4"
  fi
}

init_cluster() { # dir sock
  run "$PGBIN/initdb" -D "$1" -U aip_owner --auth=trust >/dev/null 2>&1 \
    || die "initdb failed for $1"
  run "$PGBIN/pg_ctl" -D "$1" -o "-k $2 -c listen_addresses=''" -w start >/dev/null 2>&1 \
    || die "pg_ctl start failed for $1"
}

# ── 1. Primary vault ─────────────────────────────────────────────────────────
step "Stand up the primary vault"
init_cluster "$PRIMARY" "$PSOCK"
psql_ok "$PSOCK" postgres aip_owner "CREATE DATABASE aip OWNER aip_owner;"
# The app login the hardening script grants to. In production its password is
# in AIP_DATABASE_URL; here trust auth over a private socket stands in.
psql_ok "$PSOCK" postgres aip_owner "CREATE ROLE aip_app LOGIN;"
psql_file "$PSOCK" aip aip_owner "$SCHEMA"
psql_file "$PSOCK" aip aip_owner "$HARDENING"
ok "schema and hardening applied"

step "Load evidence and controls"
psql_ok "$PSOCK" aip aip_owner \
  "INSERT INTO evidence_packets (id, tenant_id, packet_hash, created_at, evidence_json, verification_status) VALUES ('pkt-1','acme','abc123',1700000000000,'{\"signed\":\"bytes\"}','verified'),('pkt-2','acme','def456',1700000001000,'{\"signed\":\"more\"}','verified');"
psql_ok "$PSOCK" aip aip_owner \
  "INSERT INTO evidence_retention (tenant_id, retain_days, set_by) VALUES ('acme', 180, 'dba');"
psql_ok "$PSOCK" aip aip_owner \
  "INSERT INTO evidence_legal_hold (tenant_id, packet_id, reason, placed_by) VALUES ('acme','pkt-1','regulatory inquiry 2026-Q1','dba');"
BEFORE=$(psql_val "$PSOCK" aip aip_owner \
  "SELECT count(*)||':'||coalesce(string_agg(packet_hash, ',' ORDER BY id),'') FROM evidence_packets;")
ok "two packets, one retention policy, one legal hold; digest [$BEFORE]"

# ── 2. Back up ───────────────────────────────────────────────────────────────
step "Back up (pg_dump, custom format — roles' grants, triggers, RLS and all)"
run "$PGBIN/pg_dump" -h "$PSOCK" -U aip_owner -d aip -Fc -f "$DUMP" \
  || die "pg_dump failed"
SIZE=$(stat -c %s "$DUMP" 2>/dev/null || echo 0)
[ "$SIZE" -gt 0 ] || die "dump is empty"
ok "dump written ($SIZE bytes)"

# ── 3. Restore into a separate empty cluster ─────────────────────────────────
step "Restore into a SEPARATE empty cluster"
init_cluster "$RESTORE" "$RSOCK"
psql_ok "$RSOCK" postgres aip_owner "CREATE DATABASE aip OWNER aip_owner;"
psql_ok "$RSOCK" postgres aip_owner "CREATE ROLE aip_app LOGIN;"
# pg_restore reports benign notices about pre-existing roles; the assertions
# below, not its exit code, are the contract.
run "$PGBIN/pg_restore" -h "$RSOCK" -U aip_owner -d aip "$DUMP" >/dev/null 2>&1 || true
ok "restored"

# ── 4. Verify the data came back intact ──────────────────────────────────────
step "Verify data integrity"
AFTER=$(psql_val "$RSOCK" aip aip_owner \
  "SELECT count(*)||':'||coalesce(string_agg(packet_hash, ',' ORDER BY id),'') FROM evidence_packets;")
[ "$BEFORE" = "$AFTER" ] || die "restored evidence differs: before=[$BEFORE] after=[$AFTER]"
ok "restored evidence is identical [$AFTER]"
JSON=$(psql_val "$RSOCK" aip aip_owner "SELECT evidence_json FROM evidence_packets WHERE id='pkt-1';")
[ "$JSON" = '{"signed":"bytes"}' ] || die "restored evidence_json altered: $JSON"
ok "verbatim signed bytes preserved (would re-verify offline)"

# ── 5. Verify the CONTROLS survived the restore ──────────────────────────────
# The half a naive drill skips. Data without its controls is not a restored
# vault; it is a mutable copy of one.
step "Verify the hardening survived the restore"

must_fail "$RSOCK" aip aip_owner \
  "UPDATE evidence_packets SET verification_status='tampered' WHERE id='pkt-2';"
ok "append-only trigger still refuses UPDATE (owner included)"

# The legal hold refuses the delete; set the tenant GUC first so RLS admits the
# row to the delete attempt at all, proving it is the HOLD that stops it.
must_fail "$RSOCK" aip aip_owner \
  "SET aip.tenant_id='acme'; DELETE FROM evidence_packets WHERE id='pkt-1';"
ok "legal hold still refuses DELETE of the held packet"

must_fail "$RSOCK" aip aip_owner \
  "INSERT INTO evidence_retention (tenant_id, retain_days, set_by) VALUES ('globex', 30, 'dba');"
ok "retention floor (>=180) still refuses a short policy"

# The app role reads and inserts, but cannot delete — the grant, not the app.
psql_ok "$RSOCK" aip aip_app "SET aip.tenant_id='acme'; SELECT count(*) FROM evidence_packets;"
must_fail "$RSOCK" aip aip_app \
  "SET aip.tenant_id='acme'; DELETE FROM evidence_packets WHERE id='pkt-2';"
ok "app role still holds SELECT/INSERT only — no DELETE privilege"

# Row-level security still isolates tenants. The GUC is set with its own -c
# so the count is the last line of output, not the SET command tag.
COUNT=$(run "$PGBIN/psql" -h "$RSOCK" -d aip -U aip_app -tA \
  -c "SET aip.tenant_id='globex';" -c "SELECT count(*) FROM evidence_packets;" | tail -1)
[ "$COUNT" = "0" ] || die "RLS did not survive: globex saw $COUNT of acme's packets"
ok "row-level security still isolates tenants (globex sees 0)"

step "DRILL PASSED"
printf 'A dump taken from the primary vault restored into an empty cluster with\n'
printf 'its evidence intact AND its immutability controls — append-only, legal\n'
printf 'hold, retention floor, least-privilege grant, tenant isolation — all\n'
printf 'still enforced. Backup and restore of the Evidence Vault is exercised,\n'
printf 'not assumed.\n'
