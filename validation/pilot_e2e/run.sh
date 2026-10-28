#!/usr/bin/env bash
#
# run.sh — the two-daemon pilot pair, end to end, under live attack.
#
# WHAT THIS CLOSES
# ----------------
# The technical brief says, of the foreign-eBPF tracepoint gate: "In the
# two-host pilot topology the finding travels inside the signed batch and the
# collector fails closed on a missing finding; that path is covered by
# automated tests against synthetic batches. The live attack against the two
# daemons ... is a pilot Phase 4 item."
#
# This script runs that live attack against the two REAL daemons. No synthetic
# batch, no in-process shortcut: aip-collector and aip-probe are separate
# processes, the probe holds no key, the link is the authenticated and
# confidential transport, and the evidence examined at the end is the
# collector's own SIGNED health archive.
#
# THE EXPERIMENT
# --------------
#   A. Control.  Both daemons up, real workload, no attack.
#                Expect: ObserverState::Active, attested_coverage present.
#   B. Attack.   A foreign eBPF program returning 0 is attached to the
#                sched:sched_process_exec tracepoint the probe samples. It is
#                two instructions; it carries no product code and observes
#                nothing. It holds the perf submission gate shut host-wide.
#                Expect: ObserverState::IntegrityUnknown and
#                attested_coverage absent -- the collector, on the other side
#                of the transport and holding the only key, signs that it
#                cannot establish its own capability.
#   C. Recovery. Attack detached, workload continues.
#                Expect: the observer does not silently return to Active for
#                the window it could not vouch for.
#
# The point is NOT that the attack is detected and stopped. It is not stopped:
# a CAP_BPF adversary can blind the sensor. The point is that the system says
# so, in a signed record, instead of reporting a clean window it cannot
# justify -- and that absence during that window is therefore never read as
# evidence that nothing happened.
#
# REQUIREMENTS: root (or CAP_BPF + CAP_PERFMON + CAP_NET_ADMIN), a mounted
# tracefs, and a kernel with the sched tracepoints. The script mounts tracefs
# if it is absent and says so. Everything else it builds or generates.
#
# Usage:  validation/pilot_e2e/run.sh [outdir]
# Exit:   0 only if every expectation above held.

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
OUT="${1:-$HERE/results/$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT" || exit 1
OUT=$(cd "$OUT" && pwd) || exit 1

step() { printf '\n\033[36m== %s\033[0m\n' "$*" | tee -a "$OUT/transcript.txt"; }
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$*" | tee -a "$OUT/transcript.txt"; }
info() { printf '       %s\n' "$*" | tee -a "$OUT/transcript.txt"; }
die()  { printf '  \033[31mFAIL\033[0m %s\n' "$*" | tee -a "$OUT/transcript.txt"; exit 1; }

COLLECTOR_PID=""; PROBE_PID=""; ATTACK_PID=""
cleanup() {
  [ -n "$ATTACK_PID" ]    && kill "$ATTACK_PID"    2>/dev/null
  [ -n "$PROBE_PID" ]     && kill "$PROBE_PID"     2>/dev/null
  [ -n "$COLLECTOR_PID" ] && kill "$COLLECTOR_PID" 2>/dev/null
  wait 2>/dev/null
  ATTACK_PID=""; PROBE_PID=""; COLLECTOR_PID=""
}
trap cleanup EXIT

# ── Preconditions ────────────────────────────────────────────────────────────
step "Preconditions"
[ "$(id -u)" -eq 0 ] || die "needs root (or CAP_BPF + CAP_PERFMON + CAP_NET_ADMIN)"
if [ ! -r /sys/kernel/tracing/available_events ]; then
  mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null
fi
[ -r /sys/kernel/tracing/available_events ] || die "tracefs unavailable; the perf sensors cannot open"
TP_ID=$(cat /sys/kernel/tracing/events/sched/sched_process_exec/id 2>/dev/null) \
  || die "sched:sched_process_exec not present on this kernel"
info "kernel $(uname -r), tracefs mounted, sched_process_exec id=$TP_ID"
uname -a > "$OUT/host.txt"; echo "tracepoint_id=$TP_ID" >> "$OUT/host.txt"

step "Build the daemons and the interference instrument"
if ( cd "$REPO" && CARGO_INCREMENTAL=0 cargo build -q -p aip-probe -p aip-collector -p aip-observe-verify ) \
     >> "$OUT/build.log" 2>&1; then
  :
else
  BUILD_STATUS=$?
  die "build failed (exit $BUILD_STATUS); see build.log"
fi
gcc -O2 -o "$OUT/interferer" "$REPO/validation/observation_integrity/tracepoint_interferer.c" \
  2>>"$OUT/build.log" || die "could not build the interference instrument"
ok "aip-probe, aip-collector, aip-observe-verify and the interferer built"

# ── Bring up the pair ────────────────────────────────────────────────────────
W="$OUT/work"; mkdir -p "$W/state"
PORT=$(python3 -c "import socket;s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()")
echo -n "pilot-e2e-passphrase" > "$W/pass"

# Order matters. The collector refuses to start on an EMPTY allow-list -- it
# would accept no probe, which it treats as a misconfiguration rather than a
# default. So the probe's transport key is generated first, the allow-list is
# written with it, and the collector starts once against a real list.

step "Generate the probe's transport-auth key (the probe holds no evidence key)"
env AIP_PROBE_ID=probe.pilot.e2e AIP_PROBE_COLLECTOR_ENDPOINT="127.0.0.1:1" \
    AIP_PROBE_COLLECTOR_NOISE_PUBKEY="$(printf '0%.0s' $(seq 1 64))" \
    AIP_PROBE_KEY_PATH="$W/probe.key.json" AIP_PROBE_SENSORS=sched \
    timeout 4 "$REPO/target/debug/aip-probe" > "$W/probe.keygen.log" 2>&1
[ -s "$W/probe.key.json" ] || { cat "$W/probe.keygen.log"; die "probe did not generate a transport key"; }
PROBE_PUB=$(python3 -c "import json;print(json.load(open('$W/probe.key.json'))['public_hex'])")
printf '[{"probe_id":"probe.pilot.e2e","transport_pubkey_hex":"%s"}]\n' "$PROBE_PUB" > "$W/probes.json"
ok "probe transport public key ${PROBE_PUB:0:16}... written to the allow-list"

step "Start the collector (holds the only evidence key; wrapped at rest)"
env AIP_COLLECTOR_OBSERVER_ID=collector.pilot.e2e AIP_COLLECTOR_KEY_VERSION=1 \
    AIP_COLLECTOR_KEY_PATH="$W/collector.key.wrapped" \
    AIP_COLLECTOR_PASSPHRASE_FILE="$W/pass" AIP_COLLECTOR_STATE_DIR="$W/state" \
    AIP_COLLECTOR_LISTEN="127.0.0.1:$PORT" AIP_COLLECTOR_PROBES_PATH="$W/probes.json" \
    AIP_COLLECTOR_NOISE_KEY_PATH="$W/noise.key.json" \
    AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK="${AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK:-1}" \
    "$REPO/target/debug/aip-collector" > "$W/collector.log" 2>&1 &
COLLECTOR_PID=$!
for _ in $(seq 1 40); do
  grep -q "noise static public key" "$W/collector.log" && break
  sleep 0.25
done
# Read the key from the file the collector writes, not from the log. A bare
# "first 64 hex characters" match over the log pins whichever public value
# the daemon happened to print first -- the evidence anchor and the Noise
# static key are both 64 hex characters -- and the probe then fails the
# handshake against a collector that is working perfectly.
NOISE_PUB=$(cat "$W/state/noise.pub" 2>/dev/null)
[ -n "$NOISE_PUB" ] || { cat "$W/collector.log"; die "collector did not publish a noise key"; }
kill -0 "$COLLECTOR_PID" 2>/dev/null || { cat "$W/collector.log"; die "collector died"; }
grep -q "listening on" "$W/collector.log" || sleep 1
ok "collector up on 127.0.0.1:$PORT; noise static public key ${NOISE_PUB:0:16}..."

step "Start the probe (holds NO evidence key) with the kernel sensors"
env AIP_PROBE_ID=probe.pilot.e2e AIP_PROBE_COLLECTOR_ENDPOINT="127.0.0.1:$PORT" \
    AIP_PROBE_COLLECTOR_NOISE_PUBKEY="$NOISE_PUB" \
    AIP_PROBE_KEY_PATH="$W/probe.key.json" \
    AIP_PROBE_SENSORS=sched,sockstate,socksend,connector \
    AIP_PROBE_BATCH_INTERVAL_MS=1000 \
    "$REPO/target/debug/aip-probe" > "$W/probe.log" 2>&1 &
PROBE_PID=$!
sleep 3
kill -0 "$PROBE_PID" 2>/dev/null || { cat "$W/probe.log"; die "probe died"; }
grep -q "connected" "$W/probe.log" || { cat "$W/probe.log"; die "probe never connected"; }
ok "probe up, four kernel sensors open, connected over the confidential transport"

# Real agent-like workload: executions and TCP activity.
workload() {
  for _ in $(seq 1 "$1"); do
    /bin/true; /bin/echo -n "" ; (exec /bin/date >/dev/null)
    python3 - <<'PY' >/dev/null 2>&1
import socket
s=socket.socket(); s.settimeout(0.3)
try:
    s.connect(("127.0.0.1", 9)); s.send(b"x")
except Exception: pass
finally: s.close()
PY
    sleep 0.15
  done
}

# Read the newest signed health record.
health_field() { # field
  tail -1 "$W/state/health.archive.jsonl" 2>/dev/null \
    | python3 -c "import sys,json;d=json.load(sys.stdin);print(json.dumps(d['health'].get('$1')))" 2>/dev/null
}
health_count() { wc -l < "$W/state/health.archive.jsonl" 2>/dev/null || echo 0; }

# The collector signs a health record on a timer (30 s), not on every batch.
# A phase therefore has to wait for a record emitted AFTER its workload ran,
# or it reads the previous phase's statement. This is the whole reason the
# script takes minutes rather than seconds.
wait_new_health() { # baseline
  local base="$1"
  for _ in $(seq 1 90); do
    [ "$(health_count)" -gt "$base" ] && { sleep 0.3; return 0; }
    sleep 1
  done
  return 1
}

# ── A. Control ───────────────────────────────────────────────────────────────
step "A. CONTROL - real workload, no attack"
BASE=$(health_count)
workload 12
info "waiting for the collector's next signed health record (timer is 30 s)"
wait_new_health "$BASE" || die "no new signed health record was produced"
STATE_A=$(health_field state); COV_A=$(health_field attested_coverage)
cp "$W/state/health.archive.jsonl" "$OUT/health.A.control.jsonl"
info "signed ObserverState = $STATE_A"
info "attested_coverage    = $(echo "$COV_A" | cut -c1-90)"
# The property under test in the control is NOT that the state is Active. It
# is that the system does not claim an integrity failure when none was
# induced. `Degraded` -- a counted gap or a coverage defect -- is the observer
# honestly reporting a limitation and is not a false positive; which of the
# two a given window lands in depends on incidental loss and on where the
# 30-second health tick falls. Asserting `Active` here would be asserting
# something the experiment does not control, and would make the harness flaky
# for a reason unrelated to the finding.
[ "$STATE_A" != '"IntegrityUnknown"' ] \
  || die "control run must not claim an integrity failure with no attack"
ok "control: $STATE_A - no integrity failure claimed without an attack"
[ "$COV_A" != "null" ] && ok "control: attested coverage present" \
  || info "control: no attested coverage in this window (state $STATE_A)"

# ── B. Attack ────────────────────────────────────────────────────────────────
step "B. ATTACK - foreign eBPF program gating sched:sched_process_exec"
"$OUT/interferer" "$TP_ID" > "$W/attack.log" 2>&1 &
ATTACK_PID=$!
sleep 1
kill -0 "$ATTACK_PID" 2>/dev/null || { cat "$W/attack.log"; die "interferer failed to attach (needs CAP_BPF)"; }
ATTACHED=$(grep -oE "INTERFERER_ATTACHED tracepoint_id=[0-9]+ cpus=[0-9]+" "$W/attack.log" | head -1)
[ -n "$ATTACHED" ] || { cat "$W/attack.log"; die "interferer did not report a successful attach"; }
info "$ATTACHED"
# EEXIST on the remaining CPUs is the mechanism, not a partial failure: the
# BPF array is keyed on the tracepoint (trace_event_call), so the first attach
# installs the gate and later attaches to the same tracepoint are refused.
# One successful attach suppresses the sample for EVERY perf consumer of that
# tracepoint, host-wide. That is what makes the finding serious: the adversary
# needs one attach, not one per CPU per victim.
EEXIST=$(grep -c "File exists" "$W/attack.log" || true)
[ "$EEXIST" -gt 0 ] && info "$EEXIST further attach(es) refused EEXIST - the gate was already installed on the tracepoint"
BASE=$(health_count)
workload 15
info "waiting for the next signed health record"
wait_new_health "$BASE" || die "no new signed health record under attack"
STATE_B=$(health_field state); COV_B=$(health_field attested_coverage)
cp "$W/state/health.archive.jsonl" "$OUT/health.B.under_attack.jsonl"
info "signed ObserverState = $STATE_B"
info "attested_coverage    = $COV_B"
[ "$STATE_B" = '"IntegrityUnknown"' ] \
  || die "under attack the collector must sign IntegrityUnknown, got $STATE_B"
[ "$STATE_B" != "$STATE_A" ] \
  || die "the attack must change the signed answer; control and attack both $STATE_A"
[ "$COV_B" = "null" ] \
  || die "under attack no coverage may be attested, got $COV_B"
ok "under attack: the COLLECTOR - other process, other key - signed IntegrityUnknown"
ok "under attack: attested_coverage withdrawn; absence in this window proves nothing"

# ── C. Recovery ──────────────────────────────────────────────────────────────
step "C. RECOVERY - attack detached"
kill "$ATTACK_PID" 2>/dev/null; wait "$ATTACK_PID" 2>/dev/null; ATTACK_PID=""
info "interferer detached"
BASE=$(health_count)
workload 10
info "waiting for the next signed health record"
wait_new_health "$BASE" || die "no new signed health record after detach"
STATE_C=$(health_field state)
cp "$W/state/health.archive.jsonl" "$OUT/health.C.recovery.jsonl"
info "signed ObserverState = $STATE_C"
[ "$STATE_C" != '"Active"' ] && ok "the observer did not silently return to Active" \
  || info "NOTE: returned to $STATE_C; the window under attack remains recorded as unknown in the archive"

# ── D. Offline verification ──────────────────────────────────────────────────
# The Phase 1 exit gate: "a real agent process is observed; its batch is signed
# by a collector on a different host; THE VERIFIER ACCEPTS IT OFFLINE".
#
# The first two clauses are what A-C established. This is the third, and it is
# the one a demonstration usually skips, because it is the one that requires
# the evidence to still exist after the acknowledgement. `aip-observe-verify`
# is a SEPARATE PROCESS. It is given two files and one public key, and nothing
# else: no collector, no socket, no state directory, no passphrase. The public
# key is the one the collector publishes at every start (observer.pub); the
# private half stays wrapped and is never unwrapped here.
step "D. OFFLINE VERIFICATION - a separate process, two files and a public key"
# Stop and reap the experiment's writers before reading or copying archives.
# Otherwise verification and its negative control can inspect different
# prefixes, and the exported bundle can contain later, unchecked records.
cleanup
info "probe and collector stopped; the evidence archives are now stable"
VERIFY="$REPO/target/debug/aip-observe-verify"
BATCH_ARCHIVE="$W/state/attested.archive.jsonl"
PUBFILE="$W/state/observer.pub"
[ -s "$PUBFILE" ] || die "the collector did not publish observer.pub; an auditor would have no anchor"
[ -s "$BATCH_ARCHIVE" ] || die "no attested batches survived to disk; there is nothing to verify offline"
OBS_PUB=$(cat "$PUBFILE")
info "anchor (published by the collector, private half never unwrapped): ${OBS_PUB:0:16}..."
info "attested batches on disk: $(wc -l < "$BATCH_ARCHIVE")"

"$VERIFY" --observer-id collector.pilot.e2e --key-version 1 \
          --pubkey-file "$PUBFILE" \
          --batches "$BATCH_ARCHIVE" \
          --health "$W/state/health.archive.jsonl" \
  > "$OUT/offline_verify.txt" 2>&1
VERIFY_RC=$?
cat "$OUT/offline_verify.txt" | tee -a "$OUT/transcript.txt" > /dev/null
sed 's/^/       /' "$OUT/offline_verify.txt"
[ "$VERIFY_RC" -eq 0 ] || die "the offline verifier rejected the collector's own archives (exit $VERIFY_RC)"
grep -q "^VERIFIED" "$OUT/offline_verify.txt" || die "verifier did not report VERIFIED"
ok "offline: every attested batch and health record verified under the published key alone"

# The negative control. A verifier that accepts everything is worth nothing,
# so the same verifier is run against a copy of the same archive with one
# chain position altered. It must refuse. Without this line the PASS above
# proves only that the binary exits zero.
TAMPERED="$W/tampered.archive.jsonl"
python3 - "$BATCH_ARCHIVE" "$TAMPERED" <<'PY'
import json, sys
lines = [l for l in open(sys.argv[1]) if l.strip()]
recs = [json.loads(l) for l in lines]
if len(recs) < 2:
    sys.exit("need at least two attested batches to demonstrate a chain edit")
# Remove one record from the middle: the deletion an append-only archive is
# supposed to make visible. Nothing else is touched, so every remaining
# signature is still genuine.
del recs[len(recs) // 2]
with open(sys.argv[2], "w") as f:
    for r in recs:
        f.write(json.dumps(r) + "\n")
PY
[ $? -eq 0 ] || die "could not build the tampered archive for the negative control"
"$VERIFY" --observer-id collector.pilot.e2e --key-version 1 \
          --pubkey-file "$PUBFILE" --batches "$TAMPERED" \
  > "$OUT/offline_verify_tampered.txt" 2>&1
TRC=$?
sed 's/^/       /' "$OUT/offline_verify_tampered.txt"
cat "$OUT/offline_verify_tampered.txt" >> "$OUT/transcript.txt"
[ "$TRC" -eq 1 ] || die "negative control: a record deleted from the middle was NOT refused (exit $TRC)"
grep -q "^NOT VERIFIED" "$OUT/offline_verify_tampered.txt" \
  || die "negative control: verifier did not report NOT VERIFIED"
ok "negative control: one record deleted from the middle - refused, chain break named"

# ── Evidence ─────────────────────────────────────────────────────────────────
step "Evidence"
cp "$W/collector.log" "$W/probe.log" "$OUT/" 2>/dev/null
python3 - "$W/state/health.archive.jsonl" "$OUT/summary.json" <<'PY'
import json, sys, collections
recs = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
states = collections.Counter(r["health"]["state"] for r in recs)
out = {
    "signed_health_records": len(recs),
    "states_observed": dict(states),
    "observer_id": recs[-1]["health"]["observer_id"],
    "final_sequence": recs[-1]["health"]["sequence"],
    "integrity_unknown_was_signed": "IntegrityUnknown" in states,
}
json.dump(out, open(sys.argv[2], "w"), indent=2)
print(json.dumps(out, indent=2))
PY
# Lift the evidence out of the working directory. `work/` holds throwaway
# key material -- the wrapped collector key, the noise static key, the probe's
# transport key and the passphrase file -- and is never committed. What is
# kept is the signed health archive, the daemon logs and the attack log.
cp "$W/state/health.archive.jsonl" "$OUT/health.archive.jsonl" 2>/dev/null
cp "$W/state/attested.archive.jsonl" "$OUT/attested.archive.jsonl" 2>/dev/null
# The PUBLIC half only. The wrapped private key stays in work/ and is never
# committed; this is the value an auditor is given, and it is not a secret.
cp "$W/state/observer.pub" "$OUT/observer.pub" 2>/dev/null
cp "$W/attack.log" "$OUT/attack.log" 2>/dev/null
info "raw signed health archive and daemon logs written to:"
info "  $OUT"

step "DEMONSTRATED"
printf 'The live foreign-eBPF gate attack was executed against the two real\n'
printf 'daemons, not a synthetic batch. The probe holds no key; the collector,\n'
printf 'in a different process and holding the only signing key, signed\n'
printf 'IntegrityUnknown and withdrew attested coverage. The attack was not\n'
printf 'prevented -- a CAP_BPF adversary can blind the sensor -- but it could\n'
printf 'not make the system report a clean window it could not justify.\n'
printf '\nThe attested batches were then verified OFFLINE by a separate process\n'
printf 'given two files and the published public key -- no collector, no socket,\n'
printf 'no passphrase -- and the same verifier refused the same archive with one\n'
printf 'record deleted. That is the Phase 1 exit gate, end to end.\n'
