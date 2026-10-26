#!/usr/bin/env bash
# The RBI evaluation session, end to end.
#
# WHY THIS EXISTS
# ---------------
# Section 14 of the technical brief commits us, in writing, to demonstrating
# five things to people whose job is to break them:
#
#   1. the honest path
#   2. an interfered-with observer
#   3. a refused unregistered destination
#   4. a mis-parameterised tool call against a signed receipt
#   5. offline verification performed by your side with keys you hold
#
# Promising a live demonstration we have not rehearsed end to end is the
# highest-risk item in the engagement: every other open item is a document, and
# this one fails in the room. This script is the rehearsal, and its transcript
# is the evidence that the rehearsal happened.
#
# HONESTY ABOUT WHAT EACH ACT IS
# ------------------------------
# Acts 1, 2 and 5 are a FULL-SYSTEM run: two real daemons in separate
# processes, a real kernel, a real foreign-eBPF attack, and an offline verifier
# given two files and a public key. Acts 3 and 4 are LIBRARY-LEVEL: the
# decision point and the tool boundary are libraries, exercised here through
# their own test suites against genuinely signed documents. The transcript
# labels each one, because presenting a library test as a system demonstration
# is the kind of thing this whole programme exists not to do.
#
# Usage: validation/rbi_demo/run.sh [outdir]
#        AIP_DEMO_SKIP_SYSTEM=1  skip acts 1/2/5 (no root or no tracefs)
set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
OUT="${1:-$HERE/results/$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT" || exit 1
OUT=$(cd "$OUT" && pwd) || exit 1
T="$OUT/transcript.txt"

act()  { printf '\n\033[36m== %s\033[0m\n' "$*" | tee -a "$T"; }
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$*" | tee -a "$T"; }
info() { printf '       %s\n' "$*" | tee -a "$T"; }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$*" | tee -a "$T"; }
promise() { printf '       brief §14 promises: "%s"\n' "$*" | tee -a "$T"; }

FAILED=0
note_fail() { FAILED=$((FAILED+1)); bad "$*"; }

{ echo "RBI evaluation session — rehearsal transcript"; date -u +"%Y-%m-%dT%H:%M:%SZ";
  uname -a; echo "repo $(git -C "$REPO" rev-parse --short HEAD)"; } > "$T"

act "PRECONDITIONS — check these on the ACTUAL demo host, not only here"
# Found by the first rehearsal. The observer is designed to withhold coverage
# when it cannot vouch for a window, and an unsynchronised clock is one such
# reason: the collector stamps and signs every attested batch, so its clock
# discipline is the accuracy of all of it. On a host without NTP the honest
# path therefore shows IntegrityUnknown rather than Active -- correct
# behaviour, and a terrible thing to discover live in front of the Department,
# where it costs the session explaining clocks instead of showing
# accountability.
# A running time daemon is not evidence of synchronisation. Query the machine
# property, requiring both a successful query and an exact affirmative value.
# Missing/unusable evidence stays unknown; it must never become a PASS.
CLOCK_STATE=unknown
if command -v timedatectl >/dev/null 2>&1; then
  if CLOCK_SYNC=$(LC_ALL=C timedatectl show --property=NTPSynchronized --value 2> "$OUT/clock.log"); then
    printf 'NTPSynchronized=%s\n' "$CLOCK_SYNC" >> "$OUT/clock.log"
    case "$CLOCK_SYNC" in
      yes) CLOCK_STATE=synchronised ;;
      no)  CLOCK_STATE=unsynchronised ;;
    esac
  else
    info "clock query failed; see clock.log"
  fi
else
  info "clock query unavailable: timedatectl is missing"
fi
if [ "$CLOCK_STATE" = "synchronised" ]; then
  ok "clock: synchronised (timedatectl NTPSynchronized=yes)"
else
  info "clock: $CLOCK_STATE; synchronisation has not been established."
  info "Without synchronisation, the observer can withhold attested coverage."
  info "Unknown here means missing evidence, not proof that the clock is wrong."
  info "FIX before the session: check chrony (deploy/pilot/chrony-cert-in.conf)"
  info "and the timedatectl query. Re-run until Act 1 reports Active."
  note_fail "clock precondition not met on this host"
fi
[ -r /sys/kernel/tracing/available_events ] || mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null
if [ -r /sys/kernel/tracing/available_events ]; then
  ok "tracefs available (the perf sensors can open)"
else
  note_fail "tracefs unavailable — the kernel sensors cannot open on this host"
fi
[ "$(id -u)" -eq 0 ] && ok "running as root" || note_fail "not root; the kernel sensors need privilege"

act "Build"
# Branch on the build command's exit status, never on its diagnostic text.
# In particular, pipefail + grep can hide a Cargo failure from an && handler.
if ( cd "$REPO" && CARGO_INCREMENTAL=0 cargo build -q \
    -p aip-probe -p aip-collector -p aip-observe-verify ) >> "$OUT/build.log" 2>&1; then
  ok "daemons and offline verifier built"
else
  BUILD_STATUS=$?
  note_fail "build failed (exit $BUILD_STATUS); see build.log"
  exit 1
fi

# ── Acts 1, 2 and 5: the full-system run ─────────────────────────────────
if [ "${AIP_DEMO_SKIP_SYSTEM:-0}" = "1" ]; then
  act "ACTS 1, 2 and 5 — SKIPPED by request (AIP_DEMO_SKIP_SYSTEM=1)"
  info "These are the full-system acts. Skipping them means the session has"
  info "NOT been rehearsed end to end. Do not present this transcript as one."
  SYSTEM_RUN="skipped"
else
  act "ACTS 1, 2 and 5 — full-system run (two daemons, live kernel, live attack)"
  promise "the honest path, an interfered-with observer ... and offline verification"
  info "running validation/pilot_e2e/run.sh: control -> attack -> recovery -> offline verify"
  if AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK=1 timeout 900 bash "$REPO/validation/pilot_e2e/run.sh" "$OUT/system" \
       > "$OUT/system_run.log" 2>&1 \
     && python3 "$HERE/check_control.py" "$OUT/system/health.A.control.jsonl" \
       > "$OUT/control_check.log" 2>&1; then
    SYSTEM_RUN="pass"
    grep -E "PASS|DEMONSTRATED" "$OUT/system_run.log" | sed 's/^/       /' | tee -a "$T" >/dev/null
    SYSTEM_CHECKS=$(grep -cE "PASS" "$OUT/system_run.log")
    info "$SYSTEM_CHECKS checks passed in the system run"
    ok "Act 1 honest path: observer Active, attested coverage present"
    ok "Act 2 interfered observer: collector signed IntegrityUnknown, coverage withdrawn"
    ok "Act 5 offline verification: separate process, two files, a public key"
  else
    SYSTEM_RUN="fail"
    note_fail "the full-system RBI requirements did not pass — see system_run.log and control_check.log"
    tail -20 "$OUT/system_run.log" | sed 's/^/       /' | tee -a "$T" >/dev/null
  fi
fi

# ── Act 3: a destination the institution never named ─────────────────────
act "ACT 3 — a refused unregistered destination (library-level)"
promise "a refused unregistered destination"
info "The decision point resolves every network destination against a registry"
info "the institution's infrastructure owner SIGNED. An address that registry"
info "never named is denied outright — DestinationUnregistered is a denial,"
info "never a pass-through."
if ( cd "$REPO" && cargo test -p aip-authorize --test resources 2>&1 ) \
     > "$OUT/act3_destination.log" 2>&1; then
  A3=$(grep -cE "^test .* ok$" "$OUT/act3_destination.log")
  grep -E "^test (an_address_the_institution_never_named|the_right_host_on_an_unnamed_port|a_named_resource_the_chain_never_granted)" \
    "$OUT/act3_destination.log" | sed 's/^/       /' | tee -a "$T" >/dev/null
  ok "Act 3: $A3 resource-scoping assertions hold, including outright refusal of an unnamed address"
else
  note_fail "Act 3 assertions did not hold"
  tail -15 "$OUT/act3_destination.log" | sed 's/^/       /' | tee -a "$T" >/dev/null
fi

# ── Act 4: a mis-parameterised tool call ─────────────────────────────────
act "ACT 4 — a mis-parameterised tool call against a signed receipt (library-level)"
promise "a mis-parameterised tool call against a signed receipt"
info "The decision point seals the digest of the AUTHORISED arguments. The"
info "gateway signs a receipt over its own recomputation of what it RECEIVED."
info "The two are compared. The decisive property: the finding stands with the"
info "agent's own claim ABSENT from the evidence."
if ( cd "$REPO" && cargo test -p aip-mcp-gateway 2>&1 ) > "$OUT/act4_toolcall.log" 2>&1; then
  A4=$(grep -cE "^test .* ok$" "$OUT/act4_toolcall.log")
  grep -E "^test (a_misparameterised_call_diverges|the_authorised_call_agrees|a_receipt_signed_under_the_agents_key|key_order_does_not)" \
    "$OUT/act4_toolcall.log" | sed 's/^/       /' | tee -a "$T" >/dev/null
  ok "Act 4: $A4 tool-boundary assertions hold, including divergence with no agent claim in evidence"
else
  note_fail "Act 4 assertions did not hold"
  tail -15 "$OUT/act4_toolcall.log" | sed 's/^/       /' | tee -a "$T" >/dev/null
fi

# ── Act 4b: the gateway is a real program, not only a format ─────────────
act "ACT 4b — the gateway signing a receipt, live"
GW="$REPO/target/debug/aip-mcp-gateway"
run_gateway_demo() {
  if ( cd "$REPO" && cargo build -q -p aip-mcp-gateway ) >> "$OUT/build.log" 2>&1; then
    [ -x "$GW" ] || { info "gateway executable is missing"; return 1; }
  else
    info "gateway build failed (exit $?); see build.log"
    return 1
  fi
  KEY=$(python3 -c "import secrets;print(secrets.token_hex(32))") || return 1
  RCPT="$OUT/receipts.jsonl"
  : > "$RCPT" || return 1
  if printf '%s\n' \
    '{"jsonrpc":"2.0","id":1,"method":"tools/call","authorization":{"agent_id":"agent.demo","decision_id":"07070707070707070707070707070707"},"params":{"name":"banking.transfer","arguments":{"amount":500,"beneficiary":"acct-9"}}}' \
    '{"jsonrpc":"2.0","id":2,"method":"tools/call","authorization":{"agent_id":"agent.demo","decision_id":"07070707070707070707070707070707"},"params":{"name":"banking.transfer","arguments":{"amount":5000000,"beneficiary":"acct-mule"}}}' \
  | env AIP_GATEWAY_KEY="$KEY" AIP_GATEWAY_ID=gateway.demo AIP_GATEWAY_RECEIPTS="$RCPT" \
      timeout 30 "$GW" > "$OUT/act4b_gateway.out" 2> "$OUT/act4b_gateway.err"; then
    :
  else
    info "gateway execution failed (exit $?); see act4b_gateway.err"
    return 1
  fi
  # Parse through argv, not interpolated Python source: output paths may contain
  # quotes. Failed parsing or equal commitments must never be followed by PASS.
  python3 - "$RCPT" >> "$T" 2> "$OUT/act4b_receipt_check.err" <<'PY'
import json, sys
records = [json.loads(line)["receipt"] for line in open(sys.argv[1]) if line.strip()]
if len(records) != 2:
    sys.exit(f"expected exactly 2 receipts, got {len(records)}")
commitments = []
for i, receipt in enumerate(records, 1):
    value = receipt["parameter_commitment"]
    commitment = bytes(value) if isinstance(value, list) else bytes.fromhex(value)
    if len(commitment) != 32:
        sys.exit("parameter commitment must be 32 bytes")
    commitments.append(commitment)
    print(f"       receipt {i}: tool={receipt['tool_id']} gateway={receipt['gateway_id']} commitment={commitment.hex()[:24]}...")
if commitments[0] == commitments[1]:
    sys.exit("the two calls produced the same commitment")
PY
}
if run_gateway_demo; then
  info "the two calls committed to DIFFERENT parameters — which is what the"
  info "decision point's sealed digest is compared against"
  ok "Act 4b: the gateway signed a receipt per call, live, with its own key"
else
  note_fail "Act 4b failed; see build.log, act4b_gateway.err and act4b_receipt_check.err"
fi

# ── Result ───────────────────────────────────────────────────────────────
act "SESSION REHEARSAL RESULT"
{
printf 'Brief §14 promises five demonstrations. This run covered:\n\n'
printf '  1. the honest path .......................... %s (full system)\n' "$SYSTEM_RUN"
printf '  2. an interfered-with observer .............. %s (full system)\n' "$SYSTEM_RUN"
printf '  3. a refused unregistered destination ....... see Act 3 (library)\n'
printf '  4. a mis-parameterised tool call ............ see Act 4 / 4b\n'
printf '  5. offline verification by your side ........ %s (full system)\n' "$SYSTEM_RUN"
printf '\nActs 3 and 4 are library-level and are labelled as such. The decision\n'
printf 'point and the tool boundary are libraries; the institution integrates\n'
printf 'them (blockers B9 and B10). Presenting them as a system demonstration\n'
printf 'would misrepresent what was shown.\n'
} | tee -a "$T"

if [ "$FAILED" -eq 0 ] && [ "$SYSTEM_RUN" = "pass" ]; then
  ok "REHEARSED: all five promises demonstrated in one run"
  exit 0
fi
bad "$FAILED check(s) failed; system run: $SYSTEM_RUN — the session is NOT rehearsed"
exit 1
