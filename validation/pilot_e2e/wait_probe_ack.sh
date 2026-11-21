#!/usr/bin/env bash
# Operational readiness only. The full signed-health and offline evidence
# checks remain mandatory; an authenticated transport ACK is not their substitute.
wait_probe_ack() {
  local probe_pid="$1" probe_log="$2" attempts="${3:-120}" round
  [[ "$probe_pid" =~ ^[1-9][0-9]*$ ]] || return 1
  [[ "$attempts" =~ ^[1-9][0-9]{0,3}$ ]] || return 1
  (( attempts <= 1200 )) || return 1
  for ((round=0; round<attempts; round++)); do
    kill -0 "$probe_pid" 2>/dev/null || return 1
    if grep -Eq '^aip-probe: batch acked \(frame seq [1-9][0-9]*, attested_sequence [1-9][0-9]*\)$' "$probe_log" 2>/dev/null; then
      kill -0 "$probe_pid" 2>/dev/null
      return $?
    fi
    sleep 0.25
  done
  return 1
}
