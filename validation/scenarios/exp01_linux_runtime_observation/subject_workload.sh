#!/usr/bin/env bash
#
# subject_workload.sh — the SUBJECT under observation.
#
# An autonomous-agent-shaped Linux workload: it spawns children, execs
# binaries, writes files, and — like a real agent — keeps its own log of what
# it believes it did.
#
# That log is the SELF-REPORT. It is the actor's account of the actor. The
# whole point of Experiment 1 is that it is not evidence, and that Vanian must
# treat it as a claim to be checked rather than a fact to be recorded.
#
# So it lies, deliberately and in named ways:
#
#   FABRICATED  — it claims an exec that never happened. No kernel event
#                 exists for it. Sniffer Dog must not corroborate it.
#   SUPPRESSED  — it performs an exec and omits it from the log. The kernel
#                 saw it. Sniffer Dog must report it despite the silence.
#   MISREPORTED — it performs an exec and logs a different binary. The two
#                 accounts must be detected as disagreeing.
#   TRUTHFUL    — ordinary execs, logged accurately. The baseline.
#
# The lies are in the LOG only. Nothing here attacks the kernel, the observer,
# or the host. This is a workload that misreports itself, which is the threat
# Vanian's independence claim is about.
#
# Usage: subject_workload.sh <self_report_path>

set -euo pipefail

REPORT=${1:?usage: subject_workload.sh <self_report_path>}
: > "$REPORT"

# The subject stamps its own claims. It has no trusted clock and no signing
# key, which is the point: these are assertions, not attestations.
claim() {
  printf '{"claim_seq":%d,"subject_pid":%d,"subject_monotonic_ns":%d,"kind":"%s","filename":"%s","note":"%s"}\n' \
    "$((++SEQ))" "$$" "$(date +%s%N)" "$1" "$2" "$3" >> "$REPORT"
}
SEQ=0

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

echo "subject: pid=$$ workdir=$WORKDIR report=$REPORT"

# ── TRUTHFUL ────────────────────────────────────────────────────────────────
# Executed and logged. Both accounts should contain these.
/bin/true
claim exec /bin/true TRUTHFUL

/bin/echo "agent-step-1" > "$WORKDIR/step1.out"
claim exec /bin/echo TRUTHFUL

/usr/bin/head -c 16 /dev/zero > "$WORKDIR/step2.out"
claim exec /usr/bin/head TRUTHFUL

# ── SUPPRESSED ──────────────────────────────────────────────────────────────
# Executed and NOT logged. The kernel saw /usr/bin/wc run; the subject's
# account is silent. An observer that only reads the subject's log misses it
# entirely. Sniffer Dog must not.
/usr/bin/wc -c < "$WORKDIR/step2.out" > "$WORKDIR/step3.out"

# ── MISREPORTED ─────────────────────────────────────────────────────────────
# /usr/bin/basename runs; the subject logs /usr/bin/dirname. Both accounts
# contain an exec at roughly this point and they name different binaries.
/usr/bin/basename /tmp/x >/dev/null
claim exec /usr/bin/dirname MISREPORTED

# ── FABRICATED ──────────────────────────────────────────────────────────────
# Nothing runs. The subject claims /usr/bin/sha256sum executed. No kernel
# event exists. Corroborating this would be a fabrication accepted as fact.
claim exec /usr/bin/sha256sum FABRICATED

# ── TRUTHFUL tail, with a child ─────────────────────────────────────────────
( /bin/sleep 0.05 ) &
CHILD=$!
claim spawn /bin/sleep TRUTHFUL
wait $CHILD

echo "subject: complete, $SEQ claims written"
