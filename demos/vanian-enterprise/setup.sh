#!/usr/bin/env bash
# Build or fetch every pinned tool into $LAB. Idempotent. Each pin is checked; a mismatch stops.
source "$(dirname "$0")/lib.sh"
"$HERE/check.sh"
mkdir -p "$BIN" "$RUNS"
if [ ! -e /sys/kernel/tracing/trace_pipe ]; then
  mount -t tracefs nodev /sys/kernel/tracing && log "mounted tracefs (not persistent across reboot)"
fi
log "building probe, collector and verifier (release, --locked)"
( cd "$REPO" && cargo build -q --release --locked -p aip-probe -p aip-collector -p aip-observe-verify )
if [ ! -x "$BIN/opa" ]; then
  log "building OPA $OPA_VERSION through the Go module proxy"
  GOBIN="$BIN" GOTOOLCHAIN=auto go install "github.com/open-policy-agent/opa@$OPA_VERSION"
fi
got=$(go version -m "$BIN/opa" | awk '$1=="mod" && $2=="github.com/open-policy-agent/opa" {print $4}')
[ "$got" = "$OPA_MODULE_H1" ] || die "OPA module hash $got != pinned $OPA_MODULE_H1"
log "ok OPA module hash matches the pin"
if [ ! -x "$VENV/bin/python" ]; then
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install -q -r "$LITELLM_LOCK"
fi
"$VENV/bin/python" -c 'import importlib.metadata as m; assert m.version("litellm") == "1.110.2", m.version("litellm")' \
  || die "litellm is not the pinned 1.110.2"
if "$VENV/bin/python" -c 'import importlib.util,sys; sys.exit(0 if importlib.util.find_spec("litellm_enterprise") else 1)'; then
  die "litellm_enterprise is installed (proprietary; item 1.3 rule)"
fi
log "ok litellm 1.110.2 core, no enterprise package"
log "setup complete: $LAB"
