#!/usr/bin/env bash
# Install a SYNTRIASS bundle on an air-gapped single node.
#
#   usage: install.sh BUNDLE_DIR PREFIX STATE_DIR PROFILE [LARGE_MODEL_FILE]
#     PROFILE: memory | balanced | speed | none
#
# Fail-closed steps (any failure aborts; nothing is left half-activated):
#   1. refuse if this host has a default route (not air-gapped);
#   2. verify every bundle file against SHA256SUMS;
#   3. check python3 + numpy for the sidecar;
#   4. copy into PREFIX/releases/<commit>/ and atomically repoint
#      PREFIX/current (the previous release stays for rollback);
#   5. create STATE_DIR (0700) and config.json (0600) if absent — an existing
#      state directory (corpus, capabilities, audit log) is never modified;
#   6. run `syntriass health`; exit status is its verdict.
# Binary rollback: ln -sfn PREFIX/releases/<previous> PREFIX/current.tmp && mv -T PREFIX/current.tmp PREFIX/current
set -euo pipefail
[[ $# -ge 4 ]] || { sed -n 2,5p "$0" >&2; exit 2; }
B=$(cd "$1" && pwd); mkdir -p "$2"; PREFIX=$(cd "$2" && pwd); STATE=$3; PROFILE=$4; LARGE=${5:-}
die() { echo "install: $*" >&2; exit 1; }

if awk 'NR>1 && $1!="lo" && $2=="00000000" && $8=="00000000" {f=1} END {exit !f}' /proc/net/route 2>/dev/null; then
  die "default route present: this host is not air-gapped (refusing)"
fi
(cd "$B" && sha256sum --quiet -c SHA256SUMS) || die "bundle integrity check failed"
python3 -c 'import sys, numpy; assert sys.version_info >= (3, 10)' 2>/dev/null || die "python3 >= 3.10 with numpy required for the sidecar"
case "$PROFILE" in memory|balanced|speed|none) ;; *) die "unknown profile $PROFILE";; esac

commit=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["git_commit"])' "$B/MANIFEST.json")
REL="$PREFIX/releases/$commit"
if [[ ! -d "$REL" ]]; then
  mkdir -p "$PREFIX/releases"
  cp -al "$B" "$REL.partial" 2>/dev/null || { rm -rf "$REL.partial"; cp -a "$B" "$REL.partial"; }  # hard links on the same filesystem
  (cd "$REL.partial" && sha256sum --quiet -c SHA256SUMS) || die "copy verification failed"
  mv -T "$REL.partial" "$REL"
fi
ln -sfn "$REL" "$PREFIX/current.tmp" && mv -T "$PREFIX/current.tmp" "$PREFIX/current"
CUR=$(cd "$PREFIX/current" && pwd -P)

model_ref() {  # file-name-substring → {"path","sha256"} from MANIFEST
  python3 -I -c 'import json,sys
m=json.load(open(sys.argv[1]))["models"]; hit=[x for x in m if sys.argv[2] in x["file"]]
print(json.dumps({"path": sys.argv[3]+"/"+hit[0]["file"], "sha256": hit[0]["sha256"]}) if hit else "null")' "$CUR/MANIFEST.json" "$1" "$PREFIX/current"
}
umask 077
mkdir -p "$STATE"; chmod 0700 "$STATE"
if [[ ! -e "$STATE/config.json" ]]; then
  q4=$(model_ref q4_k_m); q8=$(model_ref q8_0)
  [[ "$q4" != null && "$q8" != null ]] || die "bundle must contain a q4_k_m and a q8_0 model"
  large=null; [[ -n "$LARGE" ]] && large=$(model_ref "$LARGE")
  cat > "$STATE/config.json" <<EOF
{"state": "$(cd "$STATE" && pwd)", "policy_version": "UNSET", "security_domain": "UNSET", "rag_k": 3,
 "approvers": {}, "experts": {},
 "python": "$(command -v python3)", "sidecar_script": "$PREFIX/current/share/research/system-one/harness/sidecar.py",
 "llama_server": "$PREFIX/current/bin/llama-server", "profile": "$PROFILE", "port": 8301,
 "q4": $q4, "q8": $q8, "large": $large}
EOF
  chmod 0600 "$STATE/config.json"
  echo "install: wrote $STATE/config.json — set policy_version, security_domain, approver and expert public keys before use" >&2
fi
exec "$PREFIX/current/bin/syntriass" health --config "$STATE/config.json"
