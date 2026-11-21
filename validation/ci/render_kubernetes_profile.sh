#!/usr/bin/env bash
# Render only. These inert fixture images are never pulled or installed.
set -euo pipefail
chart="$(cd "$(dirname "$0")/../.." && pwd)/deploy/enterprise/kubernetes/chart"
case "${1:-}" in
  collector)
    settings=(--set collector.enabled=true
      --set-string "collector.image=registry.example.invalid/vanian/collector@sha256:1111111111111111111111111111111111111111111111111111111111111111"
      --set-string collector.configMap=collector-env-fixture
      --set-string collector.allowListConfigMap=collector-allow-list-fixture
      --set-string collector.passphraseSecret=collector-secret-reference-fixture)
    ;;
  host-probe)
    settings=(--set probe.enabled=true
      --set-string "probe.image=registry.example.invalid/vanian/probe@sha256:0000000000000000000000000000000000000000000000000000000000000000"
      --set-string probe.configMap=probe-env-fixture)
    ;;
  *) echo "usage: $0 {collector|host-probe}" >&2; exit 2 ;;
esac
helm lint --strict "$chart" --set confirmSeparateAdministration=true "${settings[@]}" >&2
helm template vanian-runtime "$chart" --set confirmSeparateAdministration=true "${settings[@]}"
