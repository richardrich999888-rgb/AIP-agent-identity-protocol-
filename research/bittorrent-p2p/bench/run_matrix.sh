#!/usr/bin/env bash
# Full experiment matrix. Deterministic payload (seed 7). Results: results/matrix/*.json
set -u
OUT=${1:-results/matrix}; mkdir -p "$OUT"
B="python3 -W ignore bench/bench.py"
for rep in 1 2 3; do
  for src in 100 500; do
    for m in http_plain http_range bittorrent; do
      f=$OUT/${m}_256_src${src}_r${rep}.json; [ -s "$f" ] || timeout 900 $B "$f" --method $m --size-mib 256 --src-mbit $src --timeout 800
    done
  done
done
for m in http_plain http_range bittorrent; do  # size and peer-count variation
  f=$OUT/${m}_64_src100_r1.json; [ -s "$f" ] || timeout 600 $B "$f" --method $m --size-mib 64 --timeout 500
  f=$OUT/${m}_256_src100_p3_r1.json; [ -s "$f" ] || timeout 900 $B "$f" --method $m --size-mib 256 --peers 3 --timeout 800
  f=$OUT/${m}_128_kill_restart.json; [ -s "$f" ] || timeout 900 $B "$f" --method $m --size-mib 128 --kill p2@0.5 --restart --timeout 800
done
f=$OUT/bittorrent_128_corrupt.json; [ -s "$f" ] || timeout 900 $B "$f" --method bittorrent --size-mib 128 --corrupt p1 --timeout 800
echo MATRIX_DONE
