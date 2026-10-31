# Distribution benchmark — reproduction

Requirements: Linux, root (network namespaces), Python 3.13, pyroute2 0.9.7,
libtorrent 2.1.1 Python bindings, openssl CLI. Work dir: `$BENCH_WORK`
(default `/home/claude/vanian-build/btwork`). Run from `research/bittorrent-p2p/`.

```sh
python3 bench/testbed.py                       # smoke: topology, no external route
bench/run_matrix.sh results/matrix             # iteration 1-3 matrix (libtorrent default disk queue
                                               #  at the time; bt_node.py now defaults to 4 MiB:
                                               #  set BT_MAX_QUEUED_DISK_BYTES=104857600 to reproduce)
B="python3 -W ignore bench/bench.py"; O=results/matrix_q4   # bounded queue (current default)
$B $O/bittorrent_128_kill_restart.json --method bittorrent --size-mib 128 --kill p2@0.5 --restart
$B $O/bittorrent_128_corrupt.json      --method bittorrent --size-mib 128 --corrupt p1
for r in 1 2 3; do $B $O/bittorrent_256_src100_r$r.json --method bittorrent --size-mib 256 --src-mbit 100; done
$B $O/bittorrent_256_src500_r1.json    --method bittorrent --size-mib 256 --src-mbit 500
O=results/authz                                # iteration 4
$B $O/control_nossl_intruder_p3.json   --method bittorrent --size-mib 64 --peers 3 --intruder p3
for k in rogue wrongscope; do $B $O/ssl_${k}_intruder_p3.json --method bittorrent --size-mib 64 --peers 3 --ssl --intruder p3 --intruder-kind $k; done
$B $O/ssl_no_intruder.json             --method bittorrent --size-mib 64 --peers 3 --ssl
python3 bench/summarize.py results/matrix results/matrix_q4 results/authz
```
