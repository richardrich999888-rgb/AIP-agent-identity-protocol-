# AIRON Bare-Metal Stress Lab

This runbook defines the physical validation lab required before making
line-rate, native-XDP, or 10/40 GbE banking claims.

## Topology

Use two physical Linux servers connected directly by a 10 GbE or 40 GbE DAC.
Do not place a switch, Docker bridge, cloud hypervisor, or Wi-Fi link between
the traffic generator and the AEGIS gateway.

| Role | Purpose | Minimum profile |
| --- | --- | --- |
| Server A: traffic generator | Runs Cisco TRex or Linux pktgen and emits packet floods | Linux, DPDK-capable NIC, isolated cores |
| Server B: AEGIS gateway | Runs `aegis-quantum-ebpf`, userspace controller, `bpftool`, and `stress-ng` | Linux 6.x, CAP_BPF/CAP_NET_ADMIN, native-XDP NIC |

Recommended native-XDP NIC families:

- Intel X710/XL710 (`i40e`)
- Intel E810 (`ice`)
- Mellanox/NVIDIA ConnectX-4/5/6 (`mlx5_core`)
- Intel 82599/X520/X540/X550 (`ixgbe`)

Generic XDP/SKB mode is acceptable for functional validation, but it is not
acceptable evidence for the p99 latency or line-rate claims in the banking
pilot dossier.

## Readiness Checks

On the AEGIS gateway:

```bash
cd aegis-quantum
sudo python3 stress-tests/run_live_fire_readiness.py \
  --role gateway \
  --iface <direct-dac-nic>
```

On the traffic-generator server:

```bash
cd aegis-quantum
sudo python3 stress-tests/run_live_fire_readiness.py \
  --role traffic-generator \
  --iface <direct-dac-nic>
```

The report is written to `pilot-results/live_fire_readiness_report.json`.

## Execution Gates

| Gate | Tool | Evidence |
| --- | --- | --- |
| Host readiness | `run_live_fire_readiness.py` | OS, NIC, driver, `bpftool`, `stress-ng`, TRex/pktgen readiness |
| Kernel load | `make build-ebpf`, `bpftool` | XDP bytecode builds, maps visible, program attached in driver mode |
| Functional packet proof | `validation/validate_xdp.py --live-fire` | pass/drop behavior on real interface |
| Host starvation | `run_chaos_suite.py --live` + `stress-ng` | maps remain inspectable; controller degrades without deadlock |
| Line-rate flood | Cisco TRex or pktgen | p50/p95/p99 latency, packet loss, `XDP_DROP`/`XDP_PASS` counters |

## Mac/Vagrant Functional Chaos

The Vagrant topology is useful for functional chaos tests, not speed claims.

```bash
cd aegis-quantum
make vagrant-up
make vagrant-chaos
```

The attacker VM runs `infra/vagrant/semantic_loop_injector.py` against the
gateway VM. This verifies semantic-loop injection and noisy-neighbor behavior
inside Linux VMs, but hypervisor overhead prevents valid 10 Gbps conclusions.

## AIP Identity Load

AIP HTTP stress testing does not require the two-server NIC lab. Use the Locust
profile in `aip-service/load-tests/` for issue, verify, delegation, chain
verification, and cascade revocation load.

```bash
make aip-load-locust USERS=500 SPAWN_RATE=50 RUN_TIME=5m
```

For a 50,000-concurrent-user result, run Locust distributed across dedicated
load-generator hosts and keep the AIP service host separate from the load
generation host.

## Claim Boundary

Passing local Rust tests, Vagrant packet injection, and readiness checks supports
TRL-5 functional validation. It does not support wire-speed, 10/40 GbE, or
TRL-7/8 operational claims until the bare-metal line-rate gates above are run
and the latency histograms are attached to the dossier.
