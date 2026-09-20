#!/usr/bin/env python3
"""Functional packet injector for the Vagrant AEGIS attacker node.

This is a VM-safe semantic-loop test, not a line-rate benchmark. It uses Scapy
to emit a rogue SYN burst plus optional legitimate traffic against the gateway.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Inject AEGIS semantic-loop traffic with Scapy.")
    parser.add_argument("--target", default="192.168.56.10", help="Gateway IP address.")
    parser.add_argument("--rogue-port", type=int, default=8443)
    parser.add_argument("--legit-port", type=int, default=443)
    parser.add_argument("--count", type=int, default=10_000, help="Rogue SYN packet count.")
    parser.add_argument("--legit-count", type=int, default=100, help="Legitimate SYN packet count.")
    parser.add_argument("--iface", default="eth1", help="Private-network interface inside the VM.")
    parser.add_argument("--inter", type=float, default=0.0, help="Inter-packet delay for Scapy send().")
    parser.add_argument("--output", type=Path, help="Optional JSON summary output path.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        from scapy.all import IP, TCP, conf, send
    except ImportError as exc:
        raise SystemExit(f"Scapy is required on the attacker node: {exc}") from exc

    conf.iface = args.iface
    started = time.perf_counter()

    rogue_packets = [
        IP(dst=args.target) / TCP(sport=20_000 + (idx % 40_000), dport=args.rogue_port, flags="S")
        for idx in range(args.count)
    ]
    send(rogue_packets, verbose=False, inter=args.inter)

    legit_packets = [
        IP(dst=args.target) / TCP(sport=10_000 + (idx % 10_000), dport=args.legit_port, flags="S")
        for idx in range(args.legit_count)
    ]
    send(legit_packets, verbose=False, inter=args.inter)

    duration_ms = int((time.perf_counter() - started) * 1000)
    report = {
        "suite": "aegis-vagrant-semantic-loop",
        "target": args.target,
        "iface": args.iface,
        "rogue": {
            "port": args.rogue_port,
            "packets_sent": args.count,
        },
        "legitimate": {
            "port": args.legit_port,
            "packets_sent": args.legit_count,
        },
        "duration_ms": duration_ms,
        "claim_boundary": "Functional Vagrant packet injection only; not line-rate or native-XDP latency evidence.",
    }

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
