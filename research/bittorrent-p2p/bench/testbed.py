"""Emulated LAN for distribution experiments (single host, Linux namespaces).

Topology: one "switch" namespace holding a Linux bridge; one namespace per
node (src, p1..pN), each connected to the bridge by a veth pair. Each node's
egress is shaped with a token-bucket filter (tbf) on its veth, emulating its
NIC uplink. The source can be given a faster uplink than the peers.

Nothing touches the host's own namespace interfaces. No route exists from
any node to anything outside 10.77.0.0/24.

Limits of the emulation (stated): all nodes share the host's 2 vCPUs and
memory bus; the bridge itself is unshaped (an ideal switch); latency is the
kernel's (~tens of µs) unless `delay_ms` is set via netem.
"""
from __future__ import annotations

import contextlib
import os
import subprocess
import sys
from dataclasses import dataclass

from pyroute2 import IPRoute, NetNS, netns

PREFIX = "bt"
SUBNET = "10.77.0"


@dataclass
class Node:
    name: str
    ns: str
    ip: str
    rate_mbit: float


def _shape(ns: str, ifname: str, rate_mbit: float, delay_ms: float = 0.0) -> None:
    with NetNS(ns) as n:
        idx = n.link_lookup(ifname=ifname)[0]
        rate = int(rate_mbit * 1_000_000 / 8)  # bytes/s
        # tbf: rate, burst ≈ 10 ms of traffic (≥ 1 MTU), latency bound 50 ms.
        burst = max(1600, rate // 100)
        n.tc("add", "tbf", index=idx, rate=rate, burst=burst, latency=50_000)
        if delay_ms:
            raise NotImplementedError("netem delay not used in iteration 1")


def build(peers: int, peer_mbit: float, src_mbit: float) -> list:
    """Create the topology. Returns [src, p1..pN]."""
    teardown()
    sw = f"{PREFIX}-sw"
    netns.create(sw)
    with NetNS(sw) as s:
        s.link("add", ifname="br0", kind="bridge")
        br = s.link_lookup(ifname="br0")[0]
        s.link("set", index=br, state="up")
        s.link("set", index=s.link_lookup(ifname="lo")[0], state="up")
    nodes = []
    names = ["src"] + [f"p{i}" for i in range(1, peers + 1)]
    for i, name in enumerate(names):
        ns = f"{PREFIX}-{name}"
        netns.create(ns)
        ip = f"{SUBNET}.{i + 1}"
        a, b = f"{name}-n", f"{name}-s"  # node side, switch side
        with IPRoute() as ipr:
            ipr.link("add", ifname=a, kind="veth", peer=b)
            ipr.link("set", index=ipr.link_lookup(ifname=a)[0], net_ns_fd=ns)
            ipr.link("set", index=ipr.link_lookup(ifname=b)[0], net_ns_fd=sw)
        with NetNS(sw) as s:
            idx = s.link_lookup(ifname=b)[0]
            s.link("set", index=idx, master=s.link_lookup(ifname="br0")[0], state="up")
        with NetNS(ns) as n:
            idx = n.link_lookup(ifname=a)[0]
            n.addr("add", index=idx, address=ip, prefixlen=24)
            n.link("set", index=idx, state="up")
            n.link("set", index=n.link_lookup(ifname="lo")[0], state="up")
        rate = src_mbit if name == "src" else peer_mbit
        _shape(ns, a, rate)
        nodes.append(Node(name, ns, ip, rate))
    return nodes


def teardown() -> None:
    for ns in netns.listnetns():
        if ns.startswith(PREFIX + "-"):
            with contextlib.suppress(Exception):
                netns.remove(ns)


def spawn(node: Node, argv: list, **kw) -> subprocess.Popen:
    """Run argv inside the node's namespace via a tiny setns trampoline."""
    tramp = [sys.executable, "-I", "-c",
             "import sys,os; from pyroute2 import netns; netns.setns(sys.argv[1]); os.execvp(sys.argv[2], sys.argv[2:])",
             node.ns] + argv
    return subprocess.Popen(tramp, **kw)


def tx_bytes(node: Node) -> int:
    """Bytes the node has sent on its LAN interface (kernel counter)."""
    with NetNS(node.ns) as n:
        link = n.get_links(n.link_lookup(ifname=f"{node.name}-n")[0])[0]
        return link.get_attr("IFLA_STATS64")["tx_bytes"]


if __name__ == "__main__":
    # Smoke test: build, ping-equivalent TCP check, tear down.
    ns = build(peers=2, peer_mbit=100, src_mbit=100)
    p = spawn(ns[1], [sys.executable, "-I", "-c", f"import socket; s=socket.create_connection(('{ns[0].ip}', 9), timeout=2)"],
              stderr=subprocess.PIPE)
    p.wait()
    print("connect to src:9 ->", "refused (route ok)" if b"Refused" in p.stderr.read() else "other")
    q = spawn(ns[1], [sys.executable, "-I", "-c", "import socket; socket.create_connection(('1.1.1.1', 443), timeout=2)"],
              stderr=subprocess.PIPE)
    q.wait()
    print("external route:", "absent" if b"unreachable" in q.stderr.read().lower() else "PRESENT?")
    teardown()
    print("namespaces left:", [n for n in netns.listnetns() if n.startswith(PREFIX)])
