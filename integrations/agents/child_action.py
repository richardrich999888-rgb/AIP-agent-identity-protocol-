#!/usr/bin/env python3
"""The child sub-agent — a real, separate OS process the observer must see.

This is deliberately its own executable rather than a function call inside the
parent, because the whole point of the observation is that the kernel reports a
`fork` + `exec` pair (netlink connector) and an exec tracepoint sample (perf)
for a distinct process. A thread or a function call would produce neither, and
the parent → child lineage Phase 3 attributes rests on this being a real exec.

It performs exactly two consequential effects, both chosen because the
kernel-side observer can see them without reading any application payload:

  1. a file write to a marked path (visible to fanotify, and as a process the
     tracepoints see executing);
  2. one outbound TCP connect (visible to the socket-state tracepoint and the
     AF_PACKET header tap as metadata — never content).

It prints its own pid so the harness can confirm the observed exec is this
process and not something else on the host.
"""

from __future__ import annotations

import os
import socket
import sys


def main() -> int:
    marked_path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/aip_agent_child_marker"
    host = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 9

    print(f"CHILD pid={os.getpid()} ppid={os.getppid()}", flush=True)

    # (1) The file write. Content is irrelevant to the observer; the act is
    # what is observed.
    with open(marked_path, "w", encoding="utf-8") as f:
        f.write(f"written by child pid {os.getpid()}\n")

    # (2) One outbound TCP connect. A short timeout because the point is the
    # connect attempt (SYN), which the socket-state tracepoint records
    # regardless of whether anything is listening.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.3)
    try:
        s.connect((host, port))
        s.send(b"x")
    except OSError:
        # Refused/timed out is fine: the connect was attempted, which is the
        # observable act.
        pass
    finally:
        s.close()

    print(f"CHILD done pid={os.getpid()}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
