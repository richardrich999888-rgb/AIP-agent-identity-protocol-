#!/usr/bin/env python3
"""Run a bounded command while four threads churn synthetic loopback sockets.

This measures command stability under churn, not an agent capture rate or an
independent administrative domain. Child stdout/stderr remains unchanged.
"""

import argparse
import json
from pathlib import Path
import socket
import subprocess
import threading
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=180)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a command is required")
    stop = threading.Event()
    ready = [threading.Event() for _ in range(4)]
    counts = [0] * 4
    errors = []

    def churn(index):
        try:
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen()
                listener.settimeout(2)
                while not stop.is_set():
                    with socket.create_connection(listener.getsockname(), timeout=2) as client:
                        peer, _ = listener.accept()
                        with peer:
                            client.sendall(b"x")
                            if peer.recv(1) != b"x":
                                raise RuntimeError("synthetic peer did not receive its byte")
                        counts[index] += 1
                        ready[index].set()
        except Exception as exc:
            errors.append({"thread": index, "error": repr(exc)})
            ready[index].set()

    threads = [threading.Thread(target=churn, args=(i,)) for i in range(4)]
    start = time.monotonic()
    for thread in threads:
        thread.start()
    code = 2
    try:
        for event in ready:
            if not event.wait(5):
                raise RuntimeError("churn worker did not start")
        if errors:
            raise RuntimeError("churn precondition failed")
        code = subprocess.run(command, timeout=args.timeout).returncode
    except Exception as exc:
        errors.append({"harness": repr(exc)})
    finally:
        stop.set()
        for thread in threads:
            thread.join(5)
        if any(thread.is_alive() for thread in threads):
            errors.append({"harness": "churn worker did not stop"})
    result = {
        "schema": "vanian.p0-048.socket-churn.v1",
        "scope": "Synthetic loopback churn; same host and administrator",
        "command": command,
        "command_exit_code": code,
        "elapsed_seconds": round(time.monotonic() - start, 6),
        "completed_connections_per_thread": counts,
        "errors": errors,
        "status": "PASS" if code == 0 and not errors and all(counts) else "FAIL",
    }
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result), flush=True)
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
