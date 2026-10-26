#!/usr/bin/env python3
"""Check RBI health claims after the pilot's offline signature verification.

The generic pilot permits a degraded control. RBI promises Active with coverage.
This checks that extra claim; it does not replace cryptographic verification.
Recovery must also leave every recorded integrity-unknown interval uncovered.
"""

import json
from pathlib import Path
import sys


def records_at(path):
    records = [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]
    if not records:
        raise ValueError(f"archive is empty: {path}")
    return records


def coverage_window(coverage):
    if not isinstance(coverage, dict):
        raise ValueError("RBI honest path requires attested coverage")
    start, end = coverage["from_ms"], coverage["to_ms"]
    if type(start) is not int or type(end) is not int or not 0 <= start < end:
        raise ValueError("coverage must have increasing integer timestamps")
    return start, end


def check_control(path):
    health = records_at(path)[-1]["health"]
    if health["state"] != "Active":
        raise ValueError(f"RBI honest path requires Active, got {health['state']!r}")
    coverage_window(health["attested_coverage"])


def check_recovery(health_path, batch_path):
    batches = {record["sequence"]: record["batch"] for record in records_at(batch_path)}
    unknown_until = None
    for record in records_at(health_path):
        health = record["health"]
        coverage = health["attested_coverage"]
        if health["state"] == "IntegrityUnknown":
            if coverage is not None:
                raise ValueError("unknown integrity cannot carry attested coverage")
            # Use the signed batch interval, not the later health emission
            # time: these are the observations the health record describes.
            batch = batches[health["sequence"]]
            _, end = coverage_window({
                "from_ms": batch["claimed_from_ms"], "to_ms": batch["claimed_to_ms"],
            })
            unknown_until = max(unknown_until or 0, end)
        elif coverage is not None:
            start, _ = coverage_window(coverage)
            if unknown_until is not None and start < unknown_until:
                raise ValueError("recovery coverage backfills an integrity-unknown interval")
    if unknown_until is None:
        raise ValueError("no recorded integrity-unknown interval to check")


if __name__ == "__main__":
    try:
        if len(sys.argv) != 4:
            raise ValueError("usage: check_control.py CONTROL_HEALTH_ARCHIVE HEALTH_ARCHIVE BATCH_ARCHIVE")
        check_control(sys.argv[1])
        check_recovery(sys.argv[2], sys.argv[3])
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
    print("PASS: recorded control is Active with coverage; recovery does not backfill unknown integrity")
