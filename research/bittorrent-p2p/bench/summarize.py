"""Aggregate benchmark JSONs into results/summary.json (median and range per config).

usage: summarize.py RESULTS_DIR [RESULTS_DIR ...]
"""
from __future__ import annotations

import glob
import json
import os
import re
import statistics
import sys


def key(path: str) -> str:
    return re.sub(r"_r\d+\.json$", "", os.path.basename(path)).removesuffix(".json")


def main() -> None:
    groups: dict[str, list[dict]] = {}
    for d in sys.argv[1:]:
        for f in sorted(glob.glob(os.path.join(d, "*.json"))):
            if f.endswith("report.json"):
                continue
            groups.setdefault(f"{os.path.basename(d)}/{key(f)}", []).append(json.load(open(f)))
    out = {}
    for k, runs in sorted(groups.items()):
        P = runs[0]["payload_bytes"]

        def agg(fn):
            v = [fn(r) for r in runs]
            return {"median": round(statistics.median(v), 3), "min": round(min(v), 3), "max": round(max(v), 3)}

        out[k] = {"n": len(runs), "all_verified": all(r["all_verified"] for r in runs),
                  "fleet_seconds": agg(lambda r: r["fleet_seconds"]),
                  "src_tx_x_payload": agg(lambda r: r["src_tx_bytes"] / P),
                  "total_tx_x_payload": agg(lambda r: r["total_tx_bytes"] / P),
                  "cpu_seconds": agg(lambda r: r["cpu_seconds"]),
                  "peak_rss_mb": agg(lambda r: r["peak_rss_mb"])}
    json.dump(out, open(os.path.join(os.path.dirname(sys.argv[1].rstrip("/")), "summary.json"), "w"), indent=1)
    for k, v in out.items():
        print(f"{k:45s} n={v['n']} t={v['fleet_seconds']['median']:7.2f} [{v['fleet_seconds']['min']}-{v['fleet_seconds']['max']}] "
              f"src={v['src_tx_x_payload']['median']:.2f} tot={v['total_tx_x_payload']['median']:.2f} "
              f"cpu={v['cpu_seconds']['median']:.1f} rss={v['peak_rss_mb']['median']:.0f} ok={v['all_verified']}")


if __name__ == "__main__":
    main()
