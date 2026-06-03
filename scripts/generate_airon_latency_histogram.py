#!/usr/bin/env python3
"""Generate AIRON pilot latency histograms from measured samples.

The script is intentionally measurement-only: if a pilot team has not supplied
samples for a metric, the output marks that metric NOT_MEASURED instead of
inventing numbers.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]

TARGETS: dict[str, dict[str, Any]] = {
    "aegis_ingress_hook_us": {
        "zone": "invisible_kernel_enforcement",
        "label": "AEGIS ingress hook latency",
        "unit": "us",
        "direction": "max",
        "target": 15.0,
        "proof": "Packet interception and parse at NIC/XDP ingress remains invisible.",
    },
    "aegis_circuit_breaker_detonation_us": {
        "zone": "invisible_kernel_enforcement",
        "label": "Circuit breaker detonation",
        "unit": "us",
        "direction": "max",
        "target": 50.0,
        "proof": "Rogue-loop detection can update the kernel blocklist fast enough to stop machine-speed cascades.",
    },
    "aegis_throughput_gbps": {
        "zone": "invisible_kernel_enforcement",
        "label": "AEGIS line-rate throughput",
        "unit": "gbps",
        "direction": "min",
        "target": 10.0,
        "proof": "Gateway sustains regional clearway burst volume without dropping legitimate traffic.",
    },
    "ml_kem_handshake_ms": {
        "zone": "pqc_identity_handshake",
        "label": "ML-KEM/Kyber handshake",
        "unit": "ms",
        "direction": "max",
        "target": 2.5,
        "proof": "Hybrid PQC exchange avoids the usual cryptographic latency tax.",
    },
    "signature_verification_us": {
        "zone": "pqc_identity_handshake",
        "label": "Delegation certificate or token signature verification",
        "unit": "us",
        "direction": "max",
        "target": 500.0,
        "proof": "AIP identity verification remains fast enough for REST/API hot paths.",
    },
    "trust_cache_injection_us": {
        "zone": "pqc_identity_handshake",
        "label": "Trust-cache to AEGIS SESSION_MAP injection",
        "unit": "us",
        "direction": "max",
        "target": 100.0,
        "proof": "Verified AIP trust state can be injected into the enforcement plane without blocking the flow.",
    },
    "evidence_packet_assembly_ms": {
        "zone": "accountability_evidence",
        "label": "EvidencePacket assembly",
        "unit": "ms",
        "direction": "max",
        "target": 150.0,
        "proof": "Decision hash, trace binding, receipt binding, and packet signature can run asynchronously without user-visible delay.",
    },
    "audit_export_ms": {
        "zone": "accountability_evidence",
        "label": "Audit export latency",
        "unit": "ms",
        "direction": "max",
        "target": 1000.0,
        "proof": "Auditors can retrieve a complete non-repudiable JSON evidence packet quickly.",
    },
    "storage_overhead_kb": {
        "zone": "accountability_evidence",
        "label": "Evidence storage overhead per action",
        "unit": "kb",
        "direction": "max",
        "target": 50.0,
        "proof": "Long-retention evidence is compact enough for practical storage economics.",
    },
}


def percentile(values: list[float], pct: float) -> float:
    if not values:
        raise ValueError("percentile requires at least one value")
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * pct
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    weight = rank - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def summarize(values: list[float]) -> dict[str, float | int]:
    return {
        "count": len(values),
        "min": round(min(values), 6),
        "p50": round(percentile(values, 0.50), 6),
        "p95": round(percentile(values, 0.95), 6),
        "p99": round(percentile(values, 0.99), 6),
        "max": round(max(values), 6),
    }


def target_passes(stats: dict[str, float | int], target: dict[str, Any]) -> bool:
    direction = target["direction"]
    if direction == "max":
        return float(stats["p99"]) <= float(target["target"])
    if direction == "min":
        return float(stats["min"]) >= float(target["target"])
    raise ValueError(f"unsupported direction: {direction}")


def load_samples(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {"metadata": {}, "samples": {}}
    with path.open("r", encoding="utf-8") as fh:
        raw = json.load(fh)
    if "samples" not in raw:
        raise ValueError("input JSON must contain a top-level 'samples' object")
    return raw


FULL_EVIDENCE_SCOPES = {"banking_pilot", "bare_metal", "production_like"}


def scoped_status(passed: bool, scope: str | None) -> str:
    if not passed:
        return "FAIL"
    if scope in FULL_EVIDENCE_SCOPES:
        return "PASS"
    return "PASS_LOCAL_SCOPE"


def metric_report(metric: str, raw_values: Any, scope: str | None = None, note: str | None = None) -> dict[str, Any]:
    target = TARGETS[metric]
    base = {
        "zone": target["zone"],
        "label": target["label"],
        "unit": target["unit"],
        "target": {
            "direction": target["direction"],
            "p99_or_min": target["target"],
        },
        "proof": target["proof"],
        "measurement_scope": scope,
        "note": note,
    }
    if raw_values is None:
        return {**base, "status": "NOT_MEASURED", "stats": None}
    if not isinstance(raw_values, list) or not raw_values:
        return {**base, "status": "NOT_MEASURED", "stats": None}
    values = [float(value) for value in raw_values]
    stats = summarize(values)
    status = scoped_status(target_passes(stats, target), scope)
    return {**base, "status": status, "stats": stats}


def delta_report(samples: dict[str, Any], scope: str | None = None, note: str | None = None) -> dict[str, Any]:
    baseline = samples.get("baseline_transaction_rtt_ms")
    active = samples.get("airon_active_transaction_rtt_ms")
    base = {
        "label": "Baseline vs AIRON-active transaction RTT delta",
        "unit": "percent",
        "target": {"p99_delta_percent_max": 3.0},
        "measurement_scope": scope,
        "note": note,
    }
    if not baseline or not active:
        return {**base, "status": "NOT_MEASURED", "stats": None}
    baseline_stats = summarize([float(value) for value in baseline])
    active_stats = summarize([float(value) for value in active])
    p99_baseline = float(baseline_stats["p99"])
    p99_active = float(active_stats["p99"])
    if p99_baseline <= 0:
        return {**base, "status": "INVALID_BASELINE", "stats": None}
    delta = ((p99_active - p99_baseline) / p99_baseline) * 100.0
    return {
        **base,
        "status": scoped_status(delta <= 3.0, scope),
        "stats": {
            "baseline_rtt_ms": baseline_stats,
            "airon_active_rtt_ms": active_stats,
            "p99_delta_percent": round(delta, 6),
        },
    }


def build_report(raw: dict[str, Any]) -> dict[str, Any]:
    samples = raw.get("samples", {})
    scopes = raw.get("measurement_scope", {})
    notes = raw.get("notes", {})
    metrics = {
        metric: metric_report(metric, samples.get(metric), scopes.get(metric), notes.get(metric))
        for metric in TARGETS
    }
    measured = [m for m in metrics.values() if m["status"] != "NOT_MEASURED"]
    failed = [m for m in metrics.values() if m["status"] == "FAIL"]
    delta = delta_report(
        samples,
        scopes.get("transaction_rtt_delta"),
        notes.get("transaction_rtt_delta"),
    )
    if delta["status"] == "FAIL":
        failed.append(delta)

    if failed:
        status = "FAIL"
    elif len(measured) == len(TARGETS) and delta["status"] == "PASS":
        status = "PASS"
    else:
        status = "PARTIAL"

    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return {
        "component": "AIRON Trust Gateway",
        "generated_at": generated_at,
        "status": status,
        "metadata": raw.get("metadata", {}),
        "measurement_policy": {
            "latency_gate": "p99 must satisfy the target unless the metric is throughput, where minimum measured throughput must satisfy the target.",
            "rtt_delta_gate": "AIRON-active p99 RTT overhead must be <= 3% over baseline p99 RTT.",
            "full_evidence_scopes": sorted(FULL_EVIDENCE_SCOPES),
            "local_scope_status": "PASS_LOCAL_SCOPE means the metric satisfied its numeric target in a local/dev measurement scope, but is not yet banking-pilot evidence.",
            "no_fabricated_values": True,
        },
        "metrics": metrics,
        "transaction_rtt_delta": delta,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", help="JSON file containing measured pilot samples")
    parser.add_argument("--output", default="airon_latency_report.json", help="Output report path")
    args = parser.parse_args()

    samples_path = Path(args.samples).resolve() if args.samples else None
    report = build_report(load_samples(samples_path))
    output = (REPO_ROOT / args.output).resolve()
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
