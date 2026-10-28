#!/usr/bin/env python3
"""Compose a non-secret customer installation kit using existing validators.

This is offline planning and file preparation. Only CONFIGURATION_VALID can
be established here. Live assurance stages require the existing native evidence
verifiers and independently administered infrastructure.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import service_onboard
from enrollments import allowlist, load_enrollments

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("vanian_package", ROOT / "deploy/enterprise/linux/package.py")
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
STAGES = ("CONFIGURATION_VALID", "INSTALLED", "OBSERVER_ACTIVE", "SIGNED_EVIDENCE_AVAILABLE",
          "AUTHORIZATION_VERIFIED", "EXECUTION_RECONCILED", "PILOT_ACCEPTED")


def read_json(path):
    data = Path(path).read_bytes()
    if len(data) > 65536:
        raise ValueError("onboarding JSON exceeds 64 KiB")
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate onboarding JSON key")
            value[key] = item
        return value
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite JSON")))


def prepare(args):
    manifest = service_onboard.validate(read_json(args.manifest))
    plan = service_onboard.plan(manifest)
    archive_manifest, _ = runtime.verified_package(args.runtime_archive, args.expected_sha256)
    if type(args.retention_days) is not int or not 1 <= args.retention_days <= 3650:
        raise ValueError("explicit desired retention between 1 and 3650 days required")
    hosts = {h["host_id"] for h in manifest["agent_hosts"]}
    configs = {}
    for pair in args.probe_config:
        host, separator, file = pair.partition("=")
        if not separator or host not in hosts or host in configs:
            raise ValueError("each approved host needs exactly one HOST=CONFIG entry")
        parsed = runtime.parse_config(file, "probe")
        if parsed["AIP_PROBE_ID"] != host:
            raise ValueError("probe ID must equal the planned host reference")
        configs[host] = (parsed, Path(file).read_bytes())
    if set(configs) != hosts:
        raise ValueError("missing probe configuration")
    enrollment = load_enrollments(args.enrollment, hosts)
    collector = runtime.parse_config(args.collector_config, "collector")
    if collector["AIP_COLLECTOR_OBSERVER_ID"] != manifest["collector"]["host_id"]:
        raise ValueError("collector ID differs from the approved topology")
    pins = {value[0]["AIP_PROBE_COLLECTOR_NOISE_PUBKEY"] for value in configs.values()}
    endpoints = {value[0]["AIP_PROBE_COLLECTOR_ENDPOINT"] for value in configs.values()}
    if len(pins) != 1 or len(endpoints) != 1 or next(iter(pins)) == "00"*32:
        raise ValueError("all probes must pin the same explicitly selected collector")
    files = {"service-plan.json": runtime.canonical(plan),
        "customer-manifest.json": runtime.canonical(manifest),
        "software-manifest.json": runtime.canonical(archive_manifest),
        "collector/collector.env": Path(args.collector_config).read_bytes(),
        "collector/probes.json": runtime.canonical(allowlist(enrollment)),
        "requested-retention.json": runtime.canonical({"days": args.retention_days,
            "enforcement": "NOT_CONFIGURED_BY_THIS_TOOL", "legal_hold": "REQUIRES_INSTITUTION_POLICY",
            "raw_export_authorization": "REQUIRES_EXISTING_API_ADMIN_OR_MACHINE_CONTROLS"})}
    for host in sorted(hosts):
        files[f"probes/{host}/probe.env"] = configs[host][1]
        files[f"probes/{host}/public-enrollment.json"] = runtime.canonical(enrollment[host])
    status = {"schema": "vanian.onboarding-readiness.v1", "tenant_id": manifest["tenant_id"],
        "deployment_name": manifest["deployment_name"], "mode": "OBSERVER_ONLY",
        "stages": {stage: "CONFIGURATION_VALID" if stage == "CONFIGURATION_VALID" else "NOT_ASSESSED" for stage in STAGES},
        "host_separation": "OPERATOR_DECLARED_NOT_INDEPENDENTLY_VERIFIED",
        "transport_key_possession": "REQUIRES_AUTHENTICATED_HANDSHAKE",
        "workload_identity_binding": "NOT_ESTABLISHED", "live_coverage": "UNAVAILABLE",
        "runtime_archive_sha256": args.expected_sha256.lower()}
    files["readiness.json"] = runtime.canonical(status)
    files["INSTALL.md"] = (
        "# Customer installation kit\n\nConfiguration validated only. No installation or live assurance is established.\n\n"
        "Obtain the runtime artifact and its digest through the institution's independently authenticated release-approval channel. "
        "This kit contains public enrollment references, configuration and desired retention, not release approval, private keys or API credentials.\n\n"
        "On the collector host, install its approved DEB, provision /etc/aip/collector-passphrase from the secret manager "
        "(root-owned 0600) and copy collector/probes.json to /etc/aip/probes.json. Run:\n\n"
        "```sh\nsudo vanian-evidence-collector configure --config collector/collector.env --confirm-separate-host\n```\n\n"
        "On each approved probe host, install its approved DEB and run:\n\n"
        "```sh\nsudo vanian-snifferdog-agent configure --config probes/HOST/probe.env --confirm-separate-host\n```\n\n"
        "Replace HOST with that host's approved ID. For the tar installation instead, use package.py install --role probe|collector "
        "with that role's config, approved archive, --expected-sha256 and --confirm-separate-host; do not mix DEB and tar ownership.\n\n"
        "Review deploy/enterprise/runbooks/OPERATIONS.md before explicitly starting the services. Pin the collector's actual public Noise key "
        "and independently agree its observer-signing anchor. An enrollment record proves neither key possession nor a logical agent identity. "
        "Require fresh signed Active coverage, a same-run authorization/gateway/observation reconciliation and auditor verification before acceptance. "
        "Requested retention is not an API/storage retention configuration.\n").encode()
    files["SHA256SUMS.json"] = runtime.canonical({name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())})
    output = Path(args.output)
    if output.exists():
        raise ValueError("refusing to overwrite an existing onboarding kit")
    output.mkdir(mode=0o700, parents=True)
    for name, data in files.items():
        destination = output / name
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with destination.open("xb") as stream:
            stream.write(data)
        destination.chmod(0o600)
    print(json.dumps(status))
    return status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--runtime-archive", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--collector-config", required=True)
    parser.add_argument("--probe-config", action="append", required=True)
    parser.add_argument("--enrollment", action="append", required=True)
    parser.add_argument("--retention-days", type=int, required=True)
    parser.add_argument("--output", required=True)
    try:
        prepare(parser.parse_args())
        return 0
    except (ValueError, TypeError, OSError, KeyError) as error:
        print(f"ONBOARDING REFUSED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
