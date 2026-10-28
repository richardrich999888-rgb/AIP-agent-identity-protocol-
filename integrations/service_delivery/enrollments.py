#!/usr/bin/env python3
"""Convert public probe enrollment records to the collector's native allow-list.

Records require out-of-band institution approval. This tool does not prove
key possession, host identity or sensor coverage and never reads private keys.
"""
import argparse
import json
from pathlib import Path
import re


def load_enrollments(paths, hosts=None):
    records, keys = {}, set()
    expected = {"schema", "probe_id", "transport_pubkey_hex", "status", "observation", "workload_identity_binding"}
    for path in paths:
        data = Path(path).read_bytes()
        if len(data) > 4096:
            raise ValueError("public enrollment exceeds 4 KiB")
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError("duplicate enrollment JSON key")
                result[key] = value
            return result
        record = json.loads(data, object_pairs_hook=pairs)
        if not isinstance(record, dict) or set(record) != expected:
            raise ValueError("expected the exact public aip-probe enrollment record")
        host, key = record["probe_id"], record["transport_pubkey_hex"]
        if (not isinstance(host, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", host)
                or hosts is not None and host not in hosts or host in records or not isinstance(key, str)
                or not re.fullmatch(r"[0-9a-f]{64}", key) or key == "00"*32 or key in keys):
            raise ValueError("unknown/duplicate probe or colliding/invalid transport public key")
        if (record["schema"] != "vanian.probe-enrollment.v1" or record["status"] != "PUBLIC_KEY_READY"
                or record["observation"] != "NOT_STARTED" or record["workload_identity_binding"] != "NOT_ESTABLISHED"):
            raise ValueError("enrollment cannot assert runtime assurance")
        records[host] = record
        keys.add(key)
    if not records or hosts is not None and set(records) != hosts:
        raise ValueError("every planned host needs a public enrollment record")
    return records


def allowlist(records):
    return [{"probe_id": host, "transport_pubkey_hex": records[host]["transport_pubkey_hex"]} for host in sorted(records)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", action="append", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    records = load_enrollments(args.record)
    with Path(args.output).open("x") as stream:
        json.dump(allowlist(records), stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
