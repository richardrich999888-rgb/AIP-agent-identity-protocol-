#!/usr/bin/env python3
"""Reverify public receipts using the existing Rust verifier and external anchor."""
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--anchor", type=Path, required=True,
                        help="Independently establish this trust anchor before use")
    parser.add_argument("--verifier", type=Path, required=True)
    args = parser.parse_args()
    anchor = json.loads(args.anchor.read_text())
    env = {"PATH": os.defpath, "AIP_GATEWAY_ID": anchor["gateway_id"],
           "AIP_GATEWAY_KEY_VERSION": str(anchor["key_version"]),
           "AIP_GATEWAY_PUBLIC_KEY": anchor["public_key"]}
    receipts = [json.loads(line) for line in args.archive.read_text().splitlines() if line]
    if not receipts:
        raise ValueError("empty archive")
    def verify(value):
        return subprocess.run([str(args.verifier.resolve()), "verify"],
            input=json.dumps(value), text=True, capture_output=True, env=env)
    for receipt in receipts:
        if verify(receipt).returncode:
            raise ValueError("receipt verification failed")
    altered = copy.deepcopy(receipts[0])
    altered["receipt"]["parameter_commitment"][0] ^= 1
    if verify(altered).returncode == 0:
        raise ValueError("modified parameter commitment was accepted")
    print(json.dumps({"receipt_signatures": "VERIFIED", "count": len(receipts),
        "altered_receipt_refused": True, "kernel_execution": "CANNOT_PROVE",
        "anchor_authority": "MUST_BE_ESTABLISHED_EXTERNALLY"}))

if __name__ == "__main__":
    main()

