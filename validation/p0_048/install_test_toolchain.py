#!/usr/bin/env python3
"""Restore only the already audited Rust compiler/std/cargo pins for CI.

Evaluation build step, not a runtime downloader or an air-gap installer.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--record", type=Path, required=True)
    args = parser.parse_args()
    pins = json.loads(Path(__file__).with_name("native_ci_pins.json").read_text())["compiler"]
    args.prefix.mkdir(parents=True, exist_ok=False)
    report = {"version": pins["version"], "license": pins["license"], "components": []}
    with tempfile.TemporaryDirectory(prefix="p0-048-rust-") as temp:
        for component in pins["components"]:
            if component["name"] not in {"rustc", "rust-std", "cargo"}:
                continue
            data = urllib.request.urlopen(component["url"], timeout=60).read()
            if hashlib.sha256(data).hexdigest() != component["sha256"]:
                raise ValueError("toolchain component checksum mismatch: " + component["name"])
            archive = Path(temp) / component["url"].rsplit("/", 1)[1]
            archive.write_bytes(data)
            with tarfile.open(archive) as contents:
                contents.extractall(temp, filter="data")
            unpacked = Path(temp) / archive.name.removesuffix(".tar.xz")
            for license_pin in component["license_files"]:
                actual = hashlib.sha256((unpacked / license_pin["path_in_archive"]).read_bytes()).hexdigest()
                if actual != license_pin["sha256"]:
                    raise ValueError("toolchain licence checksum mismatch")
            subprocess.run(["bash", str(unpacked / "install.sh"), "--prefix=" + str(args.prefix.resolve()),
                            "--disable-ldconfig"], check=True)
            report["components"].append(component)
    report["rustc"] = subprocess.check_output([str(args.prefix / "bin/rustc"), "--version", "--verbose"], text=True)
    args.record.parent.mkdir(parents=True, exist_ok=True)
    args.record.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
