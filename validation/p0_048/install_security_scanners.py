#!/usr/bin/env python3
"""Install the reviewed Linux x86_64 scanner binaries into a caller-owned folder."""

import argparse
import hashlib
import io
import json
from pathlib import Path
import platform
import tarfile
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise SystemExit("Only the pinned Linux x86_64 artifacts are supported")
    pins = json.loads(Path(__file__).with_name("security_scanners.lock.json").read_text())
    args.prefix.mkdir(parents=True, exist_ok=True)
    for name, pin in pins.items():
        with urllib.request.urlopen(pin["archive_url"], timeout=90) as response:
            data = response.read()
        if hashlib.sha256(data).hexdigest() != pin["archive_sha256"]:
            raise SystemExit(name + " archive checksum mismatch")
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            member = archive.getmember(name)
            if not member.isfile():
                raise SystemExit(name + " is not a regular archive member")
            binary = archive.extractfile(member).read()
        if hashlib.sha256(binary).hexdigest() != pin["binary_sha256"]:
            raise SystemExit(name + " executable checksum mismatch")
        path = args.prefix / name
        path.write_bytes(binary)
        path.chmod(0o755)
        print(json.dumps({"tool": name, "version": pin["version"], "sha256": pin["binary_sha256"]}))


if __name__ == "__main__":
    main()
