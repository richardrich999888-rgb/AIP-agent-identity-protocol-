#!/usr/bin/env python3
"""Apply the unchanged P0-048 native archive checks to the P0-057 source run.

Only the explicit artifact/source locations differ. All assertions, including
absent coverage after loss, original/tamper/wrong-key checks, remain unchanged.
"""
import argparse
import importlib.util
from pathlib import Path
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = Path(__file__).resolve().parent / "iteration-002/hosted"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location("p048_native_verification",
        ROOT / "validation/p0_048/iteration-004/verify_hosted_evidence.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ROOT = ROOT
    module.HOSTED = EVIDENCE / "native/p0-native-evidence"
    module.SOURCE = "5be83a87bec680d26510c2be93e66fdfda008b1e"
    module.ZIP_HASH = "f6859f1235aa10755df8949ceb6b4d055d9d452512a15194f1a7026497d21996"
    with tempfile.TemporaryDirectory(prefix="p057-native-replay-") as tmp:
        module.HERE = Path(tmp)
        shutil.copyfile(EVIDENCE / "native-original.zip", module.HERE / "hosted-artifact.zip")
        sys.argv = [__file__, "--verifier", str(args.verifier.resolve()), "--out", str(args.out.resolve())]
        module.main()


if __name__ == "__main__":
    main()
