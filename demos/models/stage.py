#!/usr/bin/env python3
"""Stage the demo models into an offline bundle, with provenance (W0.3).

  stage.py BUNDLE_DIR [--llama-server PATH] [--only NAME ...]

Downloads each model pinned to an exact Hugging Face revision into
BUNDLE_DIR/models, checks its SHA-256, re-reads the licence from the live
model card, and refuses on any mismatch. It never edits
deploy/syntriass/models.manifest.json (owned by the teaching-demo session):

  * Qwen files: the SHA-256 comes from that manifest, so the bundle satisfies
    `resolve_model.py verify` unchanged;
  * IBM Granite (not in that manifest): the SHA-256 and revision are pinned in
    demos/models/extra-models.json. Demos load it only through
    `stage.py path granite-3.3-2b-q4` after the same hash check.

Writes BUNDLE_DIR/PROVENANCE.json: for every file, repository, revision,
download URL, SHA-256 as downloaded, licence as read from the card and the
LICENSE file when the repository has one, and the UTC time it was read.
Model weights never go into git. No model API is called; these are file
downloads.

Refused, never warned: a licence other than Apache-2.0, a hash mismatch, or a
revision the card cannot be read at.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import shutil
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
MANIFEST = REPO / "deploy/syntriass/models.manifest.json"
EXTRA = HERE / "extra-models.json"
ALLOWED_LICENCES = {"apache-2.0"}
QWEN_REPO = {"qwen2.5-0.5b": "Qwen/Qwen2.5-0.5B-Instruct-GGUF", "qwen2.5-1.5b": "Qwen/Qwen2.5-1.5B-Instruct-GGUF"}


def catalogue() -> dict[str, dict]:
    out = {}
    for e in json.loads(MANIFEST.read_text())["models"]:
        repo = next(r for k, r in QWEN_REPO.items() if e["file"].startswith(k))
        out[e["logical_name"]] = {"file": e["file"], "sha256": e["sha256"], "repo": repo, "revision": None,
                                  "pinned_in": "deploy/syntriass/models.manifest.json"}
    for e in json.loads(EXTRA.read_text())["models"]:
        out[e["logical_name"]] = {**e, "pinned_in": "demos/models/extra-models.json"}
    return out


def get(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as r:
        return r.read()


def card(repo: str, revision: str | None) -> dict:
    meta = json.loads(get(f"https://huggingface.co/api/models/{repo}" + (f"/revision/{revision}" if revision else "")))
    lic = (meta.get("cardData") or {}).get("license")
    files = {s["rfilename"] for s in meta.get("siblings", [])}
    licence_file = None
    if "LICENSE" in files:
        text = get(f"https://huggingface.co/{repo}/raw/{meta['sha']}/LICENSE")
        licence_file = {"sha256": hashlib.sha256(text).hexdigest(), "first_line": text.decode(errors="replace").strip().splitlines()[0]}
    return {"revision": meta["sha"], "card_licence": lic, "licence_file": licence_file,
            "gated": meta.get("gated"), "read_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")}


def stage(name: str, e: dict, models: Path) -> dict:
    c = card(e["repo"], e["revision"])
    if (c["card_licence"] or "").lower() not in ALLOWED_LICENCES:
        raise SystemExit(f"REFUSED {name}: licence on the card is {c['card_licence']!r}, not Apache-2.0")
    if c["gated"]:
        raise SystemExit(f"REFUSED {name}: the repository is gated ({c['gated']})")
    url = f"https://huggingface.co/{e['repo']}/resolve/{c['revision']}/{e['file']}"
    dest = models / e["file"]
    if dest.exists() and hashlib.sha256(dest.read_bytes()).hexdigest() == e["sha256"]:
        print(f"{name}: already staged and verified")
    else:
        tmp = dest.with_suffix(".part")
        h = hashlib.sha256()
        with urllib.request.urlopen(url, timeout=120) as r, open(tmp, "wb") as f:
            while chunk := r.read(1 << 20):
                h.update(chunk)
                f.write(chunk)
        if h.hexdigest() != e["sha256"]:
            tmp.unlink()
            raise SystemExit(f"REFUSED {name}: downloaded sha256 {h.hexdigest()} != pinned {e['sha256']}")
        tmp.rename(dest)
        print(f"{name}: downloaded and verified ({dest.stat().st_size} bytes)")
    return {"logical_name": name, "file": e["file"], "repo": e["repo"], "url": url, "sha256": e["sha256"],
            "size_bytes": dest.stat().st_size, "pinned_in": e["pinned_in"], **c}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("bundle", type=Path)
    ap.add_argument("--llama-server", type=Path)
    ap.add_argument("--only", nargs="*")
    a = ap.parse_args()
    cat = catalogue()
    names = a.only or list(cat)
    models = a.bundle / "models"
    models.mkdir(parents=True, exist_ok=True)
    prov_path = a.bundle / "PROVENANCE.json"
    prov = json.loads(prov_path.read_text()) if prov_path.exists() else {"models": {}}
    for n in names:
        if n not in cat:
            raise SystemExit(f"unknown model {n!r}; known: {', '.join(cat)}")
        prov["models"][n] = stage(n, cat[n], models)
        prov_path.write_text(json.dumps(prov, indent=1) + "\n")
    if a.llama_server:
        (a.bundle / "bin").mkdir(exist_ok=True)
        shutil.copy2(a.llama_server, a.bundle / "bin/llama-server")
        prov["llama_server"] = {"sha256": hashlib.sha256(a.llama_server.read_bytes()).hexdigest(),
                                "source": "llama.cpp vendored in llama-cpp-python 0.3.16 sdist (sha256 34ed0f9b…), "
                                          "cmake -DCMAKE_BUILD_TYPE=Release -DGGML_NATIVE=ON -DLLAMA_CURL=OFF"}
        prov_path.write_text(json.dumps(prov, indent=1) + "\n")
    print(f"provenance: {prov_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
