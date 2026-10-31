"""Throwaway test PKI for SSL-torrent experiments (openssl CLI).

Creates, under OUT_DIR: a publisher CA, one leaf certificate per authorised
node signed by it, and certificates for intruders of two kinds:
  rogue      leaf signed by a different CA
  wrongscope leaf signed by the publisher CA but scoped to another release

Scoping: libtorrent accepts a peer certificate for an SSL torrent only if its
subject CN / SAN DNS name equals the torrent name or "*" (found empirically:
leaves with arbitrary CNs fail the handshake with "tlsv1 alert internal
error"). Leaves here are scoped to the release name, never "*". Keys are
generated per run in the work directory and deleted by the bench afterwards;
nothing here is a production key and nothing is committed.
"""
from __future__ import annotations

import os
import subprocess

DAYS = "2"
KEY = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"]


def _run(*args: str) -> None:
    subprocess.run(["openssl", *args], check=True, capture_output=True)


def make_ca(d: str, name: str) -> tuple[str, str]:
    crt, key = os.path.join(d, f"{name}.crt"), os.path.join(d, f"{name}.key")
    _run("req", "-x509", *KEY, "-keyout", key, "-out", crt, "-days", DAYS, "-subj", f"/CN={name}")
    return crt, key


def make_leaf(d: str, name: str, ca: tuple[str, str], scope: str) -> tuple[str, str]:
    """Leaf for node `name`, valid for the torrent named `scope`."""
    if not scope or scope == "*" or "/" in scope:
        raise ValueError("leaf scope must be one concrete torrent name")
    csr, crt, key = (os.path.join(d, f"{name}.{e}") for e in ("csr", "crt", "key"))
    _run("req", *KEY, "-keyout", key, "-out", csr, "-subj", f"/CN={scope}")
    _run("x509", "-req", "-in", csr, "-CA", ca[0], "-CAkey", ca[1], "-CAcreateserial", "-out", crt, "-days", DAYS)
    return crt, key


def build(d: str, release: str, authorised: list[str], intruders: list[str], kind: str = "rogue") -> dict:
    """Return {node: (cert, key)} plus 'ca' -> publisher CA cert path."""
    if kind not in ("rogue", "wrongscope"):
        raise ValueError("kind must be rogue or wrongscope")
    os.makedirs(d, exist_ok=True)
    ca = make_ca(d, "publisher-ca")
    rogue = make_ca(d, "rogue-ca")
    out = {n: make_leaf(d, n, ca, release) for n in authorised}
    for n in intruders:
        out[n] = make_leaf(d, n, rogue, release) if kind == "rogue" else make_leaf(d, n, ca, release + ".other")
    out["ca"] = ca[0]
    return out
