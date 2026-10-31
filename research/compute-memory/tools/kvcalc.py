"""KV-cache size from a model's architecture (no model execution).

Per token, a decoder layer stores one K and one V vector per KV head:

    bytes_per_token = 2 (K,V) * n_layers * n_kv_heads * head_dim * bytes_per_elem
    head_dim        = d_model / n_heads          (Qwen2/Llama convention)

Assumptions: standard (grouped-query) attention, dense cache, no sliding
window, no MLA/latent compression, same dtype for K and V. Models violating
these (Gemma sliding window, DeepSeek MLA) need their own formula — the
function refuses inputs it cannot represent rather than guessing.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass

BYTES_PER_ELEM = {"f32": 4.0, "f16": 2.0, "bf16": 2.0, "q8_0": 34 / 32, "q4_0": 18 / 32}
# q8_0 / q4_0 include the per-32-element fp16 scale used by llama.cpp blocks.


@dataclass(frozen=True)
class Arch:
    """Attention geometry needed for the KV-cache formula."""
    n_layers: int
    d_model: int
    n_heads: int
    n_kv_heads: int

    def __post_init__(self) -> None:
        for k in ("n_layers", "d_model", "n_heads", "n_kv_heads"):
            if getattr(self, k) <= 0:
                raise ValueError(f"{k} must be positive")
        if self.d_model % self.n_heads:
            raise ValueError("d_model not divisible by n_heads")
        if self.n_heads % self.n_kv_heads:
            raise ValueError("n_heads not divisible by n_kv_heads (not GQA)")

    @property
    def head_dim(self) -> int:
        return self.d_model // self.n_heads


def kv_bytes_per_token(a: Arch, dtype: str = "f16") -> float:
    """Bytes of K+V cache per token per sequence."""
    if dtype not in BYTES_PER_ELEM:
        raise ValueError(f"unknown dtype {dtype}")
    return 2 * a.n_layers * a.n_kv_heads * a.head_dim * BYTES_PER_ELEM[dtype]


def kv_bytes(a: Arch, n_ctx: int, n_seq: int = 1, dtype: str = "f16") -> float:
    """Total KV bytes for n_seq concurrent sequences of n_ctx tokens each."""
    if n_ctx <= 0 or n_seq <= 0:
        raise ValueError("n_ctx and n_seq must be positive")
    return kv_bytes_per_token(a, dtype) * n_ctx * n_seq


def from_gguf(path: str) -> Arch:
    """Read the architecture from GGUF metadata (needs llama.cpp's gguf-py)."""
    import gguf  # local import: optional dependency

    r = gguf.GGUFReader(path)
    arch = bytes(r.fields["general.architecture"].parts[-1]).decode()

    def f(key: str) -> int:
        v = r.fields[f"{arch}.{key}"]
        return int(v.parts[v.data[0]][0])

    return Arch(f("block_count"), f("embedding_length"), f("attention.head_count"), f("attention.head_count_kv"))


# Values read from the GGUF files used in this research (see KV_CACHE in
# LLM_EXPERIMENTS.md); kept here so tests need no model file.
QWEN25_05B = Arch(n_layers=24, d_model=896, n_heads=14, n_kv_heads=2)
QWEN25_15B = Arch(n_layers=28, d_model=1536, n_heads=12, n_kv_heads=2)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("gguf")
    ap.add_argument("--ctx", type=int, nargs="+", default=[2048, 4096, 8192, 32768])
    ap.add_argument("--seq", type=int, default=1)
    a = ap.parse_args()
    arch = from_gguf(a.gguf)
    out = {"arch": arch.__dict__, "head_dim": arch.head_dim,
           "kib_per_token_f16": kv_bytes_per_token(arch) / 1024,
           "mib": {d: {c: round(kv_bytes(arch, c, a.seq, d) / 2**20, 2) for c in a.ctx} for d in ("f16", "q8_0", "q4_0")}}
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
