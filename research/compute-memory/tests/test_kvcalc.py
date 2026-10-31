import os, sys, pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from kvcalc import Arch, QWEN25_05B, QWEN25_15B, kv_bytes, kv_bytes_per_token

MiB = 2**20

def test_matches_llama_cpp_allocation_05b():
    # llama-server log: "size = 24.00 MiB (2048 cells, 24 layers, 1/1 seqs)"
    assert kv_bytes(QWEN25_05B, 2048) == 24 * MiB

def test_matches_llama_cpp_allocation_15b():
    # llama-server log: "size = 56.00 MiB (2048 cells, 28 layers, 1/1 seqs)"
    assert kv_bytes(QWEN25_15B, 2048) == 56 * MiB

def test_linear_in_ctx_and_seq():
    assert kv_bytes(QWEN25_15B, 4096, 3) == 6 * kv_bytes(QWEN25_15B, 2048)

def test_gqa_vs_mha():
    mha = Arch(28, 1536, 12, 12)
    assert kv_bytes_per_token(mha) == 6 * kv_bytes_per_token(QWEN25_15B)

def test_q8_smaller_than_f16():
    assert kv_bytes_per_token(QWEN25_15B, "q8_0") < kv_bytes_per_token(QWEN25_15B)

@pytest.mark.parametrize("args", [(0, 896, 14, 2), (24, 897, 14, 2), (24, 896, 14, 3), (24, 896, 14, -1)])
def test_rejects_invalid_geometry(args):
    with pytest.raises(ValueError):
        Arch(*args)

def test_rejects_bad_dtype_and_ctx():
    with pytest.raises(ValueError):
        kv_bytes_per_token(QWEN25_05B, "fp8")
    with pytest.raises(ValueError):
        kv_bytes(QWEN25_05B, 0)
