"""Unit tests for the benchmark's deterministic helpers (no namespaces, no network)."""
import hashlib, os, sys, pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bench"))
import bench, pki, summarize


def test_payload_deterministic(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    assert bench.make_payload(str(a), 2, 7) == bench.make_payload(str(b), 2, 7)
    assert bench.make_payload(str(tmp_path / "c"), 2, 8) != bench.make_payload(str(a), 2, 7)


def test_corrupt_copy_flips_every_nth_piece(tmp_path):
    src, dst = tmp_path / "s", tmp_path / "d"
    bench.make_payload(str(src), 2, 7)
    piece = 64 << 10
    n = bench.make_corrupt_copy(str(src), str(dst), piece)
    s, d = src.read_bytes(), dst.read_bytes()
    assert len(s) == len(d) and n == (len(s) // piece + bench.CORRUPT_EVERY - 1) // bench.CORRUPT_EVERY
    for i in range(len(s) // piece):
        same = s[i * piece:(i + 1) * piece] == d[i * piece:(i + 1) * piece]
        assert same == (i % bench.CORRUPT_EVERY != 0)


def test_sha256_helper(tmp_path):
    f = tmp_path / "x"; f.write_bytes(b"abc")
    assert bench.sha256(str(f)) == hashlib.sha256(b"abc").hexdigest()
    assert bench.sha256(str(tmp_path / "missing")) is None


@pytest.mark.parametrize("scope", ["", "*", "a/b"])
def test_pki_refuses_wildcard_or_bad_scope(tmp_path, scope):
    with pytest.raises(ValueError):
        pki.make_leaf(str(tmp_path), "n", ("ca.crt", "ca.key"), scope)


def test_pki_rejects_unknown_intruder_kind(tmp_path):
    with pytest.raises(ValueError):
        pki.build(str(tmp_path), "model.bin", ["src"], ["p3"], kind="other")


def test_pki_scopes_leaves(tmp_path):
    import subprocess
    out = pki.build(str(tmp_path), "model.bin", ["src", "p1"], ["p2"], kind="wrongscope")
    subj = lambda n: subprocess.run(["openssl", "x509", "-in", out[n][0], "-noout", "-subject"], capture_output=True, text=True).stdout
    assert "CN = model.bin" in subj("p1") and "CN = model.bin.other" in subj("p2")
    ok = subprocess.run(["openssl", "verify", "-CAfile", out["ca"], out["p1"][0]], capture_output=True)
    assert ok.returncode == 0


def test_summarize_groups_repeats():
    assert summarize.key("/x/bittorrent_256_src100_r3.json") == "bittorrent_256_src100"
    assert summarize.key("/x/bittorrent_128_corrupt.json") == "bittorrent_128_corrupt"
