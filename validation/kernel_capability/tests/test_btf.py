#!/usr/bin/env python3
"""Unit tests for the minimal BTF reader.

The regression that motivated most of these: BTF_KIND_FLOAT carries no
trailing payload (its width lives in btf_type.size). An earlier table gave
it 4 bytes, the cursor drifted, and the walk died on a kind-0 header ~8200
types in. A silently wrong walk is worse than a crash, because a wrong
attach_btf_id loads a program onto the wrong kernel function.
"""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from btf import (BTF_MAGIC, KIND_FLOAT, KIND_FUNC, KIND_INT, KIND_PTR, PAYLOAD,
                 BtfError, find_func_id)


def blob(types, strings):
    """Assemble a minimal, valid BTF image for the reader to walk."""
    string_section = b"\x00" + b"".join(s.encode() + b"\x00" for s in strings)
    offsets, cursor = {}, 1
    for s in strings:
        offsets[s] = cursor
        cursor += len(s) + 1
    body = b""
    for name, kind, vlen, size, trailing in types:
        info = (kind << 24) | (vlen & 0xFFFF)
        body += struct.pack("<III", offsets.get(name, 0), info, size) + trailing
    header = struct.pack("<HBBI", BTF_MAGIC, 1, 0, 24) + struct.pack(
        "<IIII", 0, len(body), len(body), len(string_section))
    return header + body + string_section, offsets


class PayloadTable(unittest.TestCase):
    def test_float_has_no_trailing_payload(self):
        """The regression. FLOAT's width is in btf_type.size, not after it."""
        self.assertEqual(PAYLOAD[KIND_FLOAT], (0, 0))

    def test_int_has_four_fixed_trailing_bytes(self):
        self.assertEqual(PAYLOAD[KIND_INT], (0, 4))

    def test_func_has_no_trailing_payload(self):
        self.assertEqual(PAYLOAD[KIND_FUNC], (0, 0))

    def test_every_kind_from_1_to_19_is_covered(self):
        """An uncovered kind makes the walk raise rather than drift."""
        self.assertEqual(sorted(PAYLOAD), list(range(1, 20)))


class Walking(unittest.TestCase):
    def test_a_func_is_found_at_its_one_based_position(self):
        image, _ = blob([("i", KIND_INT, 0, 4, struct.pack("<I", 0)),
                         ("p", KIND_PTR, 0, 1, b""),
                         ("wanted", KIND_FUNC, 0, 2, b"")], ["i", "p", "wanted"])
        self.assertEqual(find_func_id("wanted", image), 3)

    def test_a_float_before_the_target_does_not_shift_the_id(self):
        """Direct regression: with FLOAT mis-sized, this id comes out wrong."""
        image, _ = blob([("f", KIND_FLOAT, 0, 4, b""),
                         ("wanted", KIND_FUNC, 0, 1, b"")], ["f", "wanted"])
        self.assertEqual(find_func_id("wanted", image), 2)

    def test_many_floats_do_not_accumulate_drift(self):
        types = [("f%d" % n, KIND_FLOAT, 0, 4, b"") for n in range(50)]
        types.append(("wanted", KIND_FUNC, 0, 1, b""))
        image, _ = blob(types, [name for name, *_ in types])
        self.assertEqual(find_func_id("wanted", image), 51)

    def test_an_absent_name_returns_zero_rather_than_guessing(self):
        image, _ = blob([("other", KIND_FUNC, 0, 1, b"")], ["other"])
        self.assertEqual(find_func_id("missing", image), 0)

    def test_a_non_func_with_the_target_name_is_not_matched(self):
        """Matching a PTR named like a function would attach to nothing."""
        image, _ = blob([("vfs_read", KIND_PTR, 0, 1, b"")], ["vfs_read"])
        self.assertEqual(find_func_id("vfs_read", image), 0)

    def test_bad_magic_is_refused(self):
        image, _ = blob([("f", KIND_FUNC, 0, 1, b"")], ["f"])
        corrupted = b"\x00\x00" + image[2:]
        with self.assertRaises(BtfError):
            find_func_id("f", corrupted)

    def test_an_unknown_kind_raises_instead_of_drifting(self):
        image, _ = blob([("x", 31, 0, 1, b"")], ["x"])
        with self.assertRaises(BtfError):
            find_func_id("x", image)


class AgainstTheRunningKernel(unittest.TestCase):
    """Cross-checks against real BTF. Skipped where it is not exposed."""

    @classmethod
    def setUpClass(cls):
        if not Path("/sys/kernel/btf/vmlinux").is_file():
            raise unittest.SkipTest("/sys/kernel/btf/vmlinux absent")

    def test_a_function_that_must_exist_resolves(self):
        self.assertGreater(find_func_id("vfs_read"), 0)

    def test_a_function_that_cannot_exist_resolves_to_zero(self):
        self.assertEqual(find_func_id("definitely_not_a_kernel_function_xyz"), 0)

    def test_distinct_hooks_get_distinct_ids(self):
        ids = {name: find_func_id(name) for name in
               ("bpf_lsm_file_open", "bpf_lsm_socket_connect", "bpf_lsm_task_alloc")}
        present = [value for value in ids.values() if value]
        self.assertEqual(len(set(present)), len(present), ids)


if __name__ == "__main__":
    unittest.main(verbosity=2)
