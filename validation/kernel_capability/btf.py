#!/usr/bin/env python3
"""Minimal BTF reader: resolve a kernel function's BTF type id by name.

Why this exists rather than a dependency: loading a `BPF_PROG_TYPE_LSM`
program requires `attach_btf_id`, the BTF type id of the kernel's
`bpf_lsm_<hook>` stub. libbpf resolves it; libbpf is not installed here and
`bpftool` is absent. The format is small and stable, so reading it directly
is cheaper and more auditable than adding a toolchain.

Only what is needed is implemented: walk the type section, and return the id
of the first BTF_KIND_FUNC whose name matches. Nothing is interpreted beyond
the kind tag and the per-kind trailing length.

Reference: Documentation/bpf/btf.rst (type encoding table).
"""
from __future__ import annotations

import struct
from pathlib import Path

BTF_MAGIC = 0xEB9F
VMLINUX_BTF = Path("/sys/kernel/btf/vmlinux")

(KIND_INT, KIND_PTR, KIND_ARRAY, KIND_STRUCT, KIND_UNION, KIND_ENUM, KIND_FWD,
 KIND_TYPEDEF, KIND_VOLATILE, KIND_CONST, KIND_RESTRICT, KIND_FUNC,
 KIND_FUNC_PROTO, KIND_VAR, KIND_DATASEC, KIND_FLOAT, KIND_DECL_TAG,
 KIND_TYPE_TAG, KIND_ENUM64) = range(1, 20)

#: Bytes of per-kind payload following the 12-byte common header. A value of
#: (0, n) means a fixed n bytes; (n, 0) means vlen * n bytes.
PAYLOAD = {
    KIND_INT: (0, 4), KIND_PTR: (0, 0), KIND_ARRAY: (0, 12),
    KIND_STRUCT: (12, 0), KIND_UNION: (12, 0), KIND_ENUM: (8, 0),
    KIND_FWD: (0, 0), KIND_TYPEDEF: (0, 0), KIND_VOLATILE: (0, 0),
    KIND_CONST: (0, 0), KIND_RESTRICT: (0, 0), KIND_FUNC: (0, 0),
    KIND_FUNC_PROTO: (8, 0), KIND_VAR: (0, 4), KIND_DATASEC: (12, 0),
    # FLOAT carries NO trailing payload: its width is in btf_type.size.
    # Giving it 4 bytes here drifts the cursor and the walk lands on a
    # kind-0 (UNKN) header a few thousand ids later, which is how this
    # was found.
    KIND_FLOAT: (0, 0), KIND_DECL_TAG: (0, 4), KIND_TYPE_TAG: (0, 0),
    KIND_ENUM64: (12, 0),
}


class BtfError(Exception):
    """The BTF blob is absent or not in a shape this reader will interpret."""


def _header(blob: bytes):
    magic, version, _flags, hdr_len = struct.unpack_from("<HBBI", blob, 0)
    if magic != BTF_MAGIC:
        raise BtfError(f"bad BTF magic {magic:#x}")
    if version != 1:
        raise BtfError(f"unsupported BTF version {version}")
    type_off, type_len, str_off, str_len = struct.unpack_from("<IIII", blob, 8)
    return hdr_len, type_off, type_len, str_off, str_len


def _name(blob: bytes, strings_at: int, strings_len: int, offset: int) -> str:
    if offset == 0 or offset >= strings_len:
        return ""
    start = strings_at + offset
    end = blob.index(b"\x00", start)
    return blob[start:end].decode("utf-8", "replace")


def find_func_id(name: str, blob: bytes | None = None) -> int:
    """BTF type id of kernel function `name`, or 0 if it is not present.

    Ids are 1-based and assigned by position in the type section, which is
    exactly what `attach_btf_id` expects.
    """
    if blob is None:
        if not VMLINUX_BTF.is_file():
            raise BtfError("/sys/kernel/btf/vmlinux is absent; CONFIG_DEBUG_INFO_BTF is off")
        blob = VMLINUX_BTF.read_bytes()
    hdr_len, type_off, type_len, str_off, str_len = _header(blob)
    cursor = hdr_len + type_off
    end = cursor + type_len
    strings_at = hdr_len + str_off
    type_id = 0
    while cursor < end:
        name_off, info, _size = struct.unpack_from("<III", blob, cursor)
        kind = (info >> 24) & 0x1F
        vlen = info & 0xFFFF
        try:
            per_member, fixed = PAYLOAD[kind]
        except KeyError:
            raise BtfError(f"unknown BTF kind {kind} at id {type_id + 1}") from None
        cursor += 12 + fixed + per_member * vlen
        type_id += 1
        if kind == KIND_FUNC and _name(blob, strings_at, str_len, name_off) == name:
            return type_id
    return 0


if __name__ == "__main__":
    import sys

    for wanted in sys.argv[1:] or ["bpf_lsm_file_open", "bpf_lsm_bprm_check_security",
                                   "bpf_lsm_socket_connect", "bpf_lsm_task_alloc"]:
        try:
            print(f"{wanted:34s} btf_id={find_func_id(wanted)}")
        except BtfError as error:
            print(f"{wanted:34s} ERROR {error}")
