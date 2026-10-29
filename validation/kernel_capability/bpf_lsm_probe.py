#!/usr/bin/env python3
"""Runtime attach-and-enforce probe for BPF-LSM. Falsifiable, no dependencies.

The question this answers is the one ADR-008 records as a trap:
`CONFIG_LSM="...,bpf"` in the boot string and `BPF_PROG_TYPE_LSM` present in
BTF are NOT evidence that BPF-LSM works. Neither is `bpf` appearing in
/sys/kernel/security/lsm. Only a program the kernel actually loaded,
actually attached, and that actually changed an outcome, is evidence.

Two stages, deliberately separated because they prove different things:

  Stage A -- ATTACHABILITY. Load an LSM program that always returns 0 (allow)
             and attach it to `file_open`. Blast radius: none, it permits
             everything. Proves the kernel accepts and installs LSM programs.

  Stage B -- ENFORCEMENT. Load a program returning -EPERM and attach it to
             `socket_connect`, then attempt a loopback connect that succeeded
             moments earlier and require EPERM. Proves the program's return
             value actually reaches the caller.

## Why Stage B is safe to run

A BPF-LSM program is global: while attached, EVERY connect(2) on this host
fails. Three properties bound that:

  * the deny program is attached for the duration of one connect attempt;
  * the attachment is owned by a BPF link fd, which the kernel releases when
    the last reference closes, so closing the fd restores connect;
  * the stage runs in a forked child, so even an uncaught crash releases the
    link when the child's fds are reaped. There is no path that leaves the
    host permanently unable to connect.

Stage B verifies recovery explicitly: a connect after detach must succeed.
A probe that denied and never checked recovery would be indistinguishable
from a probe that broke the host.

Exit 0 = both stages proven. Exit 1 = loaded/attached but did not enforce.
Exit 2 = unavailable or blocked, never conflated with proven.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import errno
import json
import os
import socket
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from btf import BtfError, find_func_id

SYS_BPF = 321
BPF_PROG_LOAD = 5
BPF_RAW_TRACEPOINT_OPEN = 17

BPF_PROG_TYPE_LSM = 29
BPF_LSM_MAC = 42

# One BPF instruction: opcode, dst|src nibbles, signed offset, signed imm.
INSN = struct.Struct("<BBhi")
BPF_ALU64_MOV_IMM = 0xB7   # BPF_ALU64 | BPF_MOV | BPF_K
BPF_JMP_EXIT = 0x95        # BPF_JMP | BPF_EXIT

libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
libc.syscall.restype = ctypes.c_long


def program(return_value: int) -> bytes:
    """`r0 = return_value; exit`. An LSM hook reads r0: 0 allows, <0 denies."""
    return (INSN.pack(BPF_ALU64_MOV_IMM, 0, 0, return_value)
            + INSN.pack(BPF_JMP_EXIT, 0, 0, 0))


def _prog_load_attr(insns: bytes, name: bytes, attach_btf_id: int,
                    license_buf, log_buf):
    """union bpf_attr, PROG_LOAD arm, laid out field by field.

    Written out explicitly rather than with a ctypes Structure because the
    union's trailing fields have grown across kernel versions; a fixed
    144-byte buffer matching current uapi is both sufficient and honest
    about what it assumes.
    """
    attr = bytearray(144)
    insn_buf = ctypes.create_string_buffer(insns)
    struct.pack_into("<I", attr, 0, BPF_PROG_TYPE_LSM)
    struct.pack_into("<I", attr, 4, len(insns) // 8)
    struct.pack_into("<Q", attr, 8, ctypes.addressof(insn_buf))
    struct.pack_into("<Q", attr, 16, ctypes.addressof(license_buf))
    struct.pack_into("<I", attr, 24, 1)                       # log_level
    struct.pack_into("<I", attr, 28, ctypes.sizeof(log_buf))  # log_size
    struct.pack_into("<Q", attr, 32, ctypes.addressof(log_buf))
    attr[48:48 + min(len(name), 15)] = name[:15]              # prog_name[16]
    struct.pack_into("<I", attr, 68, BPF_LSM_MAC)             # expected_attach_type
    struct.pack_into("<I", attr, 108, attach_btf_id)
    return attr, insn_buf


def load_lsm_program(insns: bytes, name: bytes, attach_btf_id: int):
    """Returns (prog_fd, errno, verifier_log). prog_fd < 0 means refused."""
    license_buf = ctypes.create_string_buffer(b"GPL")
    log_buf = ctypes.create_string_buffer(16384)
    attr, _insn_keepalive = _prog_load_attr(insns, name, attach_btf_id,
                                            license_buf, log_buf)
    raw = (ctypes.c_char * len(attr)).from_buffer(attr)
    ctypes.set_errno(0)
    fd = libc.syscall(ctypes.c_long(SYS_BPF), ctypes.c_long(BPF_PROG_LOAD),
                      ctypes.byref(raw), ctypes.c_uint(len(attr)))
    err = ctypes.get_errno()
    log = log_buf.value.decode("utf-8", "replace").strip()
    return int(fd), err, log


def attach_lsm(prog_fd: int):
    """BPF_RAW_TRACEPOINT_OPEN with name=NULL attaches an LSM program."""
    attr = bytearray(24)
    struct.pack_into("<Q", attr, 0, 0)          # name = NULL
    struct.pack_into("<I", attr, 8, prog_fd)
    raw = (ctypes.c_char * len(attr)).from_buffer(attr)
    ctypes.set_errno(0)
    fd = libc.syscall(ctypes.c_long(SYS_BPF),
                      ctypes.c_long(BPF_RAW_TRACEPOINT_OPEN),
                      ctypes.byref(raw), ctypes.c_uint(len(attr)))
    return int(fd), ctypes.get_errno()


def try_loopback_connect(port: int) -> dict:
    """Attempt one connect to a closed loopback port.

    ECONNREFUSED means connect(2) was permitted and the stack answered.
    EPERM means an LSM refused it before the stack saw it. Those are the two
    outcomes that matter, and they are unambiguous.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
        sock.connect(("127.0.0.1", port))
        return {"outcome": "CONNECTED", "errno": None}
    except OSError as error:
        name = errno.errorcode.get(error.errno, error.errno)
        permitted = name in ("ECONNREFUSED", "ETIMEDOUT", "EINPROGRESS")
        return {"outcome": "PERMITTED_BY_LSM" if permitted else "DENIED",
                "errno": name}
    finally:
        sock.close()


def stage_a() -> dict:
    """Attachability: an always-allow program at file_open."""
    result = {"stage": "A_attachability", "hook": "bpf_lsm_file_open"}
    try:
        btf_id = find_func_id("bpf_lsm_file_open")
    except BtfError as error:
        return {**result, "status": "BLOCKED", "detail": str(error)}
    result["attach_btf_id"] = btf_id
    if not btf_id:
        return {**result, "status": "UNAVAILABLE",
                "detail": "no bpf_lsm_file_open in kernel BTF: built without BPF-LSM hooks"}
    prog_fd, err, log = load_lsm_program(program(0), b"aip_allow", btf_id)
    if prog_fd < 0:
        return {**result, "status": "LOAD_REFUSED",
                "load_errno": errno.errorcode.get(err, err),
                "verifier_log": log[:2000]}
    try:
        link_fd, link_err = attach_lsm(prog_fd)
        if link_fd < 0:
            return {**result, "status": "ATTACH_REFUSED",
                    "attach_errno": errno.errorcode.get(link_err, link_err)}
        os.close(link_fd)
        return {**result, "status": "ATTACH_PROVEN",
                "detail": "an always-allow LSM program loaded, attached and detached"}
    finally:
        os.close(prog_fd)


def stage_b_child(write_fd: int) -> None:
    """Enforcement, in a child so the link dies with it no matter what."""
    record = {"stage": "B_enforcement", "hook": "bpf_lsm_socket_connect"}
    try:
        btf_id = find_func_id("bpf_lsm_socket_connect")
        record["attach_btf_id"] = btf_id
        if not btf_id:
            record["status"] = "UNAVAILABLE"
            raise SystemExit
        # Baseline FIRST: a port that refuses proves connect(2) reaches the
        # stack before anything is attached.
        record["baseline_connect"] = try_loopback_connect(29998)
        prog_fd, err, log = load_lsm_program(program(-1), b"aip_deny", btf_id)
        if prog_fd < 0:
            record["status"] = "LOAD_REFUSED"
            record["load_errno"] = errno.errorcode.get(err, err)
            record["verifier_log"] = log[:2000]
            raise SystemExit
        link_fd = -1
        try:
            link_fd, link_err = attach_lsm(prog_fd)
            if link_fd < 0:
                record["status"] = "ATTACH_REFUSED"
                record["attach_errno"] = errno.errorcode.get(link_err, link_err)
                raise SystemExit
            record["while_attached_connect"] = try_loopback_connect(29998)
        finally:
            if link_fd >= 0:
                os.close(link_fd)   # releasing the link restores connect(2)
            os.close(prog_fd)
        record["after_detach_connect"] = try_loopback_connect(29998)
        baseline_ok = record["baseline_connect"]["errno"] == "ECONNREFUSED"
        denied = (record["while_attached_connect"]["outcome"] == "DENIED"
                  and record["while_attached_connect"]["errno"] == "EPERM")
        recovered = record["after_detach_connect"]["errno"] == "ECONNREFUSED"
        record["predicates"] = {
            "baseline_connect_reached_the_stack": baseline_ok,
            "connect_denied_EPERM_while_attached": denied,
            "connect_recovered_after_detach": recovered,
        }
        record["status"] = ("ENFORCEMENT_PROVEN"
                            if baseline_ok and denied and recovered
                            else "ATTACHED_BUT_DID_NOT_ENFORCE")
    except SystemExit:
        pass
    except BaseException as error:
        record.setdefault("status", "BLOCKED")
        record["detail"] = f"{type(error).__name__}: {error}"
    try:
        os.write(write_fd, json.dumps(record).encode())
        os.close(write_fd)
    except OSError:
        pass
    os._exit(0)


def run() -> dict:
    lsm_list = Path("/sys/kernel/security/lsm")
    report = {
        "probe": "bpf_lsm_runtime_attach_and_enforce",
        "kernel": os.uname().release,
        "lsm_list": lsm_list.read_text().strip() if lsm_list.is_file() else "UNAVAILABLE",
        "uid": os.geteuid(),
        "note": ("CONFIG_LSM and the LSM list are not capabilities. Only the "
                 "stage results below are evidence."),
    }
    report["stage_a"] = stage_a()
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        stage_b_child(write_fd)
    os.close(write_fd)
    with os.fdopen(read_fd, "rb") as channel:
        raw = channel.read()
    os.waitpid(pid, 0)
    report["stage_b"] = json.loads(raw) if raw else {"status": "BLOCKED",
                                                     "detail": "child produced no record"}
    a = report["stage_a"]["status"]
    b = report["stage_b"]["status"]
    if a == "ATTACH_PROVEN" and b == "ENFORCEMENT_PROVEN":
        report["status"] = "ENFORCEMENT_PROVEN"
        report["conclusion"] = (
            "BPF-LSM works on this kernel: an LSM program loaded, attached, denied a "
            "connect that succeeded moments earlier with EPERM, and the host recovered "
            "on detach. EXECUTION-PROVEN, not CONFIG-OBSERVED.")
    elif a == "ATTACH_PROVEN":
        report["status"] = "ATTACH_PROVEN_ENFORCEMENT_UNPROVEN"
        report["conclusion"] = f"LSM programs attach, but stage B returned {b}"
    else:
        report["status"] = a
        report["conclusion"] = f"BPF-LSM is not usable here: stage A returned {a}"
    return report


EXIT = {"ENFORCEMENT_PROVEN": 0, "ATTACH_PROVEN_ENFORCEMENT_UNPROVEN": 1,
        "ATTACHED_BUT_DID_NOT_ENFORCE": 1, "LOAD_REFUSED": 2,
        "ATTACH_REFUSED": 2, "UNAVAILABLE": 2, "BLOCKED": 2}

if __name__ == "__main__":
    outcome = run()
    print(json.dumps(outcome, indent=2))
    sys.exit(EXIT.get(outcome["status"], 2))
