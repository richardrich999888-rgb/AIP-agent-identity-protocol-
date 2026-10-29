#!/usr/bin/env python3
"""Runtime enforcement probe for Landlock. Falsifiable, no dependencies.

ADR-008 records the trap this probe exists to avoid: a `CONFIG_LSM` string
and an entry in /sys/kernel/security/lsm are NOT evidence that an LSM
enforces anything. Only an attempt that is actually denied is.

The probe therefore does not ask "is Landlock present". It applies a real
ruleset to a real child process and requires BOTH halves to hold:

  * a path inside the allowed subtree must still be readable, and
  * a path outside it must be denied with EACCES.

A probe that only checked the denial could pass on a kernel that denied
everything, which is indistinguishable from a broken sandbox. A probe that
only checked the allow could pass on a kernel that enforced nothing at all.

Exit 0 = ENFORCEMENT_PROVEN. Exit 2 = unavailable/blocked (never conflated
with proven). Exit 1 = present but did NOT enforce, which is the finding
worth shouting about.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import errno
import json
import os
import sys
import tempfile
from pathlib import Path

# x86-64 syscall numbers. Landlock landed as 444/445/446 and these are stable
# ABI; they are not kernel-version dependent.
SYS_LANDLOCK_CREATE_RULESET = 444
SYS_LANDLOCK_ADD_RULE = 445
SYS_LANDLOCK_RESTRICT_SELF = 446

LANDLOCK_CREATE_RULESET_VERSION = 1 << 0
LANDLOCK_RULE_PATH_BENEATH = 1

# include/uapi/linux/landlock.h, ABI v1 filesystem access bits.
ACCESS_FS_EXECUTE = 1 << 0
ACCESS_FS_WRITE_FILE = 1 << 1
ACCESS_FS_READ_FILE = 1 << 2
ACCESS_FS_READ_DIR = 1 << 3

PR_SET_NO_NEW_PRIVS = 38


class RulesetAttr(ctypes.Structure):
    """struct landlock_ruleset_attr — ABI v1 has exactly this one field."""

    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class PathBeneathAttr(ctypes.Structure):
    """struct landlock_path_beneath_attr."""

    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)


def syscall(number, *args):
    """Raw syscall returning (result, errno). Never raises; callers decide."""
    libc.syscall.restype = ctypes.c_long
    ctypes.set_errno(0)
    result = libc.syscall(ctypes.c_long(number), *args)
    return result, ctypes.get_errno()


def abi_version():
    """Landlock ABI version, or (None, errno) when the LSM is not available.

    `landlock_create_ruleset(NULL, 0, VERSION)` is the documented probe and
    is side-effect free, so it is safe to call before anything is restricted.
    """
    result, err = syscall(SYS_LANDLOCK_CREATE_RULESET, None, ctypes.c_size_t(0),
                          ctypes.c_uint32(LANDLOCK_CREATE_RULESET_VERSION))
    return (result, 0) if result > 0 else (None, err)


def build_ruleset(allowed_dir: Path, handled: int, allowed: int) -> int:
    """Create a ruleset handling `handled` and permitting `allowed` beneath one dir."""
    attr = RulesetAttr(handled_access_fs=handled)
    fd, err = syscall(SYS_LANDLOCK_CREATE_RULESET, ctypes.byref(attr),
                      ctypes.c_size_t(ctypes.sizeof(attr)), ctypes.c_uint32(0))
    if fd < 0:
        raise OSError(err, "landlock_create_ruleset: " + os.strerror(err))
    parent = os.open(str(allowed_dir), os.O_PATH | os.O_CLOEXEC)
    try:
        beneath = PathBeneathAttr(allowed_access=allowed, parent_fd=parent)
        result, err = syscall(SYS_LANDLOCK_ADD_RULE, ctypes.c_int(fd),
                              ctypes.c_uint32(LANDLOCK_RULE_PATH_BENEATH),
                              ctypes.byref(beneath), ctypes.c_uint32(0))
        if result:
            raise OSError(err, "landlock_add_rule: " + os.strerror(err))
    finally:
        os.close(parent)
    return fd


def restrict_self(ruleset_fd: int) -> None:
    """Apply the ruleset irreversibly to this thread and its descendants.

    `no_new_privs` is mandatory first: without it the kernel refuses, because
    a restricted process that could regain privilege via setuid would make
    the restriction meaningless.
    """
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0):
        err = ctypes.get_errno()
        raise OSError(err, "prctl(NO_NEW_PRIVS): " + os.strerror(err))
    result, err = syscall(SYS_LANDLOCK_RESTRICT_SELF, ctypes.c_int(ruleset_fd),
                          ctypes.c_uint32(0))
    if result:
        raise OSError(err, "landlock_restrict_self: " + os.strerror(err))


def attempt_read(path: Path) -> dict:
    """Try to read one byte. Record the outcome; never let it raise."""
    try:
        with path.open("rb") as handle:
            handle.read(1)
        return {"path": str(path), "outcome": "READ_SUCCEEDED", "errno": None}
    except OSError as error:
        return {"path": str(path), "outcome": "READ_DENIED",
                "errno": errno.errorcode.get(error.errno, error.errno)}


def child_probe(allowed_file: Path, denied_file: Path, handled: int, allowed: int,
                write_fd: int) -> None:
    """Runs in the forked child. Restricts itself, then reports both attempts.

    Reports through an inherited pipe rather than a file. That is not a
    stylistic choice: an open fd survives `landlock_restrict_self`, but a
    *path* under a handled-write ruleset does not. The first version of this
    probe wrote its result to a path outside the allowed subtree and the
    kernel denied it with EACCES -- accidental proof that enforcement works,
    and the reason the channel must not be a path.

    Every exit goes through `os._exit`, so the child can never unwind into
    the parent's context managers and run their cleanup a second time.
    """
    record = {}
    try:
        fd = build_ruleset(allowed_file.parent, handled, allowed)
        restrict_self(fd)
        os.close(fd)
        record["restricted"] = True
        record["allowed_attempt"] = attempt_read(allowed_file)
        record["denied_attempt"] = attempt_read(denied_file)
        # A second independent predicate needing no extra fixture: the
        # sandbox must also deny a WRITE outside the allowed subtree.
        try:
            with denied_file.open("ab"):
                pass
            record["denied_write_attempt"] = {"outcome": "WRITE_SUCCEEDED", "errno": None}
        except OSError as error:
            record["denied_write_attempt"] = {
                "outcome": "WRITE_DENIED",
                "errno": errno.errorcode.get(error.errno, error.errno)}
    except OSError as error:
        record["restricted"] = False
        record["error"] = {"errno": errno.errorcode.get(error.errno, error.errno),
                           "detail": error.strerror}
    except BaseException as error:  # never let the child escape into the parent
        record["restricted"] = False
        record["error"] = {"errno": "UNEXPECTED", "detail": type(error).__name__}
    try:
        os.write(write_fd, json.dumps(record).encode())
        os.close(write_fd)
    except OSError:
        pass
    os._exit(0)


def run(base_dir=None) -> dict:
    version, err = abi_version()
    lsm_list = Path("/sys/kernel/security/lsm")
    report = {
        "probe": "landlock_runtime_enforcement",
        "kernel": os.uname().release,
        "lsm_list": lsm_list.read_text().strip() if lsm_list.is_file() else "UNAVAILABLE",
        "abi_version": version,
        "abi_errno": errno.errorcode.get(err, err) if version is None else None,
    }
    if version is None:
        report["status"] = "UNAVAILABLE"
        report["conclusion"] = ("landlock_create_ruleset refused the version probe, so "
                                "Landlock is not usable here regardless of CONFIG or the LSM list")
        return report

    handled = ACCESS_FS_READ_FILE | ACCESS_FS_WRITE_FILE | ACCESS_FS_READ_DIR
    allowed = ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR
    with tempfile.TemporaryDirectory(dir=base_dir) as temporary:
        root = Path(temporary)
        inside_dir = root / "inside"
        inside_dir.mkdir()
        allowed_file = inside_dir / "permitted.txt"
        allowed_file.write_text("permitted\n")
        denied_file = root / "forbidden.txt"
        denied_file.write_text("forbidden\n")
        # Prove the fixture is not self-fulfilling: both files must be
        # readable BEFORE any restriction exists.
        report["baseline"] = {"allowed": attempt_read(allowed_file),
                              "denied_target": attempt_read(denied_file)}

        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            child_probe(allowed_file, denied_file, handled, allowed, write_fd)
        os.close(write_fd)
        with os.fdopen(read_fd, "rb") as channel:
            raw = channel.read()
        _, status = os.waitpid(pid, 0)
        report["child_exit_status"] = status
        report["child"] = json.loads(raw) if raw else None

    child = report.get("child") or {}
    if not child.get("restricted"):
        report["status"] = "BLOCKED"
        report["conclusion"] = ("the ruleset could not be applied: " +
                                json.dumps(child.get("error")))
        return report

    baseline_both_readable = (report["baseline"]["allowed"]["outcome"] == "READ_SUCCEEDED"
                              and report["baseline"]["denied_target"]["outcome"] == "READ_SUCCEEDED")
    allow_held = child["allowed_attempt"]["outcome"] == "READ_SUCCEEDED"
    deny_held = (child["denied_attempt"]["outcome"] == "READ_DENIED"
                 and child["denied_attempt"]["errno"] == "EACCES")
    write = child.get("denied_write_attempt") or {}
    write_deny_held = (write.get("outcome") == "WRITE_DENIED"
                       and write.get("errno") == "EACCES")
    report["predicates"] = {
        "baseline_both_files_readable_before_restriction": baseline_both_readable,
        "allowed_subtree_still_readable_after_restriction": allow_held,
        "path_outside_subtree_denied_with_EACCES": deny_held,
        "write_outside_subtree_denied_with_EACCES": write_deny_held,
    }
    if baseline_both_readable and allow_held and deny_held and write_deny_held:
        report["status"] = "ENFORCEMENT_PROVEN"
        report["conclusion"] = (
            "Landlock actually enforced: a path outside the allowed subtree was denied "
            "EACCES in a process that could read it moments earlier, while the allowed "
            "subtree stayed readable. This is EXECUTION-PROVEN, not CONFIG-OBSERVED.")
        report["scope_limit"] = (
            "Proves filesystem-read enforcement under ABI v%s on this kernel only. It "
            "says nothing about network rules, about any other hook, or about whether "
            "root can detach the sandbox from outside the restricted process." % version)
    else:
        report["status"] = "PRESENT_BUT_DID_NOT_ENFORCE"
        report["conclusion"] = ("Landlock accepted the ruleset but the enforcement "
                                "predicates did not hold; treat Landlock as unusable here")
    return report


EXIT = {"ENFORCEMENT_PROVEN": 0, "PRESENT_BUT_DID_NOT_ENFORCE": 1,
        "UNAVAILABLE": 2, "BLOCKED": 2}

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-dir", default=None,
                        help="where to create the throwaway fixture; defaults to TMPDIR")
    outcome = run(parser.parse_args().fixture_dir)
    print(json.dumps(outcome, indent=2))
    sys.exit(EXIT[outcome["status"]])
