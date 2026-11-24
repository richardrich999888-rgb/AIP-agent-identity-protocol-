#!/usr/bin/env python3
"""Negative operations in an exact copy of the probe service security profile.

Every target is an explicit disposable canary. No real customer file or other
process memory is touched. Results are observations, never a confinement proof.
"""
import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
import select
import signal
import sys
import time


def operation(name, args):
    libc = ctypes.CDLL(None, use_errno=True)
    if name in ('outside_write', 'host_root_write', 'other_root_write', 'state_symlink_write'):
        path = args.outside_writable
        if name == 'host_root_write': path = '/proc/1/root' + path
        if name == 'other_root_write': path = f'/proc/{args.outside_pid}/root' + path
        if name == 'state_symlink_write': path = '/proc/1/root' + args.state_symlink
        try:
            with open(path, 'ab', buffering=0) as stream: stream.write(b'UNEXPECTED-PROBE-WRITE\n')
            return {'allowed': True}
        except OSError as error: return {'allowed': False, 'errno': error.errno}
    if name == 'outside_hardlink':
        # Both aliases use the host mount view; a private read-only bind mount
        # must not turn this into an unrelated EXDEV refusal.
        source = '/proc/1/root' + args.outside_writable
        target = '/proc/1/root' + str(Path(args.output).parent / 'outside-hardlink')
        try:
            os.link(source, target, follow_symlinks=False)
        except OSError as error: return {'allowed': False, 'errno': error.errno}
        try:
            os.unlink(target)
            cleanup_failed = False
        except OSError:
            cleanup_failed = True
        return {'allowed': True, 'cleanup_failed': cleanup_failed}
    if name == 'private_read':
        try:
            with open(args.outside_private, 'rb') as stream: size = len(stream.read(128))
            return {'allowed': True, 'bytes_read': size, 'content_retained': False}
        except OSError as error: return {'allowed': False, 'errno': error.errno}
    if name == 'mount':
        libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_void_p]
        libc.mount.restype = ctypes.c_int
        value = libc.mount(b'none', os.fsencode(args.mount_target), b'tmpfs', 0, None)
    elif name == 'unshare':
        libc.unshare.argtypes = [ctypes.c_int]; libc.unshare.restype = ctypes.c_int
        value = libc.unshare(0x00020000)  # CLONE_NEWNS, this disposable child only.
    elif name == 'ptrace':
        libc.ptrace.restype = ctypes.c_long
        value = libc.ptrace(ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_void_p(), ctypes.c_void_p())
    elif name == 'process_vm_writev':
        class IOVec(ctypes.Structure):
            _fields_ = [('base', ctypes.c_void_p), ('length', ctypes.c_size_t)]
        source, destination = ctypes.create_string_buffer(b'B'), ctypes.create_string_buffer(b'A')
        local, remote = IOVec(ctypes.addressof(source), 1), IOVec(ctypes.addressof(destination), 1)
        libc.process_vm_writev.argtypes = [ctypes.c_int, ctypes.POINTER(IOVec), ctypes.c_ulong, ctypes.POINTER(IOVec), ctypes.c_ulong, ctypes.c_ulong]
        libc.process_vm_writev.restype = ctypes.c_ssize_t
        value = libc.process_vm_writev(os.getpid(), ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
    else: raise ValueError('unknown negative operation')
    return {'allowed': value >= 0, 'return_value': value, 'errno': ctypes.get_errno() if value < 0 else None}


def isolated(name, args):
    read_fd, write_fd = os.pipe(); pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            result = operation(name, args)
            os.write(write_fd, json.dumps(result).encode()); os._exit(0)
        except BaseException:
            os.write(write_fd, b'{"error":"negative operation could not run"}'); os._exit(1)
    os.close(write_fd)
    reaped = False
    try:
        if not select.select([read_fd], [], [], 8)[0]: raise RuntimeError('negative operation timed out')
        data = os.read(read_fd, 8192)
        deadline = time.monotonic() + 3
        while True:
            done, _ = os.waitpid(pid, os.WNOHANG)
            if done:
                reaped = True
                break
            if time.monotonic() >= deadline: raise RuntimeError('negative child did not exit')
            time.sleep(0.02)
        return json.loads(data)
    finally:
        os.close(read_fd)
        if not reaped:
            try: os.kill(pid, signal.SIGKILL); os.waitpid(pid, 0)
            except ProcessLookupError: pass
            except ChildProcessError: pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'outside-writable', 'outside-private', 'mount-target'): parser.add_argument('--' + name, required=True)
    parser.add_argument('--outside-pid', type=int, required=True)
    parser.add_argument('--state-symlink', required=True)
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() == 0: raise RuntimeError('requires actual nonroot Linux service identity')
    status = {}
    for line in Path('/proc/self/status').read_text().splitlines():
        key, _, value = line.partition(':')
        if key in ('Uid', 'Gid', 'CapEff', 'CapBnd', 'CapAmb', 'NoNewPrivs', 'Seccomp'): status[key] = value.strip()
    operations = {name: isolated(name, args) for name in ('outside_write', 'host_root_write', 'other_root_write', 'state_symlink_write', 'outside_hardlink', 'mount', 'unshare', 'ptrace', 'process_vm_writev', 'private_read')}
    forbidden = ('outside_write', 'host_root_write', 'other_root_write', 'state_symlink_write', 'outside_hardlink', 'mount', 'unshare', 'ptrace', 'process_vm_writev')
    failures = [name for name in forbidden if operations[name].get('allowed') is not False or operations[name].get('errno') not in (errno.EPERM, errno.EACCES, errno.EROFS)]
    label = Path('/proc/self/attr/current').read_text().strip()
    result = {'status': 'FAIL' if failures else 'PASS', 'process_status': status, 'lsm_label': label, 'operations': operations, 'failed_negative_controls': failures,
              'broad_read_access_observed': operations['private_read'].get('allowed'),
              'scope': 'Disposable canaries only; allowed private read records residual CAP_DAC_READ_SEARCH visibility, not customer isolation.'}
    Path(args.output).write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'failed_negative_controls': failures}), flush=True)
    return int(bool(failures))


if __name__ == '__main__': raise SystemExit(main())
