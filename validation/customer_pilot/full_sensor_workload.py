#!/usr/bin/env python3
"""Controlled real OS actions for service qualification; not an AI workload."""
import argparse
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time


def emit(value):
    print(json.dumps(value), flush=True)


def echo(args):
    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((args.host, args.port)); server.listen(16)
        emit({'status': 'READY', 'pid': os.getpid(), 'uid': os.getuid()})
        while True:
            connection, _ = server.accept()
            with connection:
                connection.settimeout(5)
                remaining = 4096
                while remaining:
                    data = connection.recv(remaining)
                    if not data: break
                    connection.sendall(data)
                    remaining -= len(data)


def worker(args):
    work, alternate, cgroup = map(Path, (args.work_dir, args.alternate_dir, args.cgroup_dir))
    for directory in (work, alternate, cgroup):
        if not directory.is_dir(): raise RuntimeError('required owned workload directory missing')
    emit({'status': 'READY', 'pid': os.getpid(), 'uid': os.getuid()})
    serial = 0
    for line in sys.stdin:
        request = json.loads(line)
        if request == {'op': 'quit'}:
            emit({'status': 'STOPPED'}); return
        phase = request.get('phase', '')
        if request.get('op') != 'exercise' or not re.fullmatch(r'[a-z][a-z0-9-]{0,40}', phase):
            raise ValueError('unsupported controlled workload request')
        counts = {'watched_files': 0, 'alternate_files': 0, 'tcp_echoes': 0,
                  'child_processes': 0, 'cgroups_created_and_removed': 0}
        for _ in range(3):
            serial += 1
            tag = f'{phase}-{serial}'
            payload = ('controlled-sensor-test:' + tag + '\n').encode()
            for directory, key in ((work, 'watched_files'), (alternate, 'alternate_files')):
                with (directory / (tag + '.txt')).open('xb') as stream:
                    stream.write(payload); stream.flush(); os.fsync(stream.fileno())
                counts[key] += 1
            with socket.create_connection((args.host, args.port), timeout=5) as connection:
                connection.sendall(payload)
                received = b''
                while len(received) < len(payload):
                    chunk = connection.recv(len(payload) - len(received))
                    if not chunk: raise RuntimeError('echo peer closed early')
                    received += chunk
                if received != payload: raise RuntimeError('echo mismatch')
            counts['tcp_echoes'] += 1
            child = subprocess.Popen(['/bin/sleep', '1'])
            try:
                group = cgroup / ('sensor-' + tag); group.mkdir(); group.rmdir()
                counts['cgroups_created_and_removed'] += 1
            finally:
                if child.wait(timeout=5) != 0: raise RuntimeError('controlled child failed')
            counts['child_processes'] += 1
            time.sleep(0.2)
        emit({'status': 'DONE', 'phase': phase, 'pid': os.getpid(), 'uid': os.getuid(), 'counts': counts})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='mode', required=True)
    for name in ('worker', 'echo'):
        p = commands.add_parser(name); p.add_argument('--host', required=True); p.add_argument('--port', type=int, required=True)
        if name == 'worker':
            for option in ('work-dir', 'alternate-dir', 'cgroup-dir'): p.add_argument('--' + option, required=True)
    args = parser.parse_args()
    (worker if args.mode == 'worker' else echo)(args)


if __name__ == '__main__': main()
