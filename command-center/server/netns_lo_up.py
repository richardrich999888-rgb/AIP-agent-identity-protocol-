"""Bring up `lo` in the current network namespace (for `unshare -n` test runs).

No `ip` binary is assumed. It uses the SIOCGIFFLAGS and SIOCSIFFLAGS
ioctls. Afterwards it checks that an outside name does not resolve, so a
test run under it is offline by construction. It exits non-zero otherwise.
"""

import fcntl
import socket
import struct
import sys

SIOCGIFFLAGS, SIOCSIFFLAGS, IFF_UP = 0x8913, 0x8914, 0x1
OUTSIDE_NAME = "pypi.org"

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ifr = struct.pack("16sH14s", b"lo", 0, b"\0" * 14)
flags = struct.unpack("16sH14s", fcntl.ioctl(s, SIOCGIFFLAGS, ifr))[1]
fcntl.ioctl(s, SIOCSIFFLAGS, struct.pack("16sH14s", b"lo", flags | IFF_UP, b"\0" * 14))
try:
    socket.getaddrinfo(OUTSIDE_NAME, 443)
    sys.exit(f"{OUTSIDE_NAME} resolves: not isolated")
except OSError:
    print("netns: loopback up, outside unreachable")
