#!/usr/bin/env bash
# Run a command inside a fresh user+net namespace with only loopback up.
# Refuses to run if any external route is reachable (fail closed).
#   usage: offline.sh CMD [ARGS...]
set -euo pipefail
if [[ "${CM_IN_NETNS:-0}" != "1" ]]; then
  exec env CM_IN_NETNS=1 unshare --user --map-root-user --net -- "$0" "$@"
fi
python3 -I -c 'import fcntl,socket,struct
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
f=struct.unpack("16sH14x",fcntl.ioctl(s,0x8913,struct.pack("16sH14x",b"lo",0)))[1]
fcntl.ioctl(s,0x8914,struct.pack("16sH14x",b"lo",f|0x41))'
if python3 -I -c 'import socket; socket.create_connection(("1.1.1.1",443),timeout=2)' 2>/dev/null; then
  echo "external route present; refusing" >&2; exit 1
fi
exec "$@"
