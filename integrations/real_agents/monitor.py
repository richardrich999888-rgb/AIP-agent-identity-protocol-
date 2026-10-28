#!/usr/bin/env python3
"""Read-only, loopback-only status viewer. No archive browser or secret export."""
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PAGE = b'''<!doctype html><html lang="en"><meta charset="utf-8"><title>Sniffer Dog runs</title>
<style>body{font:16px system-ui;background:#101923;color:#ecf3fa;margin:3rem;max-width:1100px}
section{border:1px solid #596b7e;border-radius:8px;padding:1rem;margin:1rem 0}
pre{white-space:pre-wrap;overflow-wrap:anywhere}small{color:#aabdd0}</style>
<h1>Sniffer Dog workload observation</h1>
<p>Declared framework identity and controller status are not signed execution evidence.</p>
<small>OBSERVED: signed kernel report. AUTHORITY_VERIFIED: independently checked authority.
RECONCILED: authorization matched observed effects. UNATTRIBUTED: identity unestablished.
INTEGRITY_UNKNOWN: observation coverage insufficient. CANNOT_PROVE: required evidence missing.</small>
<main id="runs"></main><script>
async function refresh(){const root=document.getElementById('runs');try{
const response=await fetch('/status');if(!response.ok)throw Error('status unavailable');
const runs=await response.json();root.replaceChildren();
if(!runs.length)root.textContent='No runs recorded. No validation claimed.';
for(const run of runs){const box=document.createElement('section'),h=document.createElement('h2');
h.textContent=(run.framework||'Unknown framework')+' / '+run.status;box.append(h);
const pre=document.createElement('pre');pre.textContent=JSON.stringify(run,null,2);box.append(pre);root.append(box);}
}catch(e){root.textContent='INTEGRITY_UNKNOWN: '+e.message;}}
refresh();setInterval(refresh,2000);</script></html>'''


def handler(directory):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/":
                data, content = PAGE, "text/html; charset=utf-8"
            elif self.path == "/status":
                runs = []
                for path in sorted(directory.glob("*/status.json")):
                    if path.is_symlink() or not path.resolve().is_relative_to(directory):
                        continue
                    try:
                        runs.append(json.loads(path.read_text()))
                    except (OSError, ValueError):
                        runs.append({"status": "INTEGRITY_UNKNOWN", "reason": "unreadable status"})
                data, content = json.dumps(runs).encode(), "application/json"
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", content)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass
    return Handler


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    ThreadingHTTPServer(("127.0.0.1", args.port), handler(args.directory.resolve())).serve_forever()
