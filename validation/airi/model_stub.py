#!/usr/bin/env python3
"""A local HTTP endpoint standing in for a model provider.

It exists so the subject's "LLM call" is a real TCP connection and a real
syscall, not a function call. It returns a fixed body; nothing about it is a
model and nothing in the experiment depends on what it returns.

No internet access is required or used.
"""
import http.server
import socketserver
import sys
import threading


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"choices":[{"text":"use tool shell:write-marker"}]}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    ready_file = sys.argv[2] if len(sys.argv) > 2 else ""
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("127.0.0.1", port), Handler) as srv:
        actual = srv.server_address[1]
        if ready_file:
            with open(ready_file, "w") as f:
                f.write(str(actual))
        print(f"MODEL_STUB_LISTENING 127.0.0.1:{actual}", flush=True)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            t.join()
        except KeyboardInterrupt:
            srv.shutdown()


if __name__ == "__main__":
    main()
