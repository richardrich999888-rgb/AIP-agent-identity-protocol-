#!/usr/bin/env python3
"""Local Q&A interface over the existing AIP service; historical Linux evidence."""
from __future__ import annotations
import argparse
import contextlib
import json
import os
import secrets
import signal
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]


def serve(agent, api, model, port, ready_file=None):
    nonce = secrets.token_urlsafe(32)
    gate = threading.Lock()
    origins = {f'http://127.0.0.1:{port}', f'http://localhost:{port}'}
    hosts = {f'127.0.0.1:{port}', f'localhost:{port}'}
    runs = api.runs
    status = {'status': 'ready', 'model': model.model, 'frameworks': ['LangChain', 'LangGraph'],
              'inference': 'local', 'api': 'real AIP service; read-only agent access',
              'evidence': 'Recorded Linux execution; no live Mac kernel capture', 'runs': runs}
    status['fresh_observation'] = getattr(api, 'fresh_observation', None)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass  # No questions, credentials or model content in access logs.

        def send(self, status_code, body, content_type='application/json'):
            raw = body if isinstance(body, bytes) else json.dumps(body, allow_nan=False).encode()
            self.send_response(status_code)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(raw)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-" + nonce + "'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'")
            self.end_headers()
            with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                self.wfile.write(raw)

        def valid_host(self):
            return self.headers.get('Host') in hosts

        def do_GET(self):
            if not self.valid_host():
                return self.send(403, {'error': 'Local host required'})
            if self.path == '/':
                page = (HERE/'index.html').read_text().replace('__NONCE__', nonce)
                return self.send(200, page.encode(), 'text/html; charset=utf-8')
            if self.path == '/api/status':
                return self.send(200, status)
            return self.send(404, {'error': 'Not found'})

        def do_POST(self):
            if (not self.valid_host() or self.headers.get('Origin') not in origins
                    or self.headers.get('X-Demo-Nonce') != nonce):
                return self.send(403, {'error': 'Local browser session required'})
            if self.path != '/api/ask':
                return self.send(404, {'error': 'Not found'})
            if self.headers.get('Content-Type') != 'application/json' or self.headers.get('Transfer-Encoding'):
                return self.send(400, {'error': 'JSON required'})
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 1 <= length <= 8192:
                    raise ValueError()
                body = json.loads(self.rfile.read(length))
                if not isinstance(body, dict) or set(body) - {'question', 'run_id'}:
                    raise ValueError()
                question = body.get('question')
                if not isinstance(question, str) or not 1 <= len(question.strip()) <= 1200:
                    raise ValueError()
                run_id = body.get('run_id')
                if run_id is not None and not isinstance(run_id, str):
                    raise ValueError()
            except (ValueError, TypeError, UnicodeError):
                return self.send(400, {'error': 'Enter a question of 1–1,200 characters'})
            if not gate.acquire(blocking=False):
                return self.send(409, {'error': 'The local model is answering another question'})
            started = time.monotonic()
            try:
                answer = agent.ask(question, run_id=run_id)
                answer['elapsed_seconds'] = round(time.monotonic()-started, 2)
                return self.send(200, answer)
            except Exception as exc:
                print('Question failed: ' + type(exc).__name__, file=sys.stderr, flush=True)
                return self.send(422, {'error': 'The model could not complete a valid evidence answer. Try a shorter question; no answer was substituted.'})
            finally:
                gate.release()

    server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    server.daemon_threads = True
    public = {'url': f'http://127.0.0.1:{port}', **status}
    if ready_file:
        ready_file.write_text(json.dumps(public, indent=2)+'\n')
    print(json.dumps(public), flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assets', type=Path, default=Path('/private/tmp/vanian-local-evidence-agent-assets'))
    parser.add_argument('--state', type=Path, default=REPO/'.local/evidence-agent')
    parser.add_argument('--port', type=int, default=18765)
    parser.add_argument('--api-port', type=int, default=18880)
    parser.add_argument('--model-port', type=int, default=11436)
    parser.add_argument('--ready-file', type=Path)
    parser.add_argument('--fresh-evidence', type=Path, help='Original fresh Linux capture package; requires separate operator trust')
    parser.add_argument('--fresh-trust', type=Path, help='Separate approved trust/configuration for the fresh package')
    parser.add_argument('--prepare', action='store_true', help='Download/verify the pinned public assets and prepare Python')
    args = parser.parse_args()
    if (args.fresh_evidence is None) != (args.fresh_trust is None):
        parser.error('--fresh-evidence and --fresh-trust must be supplied together')
    if len({args.port, args.api_port, args.model_port}) != 3 or any(not 1024 <= p <= 65535 for p in (args.port,args.api_port,args.model_port)):
        parser.error('Three distinct unprivileged ports are required')
    from model_runtime import prepare, ModelProcess
    if args.prepare:
        print(json.dumps(prepare(args.assets), indent=2)); return
    for name in ("LANGSMITH_TRACING", "LANGCHAIN_TRACING", "LANGCHAIN_TRACING_V2"):
        os.environ[name] = "false"
    for name in ("LANGSMITH_API_KEY", "LANGCHAIN_API_KEY"):
        os.environ.pop(name, None)
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        os.environ.pop(name, None)
    os.environ["NO_PROXY"] = "127.0.0.1,localhost"
    from api_runtime import APIProcess
    from agent import EvidenceAgent
    args.state.mkdir(parents=True, exist_ok=True, mode=0o700)
    def stopped(_signum, _frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, stopped)
    with ModelProcess(args.assets, port=args.model_port) as model:
        with APIProcess(REPO, args.state, port=args.api_port,
                        fresh_evidence=args.fresh_evidence, fresh_trust=args.fresh_trust) as api:
            agent = EvidenceAgent(api.base_url, api.reader_token, model_base=model.base_url,
                                  model=model.model, seeded_runs=api.runs)
            try:
                serve(agent, api, model, args.port, args.ready_file)
            except KeyboardInterrupt:
                pass

if __name__ == '__main__':
    main()
