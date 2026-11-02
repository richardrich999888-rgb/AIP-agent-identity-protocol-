"""Actual restricted MCP read server and its actual read subprocess, for disposable tests."""
import argparse
import asyncio
import json
import os
import sqlite3
import sys
import time
from pathlib import Path


def child_read(database, loan_id, output):
    with sqlite3.connect('file:' + str(database) + '?mode=ro', uri=True) as connection:
        row = connection.execute('SELECT document_status FROM loan_documents WHERE loan_id=?', (loan_id,)).fetchone()
    if row is None:
        raise ValueError('synthetic loan not found')
    result = {'loan_id': loan_id, 'document_status': row[0], 'recommendation': 'human-review-required', 'bank_record_modified': False}
    output.write_text(json.dumps(result) + '\n')
    print(json.dumps(result), flush=True)
    # Explicit bounded validation instrumentation: keep this genuine read
    # process alive across the probe's 1s drain so procfs identity can be
    # independently bound. The sleep is not the document operation.
    time.sleep(3)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--port', type=int)
    p.add_argument('--read', action='store_true')
    p.add_argument('--database', type=Path, required=True)
    p.add_argument('--work', type=Path, required=True)
    p.add_argument('--loan-id', type=int)
    args = p.parse_args()
    if args.read:
        child_read(args.database, args.loan_id, args.work / ('loan-' + str(args.loan_id) + '-review.json'))
        return
    from mcp.server.mcpserver import MCPServer
    server = MCPServer('vanian-same-run-loan-documents')
    @server.tool()
    async def loan_read(loan_id: int, amount: int = 0) -> dict:
        """Read one synthetic loan document; cannot approve or modify banking records."""
        if type(loan_id) is not int or loan_id not in (1, 2) or amount != 0:
            raise ValueError('unsupported synthetic record/read parameters')
        child = await asyncio.create_subprocess_exec(sys.executable, str(Path(__file__).resolve()), '--read',
            '--database', str(args.database), '--work', str(args.work), '--loan-id', str(loan_id),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        raw, error = await asyncio.wait_for(child.communicate(), timeout=10)
        if child.returncode != 0 or len(raw) > 65536:
            raise ValueError('actual document read subprocess failed')
        event = {'source_authority': 'tool_server_self_report', 'server_pid': os.getpid(), 'child_pid': child.pid,
                 'tool': 'loan_read', 'loan_id': loan_id, 'amount': amount, 'result': json.loads(raw)}
        with (args.work / 'tool-events.jsonl').open('a') as stream:
            stream.write(json.dumps(event) + '\n'); stream.flush(); os.fsync(stream.fileno())
        return event['result']
    server.run(transport='streamable-http', host='127.0.0.1', port=args.port, streamable_http_path='/mcp')

if __name__ == '__main__':
    main()
