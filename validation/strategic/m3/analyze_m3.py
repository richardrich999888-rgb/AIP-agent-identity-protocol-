#!/usr/bin/env python3
"""Per-run M3 judgement under the rules fixed in run_m3.sh's header."""
import json
import os
import re
import sys

OUT = sys.argv[1]
runs = []
for line in open(os.path.join(OUT, 'agent.log')):
    m = re.match(r'\[(\w+)\] AGENT_RESULT parent_pid=(\d+) child_pid=(\d+) exit_code=(\d+)', line)
    if m:
        runs.append({'framework': m[1], 'parent': int(m[2]), 'child': int(m[3]), 'exit': int(m[4])})

verified = 'verify_exit=0' in open(os.path.join(OUT, 'offline_verify.txt')).read() and \
    re.search(r'^VERIFIED', open(os.path.join(OUT, 'offline_verify.txt')).read(), re.M) is not None
lineage_txt = open(os.path.join(OUT, 'delegation_chain.txt')).read()
edges = {(int(a), int(b)) for a, b in re.findall(r'parent pid=(\d+) .*?->\s+child pid=(\d+)', lineage_txt)}

present, bound_exec = set(), set()
for line in open(os.path.join(OUT, 'attested.archive.jsonl')):
    if not line.strip():
        continue
    for e in json.loads(line)['batch']['kernel_events']:
        name, v = next(iter(e['kind'].items()))
        if isinstance(v, dict):
            for x in v.values():
                if isinstance(x, int):
                    present.add(x)
        if e['mechanism'] == 'SchedTracepoint' and name == 'ProcessExec' and e.get('bound'):
            bound_exec.add(v['pid'])

per_fw = {}
for r in runs:
    r['present'] = r['parent'] in present and r['child'] in present
    r['child_exec_bound'] = r['child'] in bound_exec
    r['edge'] = (r['parent'], r['child']) in edges
    f = per_fw.setdefault(r['framework'], {'runs': 0, 'agent_exit_0': 0, 'present': 0, 'child_exec_bound': 0, 'edge': 0})
    f['runs'] += 1
    f['agent_exit_0'] += r['exit'] == 0
    for k in ('present', 'child_exec_bound', 'edge'):
        f[k] += r[k]
result = {'offline_verified': verified, 'edges_total_in_archive': len(edges),
          'edges_not_from_any_agent_run': len(edges - {(r['parent'], r['child']) for r in runs}),
          'per_framework': per_fw, 'runs': runs,
          'params': open(os.path.join(OUT, 'params.txt')).read().splitlines()}
cost = os.path.join(OUT, 'probe_cost.txt')
if os.path.exists(cost):
    c = dict(kv.split('=') for kv in open(cost).read().split())
    result['probe_cpu_s'] = int(c['probe_cpu_ticks']) / int(c['clk_tck'])
    result['probe_wall_s'] = int(c['probe_wall_s'])
json.dump(result, open(os.path.join(OUT, 'results.json'), 'w'), indent=2)
print(json.dumps({k: result.get(k) for k in ('offline_verified', 'probe_cpu_s', 'probe_wall_s', 'edges_total_in_archive',
                                         'edges_not_from_any_agent_run', 'per_framework')}, indent=2))
