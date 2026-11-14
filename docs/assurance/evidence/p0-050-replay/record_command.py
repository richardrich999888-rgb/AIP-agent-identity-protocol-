import datetime
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path('/workspace/scratch/8cbb8ab6ce9d/p050-teach')
OUT = Path('/workspace/scratch/8cbb8ab6ce9d/p050-local')
OUT.mkdir(exist_ok=True)
name, *command = sys.argv[1:]
env = dict(os.environ)
env.update({'PATH': '/workspace/scratch/8cbb8ab6ce9d/p0-048-tools/rust/bin:' + env['PATH'],
            'CARGO_HOME': '/workspace/scratch/8cbb8ab6ce9d/p0-048-tools/cargo-home',
            'CARGO_TARGET_DIR': '/workspace/scratch/8cbb8ab6ce9d/p0-048-tools/target',
            'CARGO_BUILD_JOBS': '4', 'CARGO_TERM_COLOR': 'never',
            'PYTHONPATH': '/workspace/scratch/8cbb8ab6ce9d/p050-tools/python',
            'PYTHONDONTWRITEBYTECODE': '1',
            'SYNTRIASS_BIN': '/workspace/scratch/8cbb8ab6ce9d/p0-048-tools/target/debug/syntriass'})
record = {'command': command, 'cwd': str(ROOT), 'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
          'source_changes': subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True).splitlines(),
          'environment': {k: env[k] for k in ['CARGO_HOME', 'CARGO_TARGET_DIR', 'CARGO_BUILD_JOBS', 'PYTHONPATH', 'SYNTRIASS_BIN']}}
start = time.monotonic()
with (OUT / (name + '.log')).open('xb') as log:
    run = subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
record.update(exit_code=run.returncode, duration_seconds=time.monotonic() - start)
(OUT / (name + '.json')).write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record))
raise SystemExit(run.returncode)
