#!/usr/bin/env python3
"""M2 — one run: independent authorization -> gateway receipt -> kernel
observation -> offline evaluation -> signed reconciliation. Local host.

What is real here: a live agent process; a decision point (separate process,
its own key) that measures the agent's process instance itself and signs an
ExpectedExecution; a gateway signer (its own key) that checks the received
call against that authorization before dispatching a real tool process and
signs a receipt; the key-less probe and the separate-process collector that
observe and attest the same window; aip-execution-assurance evaluating the
retained archives offline and signing the reconciliation with its own key.

What is NOT here, stated before any result is read:
  * No language model. The agent is a deterministic script; this is not the
    CI same-run harness (validation/enterprise/same_run_validation.py), which
    refuses to run outside GitHub-hosted runners and needs an NTP clock.
  * No MCP server framework (ContextForge). The gateway step is the tree's
    own receipt signer (aip-tool-receipt) driven by this operator script.
  * One host; collector process-separated, not host-separated; the clock is
    unsynchronized (AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK=0, bound signed).
  * The authorized action is tool_invoke. The reconciler has no kernel-
    observable class for a tool call (its classes are net connect/send,
    process exec, file write), so VERIFIED_EXECUTION is NOT an expected
    outcome. The reconciliation verdict is recorded exactly as computed.

Pre-registered PASS for the positive path: archive integrity, checkpoint,
authorization, gateway receipt and signed reconciliation all verified;
receipt received inside the authorization window; disposition Forwarded.
Pre-registered negative controls (each must be refused/flagged):
  N1 agent sends different arguments -> gateway check refuses, Refused receipt
  N2 one attested batch mutated     -> evaluation refuses
  N3 retained checkpoint mismatch   -> evaluation refuses
  N4 receipt signed by an unconfigured key under the gateway's id -> refused
  N5 signed reconciliation substituted from another verdict -> refused

Usage: run_m2.py <outdir>     (root; release binaries built)
"""
import copy
import hashlib
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
B = REPO / 'target/release'
OUT = Path(sys.argv[1]).resolve()
OUT.mkdir(parents=True, exist_ok=True)
W = OUT / 'work'
W.mkdir(mode=0o700, exist_ok=True)
STATE = W / 'state'
STATE.mkdir(mode=0o700, exist_ok=True)
TOOL = 'loan-read'
# Variant parameter, recorded in results: how long the agent process stays
# alive after its last call. 0 reproduces a ~40 ms agent; identity binding
# happens when the probe drains (1 s batches), so it may find the process gone.
LINGER = float(os.environ.get('AGENT_LINGER_S', '0'))
ARGS = {'loan_id': 'L-1001'}
results = {'checks': {}, 'negative_controls': {}}

procs = []


def now_ms():
    return int(time.time() * 1000)


def log(msg):
    print(msg, flush=True)
    with open(OUT / 'transcript.txt', 'a') as f:
        f.write(msg + '\n')


def run(cmd, stdin=None, env=None, check=True):
    p = subprocess.run([str(c) for c in cmd], input=(json.dumps(stdin).encode() if stdin is not None else b''),
                       capture_output=True, env={**os.environ, **(env or {})}, timeout=60)
    if check and p.returncode:
        raise RuntimeError(f'{Path(str(cmd[0])).name} {cmd[1] if len(cmd) > 1 else ""}: {p.stderr.decode().strip()}')
    return p


def private(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(text)


def health_lines():
    p = STATE / 'health.archive.jsonl'
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()] if p.exists() else []


def wait_new_health(base, timeout=120):
    end = time.time() + timeout
    while time.time() < end:
        h = health_lines()
        if len(h) > base:
            time.sleep(0.5)
            return health_lines()
        time.sleep(1)
    raise RuntimeError('no new signed health record')


def stop_all():
    for p in reversed(procs):
        if p.poll() is None:
            p.terminate()
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()


try:
    # ── Observer: key-less probe, separate-process collector (sole key) ──
    if not Path('/sys/kernel/tracing/available_events').exists():
        subprocess.run(['mount', '-t', 'tracefs', 'nodev', '/sys/kernel/tracing'], check=True)
    s = socket.socket(); s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]; s.close()
    private(W / 'pass', 'm2-pass')
    subprocess.run(['timeout', '4', str(B / 'aip-probe')], env={**os.environ, 'AIP_PROBE_ID': 'probe.m2',
        'AIP_PROBE_COLLECTOR_ENDPOINT': '127.0.0.1:1', 'AIP_PROBE_COLLECTOR_NOISE_PUBKEY': '0' * 64,
        'AIP_PROBE_KEY_PATH': str(W / 'probe.key.json'), 'AIP_PROBE_SENSORS': 'sched'}, capture_output=True)
    pub = json.loads((W / 'probe.key.json').read_text())['public_hex']
    (W / 'probes.json').write_text(json.dumps([{'probe_id': 'probe.m2', 'transport_pubkey_hex': pub}]))
    coll = subprocess.Popen([B / 'aip-collector'], stdout=open(W / 'collector.log', 'w'), stderr=subprocess.STDOUT,
        env={**os.environ, 'AIP_COLLECTOR_OBSERVER_ID': 'collector.m2', 'AIP_COLLECTOR_KEY_VERSION': '1',
             'AIP_COLLECTOR_KEY_PATH': str(W / 'collector.key.wrapped'), 'AIP_COLLECTOR_PASSPHRASE_FILE': str(W / 'pass'),
             'AIP_COLLECTOR_STATE_DIR': str(STATE), 'AIP_COLLECTOR_LISTEN': f'127.0.0.1:{port}',
             'AIP_COLLECTOR_PROBES_PATH': str(W / 'probes.json'), 'AIP_COLLECTOR_NOISE_KEY_PATH': str(W / 'noise.key.json'),
             'AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK': '0'})
    procs.append(coll)
    for _ in range(80):
        if (STATE / 'noise.pub').exists() and (STATE / 'observer.pub').exists():
            break
        time.sleep(0.25)
    probe = subprocess.Popen([B / 'aip-probe'], stdout=open(W / 'probe.log', 'w'), stderr=subprocess.STDOUT,
        env={**os.environ, 'AIP_PROBE_ID': 'probe.m2', 'AIP_PROBE_COLLECTOR_ENDPOINT': f'127.0.0.1:{port}',
             'AIP_PROBE_COLLECTOR_NOISE_PUBKEY': (STATE / 'noise.pub').read_text().strip(),
             'AIP_PROBE_KEY_PATH': str(W / 'probe.key.json'),
             'AIP_PROBE_SENSORS': 'sched,sockstate,socksend,connector', 'AIP_PROBE_BATCH_INTERVAL_MS': '1000'})
    procs.append(probe)
    for _ in range(40):
        if 'connected' in (W / 'probe.log').read_text() or probe.poll() is not None:
            break
        time.sleep(0.25)
    if probe.poll() is not None or 'connected' not in (W / 'probe.log').read_text():
        raise RuntimeError('probe did not start: ' + (W / 'probe.log').read_text()[-300:])
    observer_pub = (STATE / 'observer.pub').read_text().strip()
    log(f'observer collector.m2 up; observer.pub {observer_pub[:16]}…')
    base = len(health_lines())
    h = wait_new_health(base)
    log(f'first signed health: {h[-1]["health"]["state"]}')
    # The reconciler gates on Active. Wait (bounded) for it before the task.
    for _ in range(4):
        if h[-1]['health']['state'] == 'Active':
            break
        h = wait_new_health(len(h))
        log(f'signed health: {h[-1]["health"]["state"]}')
    results['observer_state_before_task'] = h[-1]['health']['state']

    # ── Decision point (its own key) provisioned by the operator ─────────
    AUTH = W / 'authority'
    prov = json.loads(run([B / 'aip-execution-assurance', 'init-authority'], stdin={
        'directory': str(AUTH), 'model_id': 'none:deterministic-agent-no-model',
        'allowed_calls': [{'tool_id': TOOL, 'arguments': ARGS}],
        'observer_id': 'collector.m2', 'observer_public_key_hex': observer_pub}).stdout)
    trust_path = Path(prov['run_trust_path'])
    log(f'decision point {prov["decision_point_id"][:24]}… gateway {prov["gateway_id"][:24]}… '
        f'reconciler {prov["reconciler_id"][:24]}…')
    gw_env = {'AIP_GATEWAY_ID': prov['gateway_id'], 'AIP_GATEWAY_KEY_VERSION': '1',
              'AIP_GATEWAY_PUBLIC_KEY': prov['gateway_public_key_hex'],
              'AIP_GATEWAY_KEY_FILE': prov['gateway_key_path'], 'AIP_GATEWAY_RECEIPTS': str(W / 'receipts.jsonl'),
              'AIP_RUN_TRUST_FILE': str(trust_path)}

    # ── The agent: a live process that proposes a tool call ──────────────
    agent_src = OUT / 'agent.py'
    agent_src.write_text(
        'import json,sys\n'
        'print(json.dumps({"propose":{"tool_id":%r,"arguments":%s}}),flush=True)\n'
        'sys.stdin.readline()  # wait for the tool result relayed by the gateway\n'
        'print(json.dumps({"propose_mismatch":{"tool_id":%r,"arguments":{"loan_id":"L-9999"}}}),flush=True)\n'
        'sys.stdin.readline()\n'
        'import time; time.sleep(%s)  # AGENT_LINGER_S: lifetime after its last call\n'
        % (TOOL, json.dumps(ARGS), TOOL, LINGER))
    t_task_start = now_ms()
    agent = subprocess.Popen([sys.executable, '-I', str(agent_src)], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    procs.append(agent)
    proposal = json.loads(agent.stdout.readline())['propose']
    log(f'agent pid {agent.pid} proposed {proposal}')

    # Decision point measures the agent instance ITSELF (pid -> binding);
    # the agent supplies no key, pid or identity.
    auth = json.loads(run([B / 'aip-execution-assurance', 'authorize'], stdin={
        'agent_id': prov['agent_id'], 'process_id': agent.pid, 'tool_id': proposal['tool_id'],
        'arguments': proposal['arguments']}, env={'AIP_AUTHORITY_CONFIG': prov['authority_config_path']}).stdout)
    expectation = auth['expectation']
    did = expectation['decision_id']
    did_hex = did if isinstance(did, str) else bytes(did).hex()
    log(f'signed ExpectedExecution decision_id {did_hex}')

    def gateway(call, label):
        received = now_ms()
        ok = run([B / 'aip-execution-assurance', 'check-authorization'], stdin={
            'expectation': expectation, 'agent_id': prov['agent_id'], 'tool_id': call['tool_id'],
            'arguments': call['arguments'], 'received_at_ms': received}, env=gw_env, check=False)
        authorized = ok.returncode == 0
        response = None
        if authorized:
            # The real tool: a separate process the gateway dispatches.
            loan = W / 'loans' / (call['arguments']['loan_id'] + '.json')
            loan.parent.mkdir(exist_ok=True)
            loan.write_text(json.dumps({'loan_id': call['arguments']['loan_id'], 'status': 'current'}))
            t = subprocess.run(['/bin/cat', str(loan)], capture_output=True, timeout=10)
            response = {'content': t.stdout.decode()}
        rec = json.loads(run([B / 'aip-tool-receipt', 'issue'], stdin={
            'method': 'tools/call', 'tool_name': call['tool_id'], 'arguments': call['arguments'],
            'agent_id': prov['agent_id'], 'decision_id': did_hex, 'tool_call_id': label,
            'headers': {'Mcp-Method': 'tools/call', 'Mcp-Name': call['tool_id']},
            'disposition': 'Forwarded' if authorized else 'Refused', 'response': response,
            'received_at_ms': received}, env=gw_env).stdout)['signed_receipt']
        log(f'gateway {label}: authorized={authorized} disposition={rec["receipt"]["disposition"]}'
            + ('' if authorized else f' (refusal: {ok.stderr.decode().strip()})'))
        return authorized, rec

    authorized, receipt = gateway(proposal, 'call-1')
    agent.stdin.write(b'{}\n'); agent.stdin.flush()
    mismatch = json.loads(agent.stdout.readline())['propose_mismatch']
    m_auth, m_receipt = gateway(mismatch, 'call-2-mismatch')
    results['negative_controls']['N1_mismatched_arguments_refused'] = (not m_auth and m_receipt['receipt']['disposition'] == 'Refused')
    agent.stdin.write(b'{}\n'); agent.stdin.flush()
    agent.wait(10 + LINGER)
    t_task_end = now_ms()

    # Close the window on a signed health record emitted after the task.
    h = wait_new_health(len(health_lines()))
    log(f'signed health after task: {h[-1]["health"]["state"]}')
    results['observer_state_after_task'] = h[-1]['health']['state']
    time.sleep(1.5)
    stop_all()

    # ── Offline evaluation by an operator holding only public anchors ────
    # Freeze the observation chain at the head the newest signed health
    # record attests. The reconciler requires the supplied chain to end
    # exactly there (anything else could be withheld batches); batches
    # attested after it belong to no signed health statement yet.
    health = (STATE / 'health.archive.jsonl').read_text()
    attested_seq = json.loads(health.splitlines()[-1])['health']['sequence']
    all_batches = (STATE / 'attested.archive.jsonl').read_text().splitlines(keepends=True)
    batches = ''.join(l for l in all_batches if l.strip() and json.loads(l)['sequence'] <= attested_seq)
    results['chain_frozen_at_sequence'] = attested_seq
    results['batches_after_freeze_excluded'] = sum(1 for l in all_batches if l.strip()) - batches.count('\n')
    run_id = 'm2-' + did_hex[:16]
    trust = json.loads(trust_path.read_text())
    trust['checkpoints'] = {run_id: {'batches_sha256': hashlib.sha256(batches.encode()).hexdigest(),
                                     'health_sha256': hashlib.sha256(health.encode()).hexdigest()}}
    trust_path.chmod(0o600); trust_path.write_text(json.dumps(trust, indent=2))
    bundle = {'run_id': run_id, 'agent_id': prov['agent_id'], 'expectation': expectation,
              'signed_receipt': receipt, 'batches_jsonl': batches, 'health_jsonl': health,
              'verification_time_ms': now_ms()}
    ev_env = {'AIP_RUN_TRUST_FILE': str(trust_path), 'AIP_RECONCILER_KEY_FILE': prov['reconciler_key_path']}
    signed = json.loads(run([B / 'aip-execution-assurance', 'evaluate-and-sign'], stdin=bundle, env=ev_env).stdout)
    bundle['signed_reconciliation'] = signed['signed_reconciliation']
    final = json.loads(run([B / 'aip-execution-assurance', 'evaluate'], stdin=bundle, env=ev_env).stdout)
    for k in ('archive_integrity_verified', 'checkpoint_verified', 'authorization_verified',
              'gateway_receipt_verified', 'signed_reconciliation_verified', 'receipt_within_authorization'):
        results['checks'][k] = final[k]
    results['checks']['gateway_disposition'] = final['gateway_disposition']
    rec = final['reconciliation'] or {}
    results['reconciliation'] = {k: rec.get(k) for k in ('result', 'strength', 'reason', 'identity', 'action', 'temporal')}
    results['tool_boundary'] = final['tool_boundary']
    results['limitations'] = final['limitations']
    log('reconciliation: ' + json.dumps(results['reconciliation']))

    def refused(b, label):
        p = run([B / 'aip-execution-assurance', 'evaluate'], stdin=b, env=ev_env, check=False)
        log(f'{label}: exit={p.returncode} {p.stderr.decode().strip()[:160]}')
        return p.returncode != 0

    # N2 mutate one attested batch (a signed field inside the batch)
    lines = batches.splitlines(keepends=True)
    i = len(lines) // 2
    rec_b = json.loads(lines[i]); rec_b['batch']['claimed_to_ms'] += 1
    lines[i] = json.dumps(rec_b) + '\n'
    n2 = copy.deepcopy(bundle); n2['batches_jsonl'] = ''.join(lines)
    t2 = copy.deepcopy(trust)
    t2['checkpoints'][run_id]['batches_sha256'] = hashlib.sha256(n2['batches_jsonl'].encode()).hexdigest()
    trust_path.write_text(json.dumps(t2, indent=2))  # checkpoint updated so the SIGNATURE is what is tested
    results['negative_controls']['N2_mutated_batch_refused'] = refused(n2, 'N2 mutated batch')
    trust_path.write_text(json.dumps(trust, indent=2))
    # N3 checkpoint mismatch: one byte appended to the health archive
    n3 = copy.deepcopy(bundle); n3['health_jsonl'] = health + '\n'
    results['negative_controls']['N3_checkpoint_mismatch_refused'] = refused(n3, 'N3 checkpoint mismatch')
    # N4 receipt re-signed by a key the trust file does not anchor
    rogue = W / 'rogue'; rogue.mkdir(mode=0o700)
    rprov = json.loads(run([B / 'aip-execution-assurance', 'init-authority'], stdin={
        'directory': str(rogue / 'a'), 'model_id': 'x', 'allowed_calls': [{'tool_id': TOOL, 'arguments': ARGS}],
        'observer_id': 'collector.m2', 'observer_public_key_hex': observer_pub}).stdout)
    renv = {**gw_env, 'AIP_GATEWAY_PUBLIC_KEY': rprov['gateway_public_key_hex'],
            'AIP_GATEWAY_KEY_FILE': rprov['gateway_key_path'], 'AIP_GATEWAY_RECEIPTS': str(rogue / 'r.jsonl')}
    forged = json.loads(run([B / 'aip-tool-receipt', 'issue'], stdin={
        'method': 'tools/call', 'tool_name': TOOL, 'arguments': ARGS, 'agent_id': prov['agent_id'],
        'decision_id': did_hex, 'tool_call_id': 'call-1', 'headers': {}, 'disposition': 'Forwarded',
        'response': None, 'received_at_ms': receipt['receipt']['received_at_ms']}, env=renv).stdout)['signed_receipt']
    n4 = copy.deepcopy(bundle); n4['signed_receipt'] = forged
    results['negative_controls']['N4_unanchored_gateway_key_refused'] = refused(n4, 'N4 forged receipt')
    # N5 signed reconciliation from a different (mutated) bundle
    n5 = copy.deepcopy(bundle); n5['signed_reconciliation'] = copy.deepcopy(bundle['signed_reconciliation'])
    n5['signed_reconciliation']['reconciliation']['result'] = 'VerifiedExecution'
    results['negative_controls']['N5_substituted_reconciliation_refused'] = refused(n5, 'N5 substituted verdict')

    c = results['checks']
    results['positive_path_pass'] = all(c[k] is True for k in (
        'archive_integrity_verified', 'checkpoint_verified', 'authorization_verified',
        'gateway_receipt_verified', 'signed_reconciliation_verified', 'receipt_within_authorization')) \
        and c['gateway_disposition'] == 'Forwarded'
    results['negative_controls_pass'] = all(results['negative_controls'].values())
    results['task_window_ms'] = [t_task_start, t_task_end]
    results['agent_linger_s'] = LINGER
    # Public evidence kept; keys are not.
    pub_dir = OUT / 'public'; pub_dir.mkdir(exist_ok=True)
    (pub_dir / 'attested.archive.jsonl').write_text(batches)
    (pub_dir / 'health.archive.jsonl').write_text(health)
    (pub_dir / 'observer.pub').write_text(observer_pub + '\n')
    (pub_dir / 'expectation.json').write_text(json.dumps(expectation, indent=2))
    (pub_dir / 'receipts.jsonl').write_text((W / 'receipts.jsonl').read_text())
    (pub_dir / 'evaluation.json').write_text(json.dumps(final, indent=2))
    (pub_dir / 'signed_reconciliation.json').write_text(json.dumps(bundle['signed_reconciliation'], indent=2))
    pt = {k: v for k, v in trust.items()}
    (pub_dir / 'run_trust.public.json').write_text(json.dumps(pt, indent=2))
finally:
    stop_all()
    for name in ('collector.log', 'probe.log'):
        if (W / name).exists():
            shutil.copy(W / name, OUT / name)
    shutil.rmtree(W, ignore_errors=True)   # all private keys live under work/
    (OUT / 'results.json').write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))
