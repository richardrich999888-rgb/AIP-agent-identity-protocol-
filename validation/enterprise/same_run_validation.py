#!/usr/bin/env python3
"""One genuine local-model -> authority -> MCP -> kernel -> evidence -> enterprise run.

Disposable GitHub Linux only. Collector custody is LOCAL ISOLATION, not separate
administration or host-compromise resistance. No API/model secrets are loaded.
"""
from __future__ import annotations
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import select
import secrets
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'integrations/real_agents'))
from audit_crosscheck import AuditCrosscheck
from evidence import ARCHIVES, Refused, command, covered, event_time, records, sha256, verify
from harness import now, save, tamper, terminate
from prepare_local_model import MANIFEST_SHA256, MODEL, verify_model
from resource_metrics import snapshot as resource_snapshot, report as resource_report

UID_AGENT, UID_TOOL, UID_GATEWAY, UID_MODEL = 10001, 10002, 10003, 10004
MECHANISMS = ['SchedTracepoint', 'Fanotify', 'SockSendTracepoint']
MODEL_ID = 'ollama:' + MODEL + '@sha256:' + MANIFEST_SHA256
TOOL = 'same-run-loan-read'


def request(base, path, token=None, body=None, method=None, extra_headers=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    headers.update(extra_headers or {})
    req = Request(base + path, data=json.dumps(body).encode() if body is not None else None,
                  headers=headers, method=method)
    try:
        with urlopen(req, timeout=10) as response:
            raw = response.read(1048577)
            if len(raw) > 1048576:
                raise Refused('HTTP response limit')
            try:
                value = json.loads(raw) if raw else None
            except ValueError:
                value = None
            return response.status, value
    except HTTPError as error:
        error.close()
        return error.code, None


def ready_http(base, process, path='/health'):
    for _ in range(200):
        if process.poll() is not None:
            raise Refused('service exited before readiness; retain private diagnostics locally')
        try:
            status, _ = request(base, path)
            if status < 500:
                return
        except OSError:
            pass
        time.sleep(0.2)
    raise Refused('service readiness timeout')


def directory(path, uid=0, mode=0o700):
    path.mkdir(mode=mode)
    os.chown(path, uid, uid)
    return path


def protected_json(path, value, uid=0):
    path.write_text(json.dumps(value, indent=2) + '\n')
    path.chmod(0o600); os.chown(path, uid, uid)


def runtime_access(paths_by_uid, public):
    """Grant only ancestor traversal; preflight as each actual runtime UID."""
    changes, checked = [], set()
    for uid, paths in paths_by_uid.items():
        for path, access in paths:
            path = Path(path).absolute()
            for target in (path, path.resolve(strict=True)):
                ancestors = ([target] if target.is_dir() else []) + list(target.parents)
                for ancestor in ancestors:
                    key = (uid, ancestor)
                    if key in checked:
                        continue
                    checked.add(key)
                    status = ancestor.stat()
                    if status.st_uid == uid or status.st_mode & 0o001:
                        continue
                    # A hosted runner parent may be private. Add execute only
                    # to this UID, never directory listing or file-read access.
                    command(['setfacl', '-m', f'u:{uid}:--x', ancestor])
                    changes.append({'uid':uid, 'path':str(ancestor), 'permission':'traverse_only',
                                    'original_mode':oct(status.st_mode & 0o777)})
            probe = subprocess.run(['/usr/bin/python3', '-c',
                'import os,sys; sys.exit(0 if os.access(sys.argv[1],int(sys.argv[2])) else 1)',
                str(path), str(access)], user=uid, group=uid, extra_groups=[],
                cwd='/', env={'PATH':os.defpath}, capture_output=True, timeout=10)
            if probe.returncode:
                save(public/'runtime-access.json', {'ancestor_acl_changes':changes,
                    'failure':{'uid':uid,'public_asset':str(path),'required_access':access}})
                raise Refused('isolated UID cannot access declared public runtime asset')
    save(public/'runtime-access.json', {'status':'PASS','ancestor_acl_changes':changes,
        'scope':'ancestor traversal only; no runner HOME listing/read grant; private service/key directories unchanged'})


class AgentOutput:
    def __init__(self, process, public_log):
        self.process, self.log = process, public_log.open('wb')
        self.buffer = b''
        self.events = []
    def until(self, kind, timeout):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            while b'\n' in self.buffer:
                line, self.buffer = self.buffer.split(b'\n', 1)
                self.log.write(line + b'\n'); self.log.flush()
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                self.events.append(event)
                if event.get('event') == kind:
                    return event
            if self.process.poll() is not None:
                raise Refused('genuine agent exited before ' + kind)
            readable, _, _ = select.select([self.process.stdout], [], [], min(1, max(0, end-time.monotonic())))
            if readable:
                part = os.read(self.process.stdout.fileno(), 65536)
                if not part:
                    raise Refused('agent stdout closed before ' + kind)
                self.buffer += part
                if len(self.buffer) > 1048576:
                    raise Refused('agent output line limit')
        raise Refused('actual agent timeout waiting for ' + kind)
    def close(self):
        self.log.close()


class AuthorityBroker:
    """Root validates kernel peer credentials; caller cannot choose PID or key/config."""
    def __init__(self, socket_path, process, binary, config, decisions, public):
        self.process, self.binary, self.config = process, binary, config
        self.decisions, self.public = decisions, public
        self.failure = None
        self.expectation = None
        self.connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.connection.bind(str(socket_path)); os.chmod(socket_path, 0o666)
        self.connection.listen(2); self.connection.settimeout(360)
        self.thread = threading.Thread(target=self.run, daemon=True)
    def start(self):
        self.thread.start()
    def run(self):
        try:
            with self.connection.accept()[0] as peer:
                pid, uid, _gid = struct.unpack('3i', peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if uid != UID_AGENT or pid != self.process.pid or self.process.poll() is not None:
                    raise Refused('authority caller is not the externally launched live agent')
                peer.settimeout(10)
                data = b''
                while not data.endswith(b'\n'):
                    part = peer.recv(4096)
                    if not part or len(data)+len(part) > 65536:
                        raise Refused('authority request framing/size')
                    data += part
                proposal = json.loads(data)
                if set(proposal) != {'tool_id', 'arguments'}:
                    raise Refused('authority request may not supply keys, PID or identity')
                result = subprocess.run([str(self.binary), 'authorize'], input=json.dumps({
                    'agent_id': self.config['agent_id'], 'process_id': pid, **proposal}),
                    text=True, capture_output=True, timeout=10,
                    env={'PATH':os.defpath, 'AIP_AUTHORITY_CONFIG':self.config['authority_config_path']})
                if result.returncode:
                    peer.sendall(b'{"authorized":false}\n')
                    raise Refused('independent authority denied actual proposed action')
                signed = json.loads(result.stdout)
                expectation = signed['expectation']
                decision_id = bytes(expectation['decision_id']).hex()
                protected_json(self.decisions / (decision_id + '.json'), expectation, UID_GATEWAY)
                save(self.public / 'expectation.json', expectation)
                save(self.public / 'authority-request.json', {
                    'source_authority':'root_authority_controller_SO_PEERCRED', 'peer_pid':pid, 'peer_uid':uid,
                    'actual_proposal':proposal, 'authority_sig':expectation['decision_sig']})
                self.expectation = expectation
                peer.sendall(json.dumps({'authorized':True, 'decision_id':decision_id}).encode()+b'\n')
        except Exception as error:
            self.failure = type(error).__name__ + ': ' + str(error)
        finally:
            self.connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tools', type=Path, required=True)
    parser.add_argument('--contextforge-source', type=Path, required=True)
    parser.add_argument('--agent-python', type=Path, required=True)
    parser.add_argument('--client-python', type=Path, required=True)
    parser.add_argument('--model-root', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--browser', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0 or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or sys.platform != 'linux':
        raise Refused('root on explicitly disposable GitHub Linux required')
    tools = args.tools.resolve(); source = args.contextforge_source.resolve(); model_root = args.model_root.resolve()
    binary = tools / 'aip-execution-assurance'
    if subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip() != 'ff6a566a4b5c098093db90bbb4d5df483e108026':
        raise Refused('ContextForge source pin changed')
    if sha256(source / 'uv.lock') != '76ef83096d34d7a95aca91407cbf085c3da1e0c937616d86da393b9549117f0c':
        raise Refused('ContextForge dependency lock changed')
    verify_model(model_root / 'models')
    out = args.out.resolve(); out.mkdir(mode=0o755)
    public = directory(out / 'public', mode=0o755)
    private = directory(out / 'private')
    services = directory(out / 'services', mode=0o711)
    gateway_dir = directory(services / 'gateway', UID_GATEWAY)
    model_home = directory(services / 'model', UID_MODEL)
    control = directory(out / 'control', mode=0o755)
    trusted_bin = directory(control / 'bin', mode=0o755)
    for executable in ('aip-execution-assurance', 'aip-tool-receipt'):
        shutil.copyfile(tools / executable, trusted_bin / executable)
        (trusted_bin / executable).chmod(0o755)
    binary = trusted_bin / 'aip-execution-assurance'
    workload = directory(out / 'work', mode=0o755)
    processes, streams = [], []
    audits = []
    namespace = 'vanian-' + secrets.token_hex(5)
    original_net = os.open('/proc/self/ns/net', os.O_RDONLY)
    cg = Path('/sys/fs/cgroup') / namespace
    mounted = False
    namespace_created = False
    agent_output = None
    trust_path = None
    tool_work = None
    result = {'status':'FAIL', 'autonomous_workload_executed':False, 'run_id':'same-run-'+secrets.token_hex(12),
        'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        'model_id':MODEL_ID, 'task':'Read synthetic loan 1 and recommend human review, without approving/changing records.',
        'collector_custody':'LOCAL_ISOLATION_SHARED_KERNEL_AND_ROOT', 'separate_administrative_custody':'INCOMPLETE',
        'model_cloud_api_spend':0, 'model_api_credentials_used':False,
        'kernel':os.uname().release, 'started_at_ms':now()}
    save(public / 'run-manifest.json', result)
    def in_host(operation):
        current = os.open('/proc/self/ns/net', os.O_RDONLY)
        try:
            os.setns(original_net, 0)
            return operation()
        finally:
            os.setns(current, 0); os.close(current)
    libc = ctypes.CDLL(None, use_errno=True)
    last_cap = int(Path('/proc/sys/kernel/cap_last_cap').read_text())
    def spawn(name, executable, env=None, uid=0, resource=False, stdin=None, stdout=None, host=False):
        log = (private / (name+'.log')).open('wb'); streams.append(log)
        invocation = [str(x) for x in executable]
        def restrict():
            if host:
                os.setns(original_net, 0)
            if resource:
                (cg / 'cgroup.procs').write_text(str(os.getpid()))
            if uid:
                if libc.prctl(38, 1, 0, 0, 0) != 0:
                    raise OSError(ctypes.get_errno(), 'PR_SET_NO_NEW_PRIVS')
                for capability in range(last_cap + 1):
                    if libc.prctl(24, capability, 0, 0, 0) != 0:
                        raise OSError(ctypes.get_errno(), 'PR_CAPBSET_DROP')
                os.setgroups([]); os.setgid(uid); os.setuid(uid)
        child = subprocess.Popen(invocation, env={'PATH':os.environ['PATH'],'LANG':'C.UTF-8',**(env or {})},
            cwd=workload, stdin=stdin, stdout=stdout if stdout is not None else log, stderr=log,
            preexec_fn=restrict, pass_fds=(original_net,) if host else (), umask=0o077, bufsize=0)
        processes.append(child)
        return child
    def checkpoint(state):
        for name in ARCHIVES:
            shutil.copyfile(state / name, public / name)
        return {'sha256':{name:sha256(public/name) for name in ARCHIVES}}
    try:
        python = source/'.venv/bin/python'
        runtime_access({
            UID_MODEL:[(model_root/'bin/ollama',os.R_OK|os.X_OK),
                       (model_root/'lib/ollama',os.R_OK|os.X_OK),
                       (model_root/'models',os.R_OK|os.X_OK)],
            UID_TOOL:[(python,os.R_OK|os.X_OK),(ROOT/'validation/enterprise/same_run_upstream.py',os.R_OK),
                      (workload,os.X_OK)],
            UID_GATEWAY:[(python,os.R_OK|os.X_OK),(source,os.R_OK|os.X_OK),
                         (ROOT/'integrations/mcp-gateway',os.R_OK|os.X_OK),(trusted_bin,os.R_OK|os.X_OK),
                         (workload,os.X_OK)],
            UID_AGENT:[(args.agent_python.absolute(),os.R_OK|os.X_OK),
                       (ROOT/'examples/bank-ai-execution-assurance/loan_agent.py',os.R_OK),(workload,os.X_OK)],
        },public)
        if command(['timedatectl','show','--property=NTPSynchronized','--value']).strip() != 'yes':
            raise Refused('host clock not synchronized')
        trace = Path('/sys/kernel/tracing/available_events')
        if not trace.exists():
            command(['mount','-t','tracefs','nodev','/sys/kernel/tracing'])
        for event in ('sched:sched_process_exec','cgroup:cgroup_attach_task','sock:sock_send_length'):
            if event not in trace.read_text():
                raise Refused('required sensor tracepoint unavailable: '+event)
        command(['mount','-t','tmpfs','-o','size=128m,mode=755','tmpfs',workload]); mounted = True
        agent_work = directory(workload / 'agent', UID_AGENT)
        tool_work = directory(workload / 'tool', UID_TOOL)
        db = tool_work / 'synthetic-loans.sqlite3'
        with sqlite3.connect(db) as connection:
            connection.execute('CREATE TABLE loan_documents (loan_id INTEGER PRIMARY KEY, document_status TEXT NOT NULL)')
            connection.executemany('INSERT INTO loan_documents VALUES (?,?)',[(1,'Synthetic document: identity and income evidence require human review.'),(2,'Synthetic alternative record, outside the issued loan1 authorization.')])
        db.chmod(0o444); os.chown(db, UID_TOOL, UID_TOOL)
        available = set(Path('/sys/fs/cgroup/cgroup.controllers').read_text().split())
        required = {'cpu', 'memory', 'pids'}
        if not required <= available:
            raise Refused('required cgroup resource controllers unavailable')
        enabled = set(Path('/sys/fs/cgroup/cgroup.subtree_control').read_text().split())
        if required - enabled:
            Path('/sys/fs/cgroup/cgroup.subtree_control').write_text(' '.join('+'+x for x in sorted(required-enabled)))
        cg.mkdir()
        (cg/'memory.max').write_text(str(8*1024**3))
        (cg/'pids.max').write_text('512')
        (cg/'cpu.max').write_text('200000 100000')
        save(public/'resource-limits.json', {'memory_bytes':8*1024**3,'pids':512,'cpu_max':'200000 100000','agent_deadline_seconds':360})
        command(['ip','netns','add',namespace]); namespace_created = True
        command(['ip','-n',namespace,'link','set','lo','up'])
        with open('/var/run/netns/'+namespace) as ns:
            os.setns(ns.fileno(), 0)
        save(public/'network-isolation.json', {'namespace':namespace,'links':json.loads(command(['ip','-j','address'])),
            'routes':json.loads(command(['ip','-j','route'])), 'policy':'loopback only; no external interface or route; actual agent deny probe required'})
        model = spawn('model', [model_root/'bin/ollama','serve'], {
            'HOME':str(model_home), 'OLLAMA_MODELS':str(model_root/'models'),
            'LD_LIBRARY_PATH':str(model_root/'lib/ollama'), 'OLLAMA_HOST':'127.0.0.1:11434',
            'OLLAMA_NO_CLOUD':'1','OLLAMA_NOPRUNE':'1','OLLAMA_NUM_PARALLEL':'1','OLLAMA_MAX_LOADED_MODELS':'1',
            'OLLAMA_MAX_QUEUE':'1','OLLAMA_CONTEXT_LENGTH':'2048','OLLAMA_KEEP_ALIVE':'10m'},UID_MODEL,True)
        ready_http('http://127.0.0.1:11434',model,'/api/version')
        status, tags = request('http://127.0.0.1:11434','/api/tags')
        if status != 200 or not any(item['name']==MODEL and item['digest']==MANIFEST_SHA256 for item in tags['models']):
            raise Refused('running model digest not the approved local model')
        save(public/'model-tags.json',tags)
        shutil.copyfile(model_root/'model-pin.json',public/'model-pin.json')
        # Warm the CPU model before establishing the measurement window. This is
        # actual inference, never used as a replacement for the agent's responses.
        warm = Request('http://127.0.0.1:11434/api/generate',data=json.dumps({'model':MODEL,'prompt':'','stream':False,'keep_alive':'10m','options':{'num_ctx':2048,'num_thread':2}}).encode(),headers={'Content-Type':'application/json'})
        with urlopen(warm,timeout=120) as response:
            json.loads(response.read(65536))
        state = directory(private/'collector-state')
        probe_env = {'AIP_PROBE_ID':'probe.same-run','AIP_PROBE_COLLECTOR_ENDPOINT':'127.0.0.1:1',
            'AIP_PROBE_COLLECTOR_NOISE_PUBKEY':'0'*64,'AIP_PROBE_KEY_PATH':str(private/'probe.key.json'),'AIP_PROBE_SENSORS':'sched'}
        probe = spawn('probe-enrollment',[tools/'aip-probe'],probe_env,host=True)
        for _ in range(50):
            if (private/'probe.key.json').exists(): break
            time.sleep(0.1)
        terminate(probe)
        protected_json(private/'probes.json',[{'probe_id':'probe.same-run','transport_pubkey_hex':json.loads((private/'probe.key.json').read_text())['public_hex']}])
        (private/'collector-pass').write_text(secrets.token_urlsafe(48)); (private/'collector-pass').chmod(0o600)
        collector = spawn('collector',[tools/'aip-collector'],{
            'AIP_COLLECTOR_OBSERVER_ID':'collector.same-run','AIP_COLLECTOR_KEY_VERSION':'1',
            'AIP_COLLECTOR_KEY_PATH':str(private/'collector.key.wrapped'), 'AIP_COLLECTOR_PASSPHRASE_FILE':str(private/'collector-pass'),
            'AIP_COLLECTOR_STATE_DIR':str(state),'AIP_COLLECTOR_LISTEN':'127.0.0.1:19991',
            'AIP_COLLECTOR_PROBES_PATH':str(private/'probes.json'),'AIP_COLLECTOR_NOISE_KEY_PATH':str(private/'noise.key.json'),
            'AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK':'1','AIP_COLLECTOR_CONTINUITY':'strict'},host=True)
        for _ in range(100):
            if (state/'noise.pub').exists(): break
            if collector.poll() is not None: raise Refused('collector startup failed')
            time.sleep(0.1)
        anchor = {'observer_id':'collector.same-run','key_version':1,'public_key':(state/'observer.pub').read_text().strip()}
        save(out/'observer-anchor.json',anchor)
        authority = directory(private/'authority')
        initialized = json.loads(command([binary,'init-authority'],input=json.dumps({'directory':str(authority),'model_id':MODEL_ID,
            'allowed_calls':[{'tool_id':TOOL,'arguments':{'loan_id':1,'amount':0}}],
            'observer_id':anchor['observer_id'],'observer_public_key_hex':anchor['public_key']})))
        shutil.copyfile(initialized['gateway_key_path'],gateway_dir/'gateway.key')
        os.chown(gateway_dir/'gateway.key',UID_GATEWAY,UID_GATEWAY); (gateway_dir/'gateway.key').chmod(0o600)
        trust_path = Path(initialized['run_trust_path'])
        save(out/'run-trust.json',json.loads(trust_path.read_text()))
        protected_json(gateway_dir/'trust.json',json.loads(trust_path.read_text()),UID_GATEWAY)
        decisions = directory(gateway_dir/'decisions',UID_GATEWAY)
        import jwt
        secret = secrets.token_hex(32)
        admin, principal = 'operator@vanian.example','agent@vanian.example'
        def token(email, is_admin):
            return jwt.encode({'sub':email,'user':{'email':email,'is_admin':is_admin},'is_admin':is_admin,
                'teams':None if is_admin else [],'token_use':'api','jti':secrets.token_hex(16),'aud':'mcpgateway-api',
                'iss':'mcpgateway','iat':int(time.time()),'exp':int(time.time())+900},secret,algorithm='HS256')
        admin_token, agent_token = token(admin,True),token(principal,False)
        config = {'plugin_dirs':[str(ROOT/'integrations/mcp-gateway')],
            'plugin_settings':{'parallel_execution_within_band':False,'plugin_timeout':15,'fail_on_plugin_error':True,'include_user_info':True},
            'plugins':[{'name':'VanianToolReceipt','kind':'vanian_contextforge.VanianToolReceiptPlugin',
                'hooks':['tool_pre_invoke','tool_post_invoke'],'mode':'sequential','on_error':'fail','priority':2147483647,
                'config':{'signer_binary':str(trusted_bin/'aip-tool-receipt'),'authorization_binary':str(binary),
                    'replay_database':str(gateway_dir/'requests.sqlite3'),'tools':[TOOL],
                    'agent_principals':{principal:initialized['agent_id']},'require_authorization':True,
                    'authorized_decisions_directory':str(decisions)}}]}
        protected_json(gateway_dir/'plugins.json',config,UID_GATEWAY)
        headers = ['X-AIP-Agent-Id','X-AIP-Decision-Id','X-AIP-Request-Id','Mcp-Method','Mcp-Name']
        gateway_env = {'HOME':str(gateway_dir),'PYTHONPATH':os.pathsep.join([str(source),str(ROOT/'integrations/mcp-gateway')]),
            'PYTHONUNBUFFERED':'1','DATABASE_URL':'sqlite:///'+str(gateway_dir/'gateway.sqlite3'),
            'JWT_SECRET_KEY':secret,'AUTH_ENCRYPTION_SECRET':secrets.token_hex(32),'PLATFORM_ADMIN_EMAIL':admin,
            'PLATFORM_ADMIN_PASSWORD':secrets.token_urlsafe(32),'DEFAULT_USER_PASSWORD':secrets.token_urlsafe(32),'BASIC_AUTH_PASSWORD':secrets.token_urlsafe(32),
            'AUTH_REQUIRED':'true','MCP_REQUIRE_AUTH':'true','EMAIL_AUTH_ENABLED':'true','MCP_ALLOWED_ORIGINS':json.dumps(['http://127.0.0.1:19992']),
            'SECURE_COOKIES':'false','ENVIRONMENT':'development','EMBED_ENVIRONMENT_IN_TOKENS':'false','VALIDATE_TOKEN_ENVIRONMENT':'false',
            'PLUGINS_ENABLED':'true','PLUGINS_CONFIG_FILE':str(gateway_dir/'plugins.json'),'ENABLE_HEADER_PASSTHROUGH':'true',
            'PASSTHROUGH_HEADERS_SOURCE':'env','DEFAULT_PASSTHROUGH_HEADERS':json.dumps(headers),
            'SSRF_ALLOW_LOCALHOST':'true','SSRF_ALLOW_PRIVATE_NETWORKS':'false','TOOL_TIMEOUT':'20','MAX_TOOL_RETRIES':'0',
            'GATEWAY_TOOL_NAME_SEPARATOR':'-','MCPGATEWAY_UI_ENABLED':'false','MCPGATEWAY_ADMIN_API_ENABLED':'true',
            'AIP_GATEWAY_KEY_FILE':str(gateway_dir/'gateway.key'),'AIP_GATEWAY_PUBLIC_KEY':initialized['gateway_public_key_hex'],
            'AIP_GATEWAY_ID':initialized['gateway_id'],'AIP_GATEWAY_KEY_VERSION':'1','AIP_GATEWAY_RECEIPTS':str(gateway_dir/'receipts.jsonl'),
            'AIP_RUN_TRUST_FILE':str(gateway_dir/'trust.json'),'AIP_AUTHORIZATION_DIR':str(decisions)}
        python = source/'.venv/bin/python'
        upstream = spawn('upstream',[python,ROOT/'validation/enterprise/same_run_upstream.py','--port','19993','--database',db,'--work',tool_work],
            {'HOME':str(tool_work),'PYTHONUNBUFFERED':'1'},UID_TOOL,True)
        ready_http('http://127.0.0.1:19993',upstream,'/mcp')
        gateway = spawn('gateway',[python,'-m','uvicorn','mcpgateway.main:app','--host','127.0.0.1','--port','19992','--no-access-log'],gateway_env,UID_GATEWAY,True)
        base = 'http://127.0.0.1:19992'; ready_http(base,gateway)
        status, _ = request(base,'/gateways',admin_token,{'name':'same-run','url':'http://127.0.0.1:19993/mcp',
            'transport':'STREAMABLEHTTP','passthrough_headers':headers,'visibility':'public'})
        if status not in (200,201): raise Refused('actual MCP upstream registration failed')
        status, tools_list = request(base,'/tools?limit=0',admin_token)
        registered_tools = tools_list if isinstance(tools_list,list) else tools_list.get('tools',[]) if isinstance(tools_list,dict) else []
        save(public/'registered-tool-identities.json',{'source_authority':'gateway_admin_registration_response','tools':[{k:t.get(k) for k in ('name','original_name','id','gateway_id')} for t in registered_tools]})
        if status != 200 or not any(tool.get('name')==TOOL for tool in registered_tools):
            raise Refused('actual registered canonical MCP tool identity differs from exact authority policy')
        status, _ = request(base,'/auth/email/admin/users',admin_token,{'email':principal,'password':secrets.token_urlsafe(32)+'Aa1!',
            'full_name':'Disposable read-only agent','is_admin':False})
        if status != 201: raise Refused('non-admin gateway principal creation failed')
        status, role = request(base,'/rbac/roles',admin_token,{'name':'same_run_tool_reader','scope':'global',
            'permissions':['tools.read','tools.execute'],'description':'Only read/execute public allowlisted test tools.'})
        if status not in (200,201): raise Refused('restricted gateway role creation failed')
        status, _ = request(base,'/rbac/users/'+quote(principal,safe='')+'/roles',admin_token,
            {'role_id':role['id'],'scope':'global'})
        if status not in (200,201): raise Refused('restricted gateway role assignment failed')
        status, assignments = request(base,'/rbac/users/'+quote(principal,safe='')+'/roles',admin_token)
        if status != 200 or not isinstance(assignments,list):
            raise Refused('cannot inspect default gateway role assignments')
        for assignment in assignments:
            if assignment['scope']=='global' and assignment['role_id']!=role['id']:
                status, _ = request(base,'/rbac/users/'+quote(principal,safe='')+'/roles/'+assignment['role_id']+'?scope=global',admin_token,method='DELETE')
                if status != 200: raise Refused('cannot revoke automatic broad gateway role')
        status, permissions = request(base,'/rbac/my/permissions',agent_token)
        if status != 200 or set(permissions) != {'tools.read','tools.execute'}:
            raise Refused('agent gateway permissions exceed explicitly permitted tool reads')
        save(public/'gateway-agent-permissions.json',{'source_authority':'gateway_effective_RBAC','permissions':permissions,'is_admin':False,'jwt_team_scope':[]})
        denied_registration={'name':'forbidden-agent-registration','url':'http://127.0.0.1:19993/mcp','transport':'STREAMABLEHTTP','visibility':'public'}
        if request(base,'/gateways',agent_token,denied_registration,method='POST')[0] != 403:
            raise Refused('agent token did not refuse gateway administration')
        probe_env.update(AIP_PROBE_COLLECTOR_ENDPOINT='127.0.0.1:19991',
            AIP_PROBE_COLLECTOR_NOISE_PUBKEY=(state/'noise.pub').read_text().strip(),
            AIP_PROBE_SENSORS='sched,cgroup,connector,fanotify,sockstate,socksend',
            AIP_PROBE_FANOTIFY_PATH=str(workload),AIP_PROBE_BATCH_INTERVAL_MS='1000')
        probe = spawn('probe',[tools/'aip-probe'],probe_env,host=True)
        for uid in (UID_AGENT,UID_TOOL):
            audit = AuditCrosscheck()
            audit.rule[audit.rule.index('euid=10001')] = 'euid='+str(uid)
            in_host(audit.start); audits.append(audit)
        for _ in range(40):
            time.sleep(2)
            if probe.poll() is not None or collector.poll() is not None: raise Refused('observer exited')
            if not all((state/name).exists() for name in ARCHIVES): continue
            cp=checkpoint(state); verify(public,tools,anchor,cp)
            health=records(public/ARCHIVES[1]); window=health[-1]['health'].get('attested_coverage')
            if window and covered(health,window['to_ms']-1,window['to_ms'],MECHANISMS): break
        else: raise Refused('signed Active coverage unavailable')
        command(['iptables','-A','OUTPUT','-m','owner','--uid-owner',str(UID_AGENT),'-d','127.0.0.1','-p','tcp','-m','multiport','--dports','11434,19992','-j','ACCEPT'])
        command(['iptables','-A','OUTPUT','-m','owner','--uid-owner',str(UID_AGENT),'-j','REJECT'])
        save(public/'agent-egress-policy.json',{'source_authority':'root_namespace_network_policy','rules':command(['iptables','-S','OUTPUT']),'allowed_agent_tcp_destinations':['127.0.0.1:11434','127.0.0.1:19992'],'direct_mcp_upstream':'DENIED_BY_UID_OUTPUT_RULE'})
        start=now(); time.sleep(1)
        agent_env={'HOME':str(agent_work),'PYTHONUNBUFFERED':'1','VANIAN_BANK_MEASURED':'1','VANIAN_BANK_MODEL':MODEL,
            'VANIAN_BANK_GATEWAY_BASE_URL':base,'VANIAN_BANK_GATEWAY_TOKEN':agent_token,'VANIAN_BANK_TOOL_NAME':TOOL,
            'VANIAN_BANK_AGENT_ID':initialized['agent_id'],'VANIAN_BANK_AUTHORITY_SOCKET':str(control/'authority.sock'),
            'VANIAN_BANK_FORBIDDEN_FILES':json.dumps([str(Path(initialized['authority_config_path'])),str(gateway_dir/'gateway.key'),str(private/'collector.key.wrapped')])}
        agent=spawn('agent',[args.agent_python.absolute(),ROOT/'examples/bank-ai-execution-assurance/loan_agent.py'],agent_env,UID_AGENT,True,subprocess.PIPE,subprocess.PIPE)
        agent_output=AgentOutput(agent,public/'agent-events.jsonl')
        actual_ready=agent_output.until('ready',30)
        if actual_ready['pid'] != agent.pid or actual_ready['uid'] != UID_AGENT:
            raise Refused('readiness process did not match externally launched instance')
        metric_processes={'probe':probe.pid,'collector':collector.pid,'model':model.pid,'gateway':gateway.pid,'upstream':upstream.pid,'agent':agent.pid}
        metrics_before=resource_snapshot(metric_processes,cg)
        broker=AuthorityBroker(control/'authority.sock',agent,binary,initialized,decisions,public)
        broker.start(); agent.stdin.write(b'start\n'); agent.stdin.flush()
        agent_deadline=time.monotonic()+360
        agent_output.until('tool_result',max(1,agent_deadline-time.monotonic()))
        broker.thread.join(timeout=10)
        if broker.failure or broker.expectation is None:
            raise Refused(broker.failure or 'authority did not issue an expectation')
        mismatch_id=secrets.token_hex(16)
        mismatch_arguments={'loan_id':2,'amount':0}
        mismatch_decision=bytes(broker.expectation['decision_id']).hex()
        stimulus={'source_authority':'root_validation_controller','actor':'controlled negative request, not agent/model output',
            'request_id':mismatch_id,'decision_id':mismatch_decision,'actual_sent_arguments':mismatch_arguments,'sent_at_ms':now()}
        mismatch_status,mismatch_reply=request(base,'/rpc',agent_token,{'jsonrpc':'2.0','id':mismatch_id,'method':'tools/call',
            'params':{'name':TOOL,'arguments':mismatch_arguments}},extra_headers={
                'X-AIP-Agent-Id':initialized['agent_id'],'X-AIP-Decision-Id':mismatch_decision,'X-AIP-Request-Id':mismatch_id})
        stimulus.update(http_status=mismatch_status,response=mismatch_reply)
        save(public/'parameter-mismatch-stimulus.json',stimulus)
        if mismatch_status==200 and mismatch_reply and 'result' in mismatch_reply and not mismatch_reply['result'].get('isError',False):
            raise Refused('mismatched parameters were dispatched instead of refused')
        agent_output.until('complete',max(1,agent_deadline-time.monotonic()))
        broker.thread.join(timeout=10)
        if broker.failure or broker.expectation is None:
            raise Refused(broker.failure or 'authority did not issue an expectation')
        metrics_after=resource_snapshot(metric_processes,cg)
        agent.stdin.write(b'finish\n'); agent.stdin.flush()
        if agent.wait(timeout=10) != 0: raise Refused('genuine agent returned failure')
        result['autonomous_workload_executed']=True
        time.sleep(1); end=now()
        result.update(agent_id=initialized['agent_id'],agent_pid=agent.pid,from_ms=start,to_ms=end,
            elapsed_ms=end-start,model_calls=len([e for e in agent_output.events if e.get('event')=='model_response']))
        for _ in range(30):
            time.sleep(2); cp=checkpoint(state); verify(public,tools,anchor,cp)
            if covered(records(public/ARCHIVES[1]),start,end,MECHANISMS): break
        else: raise Refused('actual workload window lacks signed Active coverage')
        for index,audit in enumerate(audits):
            save(public/f'audit-{index}-status.json',in_host(lambda: audit.export(public/f'audit-{index}.log')))
            in_host(audit.close)
        terminate(probe)
        # Freeze capture, then require the collector's latest signed health
        # to acknowledge the complete retained chain. Never trim signed tails
        # or select an older Active record merely to obtain a verdict.
        for _ in range(25):
            time.sleep(2); cp=checkpoint(state); verify(public,tools,anchor,cp)
            final_batch=records(public/ARCHIVES[0])[-1]
            final_health=records(public/ARCHIVES[1])[-1]['health']
            if (final_health['sequence']==final_batch['sequence']
                    and final_health['head']==final_batch['attestation']['payload_hash']):
                break
        else: raise Refused('collector did not sign health for the complete frozen observation chain')
        terminate(collector)
        cp=checkpoint(state); save(out/'checkpoint.json',cp)
        save(public/'offline-verification.json',verify(public,tools,anchor,cp))
        performance=resource_report(metrics_before,metrics_after,public)
        save(public/'performance.json',performance)
        save(public/'tamper.json',tamper(public,tools,anchor,cp))
        (public/'observer.pub').write_text(anchor['public_key']+'\n')
        tool_events=records(tool_work/'tool-events.jsonl')
        save(public/'tool-events.json',tool_events)
        target_pids=[agent.pid,tool_events[-1]['child_pid']]
        bound_instances = {}
        expected_binding = broker.expectation['execution_binding']
        for signed_batch in records(public/ARCHIVES[0]):
            for kernel_event in signed_batch['batch']['kernel_events']:
                bound = kernel_event.get('bound')
                when = event_time(signed_batch['batch'], kernel_event)
                if not bound or bound['process']['pid'] not in target_pids or when is None or not start <= when <= end:
                    continue
                if bound['process']['pid'] == agent.pid and when < expected_binding['bound_at_ms']:
                    continue
                process_id = bound['process']['pid']
                if process_id == agent.pid and (bound['process'] != expected_binding['process'] or bound['exe_content_sha256'] != expected_binding['exe_content_sha256']):
                    raise Refused('independently observed agent binding differs from actual signed authority binding')
                if bound['process']['pid_start_time_ticks'] > 0:
                    bound_instances[str(process_id)] = bound
        if set(bound_instances) != {str(pid) for pid in target_pids}:
            raise Refused('actual agent or tool child lacks independent full process-instance binding')
        save(public/'kernel-bound-instances.json',{'source_authority':'signed_collector_kernel_observations','instances':bound_instances,'logical_tool_to_kernel_causality':'not established by PID/self-report alone'})
        for index,pid in enumerate(target_pids):
            comparison=json.loads(command([tools/'aip-corroborate','--observer-id',anchor['observer_id'],'--key-version','1',
                '--pubkey-file',public/'observer.pub','--batches',public/ARCHIVES[0],'--external',public/f'audit-{index}.log',
                '--source','auditd','--from-ms',start,'--to-ms',end,'--json']))
            save(public/f'corroboration-{index}.json',comparison)
            if not any(x['aip']['pid']==pid for x in comparison['agreed']) or any(x['pid']==pid for x in comparison['aip_only']) or comparison['external_only'] or comparison['external_unparsed']:
                raise Refused('actual agent/tool exec independent audit disagreement')
        shutil.copyfile(gateway_dir/'receipts.jsonl',public/'receipts.jsonl')
        signed_receipts=records(public/'receipts.jsonl')
        matching=[r for r in signed_receipts if r['receipt']['decision_id']==broker.expectation['decision_id'] and r['receipt']['disposition']=='Forwarded']
        if len(matching)!=1: raise Refused('actual authorized request has no unique trustworthy Forwarded receipt')
        mismatch_receipts=[r for r in signed_receipts if r['receipt']['tool_call_id']==mismatch_id]
        if len(mismatch_receipts)!=1 or mismatch_receipts[0]['receipt']['disposition']!='Refused':
            raise Refused('controlled parameter mismatch has no unique signed refusal receipt')
        save(public/'parameter-mismatch-receipt.json',mismatch_receipts[0])
        if len(tool_events)!=1 or tool_events[0]['loan_id']!=1:
            raise Refused('mismatch changed the actual MCP upstream execution count/record')
        trust=json.loads(trust_path.read_text()); trust['checkpoints'][result['run_id']]={
            'batches_sha256':cp['sha256'][ARCHIVES[0]],'health_sha256':cp['sha256'][ARCHIVES[1]]}
        protected_json(trust_path,trust)
        # Independently retained operator trust: never inside agent/gateway writable directories.
        save(out/'run-trust.json',trust)
        bundle={'run_id':result['run_id'],'agent_id':initialized['agent_id'],'expectation':broker.expectation,
            'signed_receipt':matching[0],'batches_jsonl':(public/ARCHIVES[0]).read_text(),
            'health_jsonl':(public/ARCHIVES[1]).read_text(),'verification_time_ms':now()}
        env={'PATH':os.environ['PATH'],'AIP_RUN_TRUST_FILE':str(trust_path)}
        sign_started=time.perf_counter()
        signed=json.loads(command([binary,'evaluate-and-sign'],input=json.dumps(bundle),env={**env,
            'AIP_RECONCILER_KEY_FILE':initialized['reconciler_key_path'],'AIP_RECONCILER_ID':initialized['reconciler_id'],
            'AIP_RECONCILER_PUBLIC_KEY':initialized['reconciler_public_key_hex']}))
        sign_elapsed=(time.perf_counter()-sign_started)*1000
        bundle['signed_reconciliation']=signed['signed_reconciliation']
        save(public/'run-bundle.json',bundle)
        evaluation_started=time.perf_counter()
        evaluation=json.loads(command([binary,'evaluate'],input=json.dumps(bundle),env=env))
        performance['reconciliation_cli_wall_time_ms']={'evaluate_and_sign':sign_elapsed,'offline_evaluate':(time.perf_counter()-evaluation_started)*1000,'scope':'controller wall time including CLI process startup and all verification work; not isolated reconciler CPU'}
        save(public/'performance.json',performance)
        save(public/'evaluation.json',evaluation)
        save(public/'signed-reconciliation.json',signed['signed_reconciliation'])
        command([sys.executable,ROOT/'validation/enterprise/evaluate_captured_negatives.py',
            '--binary',binary,'--bundle',public/'run-bundle.json','--trust',trust_path,
            '--output',public/'captured-negatives.json'],timeout=120)
        # Actual synthetic result file was produced by the observed tool subprocess.
        shutil.copyfile(tool_work/'loan-1-review.json',public/'loan-1-review.json')
        api_dir=directory(private/'api')
        keys=[]; credentials={}
        for name,tenant,role in [('writer','same-run-a','machine'),('reader','same-run-a','reader'),('other','same-run-b','reader')]:
            value=secrets.token_urlsafe(32); credentials[name]=api_dir/(name+'.key')
            credentials[name].write_text(value); credentials[name].chmod(0o600)
            keys.append({'key_id':name,'tenant_id':tenant,'role':role,'secret_sha256':hashlib.sha256(value.encode()).hexdigest()})
        protected_json(api_dir/'keys.json',{'keys':keys})
        protected_json(api_dir/'trust.json',{'tenants':[{'tenant_id':'same-run-a','trust':trust}]})
        api=spawn('api',[tools/'airon-aip'],{'AIP_PORT':'19994','AIP_KEY_PATH':str(api_dir/'service.key'),
            'AIP_REVOCATION_LOG_PATH':str(api_dir/'revocations.jsonl'),'AIP_VAULT_PATH':str(api_dir/'evidence.jsonl'),
            'AIP_ARTIFACT_PATH':str(api_dir/'artifacts.jsonl'),'AIP_API_KEYS_PATH':str(api_dir/'keys.json'),
            'AIP_RUN_TRUST_PATH':str(api_dir/'trust.json'),'AIP_STORE_BACKEND':'jsonl'})
        ready_http('http://127.0.0.1:19994',api,'/.well-known/aip-configuration')
        clients=[args.client_python.absolute(),ROOT/'validation/enterprise/run_client_smoke.py','--url','http://127.0.0.1:19994',
            '--writer-key-file',credentials['writer'],'--reader-key-file',credentials['reader'],'--other-key-file',credentials['other'],
            '--bundle',public/'run-bundle.json','--output',public/'enterprise-clients.json']
        if args.browser: clients += ['--browser','--screenshot',public/'console.png']
        command(clients,timeout=120,env={**os.environ,'PYTHONPATH':str(ROOT/'sdk/python')})
        result.update(status='PASS',agent_id=initialized['agent_id'],agent_pid=agent.pid,tool_child_pid=target_pids[1],
            from_ms=start,to_ms=end,elapsed_ms=end-start,signed_batches=len(records(public/ARCHIVES[0])),
            signed_health_records=len(records(public/ARCHIVES[1])),model_calls=len([e for e in agent_output.events if e.get('event')=='model_response']),
            signed_receipts=len(signed_receipts),evaluation=evaluation,
            observation_coverage='SIGNED_ACTIVE_FOR_WINDOW',logical_subagent_attribution='NOT_ESTABLISHED',
            business_outcome='Synthetic read only; no loan approval or bank transaction',finished_at_ms=now())
    except Exception as error:
        result['failure']={'type':type(error).__name__,'detail':str(error)}
        raise
    finally:
        cleanup_errors = []
        def cleanup(step, operation):
            try:
                return operation()
            except Exception as error:
                cleanup_errors.append({'step':step,'type':type(error).__name__,'detail':str(error)})
        for audit in audits:
            cleanup('remove_audit_rule', lambda: in_host(audit.close))
        for child in reversed(processes): cleanup('terminate_child', lambda: terminate(child))
        if agent_output: cleanup('close_agent_output', agent_output.close)
        for stream in streams: cleanup('close_log', stream.close)
        probe_log=private/'probe.log'
        if probe_log.is_file():
            # Retain only the fixed numeric diagnostic, never framework logs,
            # authentication data or arbitrary probe stderr.
            diagnostics=[line for line in probe_log.read_text(errors='replace').splitlines()
                if re.fullmatch(r'AIP_PERF_QUERY_BPF_ERROR errno=-?\d+ cpu=\d+ fd=\d+',line)]
            save(public/'probe-query-diagnostics.json',{'source_authority':'probe_kernel_query_diagnostic',
                'lines':diagnostics,'effect':'failed query remains Unverifiable and resets signed coverage'})
        # Preserve any independently signed partial archives from a failed run.
        state=private/'collector-state'
        for name in ARCHIVES:
            if (state/name).is_file(): cleanup('retain_archive', lambda: shutil.copyfile(state/name,public/name))
        # Public anchors and the controller's checkpoint survive a coverage
        # refusal too. They establish retained bytes, never successful scope.
        if all((public/name).is_file() for name in ARCHIVES):
            failure_cp={'sha256':{name:sha256(public/name) for name in ARCHIVES}}
            save(out/'checkpoint.json',failure_cp)
            if trust_path is not None and trust_path.is_file():
                retained_trust=json.loads(trust_path.read_text())
                retained_trust['checkpoints'][result['run_id']]={
                    'batches_sha256':failure_cp['sha256'][ARCHIVES[0]],
                    'health_sha256':failure_cp['sha256'][ARCHIVES[1]]}
                save(out/'run-trust.json',retained_trust)
        if (gateway_dir/'receipts.jsonl').is_file():
            cleanup('retain_gateway_receipts',lambda: shutil.copyfile(gateway_dir/'receipts.jsonl',public/'receipts.jsonl'))
        if tool_work is not None:
            for source_name,target_name in [('tool-events.jsonl','tool-events.jsonl'),('loan-1-review.json','loan-1-review.json')]:
                if (tool_work/source_name).is_file():
                    cleanup('retain_synthetic_tool_result',lambda: shutil.copyfile(tool_work/source_name,public/target_name))
        cleanup('restore_host_network',lambda: os.setns(original_net,0))
        cleanup('close_host_network',lambda: os.close(original_net))
        # A child can leave descendants behind. Kill the whole dedicated
        # cgroup before unmounting the working directory, and ensure the
        # controller itself holds no cwd reference to that mount.
        cleanup('restore_controller_cwd',lambda: os.chdir(ROOT))
        if cg.exists():
            usage = {}
            for name in ('memory.peak','memory.events','cpu.stat','pids.peak'):
                if (cg/name).exists(): usage[name] = (cg/name).read_text()
            save(public/'resource-usage.json',usage)
            if (cg/'cgroup.kill').exists(): cleanup('kill_cgroup',lambda: (cg/'cgroup.kill').write_text('1'))
            for _ in range(40):
                try:
                    cg.rmdir(); break
                except OSError:
                    time.sleep(0.1)
            if cg.exists(): cleanup_errors.append({'step':'remove_cgroup','type':'Busy','detail':'dedicated cgroup remained after termination'})
        if namespace_created: cleanup('delete_network_namespace',lambda: command(['ip','netns','delete',namespace]))
        if mounted:
            def unmount():
                status=subprocess.run(['umount',str(workload)],cwd='/',capture_output=True,text=True,timeout=10)
                if status.returncode:
                    # This fixed command reports only the public mount path;
                    # it cannot contain framework credentials.
                    raise Refused(f'umount exited {status.returncode}: {status.stderr.strip()[:512]}')
            cleanup('unmount_workload',unmount)
        result['cleanup_errors']=cleanup_errors
        result['finished_at_ms']=now()
        if cleanup_errors and result['status']=='PASS':
            result['status']='FAIL'
            result['failure']={'type':'CleanupFailure','detail':'disposable runtime cleanup did not complete'}
        save(public/'run-manifest.json',result)
        # Preserve the original execution exception when both work and
        # cleanup fail. A successful run still requires successful cleanup.
        if cleanup_errors and sys.exc_info()[0] is None:
            raise Refused('disposable runtime cleanup did not complete')
    print(json.dumps(result))

if __name__=='__main__':
    main()
