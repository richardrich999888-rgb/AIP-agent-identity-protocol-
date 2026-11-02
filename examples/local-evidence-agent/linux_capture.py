#!/usr/bin/env python3
"""Observe the real local EvidenceAgent on a disposable GitHub Linux runner.

Existing probe/collector formats, strict coverage and Rust offline verifiers are
reused. No QA answer is promoted to signed application-action proof. Collector
custody is local UID isolation under one trusted kernel/root administrator.
"""
from __future__ import annotations
import argparse
import ctypes
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / 'integrations/real_agents'))
sys.path.insert(0, str(ROOT / 'validation/enterprise'))
from audit_crosscheck import AuditCrosscheck
from evidence import ARCHIVES, Refused, command, covered, event_time, records, sha256, summarize, verify
from harness import now, proc_identity, save, tamper, terminate
from same_run_validation import AgentOutput, directory, runtime_access
from api_runtime import APIProcess
from linux_workload import QUESTIONS, validate_result, focus_groups_from_source

MECHANISMS = ['SchedTracepoint', 'CgroupTracepoint', 'ProcConnector', 'Fanotify',
              'SockStateTracepoint', 'SockSendTracepoint']
SOURCE_FILES = ('examples/local-evidence-agent/agent.py', 'examples/local-evidence-agent/linux_workload.py',
    'examples/local-evidence-agent/linux_capture.py', 'examples/local-evidence-agent/api_runtime.py',
    'examples/local-evidence-agent/linux_model_runtime.py', 'examples/local-evidence-agent/requirements.lock',
    'sdk/python/vanian/__init__.py', 'sdk/python/vanian/client.py', 'aip-service/src/main.rs',
    'examples/local-evidence-agent/model_runtime.py', 'examples/local-evidence-agent/model.lock.json',
    'examples/local-evidence-agent/linux_model.lock.json', 'validation/enterprise/same_run_validation.py',
    'integrations/real_agents/evidence.py', 'integrations/real_agents/harness.py',
    'integrations/real_agents/audit_crosscheck.py', 'validation/enterprise/prepare_local_model.py')


def request(base, path, body=None, timeout=10):
    address = urlsplit(base)
    if address.scheme != 'http' or address.hostname != '127.0.0.1' or address.path:
        raise Refused('controller service origin must be literal loopback')
    conn = http.client.HTTPConnection('127.0.0.1', address.port, timeout=timeout)
    try:
        raw = None if body is None else json.dumps(body).encode()
        conn.request('GET' if raw is None else 'POST', path, body=raw,
                     headers={'Content-Type':'application/json'})
        response = conn.getresponse()
        if response.status != 200:
            raise Refused('controller local service HTTP failure')
        data = response.read(262145)
        if len(data) > 262144:
            raise Refused('controller service response limit')
        return json.loads(data)
    finally:
        conn.close()


def source_identity():
    return {'source_commit':command(['git','rev-parse','HEAD'],cwd=ROOT).strip(),
            'files':{name:sha256(ROOT/name) for name in SOURCE_FILES}}


def measured_launch(pid):
    launch = proc_identity(pid)
    launch.update(probe_id='probe.local.qa', exe_content_sha256=list(bytes.fromhex(sha256(Path(f'/proc/{pid}/exe')))))
    return launch


def questions_for(catalog):
    rows = {row['profile']:row for row in catalog}
    return [{'case_id':i, 'profile':profile, 'question':text,
             'run_artifact_id':rows[profile]['run_artifact_id']} for i,(profile,text) in enumerate(QUESTIONS,1)]


def public_outputs(work, public, run_id, source_commit):
    """Copy only four known regular QA outputs, never service/config/key files."""
    answer_files = {}
    (public/'answers').mkdir(exist_ok=True)
    work_fd=os.open(work,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        try:answers_fd=os.open('answers',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=work_fd)
        except FileNotFoundError:answers_fd=None
        except OSError:raise Refused('unsafe workload answer directory') from None
        if answers_fd is not None:
            try:
                for index in range(1,5):
                    name=f'case-{index}.json';relative='answers/'+name
                    try:
                        before=os.stat(name,dir_fd=answers_fd,follow_symlinks=False)
                        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=answers_fd)
                    except FileNotFoundError:continue
                    except OSError:raise Refused('unsafe workload output open') from None
                    try:
                        actual=os.fstat(fd)
                        if (not stat.S_ISREG(actual.st_mode) or actual.st_size>262144 or actual.st_uid!=10001
                                or actual.st_nlink!=1 or (before.st_dev,before.st_ino)!=(actual.st_dev,actual.st_ino)):
                            raise Refused('unsafe or changed workload output file')
                        with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(262145)
                        if len(raw)>262144:raise Refused('workload output read exceeds bound')
                    finally:os.close(fd)
                    json.loads(raw)
                    (public/relative).write_bytes(raw)
                    answer_files[relative]=hashlib.sha256(raw).hexdigest()
            finally:os.close(answers_fd)
    finally:os.close(work_fd)
    output = {'schema':'vanian-local-qa-output-manifest-v1', 'run_id':run_id,
              'source_commit':source_commit, 'answer_files':answer_files,
              'task_manifest_sha256':sha256(public/'task-manifest.json') if (public/'task-manifest.json').exists() else None,
              'launch_sha256':sha256(public/'launch.json') if (public/'launch.json').exists() else None,
              'result_scope':'ROOT_CONTROLLER_APPLICATION_CORRELATION',
              'signed_by_collector':False,
              'limit':'Hashes associate controller-collected QA files with this process run; kernel observations do not sign answer contents or prove application semantics.'}
    save(public/'task-output-manifest.json',output)
    return output


def signed_answer_paths(batches, launch, start):
    paths=set()
    for signed in batches:
        for event in signed['batch']['kernel_events']:
            stamp=event_time(signed['batch'],event)
            bound=event.get('bound')
            if stamp is None or stamp<start or not bound or bound.get('process')!=launch['process']:
                continue
            if (bound.get('exe_content_sha256')!=launch['exe_content_sha256'] or
                    any((bound.get('container') or {}).get(key)!=launch['container'][key]
                        for key in ('pid_ns_inode','mnt_ns_inode','net_ns_inode'))):
                continue
            file=event['kind'].get('FileEvent')
            if isinstance(file,dict) and isinstance(file.get('path'),str):paths.add(file['path'])
    return paths


def actual_model_context(identity, resident):
    matches=[row for row in resident.get('models',[]) if row.get('name')==identity['model']['model']+':latest'
             and row.get('digest')==identity['model']['manifest_sha256']]
    if len(matches)!=1 or type(matches[0].get('context_length')) is not int or matches[0]['context_length']!=8192:
        raise Refused('actual capture model context or manifest differs')
    return {'status':'PASS','canonical_model':matches[0]['name'],'manifest_sha256':matches[0]['digest'],
            'actual_service_context_length':matches[0]['context_length'],'actual_service_vram_bytes':matches[0].get('size_vram'),
            'source_authority':'ROOT_CONTROLLER_HTTP_RESPONSE_NOT_KERNEL_PROOF'}


def controller_trust(out, public, run_id, source_commit, anchor, checkpoint):
    files = {}
    public.chmod(0o755)
    for path in sorted(public.rglob('*')):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise Refused('unsafe public artifact path')
        if path.is_dir():path.chmod(0o755)
        if path.is_file():
            path.chmod(0o444)  # Public allowlisted evidence, never private logs/keys.
            files[path.relative_to(public).as_posix()] = sha256(path)
    trust = {'schema':'vanian-local-qa-controller-trust-v1', 'publication_role':'PUBLIC_ANCHORS_CHECKPOINT_AND_HASHES_NO_SECRETS', 'run_id':run_id,
             'source_commit':source_commit, 'public_files':files,
             'observer_anchor':anchor, 'checkpoint':checkpoint,
             'task_manifest_sha256':files.get('task-manifest.json'), 'launch_sha256':files.get('launch.json'),
             'task_interval':({key:json.loads((public/'task-manifest.json').read_text()).get(key)
                               for key in ('from_ms','to_ms')} if (public/'task-manifest.json').exists() else None),
             'collector_custody':'LOCAL_ISOLATION_SHARED_KERNEL_AND_ROOT',
             'separate_administrative_custody':'NOT_ESTABLISHED',
             'qa_output_authority':'ROOT_CONTROLLER_APPLICATION_CORRELATION_NOT_SIGNED_ACTION_PROOF'}
    for name in ('observer-anchor.json','checkpoint.json'):
        if (out/name).is_file() and not (out/name).is_symlink():(out/name).chmod(0o444)
    save(out/'controller-trust.json',trust)
    (out/'controller-trust.json').chmod(0o444)
    return trust


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tools',type=Path,required=True)
    parser.add_argument('--agent-python',type=Path,required=True)
    parser.add_argument('--model-root',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    args = parser.parse_args(argv)
    if sys.platform != 'linux' or os.geteuid() != 0 or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted':
        raise Refused('root on explicitly disposable GitHub Linux required')
    tools, python, model_root = args.tools.resolve(), args.agent_python.absolute(), args.model_root.resolve()
    if tools != ROOT/'target/debug':
        raise Refused('actual API bootstrap requires this checkout target/debug tools')
    for name in ('aip-probe','aip-collector','aip-observe-verify','aip-corroborate','airon-aip','aip-execution-assurance'):
        if not (tools/name).is_file():
            raise Refused('required existing executable missing')
    from linux_model_runtime import verify as verify_model, runtime_environment, verify_service
    model_identity = verify_model(model_root)  # Offline assets only; no downloads here.
    identity = source_identity()
    focus_groups = focus_groups_from_source(HERE/'agent.py')
    workflow_run_id=os.environ.get('GITHUB_RUN_ID','')
    if not workflow_run_id.isdecimal() or int(workflow_run_id)<=0:raise Refused('actual GitHub workflow run ID required')
    out = args.out.resolve(); out.mkdir(mode=0o755)
    public = directory(out/'public',mode=0o755)
    private = directory(out/'private')
    state = directory(private/'collector-state')
    services = directory(out/'services',mode=0o711)
    model_home = directory(services/'model-home',10004)
    model_tmp = directory(services/'model-tmp',10004)
    work = directory(out/'work',10001,0o700)
    run_id = 'local-qa-'+secrets.token_hex(12)
    result = {'schema':'vanian-local-qa-capture-v1','run_id':run_id,'source_commit':identity['source_commit'],
        'status':'FAIL','workload_executed':False,'autonomous_workload_executed':False,
        'workflow_run_id':int(workflow_run_id),'kernel':os.uname().release,
        'collector_custody':'LOCAL_ISOLATION_SHARED_KERNEL_AND_ROOT',
        'separate_administrative_custody':'NOT_ESTABLISHED',
        'application_action_proof':'CANNOT_PROVE','qa_output_authority':'ROOT_CONTROLLER_APPLICATION_CORRELATION'}
    save(public/'source-hashes.json',identity['files']); save(public/'model-identity.json',model_identity)
    save(public/'run-manifest.json',result)
    namespace = 'local-qa-'+secrets.token_hex(6)
    original_net = os.open('/proc/self/ns/net',os.O_RDONLY)
    cg = Path('/sys/fs/cgroup')/namespace
    mounted = namespace_created = False
    probe = collector = agent = model = api = agent_output = None
    anchor = checkpoint = launch = None
    task = None
    audits = AuditCrosscheck(); streams=[]; processes=[]
    phase='preflight'; cleanup_errors=[]
    libc=ctypes.CDLL(None,use_errno=True)
    last_cap=int(Path('/proc/sys/kernel/cap_last_cap').read_text())
    def in_host(operation):
        current=os.open('/proc/self/ns/net',os.O_RDONLY)
        try:
            os.setns(original_net,0); return operation()
        finally:
            os.setns(current,0); os.close(current)
    def spawn(name,argv,env=None,uid=0,resource=False,host=False,stdin=None,stdout=None,cwd=None):
        log=(private/(name+'.log')).open('wb');streams.append(log)
        def restrict():
            if host:os.setns(original_net,0)
            if resource:(cg/'cgroup.procs').write_text(str(os.getpid()))
            if uid:
                if libc.prctl(38,1,0,0,0):raise OSError('no_new_privileges_failed')
                for cap in range(last_cap+1):
                    if libc.prctl(24,cap,0,0,0):raise OSError('capability_drop_failed')
                os.setgroups([]);os.setgid(uid);os.setuid(uid)
        process=subprocess.Popen([str(x) for x in argv],cwd=cwd or work,
            env={'PATH':os.environ['PATH'],'LANG':'C.UTF-8',**(env or {})},
            stdin=stdin,stdout=stdout if stdout is not None else log,stderr=log,
            preexec_fn=restrict,pass_fds=(original_net,) if host else (),umask=0o077,bufsize=0)
        processes.append(process);return process
    def snapshot():
        for name in ARCHIVES:shutil.copyfile(state/name,public/name)
        cp={'sha256':{name:sha256(public/name) for name in ARCHIVES}}
        save(out/'checkpoint.json',cp)
        return cp
    def cleanup(stage,function):
        try:return function()
        except BaseException as error:
            cleanup_errors.append({'stage':stage,'type':type(error).__name__});return None
    try:
        runtime_access({10001:[(python,os.R_OK|os.X_OK),(python.parent.parent,os.R_OK|os.X_OK),
            (HERE,os.R_OK|os.X_OK),(ROOT/'sdk/python',os.R_OK|os.X_OK),(work,os.W_OK|os.X_OK)],
            10004:[(Path(model_identity['binary']['path']),os.R_OK|os.X_OK),(model_root/'lib/ollama',os.R_OK|os.X_OK),
            (model_root/'models',os.R_OK|os.X_OK)]},public)
        if command(['timedatectl','show','--property=NTPSynchronized','--value']).strip()!='yes':
            raise Refused('host clock not synchronized')
        trace=Path('/sys/kernel/tracing/available_events')
        if not trace.exists():command(['mount','-t','tracefs','nodev','/sys/kernel/tracing'])
        for name in ('sched:sched_process_exec','cgroup:cgroup_attach_task','sock:sock_send_length'):
            if name not in trace.read_text():raise Refused('required tracepoint missing')
        command(['mount','-t','tmpfs','-o','size=128m,uid=10001,gid=10001,mode=700','tmpfs',work]);mounted=True
        required={'cpu','memory','pids'}
        available=set(Path('/sys/fs/cgroup/cgroup.controllers').read_text().split())
        if not required<=available:raise Refused('required cgroup controllers unavailable')
        enabled=set(Path('/sys/fs/cgroup/cgroup.subtree_control').read_text().split())
        if required-enabled:Path('/sys/fs/cgroup/cgroup.subtree_control').write_text(' '.join('+'+x for x in sorted(required-enabled)))
        cg.mkdir();(cg/'memory.max').write_text(str(8*1024**3));(cg/'pids.max').write_text('512');(cg/'cpu.max').write_text('200000 100000')
        save(public/'resource-limits.json',{'combined_agent_and_model_memory_bytes':8*1024**3,'pids':512,'cpu_max':'200000 100000','task_deadline_seconds':900})
        command(['ip','netns','add',namespace]);namespace_created=True
        command(['ip','-n',namespace,'link','set','lo','up'])
        with open('/var/run/netns/'+namespace) as ns:os.setns(ns.fileno(),0)
        phase='model_start'
        env=runtime_environment(model_root,11436,home=model_home,tmpdir=model_tmp)
        model=spawn('model',[model_identity['binary']['path'],'serve'],env,uid=10004,resource=True,cwd=model_home)
        for _ in range(150):
            if model.poll() is not None:raise Refused('model exited before startup')
            try:
                service=verify_service('http://127.0.0.1:11436',model_identity);break
            except (OSError,ValueError,RuntimeError,http.client.HTTPException):time.sleep(.2)
        else:raise Refused('pinned local model startup timeout')
        save(public/'model-service.json',service)
        phase='api_start'
        api=APIProcess(ROOT,services/'api',port=18880).start()
        save(public/'historical-api-inputs.json',api.public_summary())
        # Warm-up is outside the measured QA interval and is not a QA response.
        request('http://127.0.0.1:11436','/api/generate',{'model':model_identity['model']['model'],
            'prompt':'','stream':False,'keep_alive':'10m','options':{'num_ctx':8192,'num_predict':1,'num_thread':2}},timeout=120)
        save(public/'model-context.json',actual_model_context(model_identity,request('http://127.0.0.1:11436','/api/ps')))
        phase='observer_enrollment'
        def free_port():
            with socket.socket() as connection:
                connection.bind(('127.0.0.1',0));return connection.getsockname()[1]
        collector_port=in_host(free_port)
        probe_env={'AIP_PROBE_ID':'probe.local.qa','AIP_PROBE_COLLECTOR_ENDPOINT':'127.0.0.1:1',
            'AIP_PROBE_COLLECTOR_NOISE_PUBKEY':'0'*64,'AIP_PROBE_KEY_PATH':str(private/'probe.key.json'),'AIP_PROBE_SENSORS':'sched'}
        probe=spawn('probe-enrollment',[tools/'aip-probe'],probe_env,host=True)
        for _ in range(80):
            if (private/'probe.key.json').exists():break
            time.sleep(.1)
        terminate(probe);probe=None
        transport=json.loads((private/'probe.key.json').read_text())['public_hex']
        save(private/'probes.json',[{'probe_id':'probe.local.qa','transport_pubkey_hex':transport}])
        (private/'pass').write_text(secrets.token_urlsafe(48));(private/'pass').chmod(0o600)
        collector=spawn('collector',[tools/'aip-collector'],{'AIP_COLLECTOR_OBSERVER_ID':'collector.local.qa',
            'AIP_COLLECTOR_KEY_VERSION':'1','AIP_COLLECTOR_KEY_PATH':str(private/'collector.key.wrapped'),
            'AIP_COLLECTOR_PASSPHRASE_FILE':str(private/'pass'),'AIP_COLLECTOR_STATE_DIR':str(state),
            'AIP_COLLECTOR_LISTEN':f'127.0.0.1:{collector_port}','AIP_COLLECTOR_PROBES_PATH':str(private/'probes.json'),
            'AIP_COLLECTOR_NOISE_KEY_PATH':str(private/'noise.key.json'),'AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK':'1',
            'AIP_COLLECTOR_CONTINUITY':'strict'},host=True)
        for _ in range(100):
            if (state/'noise.pub').exists() and (state/'observer.pub').exists():break
            if collector.poll() is not None:raise Refused('collector startup failed')
            time.sleep(.1)
        anchor={'observer_id':'collector.local.qa','key_version':1,'public_key':(state/'observer.pub').read_text().strip()}
        save(out/'observer-anchor.json',anchor)
        phase='workload_waiter'
        argv=['unshare','--mount','--propagation','private','--','setpriv','--reuid=10001','--regid=10001',
            '--clear-groups','--no-new-privs','--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all',
            str(python),'-I','-B',str(HERE/'linux_workload.py'),'--wait']
        agent=spawn('agent',argv,resource=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE)
        agent_output=AgentOutput(agent,public/'agent-events.jsonl')
        ready=agent_output.until('ready',30)
        if ready.get('pid')!=agent.pid or ready.get('uid')!=10001:raise Refused('waiting agent process mismatch')
        launch=measured_launch(agent.pid);save(public/'launch.json',launch)
        if launch['container']['mnt_ns_inode']==Path('/proc/self/ns/mnt').stat().st_ino:
            raise Refused('workload mount namespace is not isolated')
        watch=Path(f'/proc/{agent.pid}/root')/str(work).lstrip('/')
        if (watch.stat().st_dev,watch.stat().st_ino)!=(work.stat().st_dev,work.stat().st_ino):
            raise Refused('workload watch does not resolve to actual private mount')
        save(public/'fanotify-watch.json',{'path':str(watch),'scope':'actual workload tmpfs mount through measured process root','device':watch.stat().st_dev,'inode':watch.stat().st_ino})
        probe_env.update(AIP_PROBE_COLLECTOR_ENDPOINT=f'127.0.0.1:{collector_port}',
            AIP_PROBE_COLLECTOR_NOISE_PUBKEY=(state/'noise.pub').read_text().strip(),
            AIP_PROBE_SENSORS='sched,cgroup,connector,fanotify,sockstate,socksend',
            AIP_PROBE_FANOTIFY_PATH=str(watch),AIP_PROBE_BATCH_INTERVAL_MS='1000')
        probe=spawn('probe',[tools/'aip-probe'],probe_env,host=True)
        phase='signed_readiness'
        for _ in range(45):
            if probe.poll() is not None or collector.poll() is not None:raise Refused('observer daemon exited')
            time.sleep(2)
            if not all((state/name).exists() for name in ARCHIVES):continue
            try:
                checkpoint=snapshot();verify(public,tools,anchor,checkpoint)
                health=records(public/ARCHIVES[1]);window=health[-1]['health'].get('attested_coverage')
            except (Refused,FileNotFoundError):continue
            if window and covered(health,window['to_ms']-1,window['to_ms'],MECHANISMS):break
        else:raise Refused('signed Active six-sensor readiness unavailable')
        if measured_launch(agent.pid)!=launch:raise Refused('waiting process binding changed')
        command(['iptables','-A','OUTPUT','-m','owner','--uid-owner','10001','-d','127.0.0.1','-p','tcp','-m','multiport','--dports','11436,18880','-j','ACCEPT'])
        command(['iptables','-A','OUTPUT','-m','owner','--uid-owner','10001','-j','REJECT'])
        save(public/'network-isolation.json',{'links':json.loads(command(['ip','-j','address'])),
            'routes':json.loads(command(['ip','-j','route'])),'agent_rules':command(['iptables','-S','OUTPUT']),
            'agent_tcp_allowlist':['127.0.0.1:11436','127.0.0.1:18880'],'external_route':'NONE'})
        in_host(audits.start);phase='genuine_agent_execution'
        start=now();deadline=time.monotonic()+900
        def remaining(cap):
            budget=min(cap,deadline-time.monotonic()-2)
            if budget<=0:raise Refused('aggregate workload deadline exceeded')
            return budget
        questions=questions_for(api.runs)
        task={'run_id':run_id,'source_commit':identity['source_commit'],'from_ms':start,'to_ms':None,
            'exit_code':None,'questions':questions,'completed_model_requests':0,'api_reads':0,
            'observed_output_paths':[str(work/f'answers/case-{index}.json') for index in range(1,5)]}
        save(public/'task-manifest.json',task)
        config={'run_id':run_id,'source_commit':identity['source_commit'],'api_base':api.base_url,
            'reader_token':api.reader_token,'model_base':'http://127.0.0.1:11436','model':model_identity['model']['model'],
            'seeded_runs':api.runs,'questions':questions}
        time.sleep(1)  # Prospective audit clock guard stays inside signed coverage.
        agent.stdin.write(b'start\n'+json.dumps(config).encode()+b'\n');agent.stdin.flush()
        executing=agent_output.until('executing',remaining(60))
        if executing.get('run_id')!=run_id or executing.get('pid')!=agent.pid:
            raise Refused('actual executing agent mismatch')
        result.update(autonomous_workload_executed=True,workload_executed=True)
        complete=agent_output.until('complete',remaining(900))
        if complete.get('run_id')!=run_id:raise Refused('completion run ID mismatch')
        # Keep the real process alive until all output path metadata is bound.
        # This is an explicit controller hold, not application latency proof.
        file_gate_start=time.monotonic();file_gate_deadline=time.monotonic()+remaining(20)
        expected_paths=set(task['observed_output_paths']);observed_paths=set()
        while time.monotonic()<file_gate_deadline:
            time.sleep(min(2,max(.01,file_gate_deadline-time.monotonic())))
            if probe.poll() is not None or collector.poll() is not None:raise Refused('observer exited before output binding')
            try:
                checkpoint=snapshot();verify(public,tools,anchor,checkpoint)
                observed_paths=signed_answer_paths(records(public/ARCHIVES[0]),launch,start)
                if expected_paths<=observed_paths:break
            except (Refused,FileNotFoundError):continue
        else:raise Refused('actual answer file events were not all bound before exit')
        save(public/'output-file-observation-gate.json',{'status':'PASS','expected_paths':sorted(expected_paths),
            'observed_paths':sorted(expected_paths & observed_paths),'controller_hold_ms':round((time.monotonic()-file_gate_start)*1000,3),
            'scope':'SIGNED_KERNEL_PATH_METADATA_NOT_FILE_CONTENT_PROOF','performance_claimed':False})
        agent.stdin.write(b'finish\n');agent.stdin.flush()
        code=agent.wait(timeout=remaining(30))
        time.sleep(1);end=now()
        task.update(to_ms=end,exit_code=code)
        if end-start>900000:raise Refused('actual task exceeded aggregate budget')
        if code!=0:raise Refused('actual evidence agent failed')
        summary=json.loads((work/'workload-summary.json').read_text())
        if summary.get('run_id')!=run_id or summary.get('completed_model_requests')!=8 or summary.get('api_reads')!=12:
            raise Refused('actual QA workload counts incomplete')
        for row in questions:
            answer=json.loads((work/f'answers/case-{row["case_id"]}.json').read_text())
            validate_result(row['case_id'],row['run_artifact_id'],answer,focus_groups)
        task.update(completed_model_requests=8,api_reads=12);save(public/'task-manifest.json',task)
        result.update(workload_executed=True,from_ms=start,to_ms=end,agent_pid=agent.pid)
        phase='post_exit_signed_coverage'
        for _ in range(45):
            time.sleep(2)
            try:
                checkpoint=snapshot();verify(public,tools,anchor,checkpoint)
                if covered(records(public/ARCHIVES[1]),start,end,MECHANISMS):break
            except (Refused,FileNotFoundError):continue
        else:raise Refused('complete post-exit task interval lacks signed coverage')
        save(public/'audit-status.json',in_host(lambda:audits.export(public/'auditd.log')));in_host(audits.close)
        terminate(probe);probe=None
        # Exact existing freeze rule: whole chain retained, never trim a tail.
        for _ in range(25):
            time.sleep(2);checkpoint=snapshot();verify(public,tools,anchor,checkpoint)
            final_batch=records(public/ARCHIVES[0])[-1]
            final_health=records(public/ARCHIVES[1])[-1]['health']
            if (final_health['sequence']==final_batch['sequence']
                    and final_health['head']==final_batch['attestation']['payload_hash']):break
        else:raise Refused('collector did not seal the complete frozen chain')
        terminate(collector);collector=None
        checkpoint=snapshot();save(public/'verification.json',verify(public,tools,anchor,checkpoint))
        health=records(public/ARCHIVES[1]);batches=records(public/ARCHIVES[0])
        if not covered(health,start,end,MECHANISMS):raise Refused('frozen final health does not cover full task')
        observation=summarize(batches,health,launch,start,end)
        observation['full_sensor_coverage']='COVERED' if covered(health,start,end,MECHANISMS) else 'INTEGRITY_UNKNOWN'
        save(public/'observation-summary.json',observation)
        public_key=private/'observer.pub';public_key.write_text(anchor['public_key']+'\n')
        comparison=json.loads(command([tools/'aip-corroborate','--observer-id',anchor['observer_id'],'--key-version','1',
            '--pubkey-file',public_key,'--batches',public/ARCHIVES[0],'--external',public/'auditd.log','--source','auditd',
            '--from-ms',start,'--to-ms',end,'--json']))
        save(public/'corroboration.json',comparison)
        counts=observation['workload_events_by_kind']
        if any(not counts.get(kind) for kind in ('ProcessExec','FileEvent','SocketSend')) or not observation['launch_instance_events']:
            raise Refused('captured workload lacks required process/file/socket observations')
        if observation['probe_reported_drops'] or observation['events_without_clock_anchor']:
            raise Refused('capture loss or missing clock anchor')
        # Root's independent fresh_verify rechecks exact full process+exe binding
        # and every audit execution reference; no PID-only verdict is asserted.
        observed={(x['batch_sequence'],x['pid'],x['wall_ms']) for x in observation['workload_executions']}
        paired={(x['aip']['batch_sequence'],x['aip']['pid'],x['aip']['wall_ms']) for x in comparison['agreed']}
        if not observed or observed-paired or comparison['external_only'] or comparison['external_unparsed']:
            raise Refused('independent audit execution disagreement')
        save(public/'tamper.json',tamper(public,tools,anchor,checkpoint))
        public_outputs(work,public,run_id,identity['source_commit'])
        if source_identity()!=identity:raise Refused('source changed during actual workload')
        result.update(status='PASS',signed_batches=len(batches),signed_health_records=len(health),
            completed_model_requests=8,api_reads=12,observation_validation='FULL_TASK_COVERED',
            application_action_proof='CANNOT_PROVE',logical_subagent_attribution='NOT_ESTABLISHED')
    except BaseException as error:
        result['failure']={'stage':phase,'type':type(error).__name__}
        raise
    finally:
        if agent is not None:cleanup('stop_workload',lambda:terminate(agent))
        if api is not None:cleanup('stop_api',api.close)
        if model is not None:cleanup('stop_model',lambda:terminate(model))
        if audits.started:
            cleanup('preserve_audit',lambda:save(public/'audit-status.json',in_host(lambda:audits.export(public/'auditd.log'))))
        cleanup('close_audit',lambda:in_host(audits.close))
        cleanup('stop_probe',lambda:terminate(probe));cleanup('stop_collector',lambda:terminate(collector))
        if anchor and all((state/name).exists() for name in ARCHIVES):
            final=cleanup('freeze_full_archive',snapshot)
            if final:
                checkpoint=final
                cleanup('verify_final_archive',lambda:save(public/'verification.json',verify(public,tools,anchor,checkpoint)))
        cleanup('preserve_public_outputs',lambda:public_outputs(work,public,run_id,identity['source_commit']))
        if agent_output is not None:cleanup('close_agent_events',agent_output.close)
        for stream in streams:cleanup('close_private_log',stream.close)
        cleanup('restore_host_net',lambda:os.setns(original_net,0));cleanup('close_host_net',lambda:os.close(original_net))
        if namespace_created:cleanup('delete_netns',lambda:command(['ip','netns','delete',namespace]))
        if cg.exists():
            if (cg/'cgroup.kill').exists():cleanup('kill_remaining_cgroup',lambda:(cg/'cgroup.kill').write_text('1'))
            cleanup('remove_cgroup',cg.rmdir)
        if mounted:cleanup('unmount_work',lambda:command(['umount',work]))
        result['cleanup_errors']=cleanup_errors
        if cleanup_errors:result['status']='FAIL'
        save(public/'run-manifest.json',result)
        try:controller_trust(out,public,run_id,identity['source_commit'],anchor,checkpoint)
        except BaseException as error:
            cleanup_errors.append({'stage':'preserve_controller_trust','type':type(error).__name__})
            result['status']='FAIL';save(public/'run-manifest.json',result)
    print(json.dumps({'status':result['status'],'run_id':run_id,'out':str(out)}))
    return 0 if result['status']=='PASS' else 1


if __name__=='__main__':
    raise SystemExit(main())
