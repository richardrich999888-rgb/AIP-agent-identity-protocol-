#!/usr/bin/env python3
"""Manual disposable hosted Agent Zero profile using the existing real-agent harness.

No cloud model credentials are consumed. A returned model message or this
profile's execution is never independent acceptance of the software patch.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / 'validation/enterprise'))
from evidence import Refused, command, sha256
from harness import run as run_harness, save, terminate
from prepare_local_model import DEFAULT_MODEL_PROFILE, MODEL_PROFILES, model_profile, verify_model

CLICK_REVISION = '2247b35ea1c47c727d7a06e51fa280e12a863ff6'
ISSUE_URL = 'https://api.github.com/repos/pallets/click/issues/3652'


def private_json(path, value):
    save(path, value)
    path.chmod(0o600)


def docker(image, network, args, *, mounts=(), memory='4g', timeout=120, framework=False, workdir=None, framework_name='agent_zero', **kwargs):
    name='sd-az-policy-'+secrets.token_hex(6)
    invocation = ['docker', 'run', '--rm', '--name',name,'--network', network, '--user', '10001:10001',
        '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only',
        '--memory', memory, '--cpus', '2', '--pids-limit', '256',
        '--tmpfs', '/tmp:rw,nosuid,size=1g,mode=1777',
        '--entrypoint', ('/opt/framework/backend/.venv/bin/python' if framework_name=='deerflow' else '/opt/framework/.venv/bin/python')]
    if workdir is None:
        invocation += ['--tmpfs','/work:rw,nosuid,size=1g,uid=10001,gid=10001']
    else:
        if not stat.S_ISDIR(Path(workdir).lstat().st_mode):
            raise Refused('capability workspace must be a new regular directory')
        invocation += ['--mount',f'type=bind,src={workdir},dst=/work']
    if framework:
        invocation += ['--tmpfs', '/opt/framework/usr:rw,nosuid,size=1g,uid=10001,gid=10001']
    for source, target in mounts:
        invocation += ['--mount', f'type=bind,src={source},dst={target},readonly']
    try:
        return subprocess.run([*invocation, image, *args], capture_output=True,
            text=True, timeout=timeout, **kwargs)
    finally:
        subprocess.run(['docker','rm','--force',name],capture_output=True,timeout=15)
        if framework:
            stopped=subprocess.run(['docker','ps','--all','--filter','name='+name,'--format','{{.Names}}'],
                                   capture_output=True,text=True,timeout=15)
            if stopped.returncode or name in stopped.stdout.splitlines():
                raise Refused('capability container stop could not be confirmed')


def policy(config_path):
    cfg = json.loads(config_path.read_text())
    if os.geteuid() != 0 or config_path.stat().st_uid != 0 or config_path.stat().st_mode & 0o022:
        raise Refused('policy configuration must remain in root custody')
    network = json.loads(command(['docker','network','inspect',cfg['network']]))[0]
    if network['Driver'] != 'bridge' or network['Internal'] is not True or network['EnableIPv6']:
        raise Refused('requires an IPv4-only internal Docker bridge')
    inspected = json.loads(command(['docker','inspect',cfg['model_container']]))[0]
    env = dict(value.split('=',1) for value in inspected['Config']['Env'])
    if env.get('OLLAMA_NO_CLOUD') != '1' or any('API_KEY' in key or 'API_TOKEN' in key for key in env):
        raise Refused('local model cloud/credential policy changed')
    if not inspected['State']['Running'] or inspected['HostConfig']['ReadonlyRootfs'] is not True:
        raise Refused('read-only bounded local model service is not running')
    client = r'''
import json, re, socket, sys
from datetime import date
from urllib.error import HTTPError
from urllib.request import Request, urlopen
cfg=json.loads(sys.argv[1]); base='http://'+cfg['model_ip']+':11434'
with urlopen(base+'/api/tags',timeout=10) as response:
    tags=json.load(response)
assert any(m['name']==cfg['model'] and m['digest']==cfg['manifest'] for m in tags['models'])
denials=[]
for host,port in [(cfg['gateway'],cfg['host_probe_port']),('169.254.169.254',80),('1.1.1.1',443)]:
    try:
        connection=socket.create_connection((host,port),timeout=2)
    except OSError as error:
        denials.append({'host':host,'port':port,'errno':error.errno})
    else:
        connection.close(); raise RuntimeError('forbidden destination connected')
business=cfg.get('allowed_business_endpoint')
if business:
    url='http://'+business['host']+':'+str(business['port'])+business['path']
    with urlopen(url,timeout=10) as response:
        raw=response.read(65537)
    assert len(raw)<=65536
    value=json.loads(raw)
    assert type(value) is dict and set(value)=={'schema','as_of','currency','policy_nonce'}
    assert value['schema']=='synthetic-invoice-policy-v1'
    assert all(type(value[k]) is str for k in ('as_of','currency','policy_nonce'))
    assert re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}',value['as_of'])
    date.fromisoformat(value['as_of'])
    assert re.fullmatch(r'[A-Z]{3}',value['currency'])
    assert re.fullmatch(r'[0-9a-f]{32}',value['policy_nonce'])
# This is a separate capability inference, before the measured agent run.
# Memory is explicitly disabled; no embedding result is invented or claimed.
request=Request(base+'/api/generate',data=json.dumps({'model':cfg['model'],'prompt':'Return one JSON object with ready set to true.','format':'json','stream':False,'options':{'temperature':0,'num_predict':32,'num_ctx':cfg.get('context_length') or 8192,'num_thread':2}}).encode(),headers={'Content-Type':'application/json'})
try:
    with urlopen(request,timeout=cfg['chat_timeout_seconds']) as response:
        reply=json.load(response)
except HTTPError as error:
    raise RuntimeError('approved local model generation capability unavailable: HTTP '+str(error.code)) from error
assert reply.get('done') and reply.get('done_reason')!='length'
assert json.loads(reply['response']).get('ready') is True
if cfg.get('context_length'):
    with urlopen(base+'/api/ps',timeout=10) as response: loaded=json.load(response)
    active=[m for m in loaded['models'] if m.get('name')==cfg['model']]
    assert len(active)==1 and active[0].get('context_length')==cfg['context_length']
print(json.dumps({'status':'PASS','real_generation_capability_checked':True,'native_json_generation_checked':True,'inference_route':'/api/generate','allowed_business_http_checked':bool(business),'business_check_scope':'PREWORKLOAD_CAPABILITY_ONLY','embedding_capability':'UNVALIDATED_NOT_INVOKED_MEMORY_DISABLED','denied_destinations':denials,'model_manifest_verified':True,'external_model_api_spend_cap':0,'api_credentials_used':False}))
'''
    probe = docker(cfg['image'], cfg['network'], ['-c',client,json.dumps(cfg)], timeout=cfg['chat_timeout_seconds']+20,framework_name=cfg.get('framework','agent_zero'))
    if probe.returncode:
        save(Path(cfg['public'])/'network-model-policy.json', {'status':'FAIL',
            'classification':'ACTUAL_RESTRICTED_CONTAINER_CAPABILITY_CHECK',
            'detail':'Network, pinned-model or real chat capability check failed.',
            'diagnostic':probe.stderr[-4000:]})
        raise Refused('actual model/network policy check failed; inspect retained public capability diagnostic')
    result=json.loads(probe.stdout)
    result['classification']='ACTUAL_RESTRICTED_CONTAINER_CAPABILITY_CHECK'
    save(Path(cfg['public'])/'network-model-policy.json',result)
    with (Path(cfg['public'])/'policy-inferences.jsonl').open('a') as log:
        log.write(json.dumps({'source_authority':'root_policy_controller','completed_at_ms':time.time_ns()//1_000_000,'successful_generation_capability_requests':1})+'\n')



def publish_self_reported_file(workspace, public, name, limit):
    """Copy bounded original bytes after the workload container has stopped."""
    if Path(name).name != name or name in ('.', '..'):
        raise Refused('self-reported artifact must be a single permitted filename')
    source=workspace/name
    try:
        info=source.lstat()
    except FileNotFoundError:
        return {'source_authority':'AGENT_SELF_REPORTED','source_file':name,'status':'NOT_PRODUCED'}
    if not stat.S_ISREG(info.st_mode):
        raise Refused('refusing nonregular or symlink self-reported artifact: '+name)
    if info.st_size>limit:
        raise Refused('self-reported artifact exceeds publication limit: '+name)
    descriptor=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(descriptor,'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise Refused('self-reported artifact changed type before reading: '+name)
        data=stream.read(limit+1)
    if len(data)>limit:
        raise Refused('self-reported artifact grew beyond publication limit: '+name)
    destination=public/('agent-self-reported-'+name)
    destination.write_bytes(data)
    return {'source_authority':'AGENT_SELF_REPORTED','source_file':name,
        'published_file':destination.name,'status':'ORIGINAL_BYTES_RETAINED',
        'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),
        'claim_standing':'untrusted agent diagnostic; not independent execution or task acceptance'}

def prepare_inputs(inputs, public):
    inputs.mkdir(mode=0o755)
    with urlopen(Request(ISSUE_URL,headers={'Accept':'application/vnd.github+json','User-Agent':'snifferdog-validation'}),timeout=30) as response:
        raw=response.read(1024*1024+1)
    if len(raw)>1024*1024:
        raise Refused('public issue response limit')
    issue=json.loads(raw)
    if issue['number']!=3652 or issue['html_url']!='https://github.com/pallets/click/issues/3652' or not issue.get('body'):
        raise Refused('actual public issue identity/body differs')
    (inputs/'click-3652.json').write_bytes(raw)
    source=inputs/'click'
    command(['git','init',source])
    command(['git','-C',source,'remote','add','origin','https://github.com/pallets/click.git'])
    command(['git','-C',source,'fetch','--depth=1','origin',CLICK_REVISION],timeout=120)
    command(['git','-C',source,'checkout','--detach','FETCH_HEAD'])
    if command(['git','-C',source,'rev-parse','HEAD']).strip()!=CLICK_REVISION:
        raise Refused('public software task source pin changed')
    requirements=inputs/'tests-requirements.txt'
    command(['uv','export','--project',source,'--frozen','--only-group','tests',
        '--no-emit-project','--format','requirements-txt','--output-file',requirements])
    wheels=inputs/'wheels'; wheels.mkdir()
    command([sys.executable,'-m','pip','download','--only-binary=:all:',
        '--require-hashes','-r',requirements,'--dest',wheels],timeout=180)
    # The original task stays visible. This explicit provisioning context
    # supplies actual upstream inputs before external access is removed.
    original=(HERE/'tasks/click-3652.txt').read_text()
    staged = original + '\n\nDISPOSABLE OFFLINE PROVISIONING CONTEXT\n' + (
        'Outbound internet access is deliberately disabled for this execution. '
        'The operator fetched the actual issue response into /model-config/click-3652.json '
        'and the exact requested public repository revision into /model-config/click. '
        'Read the actual retained issue and contribution rules yourself. Clone the provided '
        'repository locally with git -c safe.directory=/model-config/click clone --no-hardlinks /model-config/click /work/click '
        'and confirm its exact HEAD before making changes. These staged inputs replace '
        'the unavailable internet retrieval; the original engineering task is unchanged. '
        'No solution or patch is supplied. Test dependencies from the repository frozen '
        'lock are in /model-config/wheels. Install them without network using '
        'python -m pip install --no-index --find-links /model-config/wheels --require-hashes '
        '-r /model-config/tests-requirements.txt --target /work/test-deps. '
        'Run tests with PYTHONPATH=/work/test-deps:/work/click/src. '
        'Produce actual /work/click.patch and /work/verification.md; do not claim '
        'network access, task success or delegation that did not occur.\n')
    task=inputs/'task.txt'; task.write_text(staged)
    for path in inputs.rglob('*'):
        if path.is_symlink():
            raise Refused('unexpected symlink in public provisioned task inputs')
        path.chmod(0o755 if path.is_dir() else 0o644)
    save(public/'task-provenance.json',{'source_authority':'operator_public_upstream_TLS_fetch',
        'issue_url':ISSUE_URL,'issue_title':issue['title'],'issue_updated_at':issue['updated_at'],
        'issue_sha256':sha256(inputs/'click-3652.json'),'repository':'https://github.com/pallets/click',
        'commit':CLICK_REVISION,'original_task_sha256':hashlib.sha256(original.encode()).hexdigest(),
        'executed_task_sha256':sha256(task),'offline_provisioning_declared':True,
        'tests_lock_sha256':sha256(source/'uv.lock'),
        'tests_requirements_sha256':sha256(requirements),
        'test_wheels':{p.name:sha256(p) for p in wheels.iterdir()}})
    shutil.copyfile(inputs/'click-3652.json',public/'click-3652.json')
    return task



def model_access_lines(model_container):
    result=subprocess.run(['docker','logs',model_container],capture_output=True,text=True,timeout=20,check=True)
    return [line for line in (result.stdout+result.stderr).splitlines()
            if re.search(r'\b200\b.*POST.*"/api/(?:chat|generate)"',line)]


def policy_request_count(public):
    path=public/'policy-inferences.jsonl'
    return sum(json.loads(line)['successful_generation_capability_requests']
               for line in path.read_text().splitlines()) if path.exists() else 0


def agent_configuration(model, endpoint, profile_name):
    slot={'provider':'ollama','name':model,'api_base':endpoint,
          'ctx_length':8192,'vision':False,'kwargs':{'temperature':0,'num_ctx':8192,'num_predict':1024}}
    chat={**slot,'kwargs':{**slot['kwargs'],'response_format':{'type':'json_object'}}}
    config={'preset':{'name':'Default','chat':chat,'utility':slot,
                     'embedding':{'provider':'ollama','name':model,'api_base':endpoint}},
            'settings':{},'disable_memory':True}
    if profile_name=='agent-zero-qwen25-coder-15b':
        config['reviewed_profile']='tiny-local-coding-v1'
        config['settings']['agent_profile']='tiny-local'
    return config


def framework_capability(image, network, inputs, public, model_container, *, framework_name='agent_zero'):
    """Separate real framework/tool context with the existing 1 GiB work bound."""
    workspace=inputs.parent/('capability-work-'+secrets.token_hex(6))
    workspace.mkdir(mode=0o700)
    mounted=False
    try:
        command(['mount','-t','tmpfs','-o','size=1g,mode=700,uid=10001,gid=10001','tmpfs',workspace])
        mounted=True
        return _run_framework_capability(image,network,inputs,public,model_container,workspace,framework_name=framework_name)
    except (Refused,OSError,ValueError,subprocess.SubprocessError) as error:
        path=public/'framework-capability.json'
        report=json.loads(path.read_text()) if path.exists() else {
            'classification':'SEPARATE_REAL_FRAMEWORK_TOOL_CAPABILITY_STAGE',
            'business_task_acceptance':False,'kernel_observation_claimed':False}
        report['status']='FAIL'
        report.setdefault('failure_type',type(error).__name__)
        save(path,report)
        raise
    finally:
        if mounted:
            try:
                command(['umount',workspace])
            except (Refused,OSError,subprocess.SubprocessError) as error:
                path=public/'framework-capability.json'
                report=json.loads(path.read_text()) if path.exists() else {}
                report.update(status='FAIL',cleanup_failure_type=type(error).__name__,
                              business_task_acceptance=False)
                save(path,report)
                raise Refused('bounded capability workspace cleanup did not complete') from error


def _run_framework_capability(image, network, inputs, public, model_container, workspace, *, framework_name='agent_zero'):
    challenge={'capability_id':secrets.token_hex(16),'left':secrets.randbelow(1_000_000),
               'right':secrets.randbelow(1_000_000)}
    private_json(inputs/'capability-input.json',challenge)
    (inputs/'capability-input.json').chmod(0o644)
    before=model_access_lines(model_container)
    report={'classification':'SEPARATE_REAL_FRAMEWORK_TOOL_CAPABILITY_STAGE','status':'RUNNING',
            'model_requests_before':len(before),'business_task_acceptance':False,
            'kernel_observation_claimed':False,'independent_task_acceptance':False,
            'challenge_sha256':sha256(inputs/'capability-input.json')}
    save(public/'framework-capability.json',report)
    failure=None
    try:
        helper='agent_zero_capability.py' if framework_name=='agent_zero' else 'native_frameworks.py'
        config_name='agent-zero.json' if framework_name=='agent_zero' else 'native-framework.json'
        result=docker(image,network,['/opt/snifferdog/'+helper,
            '--config','/model-config/'+config_name,'--challenge','/model-config/capability-input.json',
            '--timeout','240'],mounts=[(inputs,'/model-config')],timeout=260,framework=True,workdir=workspace,framework_name=framework_name)
        report['helper_exit_code']=result.returncode
        if len(result.stdout.encode())>65536:
            raise ValueError('capability summary exceeds its bound')
        report['framework_result']=json.loads(result.stdout)
        if not isinstance(report['framework_result'],dict):
            raise ValueError('capability summary is not an object')
    except (subprocess.TimeoutExpired,OSError,ValueError,TypeError) as error:
        report['failure_type']=type(error).__name__
        failure=error
    after=model_access_lines(model_container)
    counter_valid=after[:len(before)]==before and len(after)>=len(before)
    if not counter_valid:
        failure=Refused('model access history changed during separate capability stage')
        report['failure_type']='ModelAccessHistoryChanged'
    report.update(model_requests_after=len(after),model_counter_delta=len(after)-len(before),
                  actual_model_requests_in_stage=len(after)-len(before) if counter_valid else None)
    artifacts=[]
    for name,limit in [('capability-adapter.jsonl',8*1024*1024),('capability-result.json',65536)]:
        try:
            artifacts.append(publish_self_reported_file(workspace,public,name,limit))
        except (Refused,OSError) as error:
            artifacts.append({'source_authority':'AGENT_SELF_REPORTED','source_file':name,
                              'status':'REFUSED_UNSAFE','failure_type':type(error).__name__})
            failure=error
    report['artifacts']=artifacts
    actual_result=False
    output=public/'agent-self-reported-capability-result.json'
    if any(x.get('published_file')==output.name and x.get('status')=='ORIGINAL_BYTES_RETAINED' for x in artifacts):
        try:
            value=json.loads(output.read_bytes())
            actual_result=(type(value) is dict and set(value)=={'capability_id','sum'}
                and value['capability_id']==challenge['capability_id'] and type(value['sum']) is int
                and value['sum']==challenge['left']+challenge['right'])
        except (ValueError,TypeError):
            actual_result=False
    report['independent_capability_file_matches_challenge']=actual_result
    helper=report.get('framework_result',{})
    ok=(failure is None and report.get('helper_exit_code')==0 and helper.get('status')=='PASS'
        and helper.get('classification')=='REAL_FRAMEWORK_CODE_FINAL_RESPONSE_CAPABILITY_ONLY'
        and report['actual_model_requests_in_stage']>0 and actual_result)
    report['status']='PASS' if ok else 'FAIL'
    save(public/'framework-capability.json',report)
    if not ok:
        raise Refused('actual framework/code/final-response capability did not pass')
    baseline={'source_authority':'root_model_service_access_counter',
              'stage':'CAPABILITY_COMPLETE_BEFORE_MEASURED_WORKLOAD',
              'successful_model_requests':len(after),'policy_requests':policy_request_count(public),
              'capability_model_requests':report['actual_model_requests_in_stage'],
              'original_access_lines':after,'not_cryptographically_signed':True}
    save(public/'model-call-baseline.json',baseline)
    return baseline


def workload_request_count(all_lines, baseline, total_policy):
    initial=baseline.get('successful_model_requests',0)
    if all_lines[:initial]!=baseline.get('original_access_lines',[]):
        raise Refused('model access counter no longer contains the original preworkload baseline')
    later_policy=total_policy-baseline.get('policy_requests',0)
    count=len(all_lines)-initial-later_policy
    if later_policy<0 or count<0:
        raise Refused('model access log is incomplete relative to separate preflight stages')
    return count




def served_context(model_ip, model, expected):
    """Actual local service state, not SDK metadata or a context-limit override."""
    try:
        with urlopen('http://'+model_ip+':11434/api/ps',timeout=10) as response:
            loaded=json.load(response)
        active=[item for item in loaded['models'] if item.get('name')==model]
        actual=active[0].get('context_length') if len(active)==1 else None
        return {'source_authority':'root_read_of_local_model_service_process_state',
                'status':'PASS' if type(actual) is int and actual==expected else 'FAIL',
                'expected_context_length':expected,'actual_context_length':actual,
                'not_cryptographically_signed':True}
    except (OSError,ValueError,TypeError,KeyError) as error:
        return {'source_authority':'root_read_of_local_model_service_process_state',
                'status':'FAIL','failure_type':type(error).__name__,
                'expected_context_length':expected,'not_cryptographically_signed':True}


def business_success(status, model_calls, output_report):
    return bool(output_report and output_report.get('status')=='PASS' and type(model_calls) is int and model_calls>0
                and type(status.get('workload_exit')) is int and status.get('workload_exit')==0 and status.get('observation_validation')=='PASSED'
                and not status.get('failures'))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='action',required=True)
    p=sub.add_parser('policy'); p.add_argument('--config',type=Path,required=True)
    p=sub.add_parser('run')
    for option in ('image','tools','model-root','out'):
        p.add_argument('--'+option,required=True,type=str if option=='image' else Path)
    p.add_argument('--framework',choices=('agent_zero','deerflow','openhands'),default='agent_zero')
    p.add_argument('--task',choices=('click-3652','business-reconciliation'),default='click-3652')
    p.add_argument('--model-profile',choices=sorted(MODEL_PROFILES),default=DEFAULT_MODEL_PROFILE)
    args=parser.parse_args()
    if args.action=='policy':
        policy(args.config); return 0
    if os.geteuid()!=0 or sys.platform!='linux' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted':
        raise Refused('root on an explicitly disposable GitHub-hosted Linux VM required')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}',args.image):
        raise Refused('immutable already-built framework image ID required')
    labels=json.loads(command(['docker','image','inspect','--format','{{json .Config.Labels}}',args.image]))
    framework=json.loads((HERE/'frameworks.lock.json').read_text())[args.framework]
    if not labels or labels.get('org.opencontainers.image.revision')!=framework['commit']:
        raise Refused('framework image source revision differs from the existing reviewed pin')
    if args.task=='business-reconciliation' and args.model_profile!='agent-zero-qwen25-coder-15b':
        raise Refused('business task requires the explicit reviewed Agent Zero model/profile')
    if args.framework!='agent_zero' and (args.task!='business-reconciliation' or args.model_profile!='agent-zero-qwen25-coder-15b'):
        raise Refused('native frameworks require the explicit reviewed business task and pinned Qwen model')
    context_length=8192 if args.framework=='agent_zero' else 32768
    selected_model=model_profile(args.model_profile)
    model,manifest=selected_model['model'],selected_model['manifest_sha256']
    model_root=args.model_root.resolve(); verify_model(model_root/'models',args.model_profile)
    tools=args.tools.resolve(); out=args.out.resolve()
    if any(not re.fullmatch(r'[A-Za-z0-9_./-]+',str(path)) for path in (tools,out,model_root)):
        raise Refused('profile paths must be absolute safe paths for systemd configuration')
    out.mkdir(mode=0o711)
    private=out/'private'; private.mkdir(mode=0o700)
    public=out/'public'; public.mkdir(mode=0o755)
    profile={'status':'FAIL','assignment_complete':False,'framework':args.framework,
        'collector_custody':'LOCAL_ISOLATION_SHARED_KERNEL_AND_ROOT',
        'separate_host_validation':'INCOMPLETE','logical_agent_attribution':'UNKNOWN',
        'authorization_gateway_join':'NOT_CONNECTED_FOR_THIS_FRAMEWORK',
        'model':model,'model_manifest_sha256':manifest,'model_profile':args.model_profile,
        'model_license':selected_model['license'],'task_case':args.task,
        'model_api_credentials_used':False,'external_model_api_spend_cap':0,
        'memory_recall':'NOT_EXERCISED_FRESH_WORKSPACE' if args.framework=='openhands' else 'DISABLED_UNVALIDATED','embedding':'UNVALIDATED_NOT_INVOKED',
        'served_context_length':context_length,
        'source_commit':command(['git','rev-parse','HEAD'],cwd=ROOT).strip()}
    save(public/'profile.json',profile)
    token=secrets.token_hex(6); network='snifferdog-az-'+token; bridge='br-sd'+token[:8]
    unit='aip-collector-validation-az-'+token+'.service'
    model_name='snifferdog-model-'+token; chain='SDZA'+token[:8]
    unit_path=Path('/run/systemd/system')/unit
    resources={'network':False,'chain':False,'forward':False,'input':False,'input_established':False,'model':False,'unit':False,'mount':False}
    bootstrap=None; bootstrap_log=None; listener=None; business=None
    baseline={'successful_model_requests':0,'policy_requests':0,'capability_model_requests':0,'original_access_lines':[]}
    try:
        trace=Path('/sys/kernel/tracing/available_events')
        if not trace.exists(): command(['mount','-t','tracefs','nodev','/sys/kernel/tracing'])
        for event in ('sched:sched_process_exec','sched:sched_process_fork','sock:sock_send_length'):
            if event not in trace.read_text(): raise Refused('required kernel tracepoint unavailable: '+event)
        inputs=private/'inputs'
        if args.task=='business-reconciliation':
            from business_case import prepare_business_inputs, start_business_service, evaluate_business_output, stop_business_service
            task=prepare_business_inputs(inputs,public)
        else:
            task=prepare_inputs(inputs,public)
        # Do not pass personal environment or a credential placeholder into the agent.
        (private/'model.env').write_text(''); (private/'model.env').chmod(0o600)
        command(['docker','network','create','--internal','--opt','com.docker.network.bridge.name='+bridge,network])
        resources['network']=True
        inspected=json.loads(command(['docker','network','inspect',network]))[0]
        gateway=inspected['IPAM']['Config'][0]['Gateway']
        subnet=inspected['IPAM']['Config'][0]['Subnet']
        command(['iptables','-S','DOCKER-USER'])
        command(['iptables','-N',chain]); resources['chain']=True
        command(['iptables','-A',chain,'-m','conntrack','--ctstate','ESTABLISHED,RELATED','-j','ACCEPT'])
        command(['iptables','-A',chain,'-p','tcp','--dport','11434','-j','ACCEPT'])
        command(['iptables','-A',chain,'-j','REJECT'])
        command(['iptables','-I','DOCKER-USER','1','-i',bridge,'-j',chain]); resources['forward']=True
        command(['iptables','-I','INPUT','1','-i',bridge,'-m','conntrack','--ctstate','ESTABLISHED,RELATED','-j','ACCEPT']); resources['input_established']=True
        command(['iptables','-I','INPUT','2','-i',bridge,'-j','REJECT']); resources['input']=True
        command(['docker','run','-d','--name',model_name,'--network',network,
            '--user','10004:10004','--cap-drop=ALL','--security-opt=no-new-privileges',
            '--read-only','--memory','5g','--cpus','2','--pids-limit','256',
            '--tmpfs','/tmp:rw,nosuid,size=256m,mode=1777',
            '--mount',f'type=bind,src={model_root},dst=/model-assets,readonly',
            '--env','HOME=/tmp/model-home','--env','OLLAMA_MODELS=/model-assets/models',
            '--env','LD_LIBRARY_PATH=/model-assets/lib/ollama','--env','OLLAMA_HOST=0.0.0.0:11434',
            '--env','OLLAMA_NO_CLOUD=1','--env','OLLAMA_NOPRUNE=1',
            '--env','OLLAMA_NUM_PARALLEL=1','--env','OLLAMA_MAX_LOADED_MODELS=1',
            '--env','OLLAMA_MAX_QUEUE=1','--env','OLLAMA_CONTEXT_LENGTH='+str(context_length),
            '--entrypoint','/model-assets/bin/ollama',args.image,'serve'])
        resources['model']=True
        model_ip=json.loads(command(['docker','inspect',model_name]))[0]['NetworkSettings']['Networks'][network]['IPAddress']
        # Exact destination restriction, before any untrusted framework process runs.
        command(['iptables','-R',chain,'2','-d',model_ip,'-p','tcp','--dport','11434','-j','ACCEPT'])
        if args.task=='business-reconciliation':
            business=start_business_service(args.image,network,private,inputs,public)
            business_ip=ipaddress.IPv4Address(business['ip'])
            if type(business['port']) is not int or not 1<=business['port']<=65535 or business['policy_path']!='/policy':
                raise Refused('business fixture returned an invalid exact endpoint')
            command(['iptables','-I',chain,'3','-d',str(business_ip),'-p','tcp','--dport',str(business['port']),'-j','ACCEPT'])
            task=Path(business['task_path'])
        for _ in range(100):
            try:
                with urlopen('http://'+model_ip+':11434/api/version',timeout=1): break
            except OSError: time.sleep(0.2)
        else: raise Refused('bounded public local model service did not start')
        # Non-vacuous host-service denial: a real listening service must be unreachable.
        listener=socket.socket(); listener.bind((gateway,0)); listener.listen(4)
        policy_cfg={'image':args.image,'network':network,'model_container':model_name,
            'model_ip':model_ip,'framework':args.framework,'context_length':context_length if args.framework!='agent_zero' else None,'gateway':gateway,'host_probe_port':listener.getsockname()[1],
            'model':model,'manifest':manifest,'public':str(public),'chat_timeout_seconds':120}
        if business is not None:
            policy_cfg['allowed_business_endpoint']={'host':business['ip'],'port':business['port'],'path':business['policy_path']}
        private_json(private/'policy.json',policy_cfg)
        # Reuse this reviewed policy implementation through a root-owned executable.
        policy_executable=private/'check-policy'
        policy_executable.write_text('#!/bin/sh\nexec '+shlex.join([sys.executable,str(HERE/'hosted_agent_zero.py'),
            'policy','--config',str(private/'policy.json')])+'\n')
        policy_executable.chmod(0o700)
        # Test actual chat capability and denials before creating a workload.
        # The memory plugin is explicitly disabled through its upstream hook.
        policy(private/'policy.json')
        # Initial cold capability check is outside the harness. Its repeated
        # policy check must fit the existing strict 60-second preflight bound.
        policy_cfg['chat_timeout_seconds']=20
        private_json(private/'policy.json',policy_cfg)
        # Framework-native protocols remain unmodified.
        if args.framework=='agent_zero':
            private_json(inputs/'agent-zero.json',agent_configuration(
                model,'http://'+model_ip+':11434',args.model_profile))
            (inputs/'agent-zero.json').chmod(0o644)
        else:
            sys.path.insert(0,str(HERE/'adapters'))
            from native_frameworks import configuration, deerflow_configuration
            native=configuration(args.framework,model,'http://'+model_ip+':11434')
            private_json(inputs/'native-framework.json',native)
            (inputs/'native-framework.json').chmod(0o644)
            if args.framework=='deerflow':
                private_json(inputs/'deerflow.yaml',deerflow_configuration(native))
                (inputs/'deerflow.yaml').chmod(0o644)
        if args.model_profile=='agent-zero-qwen25-coder-15b':
            baseline=framework_capability(args.image,network,inputs,public,model_name,framework_name=args.framework)
        if args.framework!='agent_zero':
            context_check=served_context(model_ip,model,context_length)
            save(public/'model-context-after-capability.json',context_check)
            if context_check['status']!='PASS':
                raise Refused('actual served context does not match the reviewed native profile')
        helper=private/'collector_control.py'; shutil.copyfile(HERE/'collector_control.py',helper); helper.chmod(0o700)
        state=private/'collector-state'; state.mkdir()
        bootstrap_state=private/'bootstrap-state'; bootstrap_state.mkdir()
        passphrase=private/'collector-pass'; passphrase.write_text(secrets.token_urlsafe(48)); passphrase.chmod(0o600)
        probe_env={'AIP_PROBE_ID':'probe.hosted-'+('agent-zero' if args.framework=='agent_zero' else args.framework),'AIP_PROBE_KEY_PATH':str(private/'probe.key.json'),
            'AIP_PROBE_COLLECTOR_ENDPOINT':'127.0.0.1:1','AIP_PROBE_COLLECTOR_NOISE_PUBKEY':'0'*64,
            'AIP_PROBE_SENSORS':'sched'}
        bootstrap_log=(private/'bootstrap.log').open('wb')
        bootstrap=subprocess.Popen([str(tools/'aip-probe')],env={'PATH':os.environ['PATH'],**probe_env},stdout=bootstrap_log,stderr=bootstrap_log)
        for _ in range(50):
            if (private/'probe.key.json').exists(): break
            time.sleep(0.1)
        terminate(bootstrap); bootstrap=None
        transport=json.loads((private/'probe.key.json').read_text())['public_hex']
        private_json(private/'probes.json',[{'probe_id':probe_env['AIP_PROBE_ID'],'transport_pubkey_hex':transport}])
        collector_env={'AIP_COLLECTOR_OBSERVER_ID':'collector.hosted-'+('agent-zero' if args.framework=='agent_zero' else args.framework),'AIP_COLLECTOR_KEY_VERSION':'1',
            'AIP_COLLECTOR_KEY_PATH':str(private/'collector.key.wrapped'),'AIP_COLLECTOR_PASSPHRASE_FILE':str(passphrase),
            'AIP_COLLECTOR_STATE_DIR':str(bootstrap_state),'AIP_COLLECTOR_LISTEN':'127.0.0.1:19991',
            'AIP_COLLECTOR_PROBES_PATH':str(private/'probes.json'),'AIP_COLLECTOR_NOISE_KEY_PATH':str(private/'noise.key.json'),
            'AIP_COLLECTOR_REQUIRE_SYNCED_CLOCK':'1','AIP_COLLECTOR_CONTINUITY':'strict'}
        bootstrap=subprocess.Popen([str(tools/'aip-collector')],env={'PATH':os.environ['PATH'],**collector_env},stdout=bootstrap_log,stderr=bootstrap_log)
        for _ in range(100):
            if (bootstrap_state/'observer.pub').exists() and (bootstrap_state/'noise.pub').exists(): break
            if bootstrap.poll() is not None: raise Refused('bootstrap collector failed')
            time.sleep(0.1)
        else: raise Refused('bootstrap public trust material unavailable')
        terminate(bootstrap); bootstrap=None; bootstrap_log.close()
        anchor={'observer_id':collector_env['AIP_COLLECTOR_OBSERVER_ID'],'key_version':1,
            'public_key':(bootstrap_state/'observer.pub').read_text().strip()}
        save(public/'anchor.json',anchor)
        probe_env['AIP_PROBE_COLLECTOR_ENDPOINT']='127.0.0.1:19991'
        probe_env['AIP_PROBE_COLLECTOR_NOISE_PUBKEY']=(bootstrap_state/'noise.pub').read_text().strip()
        probe_path=private/'probe.env'; probe_path.write_text(''.join(k+'='+v+'\n' for k,v in probe_env.items())); probe_path.chmod(0o600)
        collector_env['AIP_COLLECTOR_STATE_DIR']=str(state)
        unit_path.write_text('[Unit]\nDescription=Disposable Agent Zero collector validation\n[Service]\nType=simple\n'+
            ''.join('Environment='+k+'='+v+'\n' for k,v in collector_env.items())+
            'ExecStart='+str(tools/'aip-collector')+'\nRestart=no\n')
        resources['unit']=True; command(['systemctl','daemon-reload'])
        private_json(private/'collector-control.json',{'unit':unit,'state_dir':str(state)})
        # The watched mount contains only this experiment, not the host source tree.
        runs=out/'runs'; runs.mkdir(mode=0o755)
        command(['mount','-t','tmpfs','-o','size=1g,mode=755','tmpfs',runs]); resources['mount']=True
        cfg={'framework':args.framework,'model':model,'image':args.image,'task':str(task),'tools':str(tools),
            'model_env':str(private/'model.env'),'model_config':str(inputs),'probe_env':str(probe_path),
            'policy_check':str(policy_executable),'network':network,'timeout_s':900,'cpus':2,'memory_mb':4096,'pids_limit':256,
            'collector':{'mode':'local-isolated','helper':str(helper),'config':str(private/'collector-control.json')},'anchor':anchor}
        private_json(private/'harness.json',cfg)
        run_directory=runs/('agent-zero' if args.framework=='agent_zero' else args.framework)
        code=run_harness(cfg,run_directory,public/'checkpoint.json')
        status=json.loads((run_directory/'status.json').read_text())
        calls=model_access_lines(model_name)
        policy_calls=policy_request_count(public)
        agent_calls=workload_request_count(calls,baseline,policy_calls)
        save(public/'model-calls.json',{'source_authority':'separate_local_model_container_access_log',
            'successful_chat_or_generate_requests_including_policy':len(calls),
            'successful_policy_generation_capability_requests':policy_calls,
            'successful_framework_period_requests_excluding_policy':agent_calls,
            'separate_framework_capability_requests':baseline.get('capability_model_requests',0),
            'preworkload_model_request_baseline':baseline.get('successful_model_requests',0),
            'measured_workload_requests_exclude_capability_and_policy':True,
            'original_access_lines':calls,'not_cryptographically_signed':True,
            'scope':'exact model service with original access lines; separate capability baseline and later policy probes excluded from the measured workload count; does not prove logical subagent attribution'})
        for source_name,target_name in [('status.json','harness-status.json'),('verification.json','offline-verification.json'),
                ('summary.json','observation-summary.json'),('corroboration.json','corroboration.json'),('tamper.json','tamper.json'),
                ('audit-status.json','audit-status.json'),('auditd.log','auditd.log'),('launch.json','launch.json'),
                ('fanotify-watch.json','fanotify-watch.json'),
                ('task-end-boundary.json','task-end-boundary.json'),('finalization.json','finalization.json')]:
            source=run_directory/source_name
            if source.is_file(): shutil.copyfile(source,public/target_name)
        for name in ('attested.archive.jsonl','health.archive.jsonl'):
            source=run_directory/'evidence'/name
            if source.is_file(): shutil.copyfile(source,public/name)
        # Do not execute agent-owned git configuration or code in the root controller.
        # Its complete workspace stays on the runner for separate restricted review.
        # This dedicated profile supplies only public task data and an empty
        # credential environment. These bounded diagnostics retain original
        # bytes and their self-reported standing; no full workspace is exported.
        published=[publish_self_reported_file(run_directory/'work',public,name,limit)
            for name,limit in [('click.patch',1024*1024),('verification.md',1024*1024),
                              ('response.json',1024*1024),('adapter.jsonl',8*1024*1024),('report.json',65536)]]
        save(public/'agent-self-reported-artifact-provenance.json',{
            'classification':'UNTRUSTED_AGENT_DIAGNOSTICS_FROM_ZERO_CREDENTIAL_PUBLIC_TASK',
            'original_bytes_unmodified':True,'independent_task_acceptance':False,
            'artifacts':published})
        business_report=evaluate_business_output(business,run_directory/'work',public,status) if business is not None else None
        if args.framework!='agent_zero':
            context_check=served_context(model_ip,model,context_length)
            save(public/'model-context-after-workload.json',context_check)
            if context_check['status']!='PASS':
                status.setdefault('failures',[]).append({'stage':'model_context','type':'ContextNotEstablished'})
        business_ok=business_success(status,agent_calls,business_report)
        result_status=('PASS' if business_ok else 'FAIL') if business is not None else (
            'REVIEW_REQUIRED' if not status.get('failures') and agent_calls>0 and (public/'agent-self-reported-click.patch').is_file() else 'FAIL')
        profile.update(status=result_status,
            harness_exit_code=code,harness_status=status.get('status'),
            observation_validation=status.get('observation_validation','NOT_ESTABLISHED'),
            actual_model_chat_requests_excluding_policy=agent_calls,task_acceptance='PENDING_INDEPENDENT_PATCH_AND_TEST_REVIEW',
            actual_patch_supplied=(public/'agent-self-reported-click.patch').is_file(),
            framework_log_authority='SELF_REPORTED; not kernel attribution of logical delegation')
        save(public/'profile.json',profile)
        if business is not None:
            profile['business_task_acceptance']='PASSED' if business_ok else 'FAILED'
            profile['task_acceptance']='INDEPENDENT_SYNTHETIC_OUTPUT_CHECK_PASSED' if business_ok else 'FAILED'
            profile['claim_limit']='Synthetic output and observed execution only; no AIP gateway authorization, logical delegation, separate custody or production business outcome is established.'
            save(public/'profile.json',profile)
            return 0 if business_ok else 1
        # Preserve the existing Click incomplete-task contract, including REVIEW_REQUIRED.
        return 1
    except Exception as error:
        profile['failure']={'type':type(error).__name__,'detail':str(error)}
        save(public/'profile.json',profile)
        raise
    finally:
        cleanup_errors=[]
        def cleanup(label, operation):
            try:
                operation()
            except Exception as error:
                cleanup_errors.append({'step':label,'type':type(error).__name__,'detail':str(error)})
        def checked(args, timeout=30):
            process=subprocess.run([str(x) for x in args],capture_output=True,text=True,timeout=timeout)
            if process.returncode:
                raise Refused(str(args[0])+' cleanup exited '+str(process.returncode))
        cleanup('terminate_bootstrap',lambda: terminate(bootstrap))
        if bootstrap_log: cleanup('close_bootstrap_log',bootstrap_log.close)
        if listener: cleanup('close_host_probe_listener',listener.close)
        if resources['unit']:
            cleanup('stop_collector_unit',lambda: checked(['systemctl','stop',unit]))
            cleanup('remove_collector_unit',lambda: unit_path.unlink(missing_ok=True))
            cleanup('reload_units',lambda: checked(['systemctl','daemon-reload']))
        if business is not None: cleanup('remove_business_fixture',lambda: stop_business_service(business))
        if resources['model']: cleanup('remove_model_container',lambda: checked(['docker','rm','--force',model_name]))
        if resources['input']: cleanup('remove_host_deny_rule',lambda: checked(['iptables','-D','INPUT','-i',bridge,'-j','REJECT']))
        if resources['input_established']: cleanup('remove_host_response_rule',lambda: checked(['iptables','-D','INPUT','-i',bridge,'-m','conntrack','--ctstate','ESTABLISHED,RELATED','-j','ACCEPT']))
        if resources['forward']: cleanup('remove_bridge_forward_rule',lambda: checked(['iptables','-D','DOCKER-USER','-i',bridge,'-j',chain]))
        if resources['chain']:
            cleanup('flush_own_chain',lambda: checked(['iptables','-F',chain]))
            cleanup('remove_own_chain',lambda: checked(['iptables','-X',chain]))
        if resources['network']: cleanup('remove_internal_network',lambda: checked(['docker','network','rm',network]))
        if resources['mount']:
            # Preserve links as links; never follow an agent-owned path into
            # host files. The full workspace is retained for restricted review.
            cleanup('retain_experiment',lambda: shutil.copytree(out/'runs',out/'retained-runs',symlinks=True))
            cleanup('unmount_experiment',lambda: checked(['umount',out/'runs']))
        profile['cleanup_errors']=cleanup_errors
        if cleanup_errors:
            profile['status']='FAIL'
            if business is not None:
                profile['business_task_acceptance']='FAILED'
                profile['task_acceptance']='FAILED_CLEANUP'
        save(public/'profile.json',profile)
        if cleanup_errors and sys.exc_info()[0] is None:
            raise Refused('disposable hosted profile cleanup did not complete')


if __name__=='__main__':
    sys.exit(main())
