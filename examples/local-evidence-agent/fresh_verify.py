#!/usr/bin/env python3
"""Offline verification of original Linux observations and controller-scoped QA output.

No model, API, network, signing or mutable re-evaluation service is started.
The caller must separately approve the controller trust file and its provenance.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'integrations/real_agents'))
from evidence import ARCHIVES, Refused, covered, event_time, records, verify

MECHANISMS = ['SchedTracepoint', 'CgroupTracepoint', 'ProcConnector', 'Fanotify', 'SockStateTracepoint', 'SockSendTracepoint']
WEIGHT_SHA = '6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e'
MAX_PUBLIC_BYTES = 128 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise Refused(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read_json(path):
    def unique(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate JSON field')
            result[key] = value
        return result
    def nonfinite(_value):
        raise Refused('Nonfinite JSON value')
    return json.loads(Path(path).read_bytes(), object_pairs_hook=unique, parse_constant=nonfinite)


def checked_file(root, name):
    require(isinstance(name, str) and 1 <= len(name) <= 512, 'Invalid public member name')
    path = PurePosixPath(name)
    require(not path.is_absolute() and '..' not in path.parts and str(path) == name,
            'Public member escapes capture directory')
    current = root
    for part in path.parts:
        current = current / part
        require(not current.is_symlink(), 'Capture member is a symlink')
    require(current.is_file() and current.stat().st_size <= MAX_PUBLIC_BYTES,
            'Capture member missing or exceeds bound')
    return current


def command(args):
    result = subprocess.run([str(x) for x in args], capture_output=True, timeout=120,
                            env={'PATH': os.defpath})
    require(result.returncode == 0, 'Existing offline verifier refused the capture')
    return json.loads(result.stdout)


def verify_fresh(package: Path, trust: Path, tools: Path) -> dict:
    package, trust, tools = Path(package).absolute(), Path(trust).absolute(), Path(tools).absolute()
    require(package.is_dir() and not package.is_symlink(), 'Original public capture directory required')
    require(trust.is_file() and not trust.is_symlink() and not trust.resolve().is_relative_to(package.resolve()),
            'Separately approved controller trust must be outside the public capture')
    authority = read_json(trust)
    require(authority.get('schema') == 'vanian-local-qa-controller-trust-v1', 'Unsupported controller trust schema')
    source = authority.get('source_commit')
    require(isinstance(source, str) and re.fullmatch('[0-9a-f]{40}', source), 'Exact execution source commit required')
    hashes = authority.get('public_files')
    require(isinstance(hashes, dict) and 10 <= len(hashes) <= 100, 'Bounded complete public-file inventory required')
    actual = {str(path.relative_to(package)) for path in package.rglob('*') if path.is_file() or path.is_symlink()}
    require(actual == set(hashes), 'Public capture inventory changed')
    total = 0
    for name, expected in hashes.items():
        path = checked_file(package, name)
        total += path.stat().st_size
        require(total <= MAX_PUBLIC_BYTES and isinstance(expected, str)
                and re.fullmatch('[0-9a-f]{64}', expected) and digest(path) == expected,
                'Controller-pinned public file hash mismatch')
    anchor, checkpoint = authority.get('observer_anchor'), authority.get('checkpoint')
    require(isinstance(anchor, dict) and isinstance(checkpoint, dict), 'Separate observer anchor and checkpoint required')
    report = verify(package, tools, anchor, checkpoint)
    batches, health = records(package / ARCHIVES[0]), records(package / ARCHIVES[1])
    require(len(batches) >= 3, 'Insufficient real batches for retained tamper controls')
    last_batch, last_health = batches[-1], health[-1]['health']
    require(last_health['sequence'] == last_batch['sequence'] and
            last_health['head'] == last_batch['attestation']['payload_hash'],
            'Final signed health does not cover the complete retained chain')
    manifest = read_json(package / 'run-manifest.json')
    task = read_json(package / 'task-manifest.json')
    launch = read_json(package / 'launch.json')
    run_id = authority.get('run_id')
    require(isinstance(run_id, str) and manifest.get('run_id') == task.get('run_id') == run_id,
            'Controller, task and capture run identities differ')
    require(manifest.get('source_commit') == task.get('source_commit') == source,
            'Task/capture source revision mismatch')
    require(manifest.get('status') == 'PASS' and manifest.get('autonomous_workload_executed') is True,
            'Actual completed agent workload required')
    start, end = task.get('from_ms'), task.get('to_ms')
    require(type(start) is int and type(end) is int and 0 < start < end and end-start < 900000,
            'Bounded actual task interval required')
    require(authority.get('task_interval') == {'from_ms':start,'to_ms':end}
            and manifest.get('from_ms') == start and manifest.get('to_ms') == end
            and authority.get('task_manifest_sha256') == hashes['task-manifest.json']
            and authority.get('launch_sha256') == hashes['launch.json'],
            'Actual task interval or launch differs from separately approved controller record')
    require(type(task.get('exit_code')) is int and task['exit_code'] == 0,
            'Actual workload did not exit successfully')
    require(covered(health, start, end, MECHANISMS), 'Latest signed Active epoch does not cover the actual task')
    process, namespace = launch.get('process'), launch.get('container')
    require(isinstance(process, dict) and isinstance(namespace, dict)
            and type(process.get('pid_start_time_ticks')) is int and process['pid_start_time_ticks'] > 0
            and type(process.get('pid')) is int and process['pid'] > 0
            and isinstance(process.get('boot_id'), list) and len(process['boot_id']) == 16,
            'Controller-measured complete process instance required')
    executable = launch.get('exe_content_sha256')
    require(isinstance(executable, list) and len(executable) == 32 and
            all(type(x) is int and 0 <= x <= 255 for x in executable), 'Measured executable digest required')
    require(all(type(namespace.get(k)) is int and namespace[k] > 0
                for k in ('pid_ns_inode', 'mnt_ns_inode', 'net_ns_inode')), 'Measured namespaces required')
    kinds, executions, paths = Counter(), Counter(), set()
    for signed in batches:
        batch = signed['batch']
        require(batch['dropped_events'] == 0, 'Probe reported dropped observations')
        for event in batch['kernel_events']:
            when = event_time(batch, event)
            require(when is not None, 'Kernel event lacks its signed clock mapping')
            bound = event.get('bound')
            if not start <= when <= end or not bound or bound.get('process') != process:
                continue
            container = bound.get('container') or {}
            require(all(container.get(k) == namespace[k] for k in ('pid_ns_inode','mnt_ns_inode','net_ns_inode')),
                    'Observed process namespace differs from controller measurement')
            require(bound.get('exe_content_sha256') == executable, 'Observed executable differs from measured agent')
            kind = next(iter(event['kind']))
            kinds[kind] += 1
            if kind == 'ProcessExec': executions[(signed['sequence'], process['pid'], when)] += 1
            if kind == 'FileEvent': paths.add(event['kind'][kind].get('path'))
    require(all(kinds[k] > 0 for k in ('ProcessExec','FileEvent','SocketSend')),
            'Actual agent lacks signed process, file or socket observations')
    audit = read_json(package / 'audit-status.json')
    require(audit['initial']['lost'] == audit['final']['lost'] and audit['final']['backlog'] == 0
            and audit['initial']['pid'] == audit['final']['pid'], 'Independent audit reported loss or restart')
    with tempfile.TemporaryDirectory(prefix='vanian-offline-anchor-') as temporary:
        key_file = Path(temporary) / 'observer.pub'
        key_file.write_text(anchor['public_key']+'\n')
        comparison = command([tools/'aip-corroborate','--observer-id',anchor['observer_id'],
            '--key-version',str(anchor['key_version']),'--pubkey-file',key_file,
            '--batches',package/ARCHIVES[0],'--external',package/'auditd.log','--source','auditd',
            '--from-ms',str(start),'--to-ms',str(end),'--json'])
    matched = Counter((x['aip']['batch_sequence'], x['aip']['pid'], x['aip']['wall_ms'])
                      for x in comparison.get('agreed', []) if x['aip']['pid'] == process['pid'])
    require(executions and not (executions-matched) and not comparison.get('external_only')
            and not comparison.get('external_unparsed') and not any(x['pid'] == process['pid'] for x in comparison.get('aip_only', [])),
            'Fresh agent execution lacks complete independent audit agreement')
    outputs = read_json(package / 'task-output-manifest.json')
    answers = outputs.get('answer_files')
    require(isinstance(answers, dict) and set(answers)=={f'answers/case-{i}.json' for i in range(1,5)},
            'Four exact original actual answers required')
    require(outputs.get('run_id')==run_id and outputs.get('source_commit')==source
            and outputs.get('task_manifest_sha256')==hashes['task-manifest.json']
            and outputs.get('launch_sha256')==hashes['launch.json']
            and outputs.get('result_scope')=='ROOT_CONTROLLER_APPLICATION_CORRELATION'
            and outputs.get('signed_by_collector') is False, 'Controller output/task/source association differs')
    output_paths=task.get('observed_output_paths')
    require(isinstance(output_paths,list) and len(output_paths)==4 and len(set(output_paths))==4
            and all(isinstance(p,str) and p in paths for p in output_paths),
            'Every actual answer file needs a matching process-bound signed file event')
    questions=task.get('questions')
    require(isinstance(questions,list) and len(questions)==4, 'Four actual task questions required')
    calls = reads = 0
    focuses = []
    for index, (name, expected) in enumerate(sorted(answers.items())):
        require(hashes.get(name) == expected and name.startswith('answers/'), 'Output manifest does not match controller inventory')
        answer = read_json(checked_file(package, name))
        require(answer.get('answer_authority') == 'EXTRACTIVE_API_FACTS_MODEL_SELECTED'
                and answer.get('selection_authority') == 'MODEL_FOCUS_WITH_DECLARED_API_FACT_GROUP_MAPPING',
                'Original bounded EvidenceAgent output required')
        focus = answer.get('model_focus_fact_id')
        require(answer.get('model_selected_fact_ids') == [focus], 'Original model focus differs from selection')
        mapped, selected, mandatory = answer['mapped_fact_ids'], answer['selected_facts'], answer['mandatory_facts']
        require(mapped == [x['id'] for x in selected] and len(mapped) == len(set(mapped))
                and answer['mandatory_fact_ids'] == [x['id'] for x in mandatory]
                and set(answer['mandatory_fact_ids']) == {'kernel_action','authorization_window','business_outcome','record_scope','collector_custody'},
                'Extractive fact mapping or mandatory limits differ')
        expected_text = ('API facts for model-selected focus (extractive):\n'+'\n'.join(x['text'] for x in selected)
            +'\n\nAlways-required uncertainty and scope (additional facts; selected overlaps appear above):\n'
            +'\n'.join(x['text'] for x in mandatory if x['id'] not in mapped))
        require(answer['answer'] == expected_text, 'Original output contains unsupported additional text')
        allowed = [{'record_integrity','signed_authorization','kernel_action'}, {'kernel_action','authorization_window'},
                   {'record_integrity','kernel_action'}, {'business_outcome'}]
        require(focus in allowed[index], 'Actual model focus did not match the tested question')
        needed=[{'record_integrity','signed_authorization'}, {'kernel_action','authorization_window'},
                {'record_integrity','kernel_action'}, {'business_outcome'}]
        require(needed[index] <= set(mapped) and answer.get('fact_group_mapping')=={
                'focus_fact_id':focus,'base_fact_ids':mapped,'application':'EACH_RETRIEVED_RECORD'},
                'Declared fact group does not answer the actual question')
        facts=answer.get('authoritative_facts',{})
        require(facts.get('run_artifact_id')==questions[index].get('run_artifact_id')
                and facts.get('fresh_mac_kernel_capture') is False, 'Task input differs from retrieved historical record')
        evaluation=facts.get('evaluation',{})
        require(all(evaluation.get(k) is True for k in ('archive_integrity_verified','checkpoint_verified',
                'authorization_verified','gateway_receipt_verified','signed_reconciliation_verified'))
                and evaluation.get('reconciliation',{}).get('result')=='CannotProve',
                'Historical input proof boundaries changed')
        labels=answer.get('evidence_labels',[])
        require(len(labels)==1 and labels[0].get('signature_checks_verified') is True
                and labels[0].get('kernel_verdict')==evaluation['reconciliation']['result']
                and labels[0].get('kernel_reason')==evaluation['reconciliation']['reason']
                and labels[0].get('evidence_scope')=='RECORDED_LINUX_NOT_FRESH_MAC',
                'Model output labels differ from returned API findings')
        statistics = answer['model_stats']
        require(statistics.get('request_options')=={'num_ctx':8192,'num_predict':512,'temperature':0,'num_thread':2}
                and type(statistics['completed_http_requests']) is int and statistics['completed_http_requests'] == 2 and len(statistics['responses']) == 2
                and all(x.get('completed') is True and type(x.get('eval_count')) is int and x['eval_count'] > 0 for x in statistics['responses']),
                'Original output lacks two completed inference responses')
        require(len(answer['tool_trace']) == 1 and answer['tool_trace'][0]['read_only'] is True
                and len(answer['tool_trace'][0]['api_reads']) == 3 and len(answer['source_citations']) == 3,
                'Original output lacks three actual Reader API responses')
        calls += 2; reads += 3; focuses.append(focus)
    require(task.get('completed_model_requests') == calls == 8 and task.get('api_reads') == reads == 12,
            'Task and actual output counters differ')
    model = read_json(package / 'model-identity.json')
    expected_model = {'status':'PASS','classification':'PUBLIC_PINNED_LOCAL_CPU_MODEL_ASSETS',
        'repository':'Qwen/Qwen2.5-1.5B-Instruct-GGUF',
        'revision':'91cad51170dc346986eccefdc2dd33a9da36ead9','license':'Apache-2.0',
        'runtime_archive_sha256':'7bedab90dd122661be78798e9f0edf37fccf0cccf2699d2c58ea1a3afdc04b6d'}
    require(all(model.get(k)==v for k,v in expected_model.items())
        and all(model.get(k) is False for k in ('model_api_credentials_used','paid_inference_used','verification_network_used'))
        and model.get('binary',{}).get('version')=='0.40.11'
        and re.fullmatch('[0-9a-f]{64}',model.get('binary',{}).get('sha256',''))
        and model.get('model',{}).get('model')=='vanian-qwen-local'
        and model['model'].get('weight_sha256')==WEIGHT_SHA
        and type(model['model'].get('weight_bytes')) is int and model['model']['weight_bytes']==1117320736
        and type(model['model'].get('serving_context_length')) is int and model['model']['serving_context_length']==8192,
        'Controller model identity differs from the reviewed Linux runtime and HF weights')
    resident=read_json(package/'model-context.json')
    require(resident.get('status')=='PASS' and resident.get('canonical_model')=='vanian-qwen-local:latest'
            and resident.get('manifest_sha256')==model['model'].get('manifest_sha256')
            and type(resident.get('actual_service_context_length')) is int and resident['actual_service_context_length']==8192,
            'Actual serving context/manifest differs from the reviewed local model')
    source_hashes = read_json(package / 'source-hashes.json')
    require(isinstance(source_hashes,dict) and 4 <= len(source_hashes) <= 40,
            'Bounded exact execution-source inventory required')
    for name, expected in source_hashes.items():
        require(isinstance(name,str) and not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts
                and (name.startswith('examples/local-evidence-agent/') or name.startswith('integrations/real_agents/')
                     or name.startswith('validation/enterprise/') or name.startswith('sdk/python/vanian/')
                     or name=='aip-service/src/main.rs') and isinstance(expected,str)
                and re.fullmatch('[0-9a-f]{64}',expected), 'Unexpected source inventory member')
        content = subprocess.run(['git','-C',str(REPO),'show',source+':'+name],capture_output=True,timeout=30,
                                 env={'PATH':os.defpath})
        require(content.returncode==0 and hashlib.sha256(content.stdout).hexdigest()==expected,
                'Execution source does not match the approved Git commit')
    require(all('examples/local-evidence-agent/'+name in source_hashes for name in
                ('agent.py','api_runtime.py','linux_workload.py','linux_capture.py','linux_model_runtime.py',
                 'linux_model.lock.json','model_runtime.py','model.lock.json','requirements.lock'))
            and all(name in source_hashes for name in ('sdk/python/vanian/client.py','sdk/python/vanian/__init__.py',
                'aip-service/src/main.rs','integrations/real_agents/evidence.py',
                'integrations/real_agents/harness.py','integrations/real_agents/audit_crosscheck.py',
                'validation/enterprise/same_run_validation.py','validation/enterprise/prepare_local_model.py')),
            'Execution-source inventory omits required agent/runtime components')
    return {'status':'PASS','classification':'FRESH_LINUX_AGENT_OBSERVATION','run_id':run_id,
        'source_commit':source,'workflow_run_id':manifest.get('workflow_run_id'),
        'task':{'from_ms':start,'to_ms':end,'exit_code':0},
        'capture':{'platform':'Linux','signed_batches':len(batches),'health_records':len(health),
            'kernel_events':report['batches']['kernel_events'],'agent_bound_events':sum(kinds.values()),'events_by_kind':dict(kinds),'task_coverage':'SIGNED_ACTIVE_FOR_COMPLETE_TASK',
            'process_identity':'CONTROLLER_INSTANCE_MATCHED_IN_SIGNED_KERNEL_EVENTS',
            'process':process,'namespaces':namespace,'file_event_paths':sorted(p for p in paths if isinstance(p,str)),
            'required_mechanisms':MECHANISMS,'independent_audit_exec_agreements':sum(matched.values()),
            'observer_anchor':anchor,'checkpoint':checkpoint,'rust_archive_verification':report},
        'model':{'name':'Qwen2.5-1.5B-Instruct / vanian-qwen-local','completed_http_requests':calls,
            'weight_sha256':WEIGHT_SHA,'source_authority':'ROOT_CONTROLLER_APPLICATION_CORRELATION','actual_focuses':focuses},
        'api_reads':{'completed':reads,'source_authority':'ROOT_CONTROLLER_APPLICATION_CORRELATION'},
        'output':{'sha256':digest(package/'task-output-manifest.json'),'answer_files':answers,
            'source_authority':'ROOT_CONTROLLER_APPLICATION_CORRELATION'},
        'original_public_files_verified':len(hashes),'controller_trust_sha256':digest(trust),
        'api_observation_admission':'NOT_REQUESTED_OR_CLAIMED',
        'limits':['Fresh Linux kernel capture; no new Mac kernel capture.',
            'Observer signatures cover system observations, not model answer semantics or model-call counts.',
            'Task outputs, model counters and their association are separately approved controller metadata.',
            'No new gateway authorization, gateway receipt, loan approval or logical delegation proof is supplied.',
            'Collector and workload share runner administration; independent administrative custody is not established.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--trust', type=Path, required=True)
    parser.add_argument('--tools', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists() and not args.output.is_symlink()
            and not args.output.resolve(strict=False).is_relative_to(args.package.resolve()),
            'Verification output must be new and outside the original capture')
    result = verify_fresh(args.package, args.trust, args.tools)
    descriptor=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,'w') as output:
        output.write(json.dumps(result, indent=2, allow_nan=False)+'\n')
    print(json.dumps({'status':result['status'],'run_id':result['run_id'],'signed_batches':result['capture']['signed_batches'],
                      'kernel_events':result['capture']['kernel_events'],'model_responses':result['model']['completed_http_requests']}))


if __name__ == '__main__':
    main()
