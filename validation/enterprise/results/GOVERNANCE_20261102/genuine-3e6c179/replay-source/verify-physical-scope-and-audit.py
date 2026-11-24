from pathlib import Path
import collections, hashlib, ipaddress, json, os, subprocess, sys, time
REPO=Path('/Users/richardrich/.codex/worktrees/snifferdog-complete-enterprise-validation/AIP')
sys.path.insert(0,'/private/tmp/snifferdog-gov-3e6c179-replay-source/integrations/real_agents')
from evidence import covered, event_time, instance_key, records
ALL_COMPONENT_MECHANISMS=['SchedTracepoint','CgroupTracepoint','ProcConnector','Fanotify','SockStateTracepoint','SockSendTracepoint']
ROOT=Path('/private/tmp/snifferdog-gov-3e6c179-41432473155')
OUT=ROOT/'independent-offline'
summary={'classification':'DERIVED_INDEPENDENT_CORE_PHYSICAL_SCOPE_AND_ORIGINAL_CLIENT_REPORT_INSPECTION',
    'source_commit':'3e6c1794000fa23006ef623722e37700e49582b7','run_id':41432473155,
    'artifact_id':13136100222,'profiles':{},'separate_administrative_custody':'INCOMPLETE'}
commands=[]
for name in ('same-run','same-run-interruption','same-run-recovery'):
    public=ROOT/'original'/name/'public';dest=OUT/name
    m=json.loads((public/'run-manifest.json').read_text());start,end=m['from_ms'],m['to_ms']
    batches,health=records(public/'attested.archive.jsonl'),records(public/'health.archive.jsonl')
    instances=json.loads((public/'kernel-bound-instances.json').read_text())['instances']
    keys={instance_key(v['process']) for v in instances.values()}
    counts,host=collections.Counter(),collections.Counter();execs=collections.Counter();send_bytes=0
    files=[];endpoints=set();unclocked=0
    for signed in batches:
        b=signed['batch']
        for event in b['kernel_events']:
            at=event_time(b,event)
            if at is None:
                unclocked+=1;continue
            if not start<=at<=end:continue
            kind=next(iter(event['kind']));host[kind]+=1
            bound=event.get('bound')
            if not bound or instance_key(bound['process']) not in keys:continue
            counts[kind]+=1
            if kind=='ProcessExec':execs[(signed['sequence'],bound['process']['pid'],at)]+=1
            if kind=='SocketSend':send_bytes+=event['kind'][kind]['bytes']
            if kind=='FileEvent':files.append(event['kind'][kind])
            if kind=='SocketState':
                state=event['kind'][kind];remote=state['remote'];address=bytes(remote['addr'])
                address=str(ipaddress.ip_address(address if remote['is_v6'] else address[:4]))
                endpoints.add((address,remote['port'],state['old_state'],state['new_state']))
    comparisons=[]
    anchor=json.loads((ROOT/'original'/name/'observer-anchor.json').read_text())
    keyfile=dest/'separately-supplied-public-trust/observer.pub';keyfile.write_text(anchor['public_key']+'\n')
    paired=collections.Counter()
    for number in (0,1):
        cmd=[str(REPO/'target/debug/aip-corroborate'),'--observer-id',anchor['observer_id'],
             '--key-version',str(anchor['key_version']),'--pubkey-file',str(keyfile),
             '--batches',str(public/'attested.archive.jsonl'),'--external',str(public/f'audit-{number}.log'),
             '--source','auditd','--from-ms',str(start),'--to-ms',str(end),'--json']
        began=time.monotonic();p=subprocess.run(cmd,capture_output=True,env={'PATH':os.defpath},timeout=120)
        (dest/f'independent-audit-{number}.stdout.json').write_bytes(p.stdout)
        (dest/f'independent-audit-{number}.stderr.txt').write_bytes(p.stderr)
        commands.append({'arguments':cmd,'environment_keys':['PATH'],'exit_code':p.returncode,
            'seconds':time.monotonic()-began,'stdout_sha256':hashlib.sha256(p.stdout).hexdigest(),
            'stderr_sha256':hashlib.sha256(p.stderr).hexdigest()})
        if p.returncode:
            assert name=='same-run-interruption' and p.stderr.strip()==b'REFUSED: the two observation windows do not overlap'
            comparisons.append({'source':f'audit-{number}.log','status':'REFUSED_NO_OVERLAPPING_OBSERVATION_WINDOWS',
                'exit_code':p.returncode,'agreed':None,'external_only':None,
                'limit':'Actual task audit interval and original pre-interruption AIP archive do not overlap; strict corroborator refused. No earlier events were reused.'})
            continue
        a=json.loads(p.stdout)
        for item in a['agreed']:paired[(item['aip']['batch_sequence'],item['aip']['pid'],item['aip']['wall_ms'])]+=1
        comparisons.append({'source':f'audit-{number}.log','agreed':len(a['agreed']),
            'whole_host_aip_only':len(a['aip_only']),'external_only':len(a['external_only']),
            'external_unparsed':a['external_unparsed'],'external_failed_attempts':a['external_failed_attempts']})
    client=json.loads((public/'enterprise-clients.json').read_text())
    evaluation=json.loads((dest/'independent-run-evaluation.json').read_text())
    client_checks={k:v for k,v in client.items() if v=='PASS'}
    assert client['source_bundle_sha256']==hashlib.sha256((public/'run-bundle.json').read_bytes()).hexdigest()
    assert all(client['evaluation'][k]==v for k,v in evaluation.items())
    negatives=json.loads((public/'captured-negatives.json').read_text())
    latest=health[-1]['health']
    row={'actual_run_id':m['run_id'],'controller_manifest_status':m['status'],
        'controller_reported_model_calls':m['model_calls'],'actual_task_interval_ms':{'from':start,'to':end},
        'all_six_sensor_actual_task_coverage':covered(health,start,end,ALL_COMPONENT_MECHANISMS),
        'controller_coverage_annotation':m['observation_coverage'],
        'canonical_kernel_finding':{k:evaluation['reconciliation'][k] for k in ('identity','result','reason','availability','action','lineage','wire')},
        'signed_counts':{'batches':len(batches),'kernel_events':sum(len(b['batch']['kernel_events']) for b in batches),'health':len(health)},
        'exact_process_instances_recorded':len(keys),'namespace_and_instance_binding_origin':'Original signed observations; exact boot/PID/start ticks matches only, not PID alone.',
        'exact_instance_bound_event_counts':dict(counts),'whole_host_task_event_counts_not_promoted':dict(host),
        'bound_socket_send_bytes':send_bytes,'bound_file_close_events':files,
        'bound_socket_state_remote_endpoints':[{'address':a,'port':p,'old_state':o,'new_state':n} for a,p,o,n in sorted(endpoints)],
        'network_limit':'SocketState tuples describe observed state transitions/attempts. SocketSend bytes are not HTTP payloads or logical request/destination proof; reused kernel socket addresses are not promoted into an authorization/receipt join.',
        'file_limit':'mask8 is FAN_CLOSE_WRITE in existing probe source; it records writable-file close metadata, not file contents, exact changes or business correctness.',
        'unclocked_archive_events':unclocked,'reported_drops':sum(b['batch']['dropped_events'] for b in batches),
        'nonverified_batch_sequences':[b['sequence'] for b in batches if any(v['integrity']!='Verified' for v in b['batch']['mechanism_integrity'])],
        'latest_signed_health':{k:latest.get(k) for k in ('state','continuity','attested_coverage','covered_by','clock')},
        'independent_audit_replays':comparisons,'unmatched_exact_instance_exec_references':sum((execs-paired).values()),
        'original_controller_client_checks':client_checks,'client_report_source_bundle_hash_matches':True,
        'client_evaluation_matches_independent_fields':True,
        'client_limit':'Actual API/SDK/MCP/browser checks were executed by the Linux workflow. This offline replay inspects original reports and verifies their exact bundle/evaluation join; it does not repeat browser/network clients on Mac.',
        'original_captured_negative_checks':{k:v['status'] for k,v in negatives['checks'].items()},
        'negative_scope':'Original controlled mutations of captured records; live observer interruption is a separate actually executed profile. Actual Refused receipt was independently verified and reevaluated separately.',
        'business_outcome':m['business_outcome'],'logical_subagent_attribution':m['logical_subagent_attribution'],
        'performance_scope':json.loads((public/'performance.json').read_text())['classification'],
        'cleanup_errors':m['cleanup_errors']}
    summary['profiles'][name]=row
    if name!='same-run-interruption':
        assert row['all_six_sensor_actual_task_coverage'] and row['unmatched_exact_instance_exec_references']==0
        assert all(c['external_only']==0 and c['external_unparsed']==0 for c in comparisons)
    print(json.dumps({'profile':name,'signed':row['signed_counts'],'all_six_covered':row['all_six_sensor_actual_task_coverage'],
        'bound_counts':dict(counts),'unmatched_execs':row['unmatched_exact_instance_exec_references'],
        'client_pass_checks':len(client_checks),'audit':comparisons,'finding':row['canonical_kernel_finding']}))
anchors=[json.loads((ROOT/'original'/name/'observer-anchor.json').read_text())['public_key'] for name in summary['profiles']]
summary['fresh_observer_public_keys_distinct']=len(set(anchors))==3
summary['recovery_limit']='Fresh process/key/capture recovery; not same-key daemon restart continuity. No prior observation backfills the actual interruption interval.'
summary['trust_limit']='Original public anchors/checkpoints supplied separately to tools but received in the same GitHub artifact; shared host kernel/root and GitHub administration trusted. Not independent institutional custody, complete ground truth, logical delegation, authoritative bank outcomes or production approval.'
(OUT/'physical-observation-and-clients.json').write_text(json.dumps(summary,indent=2)+'\n')
(OUT/'audit-command-receipts.json').write_text(json.dumps(commands,indent=2)+'\n')
