from pathlib import Path
import json,hashlib,collections,subprocess,os,time,sys,shutil
REPO=Path('/Users/richardrich/.codex/worktrees/snifferdog-complete-enterprise-validation/AIP')
sys.path.insert(0,str(REPO/'integrations/real_agents'))
from evidence import records,summarize,covered,acceptance
from hosted_observer_smoke import ALL_COMPONENT_MECHANISMS
ROOT=Path('/private/tmp/snifferdog-agent-zero-41299438636-preserved')
PUBLIC=ROOT/'original/agent-zero-genuine/public'
OUT=ROOT/'independent-offline';OUT.mkdir(exist_ok=False)
TRUST=OUT/'separately-supplied-public-trust';TRUST.mkdir()
for n in ('anchor.json','checkpoint.json'):shutil.copyfile(PUBLIC/n,TRUST/n)
anchor=json.loads((TRUST/'anchor.json').read_text());checkpoint=json.loads((TRUST/'checkpoint.json').read_text())
for n,digest in checkpoint['sha256'].items():assert hashlib.sha256((PUBLIC/n).read_bytes()).hexdigest()==digest
(TRUST/'observer.pub').write_text(anchor['public_key']+'\n')
status=json.loads((PUBLIC/'harness-status.json').read_text());start,end=status['workload_from_ms'],status['workload_to_ms']
commands=[('archive-verifier',[str(REPO/'target/debug/aip-observe-verify'),'--observer-id',anchor['observer_id'],
    '--key-version',str(anchor['key_version']),'--pubkey',anchor['public_key'],'--batches',str(PUBLIC/'attested.archive.jsonl'),
    '--health',str(PUBLIC/'health.archive.jsonl'),'--json']),
 ('audit-corroborator',[str(REPO/'target/debug/aip-corroborate'),'--observer-id',anchor['observer_id'],'--key-version',str(anchor['key_version']),
    '--pubkey-file',str(TRUST/'observer.pub'),'--batches',str(PUBLIC/'attested.archive.jsonl'),'--external',str(PUBLIC/'auditd.log'),
    '--source','auditd','--from-ms',str(start),'--to-ms',str(end),'--json'])]
receipts=[];reports={}
for name,cmd in commands:
 t=time.monotonic();p=subprocess.run(cmd,capture_output=True,env={'PATH':os.defpath},timeout=120)
 (OUT/(name+'.stdout.json')).write_bytes(p.stdout);(OUT/(name+'.stderr.txt')).write_bytes(p.stderr)
 receipts.append({'name':name,'arguments':cmd,'environment_keys':['PATH'],'exit_code':p.returncode,'seconds':time.monotonic()-t,
    'stdout_sha256':hashlib.sha256(p.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(p.stderr).hexdigest()})
 assert p.returncode==0
 reports[name]=json.loads(p.stdout)
assert not reports['archive-verifier']['findings']
batches,health=records(PUBLIC/'attested.archive.jsonl'),records(PUBLIC/'health.archive.jsonl')
launch=json.loads((PUBLIC/'launch.json').read_text());summary=summarize(batches,health,launch,start,end)
assert summary==json.loads((PUBLIC/'observation-summary.json').read_text())
comparison=reports['audit-corroborator'];failures=acceptance(summary,comparison,status['workload_exit'])
assert failures==status['failures']
observed=collections.Counter((e['batch_sequence'],e['pid'],e['wall_ms']) for e in summary['workload_executions'])
paired=collections.Counter((e['aip']['batch_sequence'],e['aip']['pid'],e['aip']['wall_ms']) for e in comparison['agreed'])
cap=json.loads((PUBLIC/'framework-capability.json').read_text());model=json.loads((PUBLIC/'model-calls.json').read_text())
business=json.loads((PUBLIC/'business-acceptance.json').read_text());profile=json.loads((PUBLIC/'profile.json').read_text())
analysis={'classification':'INDEPENDENT_OFFLINE_VERIFICATION_OF_GENUINE_FAILED_AGENT_ZERO_BUSINESS_WORKLOAD',
 'source_commit':'0b3473046af8433a0b96a6c24403336d1a6819b1','run_id':41299438636,'artifact_id':13081566093,
 'genuine_workload':'EXECUTED','business_task_acceptance':'FAIL','workload_exit':status['workload_exit'],
 'capability_status':cap['status'],'successful_HTTP200_capability_requests':cap['actual_model_requests_in_stage'],
 'successful_HTTP200_framework_period_requests_excluding_policy':model['successful_framework_period_requests_excluding_policy'],
 'total_attempted_model_requests':'UNKNOWN_COUNTER_COUNTS_SUCCESSFUL_HTTP200_ONLY',
 'requested_task_interval_ms':{'from':start,'to':end},'task_ms':end-start,
 'original_checkpoint_bytes_match':True,'signature_chain_verification':reports['archive-verifier'],
 'independent_full_six_sensor_task_coverage':covered(health,start,end,ALL_COMPONENT_MECHANISMS),
 'six_sensor_replay_limit':'Original generic harness acceptance checks3mechanisms; this separate post-signature replay requests6explicitmechanisms from final signed health only, no epochunion/oldhealthfallback.',
 'requested_sensor_mechanisms':ALL_COMPONENT_MECHANISMS,'latest_signed_health':health[-1]['health'],
 'nonverified_batch_sequences':[b['sequence'] for b in batches if any(m['integrity']!='Verified' for m in b['batch']['mechanism_integrity'])],
 'summary_matches_original':True,'recomputed_observation_acceptance':'FAIL','recomputed_observation_failures':failures,
 'workload_namespace_bound_events':summary['workload_events_by_kind'],'exact_process_instances':summary['process_instances'],
 'launch_instance_events':summary['launch_instance_events'],'reported_drops':summary['probe_reported_drops'],
 'unclocked_events':summary['events_without_clock_anchor'],'unbound_host_events_not_attributed':summary['unbound_host_events'],
 'outside_workload_bound_events_not_attributed':summary['outside_workload_bound_events'],
 'audit_comparison':{'agreed':len(comparison['agreed']),'whole_host_aip_only':len(comparison['aip_only']),
    'external_only':len(comparison['external_only']),'external_unparsed':comparison['external_unparsed'],
    'external_failed_attempts':comparison['external_failed_attempts'],'unmatched_exact_bound_exec_references':sum((observed-paired).values())},
 'business_original_controller_report':{'status':business['status'],'failures':business['failures'],
    'actual':business['actual'],'policy_responses_in_task_window':business['business_policy_responses_in_task_window'],
    'controller_measured_client_ip':business['controller_measured_client_ip'],'actual_report_sha256':business['original_report_sha256']},
 'finalization_original':json.loads((PUBLIC/'finalization.json').read_text()),
 'limitations':['Crypto integrity and full signed task coverage do not turn failed work/no file event/missing report into success.',
   'One root HTTP-service policy response tied to measured workload IP/time is unsigned application testimony, not kernel TCP payload/URL proof or AIP authorization.',
   'Missing workload-bound FileEvent remains zero in the actual signed records; outside/unbound host events are not borrowed.',
   'No gateway receipts/AIP authority or logical delegation claim is supplied by this business profile.',
   'Original public anchor/checkpoint arrived in same GitHub artifact. Shared kernel/root/GitHub administration trusted; independentinstitutioncustody incomplete.'],
 'verifier_binaries_sha256':{Path(cmd[0]).name:hashlib.sha256(Path(cmd[0]).read_bytes()).hexdigest() for _,cmd in commands},
 'verifier_build_source':'ff99d5ce41665bf8357e724570b0b1bf80f9601a','aip_standalone_source_ff99_to_0b347_equal':True}
(OUT/'command-receipts.json').write_text(json.dumps(receipts,indent=2)+'\n')
(OUT/'recomputed-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
(OUT/'summary.json').write_text(json.dumps(analysis,indent=2)+'\n')
print(json.dumps({'path':str(OUT),'signature_findings':len(reports['archive-verifier']['findings']),
 'counts':{k:reports['archive-verifier'][k] for k in ['batches','health']},'all_six_task_coverage':analysis['independent_full_six_sensor_task_coverage'],
 'bound_events':summary['workload_events_by_kind'],'task_acceptance':'FAIL','failures':failures,'audit':analysis['audit_comparison']}))
