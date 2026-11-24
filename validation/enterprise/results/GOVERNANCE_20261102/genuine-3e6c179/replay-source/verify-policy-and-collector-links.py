"""Derived offline replay; never edits original evidence or runs an agent/model."""
from pathlib import Path
import hashlib,importlib.util,json,time,platform,re

ROOT=Path('/private/tmp/snifferdog-gov-3e6c179-41432473155')
SNAPSHOT=Path('/private/tmp/snifferdog-gov-3e6c179-replay-source')
OUT=ROOT/'independent-offline';OUT.mkdir(exist_ok=True)
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def save(path,value):Path(path).write_text(json.dumps(value,indent=2,allow_nan=False)+'\n')
def module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
opa=module('aip_exact_3e6c179_opa',SNAPSHOT/'integrations/governance/opa.py')
telemetry=module('aip_exact_3e6c179_telemetry',SNAPSHOT/'integrations/governance/telemetry.py')
OPA_ENGINE=Path('/private/tmp/snifferdog-opa-adapter-bootstrap/opa-1.22.0-darwin_arm64')
opa_identity=opa.verify_engine(OPA_ENGINE)
opa_lock=json.loads((SNAPSHOT/'integrations/governance/opa.lock.json').read_text())
otel_lock=json.loads((SNAPSHOT/'integrations/governance/otel.lock.json').read_text())
phase_names={'aip.governance.policy','aip.authorization.issue','aip.agent.execution','aip.evidence.verify','aip.enterprise.clients','aip.run'}
summary={'classification':'INDEPENDENT_OFFLINE_OPA_AUDIT_LINK_AND_ORIGINAL_COLLECTOR_RECORD_REPLAY',
 'source_commit':'3e6c1794000fa23006ef623722e37700e49582b7','run_id':41432473155,'artifact_id':13136100222,
 'additional_agent_or_model_execution':False,'network_used_for_replay':False,
 'policy_replay_engine':opa_identity,'profiles':{},'replay_module_source_manifest_sha256':sha(SNAPSHOT/'review-source-manifest.json')}
receipts=[]
for name in ('same-run','same-run-interruption','same-run-recovery'):
 public=ROOT/'original'/name/'public';gov=public/'governance';dest=OUT/name
 manifest=telemetry.read_json(public/'run-manifest.json');audit=telemetry.read_json(gov/'opa-decision.json')
 authority=telemetry.read_json(public/'authority-request.json');expectation=telemetry.read_json(public/'expectation.json')
 assert manifest['source_commit']==summary['source_commit'] and manifest['status']=='PASS'
 assert authority['source_authority']=='root_authority_controller_SO_PEERCRED'
 assert authority['peer_uid']==10001 and authority['peer_pid']==manifest['agent_pid']
 assert expectation['agent_id']==manifest['agent_id']
 decision_id=bytes(expectation['decision_id']).hex();expectation_sha=sha(public/'expectation.json')
 assert audit['run_id']==manifest['run_id'] and audit['allowed'] is True and audit['status']=='ALLOW'
 assert audit['policy_engine_completed'] is True and audit['not_signed'] is True and audit['aip_authorization'] is False
 assert audit['signed_authorization'] is False and audit['kernel_observation'] is False
 assert audit['aip_decision_id']==decision_id and audit['aip_expectation_file_sha256']==expectation_sha
 assert audit['link_authority']=='ROOT_CONTROLLER_CORRELATION_NOT_A_NEW_SIGNATURE'
 assert audit['engine_version']==opa_lock['version'] and audit['engine_sha256']==opa_lock['assets']['linux_amd64']['sha256']
 assert audit['policy_sha256']==opa_lock['policy_sha256']==sha(SNAPSHOT/'integrations/governance/opa.rego')
 t=time.monotonic()
 replay=opa.evaluate(OPA_ENGINE,proposal=authority['actual_proposal'],agent_id=manifest['agent_id'],
  peer_pid=authority['peer_pid'],peer_uid=authority['peer_uid'],peer_gid=10001,
  expected_pid=manifest['agent_pid'],expected_uid=10001,expected_gid=10001,
  allowed_calls=[{'tool_id':'same-run-loan-read','arguments':{'loan_id':1,'amount':0}}])
 assert replay['allowed'] is True and replay['status']=='ALLOW'
 for key in ('input_sha256','policy_data_sha256','proposal_sha256','policy_sha256','output_sha256','engine_version'):
  assert replay[key]==audit[key],(name,key)
 save(dest/'independent-opa-evaluation.json',replay)
 receipts.append({'profile':name,'operation':'PUBLIC_OPA_EVALUATE_WITH_EXACT_SOURCE_POLICY',
  'seconds':time.monotonic()-t,'platform':platform.system()+'-'+platform.machine(),
  'engine_sha256':opa_identity['sha256'],'policy_sha256':replay['policy_sha256'],
  'input_sha256':replay['input_sha256'],'controller_data_sha256':replay['policy_data_sha256'],
  'output_sha256':replay['output_sha256'],'allowed':True,'network_used':False})
 original=telemetry.read_json(gov/'otel/telemetry-report.json');integration=telemetry.read_json(gov/'integration-report.json')
 payload=telemetry.read_json(gov/'otel/records.json');controller=telemetry.read_json(gov/'controller-phase-records.json')
 assert set(payload)=={'nonce','records'}
 assert controller['classification']==telemetry.SOURCE and controller['export']==telemetry.MODE and controller['kernel_evidence'] is False
 assert controller['records']==payload['records']
 records=telemetry.validate_records(payload['records'])
 assert len(records)==6 and {r['phase'] for r in records}==phase_names
 assert {r['attributes']['aip.run_id'] for r in records}=={manifest['run_id']}
 assert payload['nonce']==original['nonce'] and original['status']=='PASS'
 assert original['classification']==telemetry.SOURCE and original['export_mode']==telemetry.MODE
 assert original['signed_kernel_evidence'] is False and original['independent_custody'] is False
 assert original['sdk_isolated'] is True and original['final_file_verified_after_collector_stop'] is True
 assert original['raw_collector_log_published'] is False and original['collector_exit_code']==0
 assert original['collector_version']==otel_lock['collector']['version'] and original['sdk_version']==otel_lock['sdk']['version']
 assert original['collector_binary_sha256']==otel_lock['collector']['platforms']['Linux-x86_64']['binary_sha256']
 assert {p.name for p in (gov/'otel').iterdir()}=={'records.json','collector-config.json','collector-spans.jsonl','telemetry-report.json'}
 collector=telemetry.verify_collector_file(gov/'otel/collector-spans.jsonl',records,payload['nonce'],original['trace_id'])
 for key,value in collector.items():assert original[key]==value,(name,key)
 assert collector['original_collector_file_sha256']==sha(gov/'otel/collector-spans.jsonl')
 config=telemetry.read_json(gov/'otel/collector-config.json')
 assert set(config)=={'receivers','exporters','service'} and set(config['receivers'])=={'otlp'} and set(config['exporters'])=={'file'}
 endpoint=config['receivers']['otlp']['protocols']['http']['endpoint']
 assert re.fullmatch(r'127\.0\.0\.1:[0-9]{1,5}',endpoint) and 1<=int(endpoint.rsplit(':',1)[1])<=65535
 assert config['service']['pipelines']=={'traces':{'receivers':['otlp'],'exporters':['file']}}
 assert config['exporters']['file']['path'].endswith('/private/governance-telemetry/collector-spans.jsonl')
 assert config['service']['telemetry']['metrics']=={'level':'none','readers':[]}
 by_phase={r['phase']:r for r in records}
 assert by_phase['aip.governance.policy']['attributes']['aip.policy.allowed'] is True
 assert by_phase['aip.governance.policy']['attributes']['aip.policy.sha256']==audit['policy_sha256']
 assert by_phase['aip.governance.policy']['attributes']['aip.policy.engine.sha256']==audit['engine_sha256']
 assert by_phase['aip.authorization.issue']['attributes']['aip.authorization.decision_id']==decision_id
 assert by_phase['aip.authorization.issue']['attributes']['aip.authorization.expectation_sha256']==expectation_sha
 assert by_phase['aip.evidence.verify']['attributes']['aip.evidence.bundle_sha256']==sha(public/'run-bundle.json')
 assert by_phase['aip.evidence.verify']['attributes']['aip.evidence.signed_reconciliation_sha256']==sha(public/'signed-reconciliation.json')
 assert by_phase['aip.run']['attributes']['aip.controller.status']==manifest['status']
 assert by_phase['aip.run']['attributes']['aip.kernel.coverage_status']==manifest['observation_coverage']
 assert integration['telemetry']==original and integration['run_id']==manifest['run_id'] and integration['controller_result']==manifest['status']
 assert integration['policy_allowed'] is True and integration['policy_linked_to_aip_decision'] is True
 assert integration['aip_verification_rules']=='UNCHANGED' and integration['telemetry_is_kernel_evidence'] is False
 assert integration['policy_audit_is_signed_authorization'] is False
 save(dest/'independent-collector-verification.json',collector)
 summary['profiles'][name]={'run_id':manifest['run_id'],'OPA_original_status':audit['status'],
  'OPA_original_linux_engine_pin_matches':True,'OPA_same_version_Darwin_replay':'ALLOW',
  'OPA_input_data_proposal_policy_output_hashes_match':True,'actual_signed_decision_id':decision_id,
  'original_expectation_file_sha256':expectation_sha,'OPA_audit_link_matches_original_signed_authorization':True,
  'policy_audit_is_signed_authorization':False,'original_collector_file_sha256':collector['original_collector_file_sha256'],
  'six_controller_phases_verified':True,'span_count':collector['span_count'],'trace_id':collector['trace_id'],
  'original_export_nonce':payload['nonce'],'actual_parent_trace_timestamp_attribute_values_match':True,
  'AIP_file_hash_links_match_originals':True,'original_no_raw_log_publication':True,
  'original_stopped_Collector_exit_code':0,'source_authority':telemetry.SOURCE,
  'export_mode':telemetry.MODE,'signed_kernel_evidence':False}
 print(json.dumps({'profile':name,'OPA_replay':'ALLOW','audit_decision_and_file_hash_match':True,
  'collector_spans':collector['span_count'],'original_hash_matches':True,'source_authority':telemetry.SOURCE}))
negative=telemetry.read_json(ROOT/'original/governance-unavailable/public/run-manifest.json')
negative_dir=ROOT/'original/governance-unavailable/public'
assert negative['status']=='FAIL' and negative['autonomous_workload_executed'] is False
assert negative['open_source_governance']=='INITIALIZATION_FAILED' and negative['failure']['type']=='FileNotFoundError'
assert negative['cleanup_errors']==[] and not (negative_dir/'expectation.json').exists() and not (negative_dir/'attested.archive.jsonl').exists()
summary['actual_missing_assets_negative']={'status':'EXPECTED_FAILURE_RETAINED','failure_type':'FileNotFoundError',
 'autonomous_workload_executed':False,'authorization_or_kernel_archive_produced':False,'cleanup_errors':[]}
summary['limits']=['OPA audit and trace records are unsigned root-controller application testimony, not new authorization, kernel evidence or independent custody.',
 'Offline peer-context reconstruction uses the original root authority request and source-enforced GID10001; matching hashes do not remeasure SO_PEERCRED on this Mac.',
 'Original Linux engine hash is checked against its exact source pin. Independent same-version policy replay uses the separately hash-verified Darwin asset; binary hashes differ by platform.',
 'Telemetry is delayed post-cleanup controller phase export, not model prompt capture, per-agent instrumentation, full distributed causality or proof of a business payload.',
 'Actual live profiles demonstrate OPA allowance linked to signed AIP decisions. Deny-before-sign controls belong to the separately executed component/broker tests; no denied genuine-agent proposal is invented.',
 'Core canonical kernel CannotProve/coverage semantics remain unchanged; recovery never repairs interrupted task coverage. All public trust files came in the same GitHub artifact.']
save(OUT/'governance-command-receipts.json',receipts);save(OUT/'governance-link-verification.json',summary)
