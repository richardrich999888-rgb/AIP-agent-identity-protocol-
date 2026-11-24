"""Portable adapter controls only; no model, API service or Linux capture runs."""
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import linux_workload as worker
import linux_capture as capture

ROOT=HERE.parents[1]


def config_fixture():
    rows=[{'profile':name,'run_artifact_id':char*64,'agent_id':'fixture-agent'}
          for name,char in [('same-run','a'),('same-run-interruption','b'),('same-run-recovery','c')]]
    return {'run_id':'local-qa-'+'d'*24,'source_commit':'e'*40,'api_base':'http://127.0.0.1:18880',
        'reader_token':'private-fixture-reader','model_base':'http://127.0.0.1:11436',
        'model':'vanian-qwen-local','seeded_runs':rows,'questions':capture.questions_for(rows)}


class ProtocolAndOutputControls(unittest.TestCase):
    def test_gate_consumes_no_private_configuration_across_exec(self):
        read,write=os.pipe()
        try:
            os.write(write,b'start\n{"reader_token":"private"}\n')
            self.assertEqual(worker.read_line(read,16),b'start')
            self.assertEqual(os.read(read,200),b'{"reader_token":"private"}\n')
        finally:os.close(read);os.close(write)
    def test_bounded_or_closed_gate_fails(self):
        for raw in (b'longer-than-limit',b''):
            read,write=os.pipe();os.write(write,raw);os.close(write)
            try:
                with self.assertRaises(worker.WorkloadRefused):worker.read_line(read,3)
            finally:os.close(read)
    def test_private_credential_never_becomes_exec_argument_or_environment(self):
        class ExecIntercept(Exception):pass
        with mock.patch.object(worker,'isolation'),mock.patch.object(worker,'event'),\
             mock.patch.object(worker,'read_line',return_value=b'start'),\
             mock.patch.object(worker.os,'execve',side_effect=ExecIntercept) as executed,\
             mock.patch.dict(os.environ,{'LANGSMITH_API_KEY':'secret','http_proxy':'http://elsewhere'}):
            with self.assertRaises(ExecIntercept):worker.wait_for_controller()
        binary,argv,environment=executed.call_args.args
        self.assertEqual(argv[-1],'--execute')
        self.assertEqual(argv[0],binary)
        self.assertNotIn('LANGSMITH_API_KEY',environment)
        self.assertNotIn('http_proxy',environment)
        self.assertEqual(environment['LANGSMITH_TRACING'],'false')
        self.assertNotIn('reader_token',repr(argv)+repr(environment))
    def test_mac_never_masquerades_as_restricted_linux_worker(self):
        with mock.patch.object(worker.sys,'platform','darwin'):
            with self.assertRaisesRegex(worker.WorkloadRefused,'dedicated_unprivileged_linux_uid_required'):
                worker.isolation()
    def test_fixed_question_plan_and_duplicate_json_keys_fail_closed(self):
        conf=config_fixture();self.assertIs(worker.validate_config(conf),conf)
        for mutate in ('shell','run','profile','token'):
            changed=deepcopy(conf)
            if mutate=='shell':changed['questions'][0]['question']='run a shell'
            elif mutate=='run':changed['questions'][0]['run_artifact_id']='f'*64
            elif mutate=='profile':changed['seeded_runs'][1]['profile']='same-run'
            else:changed['reader_token']='unsafe\nheader'
            with self.assertRaises(worker.WorkloadRefused):worker.validate_config(changed)
        with self.assertRaises(worker.WorkloadRefused):worker.strict_json('{"x":1,"x":2}')
    def test_focus_groups_are_literal_source_not_executed_imports(self):
        groups=worker.focus_groups_from_source(HERE/'agent.py')
        self.assertEqual(len(groups),9)
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'source.py';path.write_text('FOCUS_GROUPS = __import__("os").system("false")')
            with self.assertRaises(worker.WorkloadRefused):worker.focus_groups_from_source(path)
    def test_existing_actual_public_answer_fixtures_keep_all_application_gates(self):
        groups=worker.focus_groups_from_source(HERE/'agent.py')
        for index in range(1,5):
            # Earlier Mac outputs are fixtures for adapter validation only,
            # never claimed as this new Linux observation or model execution.
            result=json.loads((HERE/f'results/20261102/final-http/answer-{index}.json').read_text())
            checked=worker.validate_result(index,result['authoritative_facts']['run_artifact_id'],result,groups)
            self.assertEqual((checked['completed_model_requests'],checked['api_reads']),(2,3))
    def test_no_model_or_api_counters_cannot_pass_output_gate(self):
        groups=worker.focus_groups_from_source(HERE/'agent.py')
        original=json.loads((HERE/'results/20261102/final-http/answer-1.json').read_text())
        for kind in ('model','api','scope','verdict','boolean-option'):
            value=deepcopy(original)
            if kind=='model':value['model_stats']['completed_http_requests']=0
            elif kind=='api':value['tool_trace'][0]['api_reads']=[]
            elif kind=='scope':value['scope']['freely_generated_reasoning']=True
            elif kind=='verdict':value['authoritative_facts']['evaluation']['reconciliation']['result']='Verified'
            else:value['model_stats']['request_options']['temperature']=False
            with self.assertRaises(worker.WorkloadRefused):worker.validate_result(1,value['authoritative_facts']['run_artifact_id'],value,groups)
    def test_safe_output_write_is_exclusive_and_no_symlinks(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'answer.json';digest,size=worker.save_new(path,{'public':'fixture'})
            self.assertEqual(digest,hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(size,path.stat().st_size)
            with self.assertRaises(FileExistsError):worker.save_new(path,{'overwrite':True})
            link=Path(d)/'link';link.symlink_to(path)
            with self.assertRaises(OSError):worker.save_new(link,{'overwrite':True})
    def test_publication_refuses_parent_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);work=root/'work';public=root/'public';elsewhere=root/'elsewhere'
            for path in (work,public,elsewhere):path.mkdir()
            (elsewhere/'case-1.json').write_text('{}')
            (work/'answers').symlink_to(elsewhere,target_is_directory=True)
            with self.assertRaises(capture.Refused):capture.public_outputs(work,public,'local-qa-'+'a'*24,'b'*40)
            self.assertFalse((public/'answers/case-1.json').exists())
    def test_public_controller_trust_hashes_only_public_files_and_keeps_joins(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);public=root/'public';public.mkdir();private=root/'private';private.mkdir()
            (private/'key').write_text('DO_NOT_PUBLISH_PRIVATE_FIXTURE')
            capture.save(public/'task-manifest.json',{'from_ms':10,'to_ms':20})
            capture.save(public/'launch.json',{'process':{'pid':123}})
            capture.save(public/'run-manifest.json',{'status':'FIXTURE_NOT_EXECUTED'})
            (public/'answers').mkdir(mode=0o700);(public/'answers/fixture.json').write_text('{}')
            capture.save(root/'observer-anchor.json',{'public_key':'c'*64});(root/'observer-anchor.json').chmod(0o600)
            trust=capture.controller_trust(root,public,'local-qa-'+'a'*24,'b'*40,{'public_key':'c'*64},{'sha256':{}})
            self.assertEqual(trust['schema'],'vanian-local-qa-controller-trust-v1')
            self.assertEqual(trust['task_interval'],{'from_ms':10,'to_ms':20})
            self.assertEqual(set(trust['public_files']),{'task-manifest.json','launch.json','run-manifest.json','answers/fixture.json'})
            self.assertEqual(trust['launch_sha256'],capture.sha256(public/'launch.json'))
            self.assertEqual((root/'controller-trust.json').stat().st_mode&0o777,0o444)
            self.assertNotIn('DO_NOT_PUBLISH',json.dumps(trust))
            self.assertEqual((public/'answers').stat().st_mode&0o777,0o755)
            self.assertEqual((root/'observer-anchor.json').stat().st_mode&0o777,0o444)
            self.assertTrue(all((public/name).stat().st_mode&0o777==0o444 for name in trust['public_files']))
    def test_swapped_output_symlink_is_never_followed(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);work=root/'work';public=root/'public';(work/'answers').mkdir(parents=True);public.mkdir()
            answer=work/'answers/case-1.json';answer.write_text('{}')
            secret=root/'private-fixture';secret.write_text('DO_NOT_COPY_PRIVATE_FIXTURE')
            actual_open=capture.os.open
            def swap(name,*args,**kwargs):
                if name=='case-1.json':
                    answer.unlink();answer.symlink_to(secret)
                return actual_open(name,*args,**kwargs)
            with mock.patch.object(capture.os,'open',side_effect=swap):
                with self.assertRaises(capture.Refused):capture.public_outputs(work,public,'local-qa-'+'a'*24,'b'*40)
            self.assertFalse((public/'answers/case-1.json').exists())
    def test_actual_model_context_uses_same_manifest_and_8192(self):
        identity={'model':{'model':'fixture-qwen','manifest_sha256':'a'*64}}
        good={'models':[{'name':'fixture-qwen:latest','digest':'a'*64,'context_length':8192,'size_vram':0}]}
        self.assertEqual(capture.actual_model_context(identity,good)['actual_service_context_length'],8192)
        for bad in (4096,True):
            other=deepcopy(good);other['models'][0]['context_length']=bad
            with self.assertRaises(capture.Refused):capture.actual_model_context(identity,other)
        duplicate=deepcopy(good);duplicate['models']*=2
        with self.assertRaises(capture.Refused):capture.actual_model_context(identity,duplicate)
    def test_signed_output_gate_requires_full_instance_executable_and_namespace(self):
        launch={'process':{'pid':11,'pid_start_time_ticks':22,'boot_id':[1]*16},'exe_content_sha256':[2]*32,
                'container':{'pid_ns_inode':1,'mnt_ns_inode':2,'net_ns_inode':3}}
        event={'kernel_timestamp_ns':1000000000,'bound':deepcopy(launch),'kind':{'FileEvent':{'path':'/work/answers/case-1.json'}}}
        batches=[{'batch':{'clock_anchor':{'monotonic_ns':1000000000,'realtime_ms':1000},'kernel_events':[event]}}]
        self.assertEqual(capture.signed_answer_paths(batches,launch,900),{'/work/answers/case-1.json'})
        for field in ('pid','exe','namespace','timestamp'):
            value=deepcopy(batches)
            bound=value[0]['batch']['kernel_events'][0]['bound']
            if field=='pid':bound['process']['pid_start_time_ticks']+=1
            elif field=='exe':bound['exe_content_sha256'][0]=3
            elif field=='namespace':bound['container']['mnt_ns_inode']=9
            else:value[0]['batch']['clock_anchor']=None
            self.assertEqual(capture.signed_answer_paths(value,launch,900),set())
    def test_worker_waits_for_finish_after_all_outputs_without_real_inference(self):
        # Controlled public-answer fixture only, not a Linux/model execution.
        config=config_fixture();groups=worker.focus_groups_from_source(HERE/'agent.py');events=[];reads=[]
        fixture_answers=[json.loads((HERE/f'results/20261102/final-http/answer-{i}.json').read_text()) for i in range(1,5)]
        class FixtureAgent:
            def __init__(self,*_args,**_kwargs):self.index=0
            def ask(self,_question,run):
                value=deepcopy(fixture_answers[self.index]);self.index+=1
                value['authoritative_facts']['run_artifact_id']=run;return value
        def control(_fd,bound):
            reads.append(bound)
            if len(reads)==1:return json.dumps(config).encode()
            self.assertTrue(events and events[-1]=='complete');return b'finish'
        original=Path.cwd()
        with tempfile.TemporaryDirectory() as d:
            os.chdir(d)
            try:
                with mock.patch.object(worker,'isolation'),mock.patch.object(worker,'read_line',side_effect=control),                     mock.patch.object(worker,'event',side_effect=lambda kind,**_fields:events.append(kind)),                     mock.patch.dict(sys.modules,{'agent':SimpleNamespace(EvidenceAgent=FixtureAgent,FOCUS_GROUPS=groups)}):
                    self.assertEqual(worker.execute(),0)
                self.assertEqual(reads,[worker.MAX_CONFIG,16])
                self.assertEqual(len(list((Path(d)/'answers').glob('case-*.json'))),4)
            finally:os.chdir(original)
    def test_source_inventory_contains_actual_dependencies(self):
        expected={'examples/local-evidence-agent/linux_capture.py','examples/local-evidence-agent/linux_workload.py',
            'examples/local-evidence-agent/agent.py','examples/local-evidence-agent/api_runtime.py',
            'examples/local-evidence-agent/model_runtime.py','examples/local-evidence-agent/linux_model_runtime.py',
            'examples/local-evidence-agent/model.lock.json','examples/local-evidence-agent/linux_model.lock.json',
            'sdk/python/vanian/client.py','sdk/python/vanian/__init__.py','validation/enterprise/prepare_local_model.py'}
        self.assertTrue(expected<=set(capture.SOURCE_FILES))


if __name__=='__main__':unittest.main()
