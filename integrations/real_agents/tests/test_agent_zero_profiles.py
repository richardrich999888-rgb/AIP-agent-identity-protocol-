"""Controlled profile/counter/file fixtures; never actual model-run evidence."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'integrations/real_agents'))
sys.path.insert(0,str(ROOT/'integrations/real_agents/adapters'))
sys.path.insert(0,str(ROOT/'validation/enterprise'))
import prepare_local_model as preparation
from hosted_agent_zero import (agent_configuration,business_success,framework_capability,
                               workload_request_count)
from evidence import Refused
from agent_zero_runtime import reviewed_profile_settings
from agent_zero_capability import assess_result

NEW_PROFILE='agent-zero-qwen25-coder-15b'


class AgentZeroProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.inputs=self.root/'inputs';self.inputs.mkdir()
        self.public=self.root/'public';self.public.mkdir()
        self.command_patch=patch('hosted_agent_zero.command',return_value='')
        self.host_command=self.command_patch.start();self.addCleanup(self.command_patch.stop)
    def tearDown(self):
        self.temp.cleanup()

    def test_default_model_pin_and_default_agent_configuration_are_unchanged(self):
        profile=preparation.model_profile()
        self.assertEqual(profile['model'],preparation.MODEL)
        self.assertEqual(profile['manifest_sha256'],preparation.MANIFEST_SHA256)
        self.assertEqual(preparation.manifest_paths(profile),
            ('manifests/registry.ollama.ai/library/llama3.2/1b','manifests-v2/ollama.com/library/llama3.2/1b'))
        config=agent_configuration(preparation.MODEL,'http://fixture-model:11434',preparation.DEFAULT_MODEL_PROFILE)
        self.assertNotIn('reviewed_profile',config)
        self.assertEqual(config['settings'],{})
        self.assertIsNone(reviewed_profile_settings(config))

    def test_new_model_profile_has_explicit_reviewed_pin_and_opt_in_profile(self):
        profile=preparation.model_profile(NEW_PROFILE)
        self.assertEqual(profile['model'],'qwen2.5-coder:1.5b-instruct')
        self.assertEqual(profile['manifest_sha256'],'d7372fd828518a4d38b1eb196c673c31a85f2ed302b3d1e406c4c2d1b64a0668')
        self.assertEqual(profile['license'],'Apache-2.0')
        config=agent_configuration(profile['model'],'http://fixture-model:11434',NEW_PROFILE)
        self.assertEqual(config['reviewed_profile'],'tiny-local-coding-v1')
        self.assertEqual(reviewed_profile_settings(config)['agent_profile'],'tiny-local')
        self.assertEqual(config['preset']['chat']['kwargs']['response_format'],{'type':'json_object'})
        self.assertNotIn('response_format',config['preset']['utility']['kwargs'])
        with self.assertRaises(ValueError):preparation.model_profile('unreviewed')
        profile['model']='changed local copy'
        self.assertEqual(preparation.model_profile(NEW_PROFILE)['model'],'qwen2.5-coder:1.5b-instruct')

    def test_reviewed_runtime_rejects_unknown_profile_memory_or_conflicting_profile(self):
        for config in ({'reviewed_profile':'unknown','disable_memory':True},
                       {'reviewed_profile':'tiny-local-coding-v1','disable_memory':False},
                       {'reviewed_profile':'tiny-local-coding-v1','disable_memory':True,
                        'settings':{'agent_profile':'developer'}}):
            with self.subTest(config=config),self.assertRaises(ValueError):reviewed_profile_settings(config)

    def test_profile_verification_still_hashes_every_manifest_and_blob(self):
        # Synthetic bytes exercise the verifier; no downloaded model is implied.
        models=self.root/'models';blobs=models/'blobs';blobs.mkdir(parents=True)
        raw=b'ordinary controlled asset';digest=hashlib.sha256(raw).hexdigest()
        (blobs/('sha256-'+digest)).write_bytes(raw)
        manifest={'config':{'digest':'sha256:'+digest,'size':len(raw)},'layers':[]}
        encoded=json.dumps(manifest).encode();manifest_digest=hashlib.sha256(encoded).hexdigest()
        profile=preparation.model_profile(NEW_PROFILE);profile['manifest_sha256']=manifest_digest
        path=models/preparation.manifest_paths(profile)[0];path.parent.mkdir(parents=True);path.write_bytes(encoded)
        with patch.dict(preparation.MODEL_PROFILES,{NEW_PROFILE:profile}):
            self.assertEqual(preparation.verify_model(models,NEW_PROFILE),manifest)
            (blobs/('sha256-'+digest)).write_bytes(b'changed controlled asset')
            with self.assertRaises(ValueError):preparation.verify_model(models,NEW_PROFILE)

    def test_capability_and_policy_are_not_counted_as_measured_workload(self):
        before=['policy before','capability one','capability two']
        baseline={'successful_model_requests':3,'policy_requests':1,'original_access_lines':before}
        self.assertEqual(workload_request_count([*before,'policy later','task one','task two'],baseline,2),2)
        self.assertEqual(workload_request_count(['p1','p2','task'],{'original_access_lines':[]},2),1)
        with self.assertRaises(Refused):workload_request_count(['different prefix'],baseline,2)
        with self.assertRaises(Refused):workload_request_count(before,baseline,0)

    def test_real_capability_stage_requires_actual_access_counter_increment(self):
        result=SimpleNamespace(returncode=0,stdout=json.dumps({'status':'PASS',
            'classification':'REAL_FRAMEWORK_CODE_FINAL_RESPONSE_CAPABILITY_ONLY'}))
        with patch('hosted_agent_zero.model_access_lines',side_effect=[['prior'],['prior','capability']]), \
             patch('hosted_agent_zero.policy_request_count',return_value=1), \
             patch('hosted_agent_zero.docker') as launch:
            def actual_fixture(*args,**kwargs):
                challenge=json.loads((self.inputs/'capability-input.json').read_text())
                (kwargs['workdir']/'capability-result.json').write_text(json.dumps(
                    {'capability_id':challenge['capability_id'],'sum':challenge['left']+challenge['right']}))
                (kwargs['workdir']/'capability-adapter.jsonl').write_text('ordinary controlled bytes\n')
                return result
            launch.side_effect=actual_fixture
            baseline=framework_capability('fixture-image','fixture-network',self.inputs,self.public,'fixture-model')
        self.assertEqual(baseline['capability_model_requests'],1)
        self.assertTrue(launch.call_args.kwargs['framework'])
        self.assertEqual(launch.call_args.kwargs['timeout'],260)
        with patch('hosted_agent_zero.model_access_lines',return_value=['prior']), \
             patch('hosted_agent_zero.docker',return_value=result),self.assertRaises(Refused):
            framework_capability('fixture-image','fixture-network',self.inputs,self.public,'fixture-model')
        self.assertEqual(json.loads((self.public/'framework-capability.json').read_text())['status'],'FAIL')

    def test_capability_timeout_retains_failure_without_starting_business(self):
        with patch('hosted_agent_zero.model_access_lines',return_value=[]), \
             patch('hosted_agent_zero.docker',side_effect=subprocess.TimeoutExpired('controlled fixture',260)), \
             self.assertRaises(Refused):
            framework_capability('fixture-image','fixture-network',self.inputs,self.public,'fixture-model')
        result=json.loads((self.public/'framework-capability.json').read_text())
        self.assertEqual(result['status'],'FAIL')
        self.assertEqual(result['failure_type'],'TimeoutExpired')
        self.assertIs(result['business_task_acceptance'],False)
        self.assertNotIn('framework_result',result)
        calls=[call.args[0] for call in self.host_command.call_args_list]
        self.assertEqual(calls[0][:4],['mount','-t','tmpfs','-o'])
        self.assertIn('size=1g',calls[0][4])
        self.assertEqual(calls[-1][0],'umount')

    def test_capability_workspace_cleanup_failure_is_not_a_pass(self):
        self.host_command.side_effect=lambda args: (_ for _ in ()).throw(Refused('fixture umount failure')) if args[0]=='umount' else ''
        with patch('hosted_agent_zero.model_access_lines',return_value=[]), \
             patch('hosted_agent_zero.docker',side_effect=subprocess.TimeoutExpired('controlled fixture',260)), \
             self.assertRaises(Refused):
            framework_capability('fixture-image','fixture-network',self.inputs,self.public,'fixture-model')
        result=json.loads((self.public/'framework-capability.json').read_text())
        self.assertEqual(result['status'],'FAIL')
        self.assertEqual(result['cleanup_failure_type'],'Refused')

    def test_capability_file_and_tool_operation_and_final_response_are_all_required(self):
        challenge={'capability_id':'ordinary-fixture-id','left':101,'right':23}
        output=self.root/'result.json';output.write_text(json.dumps({'capability_id':challenge['capability_id'],'sum':124}))
        items=[{'type':'code_exe','kvps':{'runtime':'python','code':'ordinary controlled fixture'}}]
        self.assertEqual(assess_result(challenge,output,'ordinary-fixture-id 124',items)['status'],'PASS')
        for response,logs in [('ordinary-fixture-id 124',[]),('no matching final response',items)]:
            with self.assertRaises(ValueError):assess_result(challenge,output,response,logs)
        output.unlink();output.symlink_to(self.inputs/'missing')
        with self.assertRaises((ValueError,FileNotFoundError)):assess_result(challenge,output,'ordinary-fixture-id 124',items)

    def test_business_acceptance_never_promotes_timeout_missing_coverage_or_no_model(self):
        status={'workload_exit':0,'observation_validation':'PASSED','failures':[]}
        self.assertTrue(business_success(status,2,{'status':'PASS'}))
        for changed,calls,output in [({**status,'workload_exit':1},2,{'status':'PASS'}),
            ({**status,'failures':['workload exceeded runtime budget']},2,{'status':'PASS'}),
            ({**status,'observation_validation':'FAILED'},2,{'status':'PASS'}),
            (status,0,{'status':'PASS'}),(status,2,{'status':'FAIL'}),
            ({**status,'workload_exit':False},2,{'status':'PASS'}),(status,True,{'status':'PASS'})]:
            self.assertFalse(business_success(changed,calls,output))


if __name__=='__main__':unittest.main()
