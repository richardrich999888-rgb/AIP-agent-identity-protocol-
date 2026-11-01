"""Controlled native-profile contracts, not framework/model execution evidence."""
import json
from pathlib import Path
from types import ModuleType, SimpleNamespace
import tempfile
import sys
import unittest
from unittest.mock import patch

from native_frameworks import CONTEXT, MODEL, Progress, assess, configuration, deerflow_bash_return_status, deerflow_configuration, prepare_environment, run, safe_failure, validate
from hosted_agent_zero import agent_configuration, served_context


class Journal:
    def __init__(self): self.rows=[]
    def emit(self, kind, value): self.rows.append((kind,value)); return True


def event(kind, **fields):
    return type(kind, (), fields)()


class NativeFrameworkTests(unittest.TestCase):
    def test_profile_requires_real_native_tooling_and_32768_without_changing_agent_zero(self):
        for framework in ('deerflow','openhands'):
            config=configuration(framework,MODEL,'http://172.19.0.2:11434')
            validate(config)
            self.assertEqual(config['context_length'],32768)
            self.assertTrue(config['native_tool_calling'])
            self.assertFalse(config['model_api_credentials_used'])
            self.assertFalse(config['compatibility_string_is_credential'])
            for key,value in [('context_length',8192),('native_tool_calling',False),('model','other')]:
                with self.subTest(framework=framework,key=key),self.assertRaises(ValueError):validate({**config,key:value})
        for endpoint in ('https://172.19.0.2:11434','http://user:secret@172.19.0.2:11434','http://172.19.0.2:11434/v1','http://172.19.0.2:11434?secret=x','http://host.example:11434'):
            with self.subTest(endpoint=endpoint),self.assertRaises((ValueError,TypeError)):configuration('openhands',MODEL,endpoint)
        self.assertEqual(agent_configuration(MODEL,'http://172.19.0.2:11434','agent-zero-qwen25-coder-15b')['preset']['chat']['ctx_length'],8192)

    def test_deerflow_public_mounts_and_native_provider_match_actual_virtual_path_gates(self):
        config=deerflow_configuration(configuration('deerflow',MODEL,'http://172.19.0.2:11434'))
        self.assertEqual(config['models'][0]['use'],'langchain_ollama:ChatOllama')
        self.assertEqual(config['models'][0]['num_ctx'],CONTEXT)
        self.assertEqual(config['models'][0]['context_window'],CONTEXT)
        self.assertEqual({x['name'] for x in config['tools']},{'bash','read_file','write_file'})
        self.assertEqual(config['sandbox']['mounts'],[
            {'host_path':'/work','container_path':'/work','read_only':False},
            {'host_path':'/model-config','container_path':'/model-config','read_only':True}])
        self.assertFalse(config['memory']['enabled'])
        self.assertFalse(config['title']['enabled'])
        self.assertFalse(config['summarization']['enabled'])

    def test_deerflow_requires_matching_real_stream_tool_call_and_result_and_final_end(self):
        p=Progress();j=Journal()
        p.deerflow(event('StreamEvent',type='messages-tuple',data={'type':'tool','name':'bash','tool_call_id':'other','content':'ignored'}),j)
        self.assertFalse(p.completed)
        p.deerflow(event('StreamEvent',type='messages-tuple',data={'type':'ai','tool_calls':[{'name':'bash','id':'c1','args':{'command':'model-chosen-command'}}]}),j)
        p.deerflow(event('StreamEvent',type='messages-tuple',data={'type':'tool','name':'bash','tool_call_id':'c1','content':'Error: denied'}),j)
        self.assertFalse(p.completed)
        p.deerflow(event('StreamEvent',type='messages-tuple',data={'type':'tool','name':'bash','tool_call_id':'c1','content':'actual framework tool output'}),j)
        p.deerflow(event('StreamEvent',type='values',data={'messages':[{'type':'ai','content':'fresh-id 7'}]}),j)
        self.assertEqual(p.completed,{'c1'});self.assertFalse(p.finished)
        p.deerflow(event('StreamEvent',type='end',data={}),j)
        self.assertTrue(p.finished);self.assertEqual(p.final,'fresh-id 7')
        p.deerflow(event('StreamEvent',type='values',data={'messages':[{'type':'tool','name':'bash','content':'later tool result'}]}),j)
        self.assertEqual(p.final,'')

    def test_deerflow_nonzero_timeout_or_unknown_result_cannot_be_replaced_by_correct_file(self):
        challenge={'capability_id':'fresh-id','left':3,'right':4}
        failures=['failed\nExit Code: 1','partial\nExit Code: -9','Command exited with code 2',
                  'prefix\nExit Code: 0\nExit Code: 124','prefix\nExit Code: unknown',
                  'Command timed out after 1 second and was terminated. To run a long-lived process...\nExit Code: 124',
                  'Error: refused\nExit Code: 0','']
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'result.json'
            # A separate file tool could produce a correct file. It must not
            # rescue a failed/missing actual bash result from the same run.
            path.write_text(json.dumps({'capability_id':'fresh-id','sum':7}))
            for content in failures:
                with self.subTest(content=content):
                    p=Progress();j=Journal()
                    p.deerflow(event('StreamEvent',type='messages-tuple',data={'type':'ai','tool_calls':[
                        {'name':'bash','id':'failed-call','args':{'command':'model-chosen-command'}}]}),j)
                    p.deerflow(event('StreamEvent',type='messages-tuple',data={'type':'tool','name':'bash',
                        'tool_call_id':'failed-call','content':content}),j)
                    self.assertFalse(p.completed)
                    self.assertEqual(j.rows[-2][1]['data']['content'],content)
                    p.final='fresh-id 7';p.finished=True
                    with self.assertRaises(ValueError):assess(challenge,path,p)
            for content in ('actual tool output','(no output)','actual\nExit Code: 0','Command exited with code 0'):
                with self.subTest(success=content):
                    self.assertTrue(deerflow_bash_return_status(content)['reported_success'])
            p=Progress();j=Journal();p.calls={'replaced'};p.completed={'replaced'}
            p.deerflow(event('StreamEvent',type='messages-tuple',data={'type':'tool','name':'bash',
                'tool_call_id':'replaced','content':'latest failure\nExit Code: 1'}),j)
            self.assertFalse(p.completed)

    def test_openhands_requires_native_action_result_link_and_real_finish_action(self):
        p=Progress();j=Journal()
        p.openhands(event('ActionEvent',tool_name='terminal',tool_call_id='c1',action=SimpleNamespace(command='model-chosen-command')),j)
        p.openhands(event('ObservationEvent',tool_name='terminal',tool_call_id='other',observation=SimpleNamespace(is_error=False,metadata=SimpleNamespace(exit_code=0))),j)
        self.assertFalse(p.completed)
        p.openhands(event('ObservationEvent',tool_name='terminal',tool_call_id='c1',observation=SimpleNamespace(is_error=True,metadata=SimpleNamespace(exit_code=1))),j)
        self.assertFalse(p.completed)
        p.openhands(event('ObservationEvent',tool_name='terminal',tool_call_id='c1',observation=SimpleNamespace(is_error=False,metadata=SimpleNamespace(exit_code=0))),j)
        p.openhands(event('MessageEvent',llm_message=SimpleNamespace(content='unstructured claimed finish')),j)
        self.assertFalse(p.finished)
        p.openhands(event('ActionEvent',tool_name='finish',tool_call_id='f1',action=SimpleNamespace(message='fresh-id 7')),j)
        self.assertFalse(p.finished)
        p.openhands(event('ObservationEvent',tool_name='finish',tool_call_id='f1',observation=SimpleNamespace(is_error=False)),j)
        self.assertTrue(p.finished);self.assertEqual(p.completed,{'c1'})
        self.assertTrue(all('llm_message' not in data for _,data in j.rows))

    def test_capability_independently_checks_original_file_tool_roundtrip_and_final_response(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'result.json';challenge={'capability_id':'fresh-id','left':3,'right':4}
            p=Progress();p.final='fresh-id 7';p.finished=True;p.completed={'c1'}
            path.write_text(json.dumps({'capability_id':'fresh-id','sum':7}))
            self.assertEqual(assess(challenge,path,p)['status'],'PASS')
            for changed in ({'capability_id':'wrong','sum':7},{'capability_id':'fresh-id','sum':7.0},{'capability_id':'fresh-id','sum':7,'extra':'invented'}):
                path.write_text(json.dumps(changed))
                with self.assertRaises(ValueError):assess(challenge,path,p)
            path.write_text(json.dumps({'capability_id':'fresh-id','sum':7}))
            p.completed=set()
            with self.assertRaises(ValueError):assess(challenge,path,p)
            p.completed={'c1'}
            for final in ('proposal only','fresh-id 70','fresh-id 17','fresh-id -7','fresh-id 7.0','fresh-id 7e0'):
                p.final=final
                with self.subTest(final=final),self.assertRaises(ValueError):assess(challenge,path,p)
            id_challenge={**challenge,'capability_id':'contains7'}
            path.write_text(json.dumps({'capability_id':'contains7','sum':7}))
            p.final='contains7 only'
            with self.assertRaises(ValueError):assess(id_challenge,path,p)
            path.unlink();path.symlink_to('/etc/passwd')
            with self.assertRaises(ValueError):assess(challenge,path,p)

    def test_openhands_pinned_close_only_lifecycle_and_primary_failure_cleanup(self):
        # Controlled API fixture deliberately has no __enter__/__exit__, like
        # the exact pinned LocalConversation. This is not upstream execution.
        for fail_run,fail_close in ((False,False),(True,False),(True,True),(False,True)):
            with self.subTest(fail_run=fail_run,fail_close=fail_close):
                calls=[];j=Journal()
                class Conversation:
                    def __init__(self,**kwargs):
                        self.callbacks=kwargs['callbacks'];self.state=SimpleNamespace(execution_status='finished')
                        calls.append('create')
                    def send_message(self,prompt):calls.append('message')
                    def run(self):
                        calls.append('run')
                        if fail_run:raise RuntimeError('private-message-must-not-leak')
                        for item in [event('ActionEvent',tool_name='terminal',tool_call_id='c1',action=SimpleNamespace(command='controlled fixture')),
                            event('ObservationEvent',tool_name='terminal',tool_call_id='c1',observation=SimpleNamespace(is_error=False,metadata=SimpleNamespace(exit_code=0))),
                            event('ActionEvent',tool_name='finish',tool_call_id='f1',action=SimpleNamespace(message='fixture final')),
                            event('ObservationEvent',tool_name='finish',tool_call_id='f1',observation=SimpleNamespace(is_error=False))]:
                            for callback in self.callbacks:callback(item)
                    def close(self):
                        calls.append('close')
                        if fail_close:raise OSError(30,'private-cleanup-message')
                modules={name:ModuleType(name) for name in ('openhands','openhands.sdk','openhands.tools','openhands.tools.terminal',
                    'openhands.sdk.tool','openhands.sdk.tool.builtins','openhands.sdk.tool.builtins.finish',
                    'openhands.sdk.conversation','openhands.sdk.conversation.state')}
                sdk=modules['openhands.sdk'];sdk.Conversation=Conversation
                sdk.Agent=lambda **kwargs:SimpleNamespace(**kwargs)
                sdk.LLM=lambda **kwargs:SimpleNamespace(**kwargs)
                sdk.Tool=lambda **kwargs:SimpleNamespace(**kwargs)
                modules['openhands.tools.terminal'].TerminalTool=SimpleNamespace(name='terminal')
                modules['openhands.sdk.tool.builtins.finish'].FinishTool=SimpleNamespace(name='finish')
                modules['openhands.sdk.conversation.state'].ConversationExecutionStatus=SimpleNamespace(FINISHED='finished')
                config=configuration('openhands',MODEL,'http://172.19.0.2:11434')
                with patch.dict(sys.modules,modules), patch('native_frameworks.prepare_environment'):
                    if fail_run or fail_close:
                        with self.assertRaises(RuntimeError if fail_run else OSError):run(config,'fixture prompt','fixture',j,240)
                    else:self.assertTrue(run(config,'fixture prompt','fixture',j,240).finished)
                self.assertEqual(calls,['create','message','run','close'])
                text=json.dumps(j.rows)
                self.assertNotIn('private-message-must-not-leak',text)
                self.assertNotIn('private-cleanup-message',text)
                if fail_run or fail_close:
                    failure=[v for k,v in j.rows if k=='native_framework_failure'][-1]
                    self.assertEqual(failure['stage'],'openhands_run' if fail_run else 'openhands_close')

    def test_direct_capability_reproduces_existing_entrypoint_directories_and_deerflow_cwd(self):
        with patch.dict('os.environ',{'HOME':'/tmp/controlled-native-home'}), \
                patch('native_frameworks.Path.mkdir') as mkdir, patch('native_frameworks.os.chdir') as chdir:
            prepare_environment('deerflow')
            self.assertEqual(mkdir.call_count,3)
            for call in mkdir.call_args_list:self.assertEqual(call.kwargs,{'parents':True,'exist_ok':True})
            chdir.assert_called_once_with('/opt/framework/backend')
            chdir.reset_mock();prepare_environment('openhands');chdir.assert_not_called()

    def test_failure_diagnostic_keeps_errno_and_approved_source_locations_without_private_values(self):
        try:
            exec(compile("raise OSError(30, 'private-error-message', '/private/credential-file')",
                         '/opt/framework/backend/pinned_module.py','exec'))
        except OSError as error:report=safe_failure(error,'deerflow_stream')
        self.assertEqual(report['errno'],30)
        self.assertEqual(report['stage'],'deerflow_stream')
        approved=[f for f in report['source_frames'] if f.get('source_root')=='/opt/framework/']
        self.assertEqual(approved,[{'source_root':'/opt/framework/','file':'backend/pinned_module.py','function':'<module>','line':1}])
        text=json.dumps(report)
        for secret in ('private-error-message','credential-file','raise OSError','locals','args'):
            self.assertNotIn(secret,text)
        self.assertLessEqual(len(report['source_frames']),12)

    def test_served_context_uses_actual_service_state_and_rejects_sdk_metadata_only(self):
        class Reply:
            def __init__(self,value):self.value=value
            def __enter__(self):return self
            def __exit__(self,*_):pass
            def read(self):return json.dumps(self.value).encode()
        for actual,status in ((32768,'PASS'),(8192,'FAIL'),(None,'FAIL'),(True,'FAIL')):
            with patch('hosted_agent_zero.urlopen',return_value=Reply({'models':[{'name':MODEL,'context_length':actual}]})):
                self.assertEqual(served_context('172.19.0.2',MODEL,CONTEXT)['status'],status)
        with patch('hosted_agent_zero.urlopen',side_effect=OSError('controlled failure')):
            self.assertEqual(served_context('172.19.0.2',MODEL,CONTEXT)['status'],'FAIL')


if __name__=='__main__':unittest.main()
