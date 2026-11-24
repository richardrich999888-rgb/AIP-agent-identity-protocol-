"""Controller telemetry contracts; real Collector tests require prepared assets."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from integrations.governance import telemetry


def records():
    # Contract fixtures only, not evidence of agent/model activity.
    now = time.time_ns()
    attributes={'aip.run_id':'same-run-'+'a'*24,'aip.source_authority':telemetry.SOURCE,
                'aip.controller.status':'PASS'}
    return [{'phase':'aip.authorization.issue','start_time_unix_nano':now-9000,
             'end_time_unix_nano':now-8000,'attributes':dict(attributes)},
            {'phase':'aip.run','start_time_unix_nano':now-10000,
             'end_time_unix_nano':now-1000,'attributes':dict(attributes)}]


class TelemetryContracts(unittest.TestCase):
    def test_import_does_not_import_sdk_into_controller(self):
        script='import importlib.util,sys;before=set(sys.modules);s=importlib.util.spec_from_file_location("telemetry",'+repr(str(telemetry.HERE/'telemetry.py'))+');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);assert not any(n.startswith("opentelemetry") for n in set(sys.modules)-before)'
        subprocess.run([sys.executable,'-I','-B','-c',script],check=True,capture_output=True,timeout=10)

    def test_exact_phase_attribute_and_value_allowlists_reject_privacy_canary(self):
        canary='privacy-canary-must-never-be-exported'
        for key in ('prompt','headers','tool.params','business.records','tenant_id'):
            value=records();value[0]['attributes'][key]=canary
            with self.subTest(key=key),self.assertRaises(ValueError) as caught:telemetry.validate_records(value)
            self.assertNotIn(canary,str(caught.exception))
        for key,value in [('aip.run_id',canary),('aip.error.type',canary),
                          ('aip.controller.status',canary),('aip.policy.sha256',canary),
                          ('aip.source_authority','KERNEL_OBSERVATION')]:
            candidate=records();candidate[0]['attributes'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):telemetry.validate_records(candidate)
        candidate=records();candidate[0]['phase']='model.inference'
        with self.assertRaises(ValueError):telemetry.validate_records(candidate)
        source=records();validated=telemetry.validate_records(source)
        source[0]['attributes']['prompt']=canary
        self.assertNotIn('prompt',validated[0]['attributes'])

    def test_chronology_count_types_and_single_run_are_enforced(self):
        for mutate in (lambda r:r[0].update(start_time_unix_nano=True),
                       lambda r:r[0].update(end_time_unix_nano=0),
                       lambda r:r[0].update(end_time_unix_nano=time.time_ns()+10**12),
                       lambda r:r[0].update(start_time_unix_nano=1),
                       lambda r:r[0]['attributes'].update({'aip.policy.allowed':1}),
                       lambda r:r[0]['attributes'].update({'aip.run_id':'same-run-'+'b'*24}),
                       lambda r:r.append(copy.deepcopy(r[1]))):
            candidate=records();mutate(candidate)
            with self.assertRaises(ValueError):telemetry.validate_records(candidate)
        with self.assertRaises(ValueError):telemetry.validate_records(records()*telemetry.MAX_RECORDS)
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'not-created'
            with self.assertRaises(ValueError):telemetry.export_records('/unprepared',[],out)
            self.assertFalse(out.exists())

    def test_regular_bounded_input_refuses_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'data.json';path.write_text('{}')
            link=Path(tmp)/'linked.json';link.symlink_to(path)
            with self.assertRaises(ValueError):telemetry.read_json(link)
            with self.assertRaises(ValueError):telemetry.read_json(path,limit=1)

    def test_collector_config_has_only_loopback_receiver_and_file_exporter(self):
        config=json.loads((telemetry.HERE/'otel-collector.json').read_text())
        self.assertEqual(set(config['receivers']),{'otlp'})
        self.assertEqual(config['receivers']['otlp']['protocols'],{'http':{'endpoint':'127.0.0.1:${PORT}'}})
        self.assertEqual(set(config['exporters']),{'file'})
        self.assertEqual(config['service']['pipelines'],{'traces':{'receivers':['otlp'],'exporters':['file']}})
        self.assertEqual(config['service']['telemetry']['metrics']['level'],'none')

    def test_original_collector_correlation_rejects_tamper_and_extra_data(self):
        source=records();nonce='b'*32;trace_id='c'*32
        def attrs(value):
            return [{'key':k,'value':{'boolValue':v} if type(v)is bool else {'intValue':str(v)} if type(v)is int else {'stringValue':v}} for k,v in value.items()]
        spans=[]
        for index,record in enumerate(source):
            span={'name':record['phase'],'traceId':trace_id,'spanId':('1' if index==0 else '2')*16,
                'flags':256,'kind':1,'status':{},'startTimeUnixNano':str(record['start_time_unix_nano']),
                'endTimeUnixNano':str(record['end_time_unix_nano']),
                'attributes':attrs({**record['attributes'],'aip.telemetry.export_nonce':nonce,
                    'aip.telemetry.record_index':index,'aip.telemetry.export_mode':telemetry.MODE})}
            if index==0:span['parentSpanId']='2'*16
            spans.append(span)
        document={'resourceSpans':[{'resource':{'attributes':attrs({'service.name':'aip-validation-controller',
            'aip.source_authority':telemetry.SOURCE})},'scopeSpans':[{'scope':{'name':'aip.controller.governance','version':'1.0'},'spans':spans}]}]}
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'collector.jsonl';path.write_text(json.dumps(document)+'\n')
            self.assertEqual(telemetry.verify_collector_file(path,source,nonce,trace_id)['span_count'],2)
            for changed in ('nonce','time','trace','parent','private','event','status_message','envelope','attribute_extra'):
                bad=copy.deepcopy(document);span=bad['resourceSpans'][0]['scopeSpans'][0]['spans'][0]
                if changed=='nonce':span['attributes'][3]['value']={'stringValue':'wrong'}
                elif changed=='time':span['endTimeUnixNano']='1'
                elif changed=='trace':span['traceId']='e'*32
                elif changed=='parent':span['parentSpanId']='0'*16
                elif changed=='private':span['attributes'].append({'key':'prompt','value':{'stringValue':'privacy-canary'}})
                elif changed=='event':span['events']=[{'name':'private-canary'}]
                elif changed=='status_message':span['status']={'message':'private-canary'}
                elif changed=='envelope':bad['unapproved']='private-canary'
                elif changed=='attribute_extra':span['attributes'][0]['private']='private-canary'
                path.write_text(json.dumps(bad)+'\n')
                with self.subTest(changed=changed),self.assertRaises(ValueError):telemetry.verify_collector_file(path,source,nonce,trace_id)
            # Deliberate raw duplicate-key fixture: default last-key-wins
            # parsing hides the first, unapproved value without changing spans.
            duplicate='{"resourceSpans":{"private":"duplicate-key-privacy-canary"},"resourceSpans":'+json.dumps(document['resourceSpans'])+'}\n'
            path.write_text(duplicate)
            with self.assertRaises(ValueError):telemetry.verify_collector_file(path,source,nonce,trace_id)
            path.write_text('{"outer":{"key":"private-canary","key":"allowed"}}')
            with self.assertRaises(ValueError):telemetry.read_json(path)


@unittest.skipUnless(os.environ.get('AIP_GOVERNANCE_TEST_ROOT'),'real pinned Collector/SDK assets not configured')
class ActualCollectorRoundTrip(unittest.TestCase):
    def test_real_sdk_collector_receives_measured_controller_times_without_privacy_canaries(self):
        assets=Path(os.environ['AIP_GOVERNANCE_TEST_ROOT'])/'otel'
        canary='privacy-canary-never-export-actual-component'
        previous={key:os.environ.get(key) for key in ('OTEL_RESOURCE_ATTRIBUTES','OTEL_EXPORTER_OTLP_HEADERS','HTTP_PROXY')}
        try:
            os.environ['OTEL_RESOURCE_ATTRIBUTES']='private.canary='+canary
            os.environ['OTEL_EXPORTER_OTLP_HEADERS']='Authorization='+canary
            os.environ['HTTP_PROXY']='http://'+canary+'.invalid:1'
            # The phase times surround a real read-only asset verification.
            whole_start=time.time_ns();start=time.time_ns();telemetry.verify_telemetry(assets);end=time.time_ns();whole_end=time.time_ns()
            measured=records();measured[0].update(phase='aip.evidence.verify',start_time_unix_nano=start,end_time_unix_nano=end)
            measured[1].update(start_time_unix_nano=whole_start,end_time_unix_nano=whole_end)
            with tempfile.TemporaryDirectory() as tmp:
                out=Path(tmp)/'telemetry'
                private=Path(tmp)/'private-originals'
                report=telemetry.export_records(assets,measured,out,private_dir=private)
                self.assertEqual(report['status'],'PASS')
                self.assertEqual(report['span_count'],2)
                self.assertTrue(report['actual_collector_receipt'])
                self.assertTrue(report['actual_timestamps_preserved'])
                self.assertEqual(report['collector_exit_code'],0)
                self.assertFalse(report['signed_kernel_evidence'])
                self.assertTrue(report['final_file_verified_after_collector_stop'])
                self.assertFalse(report['raw_collector_log_published'])
                self.assertEqual(set(p.name for p in out.iterdir()),
                    {'records.json','collector-config.json','collector-spans.jsonl','telemetry-report.json'})
                self.assertTrue((private/'collector.log').is_file())
                self.assertEqual(private.stat().st_mode&0o777,0o700)
                for name in ('records.json','collector-config.json','collector-spans.jsonl','telemetry-report.json'):
                    self.assertEqual((out/name).read_bytes(),(private/name).read_bytes())
                    self.assertEqual((out/name).stat().st_mode&0o777,0o644)
                for path in out.iterdir():
                    if path.is_file():self.assertNotIn(canary.encode(),path.read_bytes())
        finally:
            for key,value in previous.items():
                if value is None:os.environ.pop(key,None)
                else:os.environ[key]=value

    def test_actual_failed_controller_operation_exports_only_numeric_error_status(self):
        assets=Path(os.environ['AIP_GOVERNANCE_TEST_ROOT'])/'otel'
        with tempfile.TemporaryDirectory() as tmp:
            whole_start=time.time_ns();start=time.time_ns()
            try:
                telemetry.verify_telemetry(Path(tmp)/'actually-unprepared-assets')
            except FileNotFoundError as error:
                error_type=type(error).__name__
            else:
                self.fail('controlled missing-assets operation unexpectedly succeeded')
            end=time.time_ns();whole_end=time.time_ns()
            measured=records()
            measured[0].update(phase='aip.evidence.verify',start_time_unix_nano=start,end_time_unix_nano=end)
            measured[0]['attributes'].update({'aip.controller.status':'ERROR','aip.error.type':error_type})
            measured[1].update(start_time_unix_nano=whole_start,end_time_unix_nano=whole_end)
            measured[1]['attributes']['aip.controller.status']='FAIL'
            out=Path(tmp)/'public'/'otel';private=Path(tmp)/'private-originals'
            report=telemetry.export_records(assets,measured,out,private_dir=private)
            self.assertEqual(report['status'],'PASS')
            spans=[span for line in (out/'collector-spans.jsonl').read_text().splitlines()
                   for resource in json.loads(line)['resourceSpans']
                   for scope in resource['scopeSpans'] for span in scope['spans']]
            self.assertEqual([span['status'] for span in spans],[{'code':2},{'code':2}])
            self.assertNotIn('message',str([span['status'] for span in spans]))
            self.assertFalse((out/'collector.log').exists())

    def test_late_unapproved_tail_after_actual_collector_exit_is_private_and_never_published(self):
        assets=Path(os.environ['AIP_GOVERNANCE_TEST_ROOT'])/'otel'
        real_popen=telemetry.subprocess.Popen
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'public'/'otel';private=Path(tmp)/'private-originals'
            injected=[]
            def with_late_tail(*args,**kwargs):
                process=real_popen(*args,**kwargs)
                command=args[0] if args else kwargs.get('args',())
                if '--config' in command:
                    wait=process.wait
                    def reaped_then_unapproved_tail(*wait_args,**wait_kwargs):
                        code=wait(*wait_args,**wait_kwargs)
                        if code==0 and not injected:
                            # Deliberate fault fixture, not a genuine observation:
                            # append only after the actual child has been reaped.
                            with (private/'collector-spans.jsonl').open('ab') as stream:
                                stream.write(b'{"unapproved":"late-tail-privacy-canary"}\n')
                            injected.append(True)
                        return code
                    process.wait=reaped_then_unapproved_tail
                return process
            with mock.patch.object(telemetry.subprocess,'Popen',side_effect=with_late_tail):
                report=telemetry.export_records(assets,records(),out,private_dir=private)
            self.assertEqual(injected,[True])
            self.assertEqual(report['status'],'FAIL')
            self.assertEqual(report['collector_exit_code'],0)
            self.assertFalse(out.exists())
            self.assertTrue((private/'collector.log').is_file())
            self.assertIn(b'late-tail-privacy-canary',(private/'collector-spans.jsonl').read_bytes())
            self.assertTrue((private/'telemetry-report.json').is_file())
            self.assertEqual(private.stat().st_mode&0o777,0o700)


if __name__=='__main__':unittest.main()
