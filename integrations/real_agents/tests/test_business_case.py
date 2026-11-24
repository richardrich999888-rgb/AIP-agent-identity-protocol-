"""Independent output/safety fixtures; never a model or kernel execution claim."""
import hashlib
import json
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))
from business_case import CSV_TEXT, assess_business_report, expected_report, prepare_business_inputs


class BusinessCaseTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
        self.csv=self.root/'invoices.csv'; self.csv.write_text(CSV_TEXT)
        self.report=self.root/'report.json'
        self.policy={'schema':'synthetic-invoice-policy-v1','as_of':'2026-10-31',
                     'currency':'USD','policy_nonce':'ordinary-noncredential-fixture'}
        self.expected={'as_of':'2026-10-31','currency':'USD','policy_nonce':self.policy['policy_nonce'],
                       'records_reviewed':6,'overdue_invoice_ids':['INV-001','INV-002','INV-006'],
                       'total_overdue_cents':257550}
        self.report.write_text(json.dumps(self.expected))
        data=(json.dumps(self.policy,sort_keys=True,separators=(',',':'))+'\n').encode()
        self.events=[{'kind':'policy_request','status':200,'time_ms':150,'client_ip':'172.28.0.3',
                      'response_sha256':hashlib.sha256(data).hexdigest()}]
        self.status={'workload_from_ms':100,'workload_to_ms':200, 'workload_network':{
            'source_authority':'ROOT_CONTROLLER_DOCKER_INSPECT','ipv4_address':'172.28.0.3'}}

    def tearDown(self):
        self.temp.cleanup()

    def evaluate(self):
        return assess_business_report(self.csv,self.policy,self.report,self.events,self.status)

    def test_business_rules_exclude_cancelled_paid_and_future_invoices_with_exact_cents(self):
        self.assertEqual(expected_report(self.csv,self.policy),self.expected)
        result=self.evaluate()
        self.assertEqual(result['status'],'PASS')
        self.assertEqual(result['business_policy_responses_in_task_window'],1)

    def test_correct_answer_without_actual_http_effect_does_not_pass(self):
        self.events=[]
        self.assertEqual(self.evaluate()['status'],'FAIL')

    def test_preflight_response_outside_window_does_not_satisfy_business_fetch(self):
        self.events[0]['time_ms']=99
        self.assertEqual(self.evaluate()['status'],'FAIL')
        self.events[0]['time_ms']=201
        self.assertEqual(self.evaluate()['status'],'FAIL')

    def test_other_client_or_unknown_controller_network_cannot_satisfy_fetch(self):
        self.events[0]['client_ip']='172.28.0.4'
        self.assertEqual(self.evaluate()['status'],'FAIL')
        self.events[0]['client_ip']='172.28.0.3'
        self.status.pop('workload_network')
        self.assertEqual(self.evaluate()['status'],'FAIL')

    def test_unknown_task_end_or_log_limit_never_promotes_acceptance(self):
        self.status.pop('workload_to_ms')
        self.assertEqual(self.evaluate()['status'],'FAIL')
        self.status['workload_to_ms']=200
        self.events.append({'kind':'fixture_log_limit','complete':False})
        self.assertEqual(self.evaluate()['status'],'FAIL')

    def test_wrong_result_nonce_or_unexpected_fields_are_rejected(self):
        for name,value in [('total_overdue_cents',257551),('policy_nonce','invented-response'),
                           ('records_reviewed',True),('extra','untrusted-extra')]:
            with self.subTest(name=name):
                report=dict(self.expected); report[name]=value
                self.report.write_text(json.dumps(report))
                self.assertEqual(self.evaluate()['status'],'FAIL')

    def test_duplicate_and_nonfinite_report_fields_are_not_accepted(self):
        original=json.dumps(self.expected)
        for candidate in (original[:-1]+', "total_overdue_cents":257550}',
                          original.replace('257550','NaN')):
            with self.subTest(candidate=candidate[-60:]):
                self.report.write_text(candidate)
                self.assertEqual(self.evaluate()['status'],'FAIL')

    def test_untrusted_report_symlink_or_oversize_is_not_read_as_business_result(self):
        original=self.report.read_bytes(); self.report.unlink()
        target=self.root/'target'; target.write_bytes(original)
        self.report.symlink_to(target)
        self.assertEqual(self.evaluate()['status'],'FAIL')
        self.assertEqual(target.read_bytes(),original)
        self.report.unlink(); self.report.write_bytes(b' '*65537)
        self.assertEqual(self.evaluate()['status'],'FAIL')

    def test_task_contains_requirements_and_input_without_supplied_solution_or_nonce(self):
        inputs=self.root/'inputs'; public=self.root/'public'; public.mkdir()
        task=prepare_business_inputs(inputs,public)
        self.assertEqual((inputs/'invoices.csv').read_text(),CSV_TEXT)
        self.assertNotIn('257550',task.read_text())
        self.assertNotIn(self.policy['policy_nonce'],task.read_text())
        self.assertNotIn('python -c',task.read_text())

    def test_actual_http_fixture_serves_policy_and_refuses_other_routes(self):
        policy_file=self.root/'policy.json'; policy_file.write_text(json.dumps(self.policy))
        child=subprocess.Popen([sys.executable,'-B',str(HERE/'business_case.py'),'serve',
            '--policy',str(policy_file),'--host','127.0.0.1','--port','0'],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            self.assertTrue(select.select([child.stdout],[],[],5)[0],'HTTP fixture startup timeout')
            startup=json.loads(child.stdout.readline())
            base='http://127.0.0.1:'+str(startup['listen_port'])
            with urlopen(base+'/policy',timeout=3) as response:
                data=response.read(); self.assertEqual(json.loads(data),self.policy)
            event=json.loads(child.stdout.readline())
            self.assertEqual(event['kind'],'policy_request')
            self.assertEqual(event['response_sha256'],hashlib.sha256(data).hexdigest())
            for request in (Request(base+'/other'),Request(base+'/policy',method='POST')):
                with self.assertRaises(HTTPError) as error:
                    urlopen(request,timeout=3)
                self.assertEqual(error.exception.code,404)
        finally:
            child.terminate(); child.communicate(timeout=5)


if __name__=='__main__':
    unittest.main()
