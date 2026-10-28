from dataclasses import dataclass
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from posture_report import collect, PostureError  # noqa: E402


@dataclass
class Page:
    items: list
    limit: int = 25
    next_offset: int | None = None


class Stub:
    def __init__(self):
        self.role = 'reader'
        self.page = Page([{"agent_id":"agent-123", "identity_source":"agent_signed_evidence_packet", "independent_identity_verified":True}])
        self.coverage = {"status":"active", "independent_execution_verified":True}
        self.health = {"status":"ok", "probe_health":"active", "collector_health":"active"}
    def access(self):
        return {"role":self.role,"tenant_id":"bank-evaluation"}
    def list_agents(self, *, limit, offset):
        assert limit == 25 and offset == 0
        return self.page
    def get_coverage(self):
        return self.coverage
    def get_health(self):
        return self.health


class PostureTests(unittest.TestCase):
    def test_service_reports_never_become_independent_proof(self):
        report = collect(Stub())
        self.assertFalse(report['coverage']['independently_verified_execution'])
        self.assertEqual(report['coverage']['independent_coverage_assessment'],'NOT_PERFORMED')
        self.assertFalse(report['agent_inventory']['items'][0]['independent_identity_verified'])
        self.assertEqual(report['audit_qualification'],'NOT_ESTABLISHED')

    def test_nonreader_denied(self):
        c=Stub(); c.role='admin'
        with self.assertRaises(PostureError):
            collect(c)

    def test_missing_tenant_denied(self):
        c=Stub(); c.access=lambda: {"role":"reader"}
        with self.assertRaises(PostureError):
            collect(c)

    def test_paginated_inventory_does_not_claim_completion(self):
        c=Stub(); c.page.next_offset=25
        self.assertFalse(collect(c)['agent_inventory']['source_pagination_complete'])

    def test_invalid_agent_record_fails(self):
        c=Stub(); c.page.items=[{"name":"not agent"}]
        with self.assertRaises(PostureError):
            collect(c)

    def test_service_unavailable_is_explicit(self):
        c=Stub(); c.coverage={'status':'unavailable'}; c.health={'status':'not_connected'}
        r=collect(c)
        self.assertEqual(r['service_health'],'api_reported_unhealthy_or_unknown')
        self.assertEqual(r['coverage']['service_reported_status'],'unavailable')
        self.assertFalse(r['coverage']['independently_verified_execution'])


if __name__=='__main__':
    unittest.main()
