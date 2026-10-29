package vanian_test

import rego.v1

request := {"principal": {"tenant": "synthetic-bank", "issuer": "https://identity.bank.example", "subject": "research-agent"}, "action": "research.read", "resource": "synthetic-loans", "arguments": {"record_id": "SYN-001"}}

test_allowed_read if {
    data.vanian.decision.allow with input as request
}

test_cross_tenant_refused if {
    not data.vanian.decision.allow with input as object.union(request, {"principal": {"tenant": "other", "issuer": "https://identity.bank.example", "subject": "research-agent"}})
}

test_write_refused if {
    not data.vanian.decision.allow with input as object.union(request, {"action": "payment.write"})
}

test_wrong_issuer_refused if {
    not data.vanian.decision.allow with input as object.union(request, {"principal": {"tenant": "synthetic-bank", "issuer": "https://attacker.example", "subject": "research-agent"}})
}
