package vanian

import rego.v1

# Reference policy only. The institution manages this endpoint and revision.
# This result is not an ExpectedExecution and cannot grant AIP authority.
default permitted := false

permitted if {
    input.principal.tenant == "synthetic-bank"
    input.principal.issuer == "https://identity.bank.example"
    input.principal.subject == "research-agent"
    input.action == "research.read"
    input.resource == "synthetic-loans"
    input.arguments.record_id in {"SYN-001", "SYN-002"}
}

decision := {"allow": permitted, "policy_version": "synthetic-research-v1"}
