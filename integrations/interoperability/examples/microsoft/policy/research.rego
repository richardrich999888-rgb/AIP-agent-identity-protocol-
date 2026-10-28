package vanian_acs

import rego.v1

default verdict := {"decision": "deny", "reason": "outside_synthetic_research_scope"}

verdict := {"decision": "allow"} if {
    input.intervention_point == "pre_tool_call"
    input.tool.name == "read_loan"
    input.policy_target.value.record_id in {"SYN-001", "SYN-002"}
}

verdict := {"decision": "allow"} if {
    input.intervention_point == "post_tool_call"
    input.tool.name == "read_loan"
}
