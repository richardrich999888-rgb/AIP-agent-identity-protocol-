package vanian_acs

import rego.v1

default verdict := {"decision": "deny", "reason": "outside_synthetic_research_scope"}

verdict := {"decision": "allow"} if {
    input.intervention_point == "pre_tool_call"
    input.tool.name == "read_loan"
    input.policy_target.value.loan_id in {17, 18}
    input.policy_target.value.amount == 0
    object.keys(input.policy_target.value) == {"loan_id", "amount"}
}

verdict := {"decision": "allow"} if {
    input.intervention_point == "post_tool_call"
    input.tool.name == "read_loan"
}
