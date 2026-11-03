package vanian_acs_test

import rego.v1

pre(args) := {"intervention_point": "pre_tool_call", "tool": {"name": "read_loan"}, "policy_target": {"value": args}}

test_exact_gateway_arguments_allowed if {
    data.vanian_acs.verdict.decision == "allow" with input as pre({"loan_id": 17, "amount": 0})
}

test_outside_resource_denied if {
    data.vanian_acs.verdict.decision == "deny" with input as pre({"loan_id": 999, "amount": 0})
}

test_changed_amount_denied if {
    data.vanian_acs.verdict.decision == "deny" with input as pre({"loan_id": 17, "amount": 1})
}

test_extra_argument_denied if {
    data.vanian_acs.verdict.decision == "deny" with input as pre({"loan_id": 17, "amount": 0, "write": true})
}
