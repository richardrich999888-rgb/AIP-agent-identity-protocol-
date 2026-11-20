package vanian.gate_test

import rego.v1

import data.vanian.gate

ok_input := {
	"agent_id": "recon-reporter", "server": "fs", "tool": "read_file",
	"authority_jtis": ["root-1", "hop-1"], "revoked_jtis": [], "delegation_depth": 1,
}

d(i) := r if {
	r := gate.decision with input as i
}

test_allow if d(ok_input) == {"outcome": "ALLOW", "reasons": []}

test_revoked_root if d(object.union(ok_input, {"revoked_jtis": ["root-1"]})) == {"outcome": "DENY", "reasons": ["authority revoked"]}

test_revoked_hop if d(object.union(ok_input, {"revoked_jtis": ["x", "hop-1"]})).outcome == "DENY"

test_explicit_deny_beats_allowlist if {
	r := d(object.union(ok_input, {"server": "shell", "tool": "exec", "delegation_depth": 0}))
	r == {"outcome": "DENY", "reasons": ["tool explicitly denied"]}
}

test_not_allowlisted if d(object.union(ok_input, {"tool": "write_file"})).reasons == ["call not in allowlist", "tool not delegable"]

test_unknown_agent if "unknown agent" in d(object.union(ok_input, {"agent_id": "ghost"})).reasons

test_too_deep if d(object.union(ok_input, {"delegation_depth": 3})).reasons == ["delegation too deep"]

test_non_delegable_tool_under_delegation if {
	r := d(object.union(ok_input, {"agent_id": "orchestrator", "delegation_depth": 1}))
	r == {"outcome": "DENY", "reasons": ["tool not delegable"]}
}

test_non_delegable_tool_direct_ok if d(object.union(ok_input, {"agent_id": "orchestrator", "delegation_depth": 0})).outcome == "ALLOW"

test_sensitive_needs_approval if {
	r := d(object.union(ok_input, {"agent_id": "payments-agent", "server": "payments", "tool": "settle_batch"}))
	r == {"outcome": "PENDING_APPROVAL", "reasons": []}
}

test_sensitive_and_revoked_is_deny if {
	i := object.union(ok_input, {"agent_id": "payments-agent", "server": "payments", "tool": "settle_batch", "revoked_jtis": ["hop-1"]})
	d(i).outcome == "DENY"
}

test_empty_input if d({}) == {"outcome": "DENY", "reasons": ["malformed input"]}

test_missing_authority if d(object.remove(ok_input, ["authority_jtis"])).reasons == ["malformed input"]

test_empty_authority if d(object.union(ok_input, {"authority_jtis": []})).outcome == "DENY"

test_non_string_jti if d(object.union(ok_input, {"authority_jtis": [1]})).outcome == "DENY"

test_negative_depth if d(object.union(ok_input, {"delegation_depth": -1})).outcome == "DENY"

test_no_data_denies if {
	r := gate.decision with input as ok_input with data.inventory as {}
	r.outcome == "DENY"
}
