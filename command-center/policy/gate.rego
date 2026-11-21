# Gate policy (enterprise WOW loop, item 3.1a). Evaluated by `opa eval` once
# per gated call; see command-center/server/opa_gate.py.
#
# Outcome is exactly one of "ALLOW", "DENY", "PENDING_APPROVAL". DENY wins
# over everything; PENDING_APPROVAL only applies to a call that would
# otherwise be allowed. Anything this policy does not positively allow is
# denied.
#
# Revocations arrive in `input.revoked_jtis`, already verified against their
# signatures by the caller. OPA checks no signatures.
package vanian.gate

import rego.v1

default outcome := "DENY"

str_field(name) if {
	is_string(input[name])
	input[name] != ""
}

well_formed if {
	str_field("agent_id")
	str_field("server")
	str_field("tool")
	is_array(input.authority_jtis)
	count(input.authority_jtis) > 0
	every j in input.authority_jtis { is_string(j) }
	is_array(input.revoked_jtis)
	is_number(input.delegation_depth)
	input.delegation_depth >= 0
}

deny contains "malformed input" if not well_formed

deny contains "unknown agent" if {
	well_formed
	not data.inventory.agents[input.agent_id]
}

deny contains "authority revoked" if {
	well_formed
	some j in input.authority_jtis
	j in input.revoked_jtis
}

deny contains "tool explicitly denied" if {
	well_formed
	some d in data.inventory.denied_tools
	d.server == input.server
	d.tool == input.tool
}

deny contains "call not in allowlist" if {
	well_formed
	not allowlisted
}

deny contains "delegation too deep" if {
	well_formed
	input.delegation_depth > data.inventory.max_delegation_depth
}

# A delegated call (depth > 0) may only use tools marked delegable.
deny contains "tool not delegable" if {
	well_formed
	input.delegation_depth > 0
	not delegable
}

allowlisted if {
	some e in data.inventory.allowlist
	e.agent_id == input.agent_id
	e.server == input.server
	e.tool == input.tool
}

delegable if {
	some e in data.inventory.allowlist
	e.agent_id == input.agent_id
	e.server == input.server
	e.tool == input.tool
	e.delegable == true
}

# A sensitive tool needs approval unless the call's amount is a number at or
# below the declared threshold. A missing or non-numeric amount needs
# approval (fail closed).
sensitive if {
	some s in data.inventory.sensitive_tools
	s.server == input.server
	s.tool == input.tool
	not below_threshold
}

below_threshold if {
	is_number(input.amount)
	input.amount <= data.inventory.approval_threshold
}

outcome := "PENDING_APPROVAL" if {
	well_formed
	count(deny) == 0
	sensitive
}

outcome := "ALLOW" if {
	well_formed
	count(deny) == 0
	not sensitive
}

decision := {"outcome": outcome, "reasons": sort([r | some r in deny])}
