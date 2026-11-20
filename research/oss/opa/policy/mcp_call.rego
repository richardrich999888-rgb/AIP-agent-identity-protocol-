# Smoke-test policy for item 1.2: the shape the demo's gateway would ask OPA.
#
# OPA only decides. This policy enforces nothing by itself: a caller that
# ignores `decision.allow`, or that treats "OPA unreachable" as allow, makes
# it advisory. The calling side must fail closed.
package vanian.mcp

import rego.v1

# Default deny: any input that does not satisfy every rule below is refused.
default allow := false

# Well-formed input: three non-empty strings. Anything else is refused with a
# reason rather than evaluated.
well_formed if {
	is_string(input.agent_id)
	is_string(input.server)
	is_string(input.tool)
	input.agent_id != ""
	input.server != ""
	input.tool != ""
}

deny contains "malformed input" if not well_formed

deny contains "agent revoked" if {
	well_formed
	input.agent_id in data.inventory.revoked
}

deny contains "unknown agent" if {
	well_formed
	not data.inventory.agents[input.agent_id]
}

deny contains "call not in allowlist" if {
	well_formed
	not exact_match
}

# Exact (agent, server, tool) triple; no wildcards, no prefix matching.
exact_match if {
	some e in data.inventory.allowlist
	e.agent_id == input.agent_id
	e.server == input.server
	e.tool == input.tool
}

allow if {
	well_formed
	count(deny) == 0
}

decision := {"allow": allow, "reasons": sort([r | some r in deny])}
