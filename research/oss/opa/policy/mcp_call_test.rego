package vanian.mcp_test

import rego.v1

import data.vanian.mcp

fixture := {
	"agents": {"recon-reporter": {}, "orchestrator": {}, "ex-worker": {}},
	"revoked": ["ex-worker"],
	"allowlist": [
		{"agent_id": "recon-reporter", "server": "fs", "tool": "read_file"},
		{"agent_id": "ex-worker", "server": "fs", "tool": "read_file"},
	],
}

call(a, s, t) := {"agent_id": a, "server": s, "tool": t}

test_allowed_exact_call if {
	mcp.decision == {"allow": true, "reasons": []} with input as call("recon-reporter", "fs", "read_file")
		with data.inventory as fixture
}

test_other_tool_refused if {
	mcp.decision == {"allow": false, "reasons": ["call not in allowlist"]} with input as call("recon-reporter", "fs", "write_file")
		with data.inventory as fixture
}

test_other_server_refused if {
	not mcp.allow with input as call("recon-reporter", "shell", "read_file")
		with data.inventory as fixture
}

test_no_prefix_match if {
	not mcp.allow with input as call("recon-reporter", "fs", "read_file_and_more")
		with data.inventory as fixture
}

# Revocation wins over an allowlist entry.
test_revoked_agent_refused_despite_allowlist if {
	mcp.decision == {"allow": false, "reasons": ["agent revoked"]} with input as call("ex-worker", "fs", "read_file")
		with data.inventory as fixture
}

test_unknown_agent_refused if {
	mcp.decision == {"allow": false, "reasons": ["call not in allowlist", "unknown agent"]} with input as call("ghost", "fs", "read_file")
		with data.inventory as fixture
}

test_empty_input_refused if {
	mcp.decision == {"allow": false, "reasons": ["malformed input"]} with input as {}
		with data.inventory as fixture
}

test_non_string_field_refused if {
	mcp.decision == {"allow": false, "reasons": ["malformed input"]} with input as {"agent_id": 7, "server": "fs", "tool": "read_file"}
		with data.inventory as fixture
}

test_empty_string_refused if {
	not mcp.allow with input as call("", "fs", "read_file")
		with data.inventory as fixture
}

# No data loaded at all: nothing is allowed.
test_no_data_refuses_everything if {
	not mcp.allow with input as call("recon-reporter", "fs", "read_file")
		with data.inventory as {}
}
