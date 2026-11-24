package aip.loan_read

import rego.v1

default allow := false

allow if {
	object.keys(input) == {"agent_id", "peer", "proposal"}
	object.keys(data.aip_context) == {"agent_id", "expected_peer", "allowed_calls"}
	is_string(input.agent_id)
	input.agent_id != ""
	input.agent_id == data.aip_context.agent_id
	object.keys(input.peer) == {"source", "pid", "uid", "gid"}
	input.peer.source == "ROOT_SO_PEERCRED"
	object.keys(data.aip_context.expected_peer) == {"pid", "uid", "gid"}
	is_number(input.peer.pid)
	is_number(input.peer.uid)
	is_number(input.peer.gid)
	input.peer.pid > 0
	input.peer.uid >= 0
	input.peer.gid >= 0
	input.peer.pid == data.aip_context.expected_peer.pid
	input.peer.uid == data.aip_context.expected_peer.uid
	input.peer.gid == data.aip_context.expected_peer.gid
	object.keys(input.proposal) == {"tool_id", "arguments"}
	is_string(input.proposal.tool_id)
	input.proposal.tool_id != ""
	object.keys(input.proposal.arguments) == {"loan_id", "amount"}
	is_number(input.proposal.arguments.loan_id)
	is_number(input.proposal.arguments.amount)
	input.proposal.arguments.loan_id == 1
	input.proposal.arguments.amount == 0
	count(data.aip_context.allowed_calls) == 1
	input.proposal == data.aip_context.allowed_calls[0]
}
