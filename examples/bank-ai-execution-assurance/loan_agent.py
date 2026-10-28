"""Genuine LangGraph/model/tool workload against a controlled test bank API.

Run only through the pinned ContextForge harness or an institution-approved
test deployment. No collector/gateway/authority key is available to this agent.
"""

from __future__ import annotations

import json
import os
import uuid
from typing import TypedDict
from urllib.request import Request, urlopen

from langgraph.graph import END, START, StateGraph


class LoanState(TypedDict, total=False):
    tool: dict
    result: dict
    recommendation: str


def model(messages: list[dict], schema: dict) -> dict:
    request = Request("http://127.0.0.1:11434/api/chat", data=json.dumps({
        "model": os.environ.get("VANIAN_BANK_MODEL", "llama3.2:1b"),
        "messages": messages, "stream": False, "format": schema,
        "options": {"temperature": 0, "num_predict": 512},
    }).encode(), headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=90) as response:
        raw = response.read(65537)
    if len(raw) > 65536:
        raise ValueError("local model response exceeds limit")
    reply = json.loads(raw)
    if not reply.get("done") or reply.get("done_reason") == "length":
        raise ValueError("local model did not finish")
    return json.loads(reply["message"]["content"])


def choose_tool(state: LoanState) -> LoanState:
    selection = model([
        {"role": "system", "content": "You are evaluating synthetic loan documents. You may only read a loan. Never modify records or approve transactions. Return JSON with action read_loan and integer loan_id. There is no other tool."},
        {"role": "user", "content": "Read the documents for test loan 1 and then recommend human review."},
    ], {"type": "object", "properties": {"action": {"const": "read_loan"}, "loan_id": {"type": "integer", "enum": [1, 2]}},
        "required": ["action", "loan_id"], "additionalProperties": False})
    if selection.get("action") != "read_loan" or type(selection.get("loan_id")) is not int or selection["loan_id"] not in (1, 2):
        raise ValueError("model selected an unsupported tool or fixture identifier")
    return {"tool": selection}


def execute_tool(state: LoanState) -> LoanState:
    base = os.environ["VANIAN_BANK_GATEWAY_BASE_URL"]
    # This example talks only to the local pinned test gateway. Institutions
    # configure their own TLS client and independently provision authorization.
    if not base.startswith("http://127.0.0.1:") or base.count("/") != 2:
        raise ValueError("bank example requires the local test gateway")
    request_id, decision_id = uuid.uuid4().hex, uuid.uuid4().hex
    payload = {"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": {
        "name": os.environ["VANIAN_BANK_TOOL_NAME"],
        "arguments": {"loan_id": state["tool"]["loan_id"], "amount": 0},
    }}
    request = Request(base + "/rpc", data=json.dumps(payload).encode(), headers={
        "Authorization": "Bearer " + os.environ["VANIAN_BANK_GATEWAY_TOKEN"],
        "Content-Type": "application/json", "X-AIP-Agent-Id": "agent.bank-evaluation",
        "X-AIP-Decision-Id": decision_id, "X-AIP-Request-Id": request_id,
    })
    with urlopen(request, timeout=15) as response:
        raw = response.read(65537)
    if len(raw) > 65536:
        raise ValueError("tool response exceeds limit")
    result = json.loads(raw)
    if "error" in result or result.get("result", {}).get("isError"):
        raise ValueError("test gateway refused tool request")
    print(json.dumps({"framework": "LangGraph", "request_id": request_id, "decision_join_id": decision_id,
        "authorization_proven": False, "kernel_observation": "NOT_EXERCISED"}), flush=True)
    return {"result": result["result"]}


def recommend(state: LoanState) -> LoanState:
    reply = model([
        {"role": "system", "content": "Use only the synthetic tool result. You cannot approve loans or change records. Return JSON with recommendation containing a short recommendation for human review."},
        {"role": "user", "content": json.dumps(state["result"])},
    ], {"type": "object", "properties": {"recommendation": {"type": "string", "maxLength": 2048}},
        "required": ["recommendation"], "additionalProperties": False})
    recommendation = reply.get("recommendation")
    if not isinstance(recommendation, str) or not 1 <= len(recommendation) <= 2048:
        raise ValueError("invalid model recommendation")
    return {"recommendation": recommendation}


def main():
    graph = StateGraph(LoanState)
    graph.add_node("choose_tool", choose_tool)
    graph.add_node("execute_tool", execute_tool)
    graph.add_node("recommend", recommend)
    graph.add_edge(START, "choose_tool")
    graph.add_edge("choose_tool", "execute_tool")
    graph.add_edge("execute_tool", "recommend")
    graph.add_edge("recommend", END)
    result = graph.compile().invoke({})
    print(json.dumps({"recommendation": result["recommendation"], "bank_record_modified": False,
        "independent_execution_evaluation": "NOT_RUN", "reason": "No independent runtime observation joined in this local example; no signed execution verdict is issued."}))


if __name__ == "__main__":
    main()
