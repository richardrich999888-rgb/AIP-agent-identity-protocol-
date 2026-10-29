#!/usr/bin/env python3
"""Two real ADK model-driven agents over mutually authenticated A2A.

Optional existing ContextForge gateway is supplied by validate_contextforge.py.
All PKI is ephemeral lab custody; no kernel or institutional-custody claim.
"""
from __future__ import annotations

import asyncio
from dataclasses import asdict
import json
import hashlib
import os
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import time
import uuid
from urllib.request import Request, urlopen

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

import httpx
import jwt
import uvicorn
from cryptography.hazmat.primitives.asymmetric import ec
from google.adk.agents import LlmAgent
from google.adk.a2a.utils.agent_to_a2a import to_a2a
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types
from google.protobuf.json_format import MessageToDict
from a2a.types import Message, Part, SendMessageRequest

from vanian_interop.a2a import A2AConnection, DelegationGuard
from vanian_interop.google_adk import VanianAdkPlugin
from vanian_interop.identity import JwtTrust, verify_identity
from vanian_interop.records import commitment, strict_json
from lab_tls import create_pki
from local_model import LocalQwen


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def run():
    output = Path(os.environ.get("VANIAN_INTEROP_RESULTS", "adk-a2a-results")).resolve()
    output.mkdir(parents=True, exist_ok=True)
    transcript = output / "model-transcript.jsonl"
    if transcript.exists():
        raise ValueError("use a fresh output directory; never append separate runs")
    model_path = os.environ["VANIAN_LOCAL_MODEL_DIR"]
    sources = [*HERE.glob("*.py"), *(HERE.parent / "src").rglob("*.py")]
    sources += list((HERE / "microsoft").rglob("*.yaml")) + list((HERE / "microsoft").rglob("*.rego"))
    (output / "source-sha256.json").write_text(json.dumps({str(path.relative_to(HERE.parent)):
        hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(sources)}, indent=2) + "\n")
    model = LocalQwen(model_path, transcript)
    events, interactions, tool_results, a2a_replies, governance_results = [], [], [], [], []
    governance_requests = []
    control = None
    negative_checks = []
    if os.environ.get("VANIAN_MICROSOFT_MANIFEST"):
        from agent_control_specification import AgentControl
        control = AgentControl.from_path(os.environ["VANIAN_MICROSOFT_MANIFEST"])
        from agent_control_specification import AgentControlBlocked
        dispatched = []
        try:
            await control.run_tool("read_loan", {"loan_id": 999, "amount": 0},
                lambda value: dispatched.append(value), snapshot={"agent": {"id": "provider_research"}})
        except AgentControlBlocked as error:
            if dispatched:
                raise AssertionError("native deny dispatched a tool")
            negative_checks.append({"check": "native_ACS_denied_out_of_scope_without_dispatch", "status": "PASS"})
        else:
            raise AssertionError("native ACS did not deny out-of-scope input")
    result = {"status": "BLOCKED", "kernel_observation": "NOT_EXECUTED",
              "institutional_key_custody": "NOT_ESTABLISHED", "logical_agent_attribution": "FRAMEWORK_ONLY",
              "remote_kernel": "UNOBSERVED", "signed_authorization": "NOT_ESTABLISHED"}
    with tempfile.TemporaryDirectory(prefix="vanian-a2a-") as temp:
        temp = Path(temp)
        create_pki(temp)
        server_port = port()
        endpoint = f"https://127.0.0.1:{server_port}"
        key = ec.generate_private_key(ec.SECP256R1())
        trust = JwtTrust("https://identity.bank.example", endpoint, "synthetic-bank", {"lab": key.public_key()})
        delegation_trust = JwtTrust(trust.issuer, endpoint, trust.tenant, trust.keys,
                                   accepted_types=("vanian-delegation+jwt",))
        def credential(profile="at+jwt", **extra):
            now = int(time.time())
            return jwt.encode({"iss": trust.issuer, "sub": "research-agent", "aud": endpoint,
                "iat": now, "exp": now + 180, **extra}, key, algorithm="ES256", headers={"kid": "lab", "typ": profile})
        identity = verify_identity(credential(), trust)
        guard = DelegationGuard(delegation_trust, str(temp / "replay.db"),
            allowed_subjects=frozenset({"research-agent"}), allowed_actions=frozenset({"research.read"}))

        def read_loan_core(arguments: dict, request_id: str, decision_id: str) -> dict:
            """Dispatch the exact arguments evaluated by ACS, without translation."""
            gateway = os.environ.get("VANIAN_BANK_GATEWAY_BASE_URL")
            if gateway:
                tool = os.environ["VANIAN_BANK_TOOL_NAME"]
                payload = {"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": "tools/call",
                           "params": {"name": tool, "arguments": arguments}}
                headers = {"Content-Type": "application/json", "Authorization": "Bearer " + os.environ["VANIAN_BANK_GATEWAY_TOKEN"],
                           "X-AIP-Agent-Id": "agent.bank-evaluation", "X-AIP-Decision-Id": decision_id,
                           "X-AIP-Request-Id": request_id, "Mcp-Method": "tools/call", "Mcp-Name": tool}
                with urlopen(Request(gateway + "/rpc", data=json.dumps(payload).encode(), headers=headers), timeout=30) as response:
                    record = json.load(response)
                if "error" in record or record.get("result", {}).get("isError"):
                    raise ValueError("actual gateway invocation failed")
                # Keep only the synthetic tool result and its signed receipt.
                tool_results.append(record)
                return {name: value for name, value in record["result"].items() if name != "_meta"}
            record = {"loan_id": arguments["loan_id"], "currency": "INR", "amount": 1000, "synthetic": True}
            tool_results.append(record)
            return record

        async def read_loan(record_id: str) -> dict:
            """Read a synthetic loan record by its record_id, such as SYN-001."""
            if record_id not in ("SYN-001", "SYN-002"):
                raise ValueError("record outside lab scope")
            arguments = {"loan_id": {"SYN-001": 17, "SYN-002": 18}[record_id], "amount": 0}
            request_id, decision_id = str(uuid.uuid4()), uuid.uuid4().hex
            if control is None:
                return read_loan_core(arguments, request_id, decision_id)
            from vanian_interop.governance import microsoft_result
            governed = await control.run_tool("read_loan", arguments,
                lambda effective: read_loan_core(effective, request_id, decision_id),
                tool_call_id=request_id,
                snapshot={"agent": {"id": "provider_research"}})
            governance_requests.append({"request_id": request_id, "decision_id": decision_id,
                "receipt_result_index": len(tool_results) - 1,
                "context_provenance": "APPLICATION_REPORTED_NOT_AUTHORITY"})
            for point, native in [("pre", governed.pre_tool_call_result), ("post", governed.post_tool_call_result)]:
                governance_results.append(asdict(microsoft_result(native, tenant="synthetic-provider",
                    request_id=request_id if point == "pre" else "post-" + request_id,
                    evaluated_at_ms=time.time_ns()//1_000_000,
                    policy_version="vanian-synthetic-research-v2", agent_id="provider_research")))
            return governed.value

        provider = LlmAgent(name="provider_research", model=model, tools=[read_loan],
            instruction="You are a research agent. Use read_loan to read the requested synthetic loan. Do not invent the record.")
        provider_runner = Runner(agent=provider, app_name="provider", session_service=InMemorySessionService(),
                                 plugins=[VanianAdkPlugin("synthetic-provider", events.append)])
        application = to_a2a(provider, host="127.0.0.1", port=server_port, protocol="https", runner=provider_runner)

        async def authenticated(scope, receive, send):
            if scope["type"] != "http":
                return await application(scope, receive, send)
            from starlette.responses import JSONResponse
            headers = dict(scope["headers"])
            try:
                bearer = headers.get(b"authorization", b"").decode()
                if not bearer.startswith("Bearer "):
                    raise ValueError("missing bearer")
                caller = verify_identity(bearer[7:], trust)
                body = b""
                if scope["method"] == "POST":
                    while True:
                        message = await receive()
                        body += message.get("body", b"")
                        if len(body) > 1_048_576:
                            raise ValueError("oversize request")
                        if not message.get("more_body"):
                            break
                    wire = strict_json(body)
                    params = wire["params"]
                    metadata = params["metadata"]
                    interaction = guard.accept(metadata["vanian_delegation"], parent_task=metadata["parent_task"],
                        request=params["message"], action="research.read", resource="synthetic-loans")
                    interactions.append(interaction)
                    # Credentials terminate at the auth boundary. ADK copies
                    # metadata into task history, including nested JSON strings.
                    # Forward only the verified reference, never the credential.
                    params["metadata"] = {"parent_task": metadata["parent_task"],
                        "delegation_reference": interaction["delegation_id"]}
                    body = json.dumps(wire).encode()
                from starlette.authentication import AuthCredentials, SimpleUser
                scope = {**scope, "user": SimpleUser(caller.subject), "auth": AuthCredentials(["authenticated"]),
                    "headers": [(k,v) for k,v in scope["headers"] if k not in (b"authorization", b"content-length")]}
                if body:
                    scope["headers"].append((b"content-length", str(len(body)).encode()))
                sent = False
                async def replay():
                    nonlocal sent
                    if not sent:
                        sent = True
                        return {"type": "http.request", "body": body, "more_body": False}
                    return await receive()
                await application(scope, replay if scope["method"] == "POST" else receive, send)
            except (ValueError, KeyError):
                await JSONResponse({"error": "authenticated scope-bound delegation required"}, status_code=403)(scope, receive, send)

        config = uvicorn.Config(authenticated, host="127.0.0.1", port=server_port, log_level="warning",
            ssl_keyfile=str(temp / "server.key"), ssl_certfile=str(temp / "server.pem"),
            ssl_ca_certs=str(temp / "ca.pem"), ssl_cert_reqs=ssl.CERT_REQUIRED)
        server = uvicorn.Server(config)
        server_task = asyncio.create_task(server.serve())
        try:
            for _ in range(100):
                if server.started: break
                if server_task.done(): raise RuntimeError("A2A server startup failed")
                await asyncio.sleep(.05)
            if not server.started: raise RuntimeError("A2A server startup timeout")
            connection = A2AConnection(endpoint, ca_file=str(temp / "ca.pem"), client_cert=str(temp / "client.pem"),
                client_key=str(temp / "client.key"), credential_provider=credential)
            card = await connection.discover()
            tls = ssl.create_default_context(cafile=str(temp / "ca.pem"))
            tls.load_cert_chain(str(temp / "client.pem"), str(temp / "client.key"))
            async with httpx.AsyncClient(verify=tls, trust_env=False, timeout=5) as probe:
                response = await probe.get(endpoint + "/.well-known/agent-card.json")
                assert response.status_code == 403
                negative_checks.append({"check": "A2A_missing_bearer_refused", "status": "PASS"})
                response = await probe.get(endpoint + "/.well-known/agent-card.json",
                    headers={"Authorization": "Bearer " + credential(aud="wrong-endpoint")})
                assert response.status_code == 403
                negative_checks.append({"check": "A2A_wrong_audience_refused", "status": "PASS"})
                response = await probe.post(endpoint, headers={"Authorization": "Bearer " + credential()},
                    json={"params": {"message": {"tampered": True}, "metadata": {"parent_task": "probe",
                        "vanian_delegation": credential("vanian-delegation+jwt", tenant=trust.tenant,
                            parent_task="probe", request_commitment=commitment({"tampered": False}),
                            action="research.read", resource="synthetic-loans", jti=str(uuid.uuid4()))}}})
                assert response.status_code == 403
                negative_checks.append({"check": "A2A_changed_delegated_request_refused", "status": "PASS"})
            async with httpx.AsyncClient(verify=ssl.create_default_context(cafile=str(temp / "ca.pem")),
                                          trust_env=False, timeout=5) as probe:
                try:
                    await probe.get(endpoint + "/.well-known/agent-card.json")
                except httpx.TransportError:
                    negative_checks.append({"check": "A2A_missing_client_certificate_refused", "status": "PASS"})
                else:
                    raise AssertionError("A2A endpoint accepted a client without mTLS")

            async def delegate_research(record_id: str) -> dict:
                """Delegate research for the requested synthetic record_id to the authenticated provider agent."""
                message = Message(message_id=str(uuid.uuid4()), role=1,
                                  parts=[Part(text=f"Read synthetic loan {record_id} using the read_loan tool.")])
                parent = "bank-task-" + str(uuid.uuid4())
                delegation = credential("vanian-delegation+jwt", tenant=trust.tenant,
                    parent_task=parent, request_commitment=commitment(MessageToDict(message)),
                    action="research.read", resource="synthetic-loans", jti=str(uuid.uuid4()))
                request = SendMessageRequest(message=message, metadata={"parent_task": parent, "vanian_delegation": delegation})
                replies = await connection.send(request)
                public_replies = [MessageToDict(reply) for reply in replies]
                # A2A tasks may echo request metadata. Retain no bearer credentials.
                def redact(value):
                    if isinstance(value, dict):
                        return {k: redact(v) for k,v in value.items() if k not in ("vanian_delegation", "authorization")}
                    if isinstance(value, list): return [redact(v) for v in value]
                    return value
                a2a_replies.extend(redact(public_replies))
                texts = [part["text"] for reply in public_replies
                    for artifact in reply.get("task", {}).get("artifacts", [])
                    for part in artifact.get("parts", []) if "text" in part]
                if not texts:
                    raise RuntimeError("provider did not return a completed research artifact")
                return {"parent_task": parent, "provider_response": texts, "remote_kernel": "UNOBSERVED"}

            bank = LlmAgent(name="bank_research", model=model, tools=[delegate_research],
                instruction="You are a bank research agent. Delegate requested record research using delegate_research. Do not invent records.")
            sessions = InMemorySessionService()
            await sessions.create_session(app_name="bank", user_id="synthetic-owner", session_id="synthetic-session")
            runner = Runner(agent=bank, app_name="bank", session_service=sessions,
                            plugins=[VanianAdkPlugin("synthetic-bank", events.append)])
            replies = []
            async for event in runner.run_async(user_id="synthetic-owner", session_id="synthetic-session",
                new_message=types.Content(role="user", parts=[types.Part(text="Research synthetic loan SYN-001 by delegating to the provider.")])):
                if event.content:
                    replies.append(event.content.model_dump(mode="json", exclude_none=True))
                if len(replies) > 12:
                    raise RuntimeError("model exceeded lab turn budget")
            if len(interactions) != 1 or len(tool_results) != 1:
                raise RuntimeError("genuine agent did not complete exactly one delegated tool operation")
            result.update(status="PARTIALLY_VERIFIED", identity=asdict(identity), agent_card=asdict(card),
                a2a_interactions=interactions, gateway="ContextForge" if os.environ.get("VANIAN_BANK_GATEWAY_BASE_URL") else "NOT_CONNECTED",
                tool_results=tool_results, agent_responses=replies, a2a_replies=a2a_replies,
                microsoft_governance=governance_results,
                governance_requests=governance_requests,
                negative_checks=negative_checks,
                model_calls=len(transcript.read_text().splitlines()),
                scope="Real local inference and authenticated A2A; same-process logical agents; no independent runtime observation.")
            await connection.close()
            await runner.close()
        finally:
            server.should_exit = True
            await server_task
            (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
            (output / "framework-events.jsonl").write_text("".join(json.dumps(asdict(event)) + "\n" for event in events))
    print(json.dumps({"status": result["status"], "model_calls": result["model_calls"], "output": str(output)}))


if __name__ == "__main__":
    asyncio.run(run())
