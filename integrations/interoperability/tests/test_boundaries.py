from dataclasses import asdict, replace
import json
import time

from cryptography.hazmat.primitives.asymmetric import ec
import jwt
import pytest

from vanian_interop.a2a import DelegationGuard
from vanian_interop.governance import openshell_event, microsoft_result, correlate_decision_request
from vanian_interop.identity import JwtTrust, verify_identity, spiffe_trust_domain
from vanian_interop.policy import OpaAdapter
from vanian_interop.records import commitment, strict_json, retain_identity_claims, reference_assessment
from vanian_interop.transport import endpoint_origin


@pytest.fixture
def keys():
    key = ec.generate_private_key(ec.SECP256R1())
    trust = JwtTrust("https://identity.bank.example", "https://provider.example", "synthetic-bank", {"one": key.public_key()})
    return key, trust


def issue(key, trust, **updates):
    now = int(time.time())
    claims = dict(iss=trust.issuer, sub="research-agent", aud=trust.audience, iat=now, exp=now + 120)
    claims.update(updates)
    return jwt.encode(claims, key, algorithm="ES256", headers={"kid": "one", "typ": trust.accepted_types[0]})


def test_valid_credential_retains_unknown_binding_and_revocation(keys):
    key, trust = keys
    token = issue(key, trust)
    identity = verify_identity(token, trust)
    assert identity.subject == "research-agent"
    assert identity.logical_agent_id is None and identity.revocation_status == "UNKNOWN"
    assert token not in json.dumps(asdict(identity))


@pytest.mark.parametrize("updates", [{"iss": "https://other.example"}, {"aud": "other"},
    {"exp": 1}, {"iat": int(time.time()) + 1000}, {"nbf": int(time.time()) + 1000},
    {"sub": ""}, {"exp": True}, {"cnf": {"jkt": "not-proof"}}, {"iat": 1}])
def test_bad_credentials_are_refused(keys, updates):
    key, trust = keys
    with pytest.raises(ValueError):
        verify_identity(issue(key, trust, **updates), trust)


def test_forged_and_wrong_token_type_refused(keys):
    key, trust = keys
    forged = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(ValueError):
        verify_identity(issue(forged, trust), trust)
    with pytest.raises(ValueError):
        verify_identity(issue(key, replace(trust, accepted_types=("JWT",))), trust)


@pytest.mark.parametrize("header", [{"alg": "HS256"}, {"jku": "https://attacker.example"},
    {"jwk": {}}, {"crit": ["custom"]}, {"kid": "missing"}])
def test_token_cannot_select_its_trust_anchor(keys, header):
    key, trust = keys
    token = issue(key, trust)
    body = token.split(".")
    hdr = jwt.get_unverified_header(token); hdr.update(header)
    body[0] = jwt.utils.base64url_encode(json.dumps(hdr).encode()).decode()
    with pytest.raises(ValueError):
        verify_identity(".".join(body), trust)


def test_identity_collision_retains_both_claims(keys):
    key, trust = keys
    first = verify_identity(issue(key, trust), trust)
    second_trust = replace(trust, issuer="https://different.example")
    second = verify_identity(issue(key, second_trust), second_trust)
    mapping = retain_identity_claims("existing-aip-id", trust.tenant, (first, second))
    assert mapping.status == "UNRESOLVED" and len(mapping.claims) == 2
    with pytest.raises(ValueError):
        retain_identity_claims("existing-aip-id", "other-tenant", (first,))


def test_jwt_svid_verified_by_separate_domain_anchor(keys):
    key, trust = keys
    trust = replace(trust, issuer="bank.example", accepted_types=("JWT",))
    token = issue(key, trust, sub="spiffe://bank.example/agent/workload")
    identity = verify_identity(token, trust, jwt_svid=True)
    assert identity.workload_identity == "spiffe://bank.example/agent/workload"
    assert identity.logical_agent_id is None
    with pytest.raises(ValueError):
        verify_identity(issue(key, trust, sub="spiffe://evil.example/agent/workload"), trust, jwt_svid=True)


@pytest.mark.parametrize("value", ["spiffe://a:443/a", "spiffe://a/x/../y", "spiffe://a/x%2Fy", "spiffe://a/x?y", "spiffe://a//b", "https://a/x"])
def test_invalid_spiffe_ids(value):
    with pytest.raises(ValueError):
        spiffe_trust_domain(value)


def test_signed_delegation_replay_survives_restart_and_binds_request(keys, tmp_path):
    key, trust = keys
    trust = replace(trust, accepted_types=("vanian-delegation+jwt",))
    request = {"record": "SYN-001"}
    claims = dict(parent_task="parent", request_commitment=commitment(request),
                  action="research.read", resource="synthetic-loans", tenant=trust.tenant,
                  jti="single-use-delegation-001")
    token = issue(key, trust, **claims)
    config = dict(allowed_subjects=frozenset({"research-agent"}), allowed_actions=frozenset({"research.read"}))
    guard = DelegationGuard(trust, str(tmp_path / "replay.db"), **config)
    with pytest.raises(ValueError):
        guard.accept(token, parent_task="parent", request={"record": "SYN-002"}, action="research.read", resource="synthetic-loans")
    result = guard.accept(token, parent_task="parent", request=request, action="research.read", resource="synthetic-loans")
    assert result["remote_kernel"] == "UNOBSERVED"
    guard = DelegationGuard(trust, str(tmp_path / "replay.db"), **config)
    with pytest.raises(ValueError, match="replay"):
        guard.accept(token, parent_task="parent", request=request, action="research.read", resource="synthetic-loans")


def test_revoked_delegation_refused(keys, tmp_path):
    key, trust = keys
    trust = replace(trust, accepted_types=("vanian-delegation+jwt",))
    request = {"record": "SYN-001"}
    token = issue(key, trust, parent_task="p", request_commitment=commitment(request),
                  action="read", resource="loans", tenant=trust.tenant, jti="revoked-delegation")
    guard = DelegationGuard(trust, str(tmp_path / "db"), allowed_subjects=frozenset({"research-agent"}),
                            allowed_actions=frozenset({"read"}), revoked_jtis=frozenset({"revoked-delegation"}))
    with pytest.raises(ValueError, match="revoked"):
        guard.accept(token, parent_task="p", request=request, action="read", resource="loans")


class Transport:
    origin = ("https", "opa.bank.example", 443)
    ca_file = "configured-ca"
    ca_sha256 = "a" * 64
    def __init__(self, result): self.result = result
    def request(self, *args, **kwargs):
        self.requested = kwargs["body"]
        return json.dumps(self.result).encode()


@pytest.mark.parametrize("result,decision", [({"result": {"allow": True, "policy_version": "v1"}}, "ALLOW"),
    ({"result": {"allow": False, "policy_version": "v1"}}, "DENY"),
    ({"result": {"allow": "true", "policy_version": "v1"}}, "INDETERMINATE"),
    ({"result": {"allow": True, "policy_version": "v2"}}, "INDETERMINATE"),
    ({}, "INDETERMINATE"), ({"result": True}, "INDETERMINATE")])
def test_opa_native_semantics_and_version_changes(keys, result, decision):
    key, trust = keys
    transport = Transport(result)
    adapter = OpaAdapter("https://opa.bank.example/v1/data/vanian/decision", transport,
        engine_version="1.21.4", policy_version="v1", authority="bank-policy-ops")
    record = adapter.evaluate(verify_identity(issue(key, trust), trust), resource="loans", action="read",
                               request_id="r1", execution_context_ref=None, arguments={"id": 1})
    assert record.decision == decision
    assert record.authorization_status == "REFERENCE_ONLY"
    assert json.loads(record.native_result_json) == result
    assert record.input_commitment == commitment(transport.requested["input"])


def test_opa_transport_failure_does_not_become_allow(keys):
    class Broken(Transport):
        def request(self, *args, **kwargs): raise TimeoutError("unavailable")
    key, trust = keys
    adapter = OpaAdapter("https://opa.bank.example/v1/data/vanian/decision", Broken({}),
        engine_version="1", policy_version="v1", authority="bank")
    with pytest.raises(TimeoutError):
        adapter.evaluate(verify_identity(issue(key, trust), trust), resource="r", action="read",
                         request_id="x", execution_context_ref=None, arguments={})


def test_openshell_denial_is_not_a_kernel_observation():
    raw = {"class_uid": 4001, "time": 123, "action_id": 2, "disposition_id": 2,
           "metadata": {"uid": "event-1", "product": {"name": "OpenShell Sandbox Supervisor"}},
           "container": {"uid": "sandbox-1"}}
    event = openshell_event(json.dumps(raw).encode(), tenant="bank")
    assert event.workload_id == "sandbox-1" and event.observation_coverage == "NOT_ESTABLISHED"
    assert event.authenticity.mechanism == "UNVERIFIED_IMPORT"
    assert json.loads(event.native_json) == raw


def test_microsoft_transform_is_not_collapsed_and_missing_evidence_stays_unknown():
    native = {"verdict": {"decision": "transform", "transform": {"path": "args", "value": {"id": 1}},
                           "warnings": [{"reason": "review"}]},
              "input_identity": "original", "enforced_identity": "modified"}
    event = microsoft_result(native, tenant="bank", request_id="r", evaluated_at_ms=100,
                             policy_version="v1", agent_id="a")
    assert json.loads(event.native_json) == native
    for received, expected in [("modified", "AGREEMENT"), ("original", "DIVERGENCE")]:
        result = correlate_decision_request(event, request_tenant="bank", evaluated_input_identity="original", received_input_identity=received)
        assert result["comparison"] == expected and result["execution"] == "CANNOT_PROVE"
    with pytest.raises(ValueError):
        correlate_decision_request(event, request_tenant="other", evaluated_input_identity="original", received_input_identity="modified")
    for present in [False, True]:
        assert reference_assessment(has_authorization=present, has_gateway_receipt=present,
            has_bound_observation=present, remote_observer_available=False)["reconciliation"] == "CANNOT_PROVE"


@pytest.mark.parametrize("raw", ['{"a":1,"a":2}', '{"x":NaN}', '{"x":Infinity}'])
def test_ambiguous_json_refused(raw):
    with pytest.raises(ValueError): strict_json(raw)


@pytest.mark.parametrize("url", ["http://example.com", "https://u:p@example.com", "https://example.com/#fragment", "file:///tmp/key"])
def test_unsafe_endpoints_refused(url):
    with pytest.raises(ValueError): endpoint_origin(url)


def test_microsoft_native_tuple_labels_and_warnings_are_retained():
    native = {"verdict": {"decision": "allow", "result_labels": ("synthetic",), "warnings": ()}}
    event = microsoft_result(native, tenant="bank", request_id="r", evaluated_at_ms=1,
                             policy_version="v1", agent_id="a")
    assert json.loads(event.native_json)["verdict"]["result_labels"] == ["synthetic"]


def test_a2a_origin_guard_refuses_card_credential_exfiltration():
    import asyncio
    import httpx
    from vanian_interop.a2a import A2AConnection
    connection = object.__new__(A2AConnection)
    connection.origin = ("https", "provider.example", 443)
    accessed = []
    connection.credential_provider = lambda: accessed.append(True)
    with pytest.raises(ValueError, match="cross-origin"):
        asyncio.run(connection._guard_request(httpx.Request("GET", "https://attacker.example/card")))
    assert not accessed
