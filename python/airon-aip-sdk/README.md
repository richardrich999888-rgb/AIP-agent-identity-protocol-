# AIRON AIP Python SDK

`airon-aip` is the Python SDK for persistent Agent Identity Protocol identities.
It lets Python agents obtain, persist, verify, delegate, revoke, and attach AIP
identity metadata to AI/ML workflows.

The core SDK has no required third-party dependencies. Framework integrations
are optional extras:

```bash
pip install -e python/airon-aip-sdk
pip install -e 'python/airon-aip-sdk[langchain,numpy,pandas,torch]'
```

Start the AIP service:

```bash
mkdir -p /tmp/airon-aip

AIP_PORT=8081 \
AIP_KEY_PATH=/tmp/airon-aip/signing.key \
AIP_DELEGATION_LOG_PATH=/tmp/airon-aip/delegation.jsonl \
AIP_REVOCATION_LOG_PATH=/tmp/airon-aip/revocation.jsonl \
AIP_ISSUER_URL=http://127.0.0.1:8081 \
cargo run --manifest-path aip-service/Cargo.toml
```

Use persistent identity:

```python
from airon_aip import AipClient, PersistentAgentIdentity

client = AipClient("http://127.0.0.1:8081")
agent = PersistentAgentIdentity(client, alias="research-agent")

identity = agent.load_or_issue(
    agent_type="ai_model",
    metadata={"framework": "langchain", "model": "gpt-5"},
)

headers = agent.authorization_headers()
print(identity.agent_id, identity.jti, headers["Authorization"])
```

Issue an AgentPassport:

```python
from airon_aip import AIPConfig, AgentPassport

passport_service = AgentPassport(AIPConfig(aip_token=identity.token))

passport = passport_service.issue(
    friendly_name="InvoiceBot",
    capabilities=["invoice.read", "ledger.post"],
    metadata={"runtime": "langchain-v0.2"},
)
passport.save("agent.passport.json")

verification = passport_service.verify(passport)
assert verification.is_valid
```

LangChain:

```python
from airon_aip.integrations.langchain import aip_runnable_config, wrap_runnable

chain = wrap_runnable(chain, identity)
# or:
config = aip_runnable_config(identity)
chain.invoke({"input": "hello"}, config=config)
```

pandas:

```python
from airon_aip.integrations.pandas import stamp_dataframe

df = stamp_dataframe(df, identity)
print(df.attrs["airon_aip"])
```

PyTorch:

```python
from airon_aip.integrations.torch import attach_aip_to_module

model = attach_aip_to_module(model, identity, persist_hash=True)
```

NumPy:

```python
from airon_aip.integrations.numpy import AipArray, array_fingerprint

wrapped = AipArray(array=my_array, identity=identity)
print(array_fingerprint(my_array))
```
