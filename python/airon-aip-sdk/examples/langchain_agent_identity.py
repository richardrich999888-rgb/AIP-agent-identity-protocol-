from airon_aip import AipClient, PersistentAgentIdentity
from airon_aip.integrations.langchain import aip_runnable_config


client = AipClient("http://127.0.0.1:8081")
agent = PersistentAgentIdentity(client, alias="langchain-demo-agent")
identity = agent.load_or_issue(
    agent_type="ai_model",
    metadata={"framework": "langchain", "example": "persistent_identity"},
)

config = aip_runnable_config(identity)
print(config)
