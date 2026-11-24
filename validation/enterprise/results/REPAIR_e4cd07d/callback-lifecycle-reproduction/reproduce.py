"""Local callback fixture only: no agent, model, network, or real upstream tool."""
import asyncio
import json
import os
import sys
import uuid
import functools
from pathlib import Path

REPO = Path('/Users/richardrich/.codex/worktrees/snifferdog-complete-enterprise-validation/AIP')
ORIGINAL = Path(__file__).resolve().parent/'original-plugin'
sys.path.insert(0,str(ORIGINAL))
os.environ['AIP_ASSURANCE_TEST_BIN_DIR']=str(REPO/'target/debug')
from test_authorization_policy import AuthorizationPolicy
from cpex.framework import GlobalContext, HttpHeaderPayload, PluginConfig
from cpex.framework.models import Config
from cpex.framework.manager import TenantPluginManager
from cpex.framework.hooks.tools import ToolPreInvokePayload, ToolPostInvokePayload
import vanian_contextforge

async def scenario(replace):
    fixture = AuthorizationPolicy()
    fixture.setUp()
    managers = []
    try:
        pc = PluginConfig(**{**fixture.plugin().config.model_dump(),
            'hooks':['tool_pre_invoke','tool_post_invoke'],'mode':'sequential','on_error':'fail'})
        config = Config(plugin_dirs=[str(ORIGINAL)], plugins=[pc])
        one = TenantPluginManager(config=config)
        managers.append(one)
        await one.initialize()
        g = GlobalContext(request_id=uuid.uuid4().hex, user={'email':'validator@example.com'})
        payload = ToolPreInvokePayload(name=fixture.tool, args=fixture.arguments,
            headers=HttpHeaderPayload(root={'X-AIP-Agent-Id':fixture.agent,
            'X-AIP-Decision-Id':fixture.decision,'X-AIP-Request-Id':uuid.uuid4().hex}))
        pre, contexts = await one.invoke_hook('tool_pre_invoke', payload, g,
                                            violations_as_exceptions=True)
        before = list(contexts or {})
        two = one
        if replace:
            await one.shutdown()
            two = TenantPluginManager(config=config)
            managers.append(two)
            await two.initialize()
        post, after = await two.invoke_hook('tool_post_invoke',
            ToolPostInvokePayload(name=fixture.tool, result={'isError':False,'content':[]}),
            g, local_contexts=contexts, violations_as_exceptions=True)
        sink = fixture.directory/'receipts.jsonl'
        receipts = [json.loads(s) for s in sink.read_text().splitlines()] if sink.exists() else []
        result = {'replace_manager':replace,'pre_allowed':pre.continue_processing,
                  'context_keys_changed':before != list(after or {}),
                  'post_modified':post.modified_payload is not None,
                  'receipts':[r['receipt']['disposition'] for r in receipts]}
        return result
    finally:
        for m in managers:
            await m.shutdown()
        fixture.tearDown()

async def main():
    results=[await scenario(False),await scenario(True)]
    old_pre=vanian_contextforge.VanianToolReceiptPlugin.tool_pre_invoke
    old_post=vanian_contextforge.VanianToolReceiptPlugin.tool_post_invoke
    @functools.wraps(old_pre)
    async def pre(self,payload,context):
        result=await old_pre(self,payload,context)
        context.global_context.state['vanian.repro.request_call']=context.get_state('vanian.receipt.call')
        return result
    @functools.wraps(old_post)
    async def post(self,payload,context):
        context.set_state('vanian.receipt.call',context.global_context.state.get('vanian.repro.request_call'))
        context.global_context.state['vanian.repro.request_call']=None
        return await old_post(self,payload,context)
    vanian_contextforge.VanianToolReceiptPlugin.tool_pre_invoke=pre
    vanian_contextforge.VanianToolReceiptPlugin.tool_post_invoke=post
    bridged=await scenario(True)
    bridged['temporary_fixture_global_state_bridge']=True
    results.append(bridged)
    print(json.dumps({'classification':'LOCAL_TYPED_CALLBACK_FIXTURE_NO_AGENT_MODEL_OR_UPSTREAM_EXECUTION',
                      'scenarios':results},indent=2))

asyncio.run(main())
