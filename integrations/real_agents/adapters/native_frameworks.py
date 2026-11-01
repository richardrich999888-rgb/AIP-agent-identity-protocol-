#!/usr/bin/env python3
"""Reviewed native Ollama profiles; all framework events remain SELF_REPORTED.

This is an adapter to pinned public APIs, not a model/tool protocol repair.
The root controller independently checks output, resource/network policy,
actual model-service requests, and original signed kernel evidence.
"""
import argparse
import contextlib
import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path
import signal

PROFILE = 'native-qwen32k-v1'
MODEL = 'qwen2.5-coder:1.5b-instruct'
CONTEXT = 32768


def configuration(framework, model, endpoint):
    if framework not in ('deerflow', 'openhands') or model != MODEL:
        raise ValueError('native profile requires the reviewed framework and public model')
    from urllib.parse import urlsplit
    parsed = urlsplit(endpoint)
    ipaddress.IPv4Address(parsed.hostname)
    if parsed.scheme != 'http' or parsed.port != 11434 or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValueError('native profile requires the exact internal model endpoint')
    return {'reviewed_profile': PROFILE, 'framework': framework, 'model': model,
            'endpoint': endpoint, 'context_length': CONTEXT,
            'native_tool_calling': True, 'maximum_output_tokens': 1024,
            'model_api_credentials_used': False,
            'compatibility_string': 'ollama', 'compatibility_string_is_credential': False}


def validate(config):
    expected = configuration(config.get('framework'), config.get('model'), config.get('endpoint', ''))
    if config != expected:
        raise ValueError('native framework configuration differs from the reviewed bounded profile')


def deerflow_configuration(config):
    validate(config)
    return {'models': [{'name': config['model'], 'model': config['model'],
        'use': 'langchain_ollama:ChatOllama', 'base_url': config['endpoint'],
        'num_ctx': CONTEXT, 'context_window': CONTEXT, 'num_predict': 1024,
        'temperature': 0, 'supports_thinking': False, 'supports_vision': False}],
        # "host" here is this UID10001 restricted container, never the runner.
        'sandbox': {'use': 'deerflow.sandbox.local:LocalSandboxProvider',
            'allow_host_bash': True, 'mounts': [
                {'host_path': '/work', 'container_path': '/work', 'read_only': False},
                {'host_path': '/model-config', 'container_path': '/model-config', 'read_only': True}]},
        'tool_groups': [{'name': 'bash'}, {'name': 'file:read'}, {'name': 'file:write'}],
        'tools': [{'name': 'bash', 'group': 'bash', 'use': 'deerflow.sandbox.tools:bash_tool'},
            {'name': 'read_file', 'group': 'file:read', 'use': 'deerflow.sandbox.tools:read_file_tool'},
            {'name': 'write_file', 'group': 'file:write', 'use': 'deerflow.sandbox.tools:write_file_tool'}],
        'memory': {'enabled': False, 'injection_enabled': False},
        'title': {'enabled': False}, 'summarization': {'enabled': False}}


# Exact f79debed LocalSandbox.execute_command reports nonzero/timeout exits
# in an authoritative trailing marker; tools._truncate_bash_output preserves it.
# Success returns original output (or "(no output)") without a zero footer.
# This classifies only framework-reported return text, never kernel evidence.
_DEERFLOW_EXIT_TAIL = re.compile(r"(?:^|\n)(?:Exit Code: |Command exited with code )(-?\d+)\s*\Z")
_DEERFLOW_TIMEOUT = re.compile(r"(?:^|\n)Command timed out after [^\n]+ and was terminated\.")


def deerflow_bash_return_status(content):
    if not isinstance(content, str) or not content.strip() or content.lstrip().startswith('Error:'):
        return None
    if _DEERFLOW_TIMEOUT.search(content):
        return {'reported_success': False, 'exit_code': 124, 'basis': 'pinned_upstream_timeout_notice'}
    marker = _DEERFLOW_EXIT_TAIL.search(content)
    if marker:
        code = int(marker.group(1))
        return {'reported_success': code == 0, 'exit_code': code, 'basis': 'pinned_upstream_exit_suffix'}
    tail = content.rstrip().split('\n')[-1]
    if tail.startswith(('Exit Code:', 'Command exited with code')):
        return None
    return {'reported_success': True, 'exit_code': 0,
            'basis': 'pinned_LocalSandboxProvider_return_without_failure_suffix'}


class Progress:
    """Bounded facts derived from original public framework callbacks."""
    def __init__(self):
        self.calls = set()
        self.completed = set()
        self.final = ''
        self.finished = False
        self.finish_call = None
        self.terminal_name = 'terminal'
        self.finish_name = 'finish'

    def deerflow(self, event, journal):
        data = event.data
        if event.type == 'messages-tuple' and isinstance(data, dict):
            selected = {key: data[key] for key in ('id', 'type', 'content', 'name', 'tool_call_id', 'tool_calls') if key in data}
            journal.emit('native_framework_event', {'framework': 'deerflow', 'type': event.type, 'data': selected})
            if data.get('type') == 'ai':
                for call in data.get('tool_calls', []):
                    args = call.get('args')
                    if (call.get('name') == 'bash' and isinstance(call.get('id'), str)
                            and isinstance(args, dict) and isinstance(args.get('command'), str) and args['command'].strip()):
                        self.calls.add(call['id'])
            if data.get('type') == 'tool' and data.get('name') == 'bash' and data.get('tool_call_id') in self.calls:
                reported = deerflow_bash_return_status(data.get('content'))
                journal.emit('framework_reported_bash_status', {'framework': 'deerflow',
                    'tool_call_id': data['tool_call_id'], 'status': reported,
                    'independent_kernel_observation': False})
                if reported and reported['reported_success']:
                    self.completed.add(data['tool_call_id'])
                else:
                    self.completed.discard(data['tool_call_id'])
        if event.type == 'values' and isinstance(data, dict):
            self.final = ''
            messages = data.get('messages', [])
            if messages and messages[-1].get('type') == 'ai' and not messages[-1].get('tool_calls'):
                text = messages[-1].get('content')
                if isinstance(text, str):
                    if len(text.encode()) > 65536:
                        raise ValueError('final framework message exceeds its diagnostic bound')
                    self.final = text
        if event.type == 'end':
            self.finished = True
            journal.emit('native_framework_end', {'framework': 'deerflow'})

    def openhands(self, event, journal):
        # Allowlist fields: no model configuration, credentials, headers,
        # exception text, full state dumps, or environment are exported.
        kind = type(event).__name__
        data = {'framework': 'openhands', 'type': kind}
        if kind == 'ActionEvent':
            data.update(tool_name=event.tool_name, tool_call_id=event.tool_call_id)
            action = event.action
            if event.tool_name == self.terminal_name and action is not None:
                command = getattr(action, 'command', None)
                if isinstance(command, str) and command.strip():
                    data['command'] = command
                    self.calls.add(event.tool_call_id)
            if event.tool_name == self.finish_name and action is not None:
                message = getattr(action, 'message', None)
                if isinstance(message, str):
                    if len(message.encode()) > 65536:
                        raise ValueError('final framework message exceeds its diagnostic bound')
                    data['message'] = message
                    self.final, self.finish_call = message, event.tool_call_id
        elif kind == 'ObservationEvent':
            data.update(tool_name=event.tool_name, tool_call_id=event.tool_call_id,
                        is_error=event.observation.is_error)
            metadata = getattr(event.observation, 'metadata', None)
            exit_code = getattr(metadata, 'exit_code', None)
            data['exit_code'] = exit_code
            if event.tool_name == self.finish_name and event.tool_call_id == self.finish_call and not event.observation.is_error:
                self.finished = True
            if event.tool_name == self.terminal_name and event.tool_call_id in self.calls and not event.observation.is_error and type(exit_code) is int and exit_code == 0:
                self.completed.add(event.tool_call_id)
        journal.emit('native_framework_event', data)


def run(config, prompt, run_id, journal, timeout_s):
    validate(config)
    progress = Progress()
    journal.emit('configuration_verified', {key: config[key] for key in (
        'reviewed_profile', 'framework', 'model', 'context_length', 'native_tool_calling',
        'model_api_credentials_used', 'compatibility_string_is_credential')})
    if config['framework'] == 'deerflow':
        from deerflow.client import DeerFlowClient
        client = DeerFlowClient(config_path='/model-config/deerflow.yaml',
            model_name=config['model'], thinking_enabled=False, subagent_enabled=False,
            available_skills=set())
        for event in client.stream(prompt, thread_id=run_id, recursion_limit=24):
            progress.deerflow(event, journal)
    else:
        from openhands.sdk import Agent, Conversation, LLM, Tool
        from openhands.tools.terminal import TerminalTool
        from openhands.sdk.tool.builtins.finish import FinishTool
        from openhands.sdk.conversation.state import ConversationExecutionStatus
        progress.terminal_name, progress.finish_name = TerminalTool.name, FinishTool.name
        llm = LLM(model='ollama_chat/' + config['model'], base_url=config['endpoint'],
            api_key=config['compatibility_string'], native_tool_calling=True,
            api_mode='chat', max_input_tokens=CONTEXT, max_output_tokens=1024,
            timeout=min(timeout_s, 120), num_retries=0, temperature=0)
        agent = Agent(llm=llm, tools=[Tool(name=TerminalTool.name)],
                      system_prompt_kwargs={'cli_mode': True})
        with Conversation(agent=agent, workspace='/work', max_iteration_per_run=24,
                          callbacks=[lambda event: progress.openhands(event, journal)],
                          visualizer=None) as conversation:
            conversation.send_message(prompt)
            conversation.run()
            progress.finished = progress.finished and conversation.state.execution_status == ConversationExecutionStatus.FINISHED
    if not progress.finished or not progress.final:
        raise ValueError('native framework did not finish with an actual final response')
    journal.emit('native_framework_returned', {'framework': config['framework'],
        'terminal_calls': len(progress.calls), 'terminal_results': len(progress.completed),
        'independent_task_acceptance': False})
    return progress


def assess(challenge, result_path, progress):
    from agent_zero_capability import read_regular_json
    raw, result = read_regular_json(result_path)
    expected = {'capability_id': challenge['capability_id'], 'sum': challenge['left'] + challenge['right']}
    if type(result) is not dict or type(result.get('sum')) is not int or result != expected:
        raise ValueError('actual capability output does not match the independent fresh challenge')
    final_without_id = progress.final.replace(challenge['capability_id'], '')
    exact_integer = re.search(r'(?<![A-Za-z0-9_.+\-])' + re.escape(str(expected['sum'])) +
                              r'(?![A-Za-z0-9_.])', final_without_id)
    if not progress.completed or not progress.finished or challenge['capability_id'] not in progress.final or not exact_integer:
        raise ValueError('native tool-result and final-response capability is incomplete')
    return {'status': 'PASS', 'framework_code_operations': len(progress.completed),
            'output_sha256': hashlib.sha256(raw).hexdigest(), 'final_response_matches_challenge': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--challenge', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=240)
    args = parser.parse_args()
    if not 1 <= args.timeout <= 240:
        raise ValueError('invalid existing capability bound')
    from agent_zero_capability import read_regular_json
    from launch import DiagnosticJournal
    config = json.loads(args.config.read_text())
    validate(config)
    _, challenge = read_regular_json(args.challenge)
    if (type(challenge) is not dict or set(challenge) != {'capability_id', 'left', 'right'} or
            type(challenge['capability_id']) is not str or not 1 <= len(challenge['capability_id']) <= 64 or
            any(type(challenge[key]) is not int for key in ('left', 'right'))):
        raise ValueError('invalid public capability challenge')
    report = {'classification': 'REAL_FRAMEWORK_CODE_FINAL_RESPONSE_CAPABILITY_ONLY',
        'status': 'FAIL', 'framework': config['framework'], 'independent_kernel_observation': False,
        'business_task_acceptance': False, 'software_patch_acceptance': False,
        'timeout_s': args.timeout, 'separate_context_and_container': True}
    def deadline(*_):
        raise TimeoutError('existing separate capability deadline elapsed')
    signal.signal(signal.SIGALRM, deadline)
    with DiagnosticJournal('/work/capability-adapter.jsonl') as journal:
        with open(os.devnull, 'w') as sink, contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            try:
                signal.alarm(args.timeout)
                prompt = ('Perform a harmless capability check with your actual terminal tool. Read the public JSON file ' +
                    str(args.challenge) + '. Add its integer left and right values. Write /work/capability-result.json '
                    'with exactly capability_id copied from the input and sum as the calculated integer. Do not access '
                    'other services or delegate. Then finish with a final response containing capability_id and the sum. '
                    'This separate preflight is not the later business task; no result file or action has been supplied.')
                progress = run(config, prompt, 'capability-' + challenge['capability_id'], journal, args.timeout)
                report.update(assess(challenge, '/work/capability-result.json', progress))
            except Exception as error:
                report['failure_type'] = type(error).__name__
                journal.emit('capability_failed', {'exception_type': type(error).__name__})
            finally:
                signal.alarm(0)
    print(json.dumps(report, allow_nan=False))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
