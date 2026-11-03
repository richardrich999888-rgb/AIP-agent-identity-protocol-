"""Actual local model inference through ADK's supported BaseLlm interface.

No canned model responses. Invalid generated tool JSON fails the workload.
Used only with synthetic records in the interoperability validation lab.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_response import LlmResponse
from google.genai import types
from pydantic import PrivateAttr


class LocalQwen(BaseLlm):
    _tokenizer: Any = PrivateAttr()
    _network: Any = PrivateAttr()
    _transcript: Path = PrivateAttr()
    _lock: Any = PrivateAttr()

    def __init__(self, model_directory: str, transcript: Path):
        super().__init__(model="Qwen/Qwen2.5-0.5B-Instruct@7ae557604adf67be50417f59c2c2f167def9a775")
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
        torch.set_num_threads(4)
        self._tokenizer = AutoTokenizer.from_pretrained(model_directory, local_files_only=True, trust_remote_code=False)
        self._network = AutoModelForCausalLM.from_pretrained(model_directory, local_files_only=True,
                                                            trust_remote_code=False, torch_dtype=torch.float32)
        self._transcript, self._lock = transcript, asyncio.Lock()

    def _generate(self, messages):
        import torch
        text = self._tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = self._tokenizer([text], return_tensors="pt")
        with torch.inference_mode():
            output = self._network.generate(**inputs, max_new_tokens=220, do_sample=False,
                pad_token_id=self._tokenizer.eos_token_id)
        return self._tokenizer.decode(output[0][inputs.input_ids.shape[1]:], skip_special_tokens=True)

    async def generate_content_async(self, llm_request, stream=False):
        tools = []
        for tool in llm_request.config.tools or []:
            for declaration in tool.function_declarations or []:
                tools.append(declaration.model_dump(mode="json", exclude_none=True))
        instruction = str(llm_request.config.system_instruction or "")
        system = instruction + "\nAvailable tools: " + json.dumps(tools) + (
            '\nWhen you need a tool, output ONLY a JSON object: {"tool": "name", "arguments": {"record_id": "SYN-001"}}. '
            'Use the record ID requested by the user. After a tool result, give a short factual answer and do not call it again.')
        messages = [{"role": "system", "content": system}]
        for content in llm_request.contents:
            parts = []
            for part in content.parts or []:
                if part.text:
                    parts.append(part.text)
                if part.function_call:
                    parts.append(json.dumps({"tool": part.function_call.name, "arguments": part.function_call.args}))
                if part.function_response:
                    parts.append("Tool result: " + json.dumps(part.function_response.response))
            messages.append({"role": "assistant" if content.role == "model" else "user", "content": "\n".join(parts)})
        async with self._lock:
            generated = await asyncio.to_thread(self._generate, messages)
            with self._transcript.open("a") as out:
                out.write(json.dumps({"model": self.model, "messages": messages, "generated": generated}) + "\n")
        stripped = generated.strip()
        if stripped.startswith("```json") and stripped.endswith("```"):
            stripped = stripped[7:-3].strip()
        if stripped.startswith("{"):
            call = json.loads(stripped)
            names = {item["name"] for item in tools}
            if "tool" in call:
                if call.get("tool") not in names or not isinstance(call.get("arguments"), dict):
                    raise ValueError("model generated an unsupported tool call")
                part = types.Part(function_call=types.FunctionCall(name=call["tool"], args=call["arguments"]))
            else:
                part = types.Part(text=generated)
        else:
            part = types.Part(text=generated)
        yield LlmResponse(content=types.Content(role="model", parts=[part]))
