"""Any OpenAI-shaped chat API (OpenAI, Groq, OpenRouter, a local Ollama) over stdlib HTTP, no SDK.

Ports WARDEN ``OpenAICompatProvider`` (design 4.3). The key goes only to the configured ``base_url`` (https, or a
keyless loopback model; checked in the settings), never through a redirect. ``output_schema`` is forced through
``tool_choice``; a server that ignores it answers in text, read as JSON, with one more request if it is not.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import Any

from hadavin_sdk.llm.common import (
    json_in_text,
    pinned,
    post_json,
    reply,
    schema_hint,
    tools_for,
    turns,
)
from hadavin_sdk.llm.retry import with_retry
from hadavin_sdk.models import Reply, ToolCall


def make(settings: Any, deps: Any) -> OpenAICompatLLM:
    name = settings.api_key_secret_name
    return OpenAICompatLLM(
        settings.base_url,
        deps.resolve(name) if name else None,
        pinned(dict(deps.routes)),
        settings.call_timeout_s,
        settings.max_attempts,
    )


def _call(tool_call: dict[str, Any]) -> ToolCall | None:
    """The function call, or None when its arguments are not a JSON object (never guessed at)."""
    fn = tool_call.get("function") or {}
    try:
        args = json.loads(fn.get("arguments") or "{}")
    except ValueError:
        return None
    return ToolCall(name=fn.get("name", ""), input=args) if isinstance(args, dict) else None


class OpenAICompatLLM:
    def __init__(
        self,
        base_url: str,
        api_key: str | None,
        routes: dict[str, Any],
        call_timeout_s: float,
        max_attempts: int,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.url = base_url.rstrip("/") + "/chat/completions"
        self._headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self.routes, self.timeout_s = routes, call_timeout_s
        self.max_attempts, self._sleep = max_attempts, sleep

    def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        system: str,
        route: str,
        tools: list[dict[str, Any]] | None = None,
        documents: list[bytes] | None = None,
        output_schema: dict[str, Any] | None = None,
    ) -> Reply:
        r = self.routes[route]
        specs, forced = tools_for(tools, output_schema)
        if forced:  # also in the prompt, for a server that ignores tool_choice
            system = schema_hint(system, output_schema)
        body: dict[str, Any] = {
            "model": r.model_id,
            "max_tokens": r.max_tokens,
            "messages": [{"role": "system", "content": system}]
            + [
                {"role": role, "content": "\n\n".join(texts)}
                for role, texts in turns(messages, documents)
            ],
        }
        if specs:
            body["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": s["name"],
                        "description": s["description"],
                        "parameters": s["input_schema"],
                    },
                }
                for s in specs
            ]
        if forced:
            body["tool_choice"] = {"type": "function", "function": {"name": forced}}
        started, used = time.monotonic(), [0, 0]
        for _ in range(2):  # the forced answer missing: one more request (design 4.3)
            resp = with_retry(
                lambda: post_json(self.url, body, self._headers, self.timeout_s),
                label="openai_compat",
                max_attempts=self.max_attempts,
                sleep=self._sleep,
            )
            choice = resp["choices"][0]
            message = choice.get("message") or {}
            text = message.get("content") or ""
            calls = [c for c in map(_call, message.get("tool_calls") or []) if c is not None]
            usage = resp.get("usage") or {}
            # Some servers (Ollama among them) omit usage: 0 here, estimated in reply().
            used = [
                used[0] + (usage.get("prompt_tokens") or 0),
                used[1] + (usage.get("completion_tokens") or 0),
            ]
            if not forced or any(c.name == forced for c in calls):
                break
            if (found := json_in_text(text)) is not None:
                calls = [ToolCall(name=forced, input=found)]
                break
        return reply(
            r,
            text=text,
            calls=calls,
            tokens=(used[0], used[1]),
            stop=choice.get("finish_reason"),
            started=started,
            sent=json.dumps(body["messages"]),
        )
