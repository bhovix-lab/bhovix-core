"""Any OpenAI-shaped chat API (OpenAI, Groq, OpenRouter, a local Ollama) over stdlib HTTP, no SDK.

Ports WARDEN ``OpenAICompatProvider`` (design 4.3). The key goes only to the configured ``base_url`` (https, or a
keyless loopback model; checked in the settings), never through a redirect, and is read on every call (a rotated
key is picked up). ``output_schema`` is forced through ``tool_choice``; a server that ignores it answers in text,
read as JSON, with one more request if it is not.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import Any

from hadavin_sdk.llm.common import (
    Answer,
    NetworkLLM,
    json_in_text,
    pinned,
    post_json,
    reply,
    schema_hint,
    stop_reason,
)
from hadavin_sdk.models import Reply, ToolCall


def make(settings: Any, deps: Any) -> OpenAICompatLLM:
    name = settings.api_key_secret_name
    return OpenAICompatLLM(
        settings.base_url,
        (lambda: deps.resolve(name)) if name else None,
        pinned(dict(deps.routes)),
        settings.call_timeout_s,
        settings.max_attempts,
        cap_field="max_completion_tokens" if settings.max_completion_tokens else "max_tokens",
    )


def _call(tool_call: dict[str, Any]) -> ToolCall | None:
    """The function call, or None when its arguments are not a JSON object (never guessed at)."""
    fn = tool_call.get("function") or {}
    try:
        args = json.loads(fn.get("arguments") or "{}")
    except ValueError:
        return None
    return ToolCall(name=fn.get("name", ""), input=args) if isinstance(args, dict) else None


class OpenAICompatLLM(NetworkLLM):
    label = "openai_compat"

    def __init__(
        self,
        base_url: str,
        key: Callable[[], str] | None,
        routes: dict[str, Any],
        call_timeout_s: float,
        max_attempts: int,
        sleep: Callable[[float], None] = time.sleep,
        cap_field: str = "max_tokens",
    ) -> None:
        super().__init__(routes, max_attempts, sleep)
        self.url = base_url.rstrip("/") + "/chat/completions"
        self._key, self.timeout_s, self.cap_field = key, call_timeout_s, cap_field

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._key()}"} if self._key else {}

    def _chat(self, route, system, turns, specs, forced, output_schema) -> Reply:
        if forced:  # also in the prompt, for a server that ignores tool_choice
            system = schema_hint(system, output_schema)
        body: dict[str, Any] = {
            "model": route.model_id,
            self.cap_field: route.max_tokens,
            "messages": ([{"role": "system", "content": system}] if system else [])
            + [{"role": role, "content": "\n\n".join(texts)} for role, texts in turns],
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
            got = self._retry(
                lambda: self._parse(post_json(self.url, body, self._headers(), self.timeout_s))
            )
            used = [used[0] + (got.tokens[0] or 0), used[1] + (got.tokens[1] or 0)]
            # Done when answered, or when asking again would end the same way (cut off, refused).
            done = stop_reason(got.stop, got.calls) in ("max_tokens", "refusal")
            if done or not forced or any(c.name == forced for c in got.calls):
                break
            if (found := json_in_text(got.text)) is not None:
                got.calls = [ToolCall(name=forced, input=found)]
                break
        # Some servers (Ollama among them) omit usage: None is estimated in reply().
        got.tokens = (used[0] or None, used[1] or None)
        return reply(route, **vars(got), started=started, sent=json.dumps(body["messages"]))

    @staticmethod
    def _parse(resp: dict[str, Any]) -> Answer:
        choice = resp["choices"][0]
        message = choice.get("message") or {}
        usage = resp.get("usage") or {}
        return Answer(
            text=message.get("content") or "",
            calls=[c for c in map(_call, message.get("tool_calls") or []) if c is not None],
            tokens=(usage.get("prompt_tokens"), usage.get("completion_tokens")),
            stop=choice.get("finish_reason"),
        )
