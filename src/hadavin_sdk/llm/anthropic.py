"""Claude through the ``anthropic`` SDK, on the Claude API, Google Vertex AI or Azure AI Foundry (``platform``).

Ports WARDEN ``AnthropicProvider`` (design 4.3): SDK retries off (``llm/retry.py`` decides), a socket timeout
per attempt, an explicit base URL on every platform, and ``output_schema`` forced through one tool.
Needs ``hadavin-sdk[anthropic]``.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import Any

import anthropic  # the extra: a missing install fails at start-up with the hint (backends.make)

from hadavin_sdk.llm.common import pinned, reply, tools_for, turns
from hadavin_sdk.llm.retry import with_retry
from hadavin_sdk.models import Reply, ToolCall

API_BASE_URL = "https://api.anthropic.com"


def _vertex_base_url(region: str) -> str:
    """As the SDK derives it. Passed explicitly because, given none, the SDK reads ANTHROPIC_VERTEX_BASE_URL
    (and the API client ANTHROPIC_BASE_URL) and sends the credential wherever that names (WARDEN review)."""
    if region == "global":
        return "https://aiplatform.googleapis.com/v1"
    if region in ("us", "eu"):
        return f"https://aiplatform.{region}.rep.googleapis.com/v1"
    return f"https://{region}-aiplatform.googleapis.com/v1"


def client(settings: Any, resolve: Callable[[str], str]) -> Any:
    common = {"timeout": settings.call_timeout_s, "max_retries": 0}
    if (
        settings.platform == "vertex"
    ):  # Google credentials from the workload's identity (ADC), no key
        return anthropic.AnthropicVertex(
            region=settings.region,
            project_id=settings.project_id,
            base_url=_vertex_base_url(settings.region),
            **common,
        )
    key = resolve(settings.api_key_secret_name)
    if settings.platform == "foundry":
        return anthropic.AnthropicFoundry(
            api_key=key,
            base_url=f"https://{settings.resource}.services.ai.azure.com/anthropic/",
            **common,
        )
    return anthropic.Anthropic(api_key=key, base_url=API_BASE_URL, **common)


def make(settings: Any, deps: Any) -> AnthropicLLM:
    return AnthropicLLM(
        client(settings, deps.resolve), pinned(dict(deps.routes)), settings.max_attempts
    )


class AnthropicLLM:
    def __init__(
        self,
        client: Any,
        routes: dict[str, Any],
        max_attempts: int,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._client, self.routes = client, routes
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
        request: dict[str, Any] = {
            "model": r.model_id,
            "max_tokens": r.max_tokens,
            "system": system,
            "messages": [
                {"role": role, "content": [{"type": "text", "text": t} for t in texts]}
                for role, texts in turns(messages, documents)
            ],
        }
        if specs:
            request["tools"] = specs
        if forced:
            request["tool_choice"] = {"type": "tool", "name": forced}
        started = time.monotonic()
        resp = with_retry(
            lambda: self._client.messages.create(**request),
            label="anthropic",
            max_attempts=self.max_attempts,
            sleep=self._sleep,
        )
        # Thinking blocks are the model's working, never its answer: only text and tool calls are read.
        return reply(
            r,
            text="".join(b.text for b in resp.content if b.type == "text"),
            calls=[
                ToolCall(name=b.name, input=b.input) for b in resp.content if b.type == "tool_use"
            ],
            tokens=(resp.usage.input_tokens, resp.usage.output_tokens),
            stop=resp.stop_reason,
            started=started,
            sent=system + json.dumps(request["messages"]),
        )
