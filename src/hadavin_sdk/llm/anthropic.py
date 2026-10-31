"""Claude through the ``anthropic`` SDK, on the Claude API, Google Vertex AI or Azure AI Foundry (``platform``).

Ports WARDEN ``AnthropicProvider`` (design 4.3): SDK retries off (``llm/retry.py`` decides), a socket timeout
(``call_timeout_s``, per socket operation, not a wall clock), an explicit base URL on every platform, the key read
on every call (a rotated key is picked up), and ``output_schema`` forced through one tool.
Needs ``hadavin-sdk[anthropic]``.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from typing import Any

import anthropic  # the extra: a missing install fails at start-up with the hint (backends.make)

from hadavin_sdk.errors import ConfigError
from hadavin_sdk.llm.common import Answer, NetworkLLM, pinned, reply
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


def client(settings: Any, key: str | None) -> Any:
    common = {"timeout": settings.call_timeout_s, "max_retries": 0}
    try:
        if (
            settings.platform == "vertex"
        ):  # Google credentials from the workload's identity (ADC), no key
            return anthropic.AnthropicVertex(
                region=settings.region,
                project_id=settings.project_id,
                base_url=_vertex_base_url(settings.region),
                **common,
            )
        if settings.platform == "foundry":
            return anthropic.AnthropicFoundry(
                api_key=key,
                base_url=f"https://{settings.resource}.services.ai.azure.com/anthropic/",
                **common,
            )
        return anthropic.Anthropic(api_key=key, base_url=API_BASE_URL, **common)
    except ValueError as exc:  # e.g. ANTHROPIC_FOUNDRY_RESOURCE set beside our explicit base URL
        raise ConfigError(f"backend llm 'anthropic' ({settings.platform}): {exc}") from exc


# Claude's moving aliases. Every Claude API id is a pinned snapshot (WARDEN, checked 2026-10-02), dated or not.
_ALIASES = re.compile(r"(?i)^(?:sonnet|opus|haiku|fable|default|best|opusplan)(?:\[1m\])?$")


def floating(model_id: str) -> bool:
    return bool(_ALIASES.match(model_id))


def retryable(exc: BaseException) -> bool | None:
    """The SDK's own network errors (a status error is decided by its `status_code`, generically)."""
    if isinstance(exc, anthropic.APIConnectionError):  # includes APITimeoutError
        return True
    try:  # Vertex refreshes a Google token through google-auth (installed with the vertex extra)
        from google.auth import exceptions as google_auth
    except ImportError:
        return None
    if isinstance(exc, google_auth.RefreshError):
        return False  # bad or missing credentials
    return True if isinstance(exc, google_auth.TransportError) else None


def make(settings: Any, deps: Any) -> AnthropicLLM:
    name = settings.api_key_secret_name if settings.platform != "vertex" else None
    key = (lambda: deps.resolve(name)) if name else None
    return AnthropicLLM(
        client(settings, key() if key else None),
        pinned(dict(deps.routes), floating),
        settings.max_attempts,
        key=key,
    )


class AnthropicLLM(NetworkLLM):
    label = "anthropic"
    retryable = staticmethod(retryable)

    def __init__(
        self,
        client: Any,
        routes: dict[str, Any],
        max_attempts: int,
        sleep: Callable[[float], None] = time.sleep,
        key: Callable[[], str] | None = None,
    ) -> None:
        super().__init__(routes, max_attempts, sleep)
        self._client, self._key = client, key

    def _chat(self, route, system, turns, specs, forced, output_schema) -> Reply:
        request: dict[str, Any] = {
            "model": route.model_id,
            "max_tokens": route.max_tokens,
            "messages": [
                {"role": role, "content": [{"type": "text", "text": t} for t in texts]}
                for role, texts in turns
            ],
        }
        if system:
            request["system"] = system
        if specs:
            request["tools"] = specs
        if forced:
            request["tool_choice"] = {"type": "tool", "name": forced}
        started = time.monotonic()
        got = self._retry(lambda: self._parse(self._current().messages.create(**request)))
        return reply(
            route,
            **vars(got),
            started=started,
            sent=system + json.dumps(request["messages"]),
        )

    def _current(self) -> Any:
        """The client with today's key: the platform secret is read per call, so rotation needs no restart."""
        return self._client.with_options(api_key=self._key()) if self._key else self._client

    @staticmethod
    def _parse(resp: Any) -> Answer:
        # Thinking blocks are the model's working, never its answer: only text and tool calls are read.
        return Answer(
            text="".join(b.text for b in resp.content if b.type == "text"),
            calls=[
                ToolCall(name=b.name, input=b.input) for b in resp.content if b.type == "tool_use"
            ],
            tokens=(resp.usage.input_tokens, resp.usage.output_tokens),
            stop=resp.stop_reason,
        )
